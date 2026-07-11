package com.example.tlswatchdog.vpn

import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.ServiceCompat
import com.example.tlswatchdog.attribution.Attribution
import com.example.tlswatchdog.data.AppSelection
import com.example.tlswatchdog.data.FlowEntity
import com.example.tlswatchdog.data.FlowRepository
import com.example.tlswatchdog.detect.FlowClassifier
import com.example.tlswatchdog.util.Notifications
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.net.InetAddress

class TlsWatchdogVpnService : VpnService(), VpnCallbacks {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var repo: FlowRepository
    private lateinit var attribution: Attribution
    private var running = false

    override fun onCreate() {
        super.onCreate()
        repo = FlowRepository(this)
        attribution = Attribution(this)
        Notifications.createChannels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (running) return
        val selected = runBlocking { AppSelection.get(this@TlsWatchdogVpnService) }
        if (selected.isEmpty()) {
            Log.w(TAG, "no apps selected; not starting")
            stopSelf()
            return
        }

        val builder = Builder()
            .setSession("TLS Watchdog")
            .setMtu(MTU)
            .addAddress("10.215.173.1", 32)
            .addRoute("0.0.0.0", 0)
            .addAddress("fd00:1:2:3::1", 128)
            .addRoute("::", 0)

        var added = 0
        for (pkg in selected) {
            try {
                builder.addAllowedApplication(pkg)
                added++
            } catch (e: PackageManager.NameNotFoundException) {
                Log.w(TAG, "package not found, skipping: $pkg")
            }
        }
        if (added == 0) {
            stopSelf()
            return
        }

        val pfd: ParcelFileDescriptor = builder.establish() ?: run {
            Log.e(TAG, "establish() returned null (missing consent?)")
            stopSelf()
            return
        }

        ServiceCompat.startForeground(
            this,
            Notifications.FOREGROUND_ID,
            Notifications.foreground(this, "Monitoring $added app(s)"),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
        )

        val fd = pfd.detachFd()
        NativeBridge.nativeStartCapture(fd, MTU, this)
        running = true
        VpnController.setRunning(true)
        Log.i(TAG, "VPN started, monitoring $added apps")
    }

    private fun stopVpn() {
        if (running) {
            NativeBridge.nativeStopCapture()
            running = false
        }
        VpnController.setRunning(false)
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        if (running) {
            NativeBridge.nativeStopCapture()
            running = false
            VpnController.setRunning(false)
        }
        super.onDestroy()
    }

    // --- VpnCallbacks (invoked on the native capture thread) ---

    override fun protectSocket(fd: Int): Boolean = protect(fd)

    override fun onFlow(
        ipver: Int,
        proto: Int,
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        firstBytes: ByteArray,
    ) {
        val dstAddr = try {
            InetAddress.getByAddress(dstIp).hostAddress ?: "?"
        } catch (e: Exception) {
            "?"
        }
        scope.launch {
            val verdict = FlowClassifier.classify(proto, firstBytes)
            val uid = attribution.uidFor(proto, srcIp, srcPort, dstIp, dstPort)
            val (pkg, label) = attribution.appFor(uid)
            repo.insert(
                FlowEntity(
                    timestamp = System.currentTimeMillis(),
                    uid = uid,
                    packageName = pkg,
                    appLabel = label,
                    srcPort = srcPort,
                    dstIp = dstAddr,
                    dstPort = dstPort,
                    proto = proto,
                    verdict = verdict.name,
                    isOffender = verdict.isOffender,
                    firstBytesHex = firstBytes.toHex(),
                ),
            )
            if (verdict.isOffender) {
                Notifications.cleartextAlert(
                    this@TlsWatchdogVpnService,
                    label ?: pkg,
                    "$dstAddr:$dstPort",
                )
            }
        }
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG = "TlsWatchdogVpn"
        const val MTU = 1500
        const val ACTION_START = "com.example.tlswatchdog.START"
        const val ACTION_STOP = "com.example.tlswatchdog.STOP"
    }
}

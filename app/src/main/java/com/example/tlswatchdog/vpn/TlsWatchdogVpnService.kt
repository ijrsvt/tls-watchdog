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
import com.example.tlswatchdog.util.PayloadRedactor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import java.net.InetAddress

class TlsWatchdogVpnService : VpnService(), VpnCallbacks {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var repo: FlowRepository
    private lateinit var attribution: Attribution
    private var running = false
    private var recordCleartext = false
    private var flagUdp = false
    private var recordCap = 0

    // Correlate native flow ids with DB row ids. onFlow (insert) and onFlowClose
    // (stats) race, so guard the maps and stash stats that arrive before the row.
    private data class FlowStats(
        val bytesOut: Long,
        val bytesIn: Long,
        val packets: Int,
        val durationMs: Long,
        val reqText: String?,
        val respText: String?,
    )
    private val flowIdToRow = HashMap<Long, Long>()
    private val flowOffender = HashMap<Long, Boolean>()
    private val pendingClose = HashMap<Long, FlowStats>()
    private val bookkeeping = kotlinx.coroutines.sync.Mutex()

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
        recordCleartext = runBlocking { AppSelection.getRecord(this@TlsWatchdogVpnService) }
        flagUdp = runBlocking { AppSelection.getFlagUdp(this@TlsWatchdogVpnService) }
        recordCap = if (recordCleartext) runBlocking { AppSelection.getCap(this@TlsWatchdogVpnService) } else 0
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

        val statusText = "Monitoring $added app(s)" + if (recordCleartext) " · recording cleartext" else ""
        ServiceCompat.startForeground(
            this,
            Notifications.FOREGROUND_ID,
            Notifications.foreground(this, statusText),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
        )

        val fd = pfd.detachFd()
        NativeBridge.nativeStartCapture(fd, MTU, recordCap, this)
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
        flowId: Long,
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
            val verdict = FlowClassifier.classify(proto, dstPort, firstBytes)
            val host = FlowClassifier.extractHost(proto, firstBytes)
            val offender = verdict.isOffender(flagUdp)
            val uid = attribution.uidFor(proto, srcIp, srcPort, dstIp, dstPort)
            val (pkg, label) = attribution.appFor(uid)
            // Payload samples are filled in by live updates / close.
            val rowId = repo.insert(
                FlowEntity(
                    timestamp = System.currentTimeMillis(),
                    uid = uid,
                    packageName = pkg,
                    appLabel = label,
                    srcPort = srcPort,
                    dstIp = dstAddr,
                    dstPort = dstPort,
                    host = host,
                    proto = proto,
                    verdict = verdict.name,
                    isOffender = offender,
                    // Redact secret-bearing headers before persisting. Stored regardless
                    // of the record toggle, but backups are blocked so it stays on-device.
                    firstBytesHex = PayloadRedactor.redactBytes(firstBytes).toHex(),
                ),
            )
            bookkeeping.withLock {
                flowIdToRow[flowId] = rowId
                flowOffender[flowId] = offender
                pendingClose.remove(flowId)?.let { s ->
                    repo.updateStats(
                        rowId, s.bytesOut, s.bytesIn, s.packets, s.durationMs,
                        if (offender) s.reqText else null, if (offender) s.respText else null,
                    )
                    flowIdToRow.remove(flowId)
                    flowOffender.remove(flowId)
                }
            }
            if (offender) {
                Notifications.cleartextAlert(
                    this@TlsWatchdogVpnService,
                    label ?: pkg,
                    host ?: "$dstAddr:$dstPort",
                )
            }
        }
    }

    override fun onFlowUpdate(
        flowId: Long,
        bytesOut: Long,
        bytesIn: Long,
        packets: Int,
        durationMs: Long,
        reqSample: ByteArray,
        respSample: ByteArray,
    ) {
        scope.launch {
            val reqText = if (reqSample.isNotEmpty()) reqSample.toPreview().redact() else null
            val respText = if (respSample.isNotEmpty()) respSample.toPreview().redact() else null
            bookkeeping.withLock {
                val rowId = flowIdToRow[flowId] ?: return@withLock
                val keep = flowOffender[flowId] ?: false
                repo.updateStats(
                    rowId, bytesOut, bytesIn, packets, durationMs,
                    if (keep) reqText else null, if (keep) respText else null,
                )
            }
        }
    }

    override fun onFlowClose(
        flowId: Long,
        bytesOut: Long,
        bytesIn: Long,
        packets: Int,
        durationMs: Long,
        reqSample: ByteArray,
        respSample: ByteArray,
    ) {
        scope.launch {
            val reqText = if (reqSample.isNotEmpty()) reqSample.toPreview().redact() else null
            val respText = if (respSample.isNotEmpty()) respSample.toPreview().redact() else null
            bookkeeping.withLock {
                val rowId = flowIdToRow.remove(flowId)
                if (rowId != null) {
                    val keep = flowOffender.remove(flowId) ?: false
                    repo.updateStats(
                        rowId, bytesOut, bytesIn, packets, durationMs,
                        if (keep) reqText else null, if (keep) respText else null,
                    )
                } else {
                    // Flow closed before its row insert finished; apply on insert.
                    pendingClose[flowId] = FlowStats(bytesOut, bytesIn, packets, durationMs, reqText, respText)
                }
            }
        }
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }

    /** Decode to a printable preview: keep ASCII text + newlines/tabs, replace the rest with '.'. */
    private fun ByteArray.toPreview(): String =
        buildString(size) {
            for (b in this@toPreview) {
                val c = b.toInt() and 0xff
                append(if (c in 0x20..0x7e || c == 0x0a || c == 0x0d || c == 0x09) c.toChar() else '.')
            }
        }

    /** Mask secret-bearing HTTP headers (Authorization, Cookie, …) before persisting. */
    private fun String.redact(): String = PayloadRedactor.redactText(this)

    companion object {
        private const val TAG = "TlsWatchdogVpn"
        const val MTU = 1500
        const val ACTION_START = "com.example.tlswatchdog.START"
        const val ACTION_STOP = "com.example.tlswatchdog.STOP"
    }
}

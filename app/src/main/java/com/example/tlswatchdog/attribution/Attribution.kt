package com.example.tlswatchdog.attribution

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Process
import java.net.InetAddress
import java.net.InetSocketAddress

/** Maps a flow's 5-tuple to the owning app via getConnectionOwnerUid (API 29+). */
class Attribution(context: Context) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val pm: PackageManager = context.packageManager
    private val labelCache = HashMap<Int, Pair<String?, String?>>() // uid -> (pkg, label)

    /** @return uid or Process.INVALID_UID if unknown. */
    fun uidFor(proto: Int, srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int): Int {
        return try {
            val local = InetSocketAddress(InetAddress.getByAddress(srcIp), srcPort)
            val remote = InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort)
            cm.getConnectionOwnerUid(proto, local, remote)
        } catch (e: Exception) {
            Process.INVALID_UID
        }
    }

    /** @return (packageName, appLabel) best-effort for the uid. */
    fun appFor(uid: Int): Pair<String?, String?> {
        if (uid == Process.INVALID_UID || uid < 0) return null to null
        labelCache[uid]?.let { return it }
        val result = try {
            val pkgs = pm.getPackagesForUid(uid)
            val pkg = pkgs?.firstOrNull()
            val label = pkg?.let {
                pm.getApplicationLabel(pm.getApplicationInfo(it, 0)).toString()
            }
            pkg to label
        } catch (e: Exception) {
            null to null
        }
        labelCache[uid] = result
        return result
    }
}

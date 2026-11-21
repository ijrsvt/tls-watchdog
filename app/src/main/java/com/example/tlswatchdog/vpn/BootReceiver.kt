package com.example.tlswatchdog.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.example.tlswatchdog.data.AppSelection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Best-effort auto-start after boot. Only works if VPN consent was already granted
 * (prepare() == null); otherwise the user must start it manually since a receiver
 * cannot show the consent dialog.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val auto = AppSelection.observeAutoStart(context).first()
                val monitorAll = AppSelection.getMonitorAllApps(context)
                val apps = AppSelection.get(context)
                if (auto && (monitorAll || apps.isNotEmpty()) && VpnService.prepare(context) == null) {
                    VpnController.start(context)
                }
            } catch (e: Exception) {
                // best effort
            } finally {
                pending.finish()
            }
        }
    }
}

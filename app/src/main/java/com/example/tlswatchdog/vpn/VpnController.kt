package com.example.tlswatchdog.vpn

import android.content.Context
import android.content.Intent
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Small global holder for VPN running state + start/stop helpers. */
object VpnController {
    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running

    fun setRunning(value: Boolean) {
        _running.value = value
    }

    fun start(context: Context) {
        val intent = Intent(context, TlsWatchdogVpnService::class.java).apply {
            action = TlsWatchdogVpnService.ACTION_START
        }
        context.startForegroundService(intent)
    }

    fun stop(context: Context) {
        val intent = Intent(context, TlsWatchdogVpnService::class.java).apply {
            action = TlsWatchdogVpnService.ACTION_STOP
        }
        context.startService(intent)
    }
}

package com.example.tlswatchdog.util

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationCompat
import com.example.tlswatchdog.R

object Notifications {
    const val CHANNEL_STATUS = "status"
    const val CHANNEL_ALERT = "cleartext_alert"
    const val FOREGROUND_ID = 1

    private var alertId = 1000

    fun createChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_STATUS,
                "Monitoring status",
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ALERT,
                "Cleartext alerts",
                NotificationManager.IMPORTANCE_HIGH,
            ).apply { description = "Fired when an app sends traffic without TLS" },
        )
    }

    fun foreground(context: Context, text: String): Notification =
        NotificationCompat.Builder(context, CHANNEL_STATUS)
            .setContentTitle("TLS Watchdog")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher)
            .setOngoing(true)
            .build()

    fun cleartextAlert(context: Context, app: String?, dest: String) {
        val nm = context.getSystemService(NotificationManager::class.java)
        val n = NotificationCompat.Builder(context, CHANNEL_ALERT)
            .setContentTitle("Cleartext detected")
            .setContentText("${app ?: "An app"} → $dest is not using TLS")
            .setSmallIcon(R.drawable.ic_launcher)
            .setAutoCancel(true)
            .build()
        nm.notify(alertId++, n)
    }
}

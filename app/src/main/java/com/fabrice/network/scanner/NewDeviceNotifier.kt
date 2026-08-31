package com.fabrice.network.scanner

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat

/**
 * Alertes « nouveaux appareils » (notification push) — v1.7.0.
 *
 * Après un scan réussi, si de nouveaux appareils apparaissent (par rapport à
 * l'historique) ET que le toggle `new_device_alerts` est ON, on envoie une
 * notification. On ne notifie JAMAIS au tout premier scan (historique vide :
 * tout serait « nouveau ») — la logique de skip est gérée par l'appelant.
 */
object NewDeviceNotifier {

    const val CHANNEL_ID = "new_devices"
    const val PREFS = "settings"
    const val KEY_ALERTS = "new_device_alerts"
    private const val NOTIFICATION_ID = 1001

    /** Le toggle d'alerte est-il actif ? (défaut ON). */
    fun isEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_ALERTS, true)

    /** Active/désactive les alertes « nouveaux appareils ». */
    fun setEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_ALERTS, enabled).apply()
    }

    /** Titre de la notification (pluriel français correct, sans concat d'affixe). */
    fun buildTitle(count: Int): String =
        if (count <= 1) "🆕 1 nouvel appareil détecté"
        else "🆕 $count nouveaux appareils détectés"

    /** Texte de la notification : noms/IP des 3 premiers + « et X autres… ». */
    fun buildNotificationText(devices: List<Device>): String {
        if (devices.isEmpty()) return ""
        val head = devices.take(3).joinToString(", ") { it.hostname.ifBlank { it.ip } }
        return if (devices.size > 3) "$head et ${devices.size - 3} autres…" else head
    }

    /** Envoie la notification (no-op si liste vide ou toggle OFF). */
    fun notify(context: Context, newDevices: List<Device>) {
        if (newDevices.isEmpty()) return
        if (!isEnabled(context)) return
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Nouveaux appareils", NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pending = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notif = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(buildTitle(newDevices.size))
            .setContentText(buildNotificationText(newDevices))
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()
        runCatching { nm.notify(NOTIFICATION_ID, notif) }
    }

    /** Alerte « credential par défaut » (même canal que les nouveaux appareils). */
    fun notifyDefaultCred(context: Context, device: Device) {
        val cred = device.defaultCred ?: return
        if (!isEnabled(context)) return
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Nouveaux appareils", NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pending = PendingIntent.getActivity(
            context, 1, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notif = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("🚨 Credential par défaut détectée")
            .setContentText("🚨 ${device.ip} (${device.hostname.ifBlank { device.ip }}) accessible avec $cred !")
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()
        runCatching { nm.notify(NOTIFICATION_ID + 1, notif) }
    }

    /** Alerte « niveau de consommable bas » sur une imprimante (même canal). */
    fun notifyTonerLow(context: Context, device: Device, supply: PrinterProbe.Supply) {
        if (!isEnabled(context)) return
        val lvl = supply.levelPercent ?: return
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Nouveaux appareils", NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pending = PendingIntent.getActivity(
            context, 2, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val label = supply.name.ifBlank { supply.color.ifBlank { supply.type } }.ifBlank { "Consommable" }
        val printer = device.hostname.ifBlank { device.ip }
        val notif = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("🖨️ Niveau bas : $label ($lvl %)")
            .setContentText("$printer — pensez à prévoir un remplacement.")
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()
        // Id stable par (imprimante, consommable) → une notif distincte par cartouche.
        runCatching { nm.notify(2000 + ((device.ip + label).hashCode() and 0xFFFF), notif) }
    }
}

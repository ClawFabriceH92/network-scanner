package com.fabrice.network.scanner

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat

/**
 * Alerte de départ (v1.9.3) : à la fin d'un scan, compare la liste courante à
 * la précédente — les appareils qui étaient là et ne répondent plus déclenchent
 * une notification « appareil absent ».
 *
 * On n'alerte JAMAIS pour : le téléphone qui scanne (isSelf), la passerelle
 * (isGateway), les appareils sans MAC (clé d'identité non fiable — l'IP peut
 * être réattribuée) ni les appareils de confiance ([TrustStore]).
 */
object DepartureAlert {

    /** Canal réutilisé (celui des « nouveaux appareils », déjà déclaré). */
    const val CHANNEL_ID = NewDeviceNotifier.CHANNEL_ID
    private const val NOTIFICATION_ID = 1003

    /**
     * Appareils présents dans [previous] mais absents de [current].
     *
     * Filtre : ignore l'appareil courant, la passerelle, les appareils sans MAC
     * (identité non fiable) et les clés de confiance [trusted].
     * Pure → testable en JVM.
     */
    fun detectDepartures(
        previous: List<Device>,
        current: List<Device>,
        trusted: Set<String> = emptySet()
    ): List<Device> {
        val now = current.map { ScanHistory.identityKey(it) }.toSet()
        return previous.filter { d ->
            val key = ScanHistory.identityKey(d)
            d.mac.isNotBlank() &&
                !d.isSelf &&
                !d.isGateway &&
                key !in trusted &&
                key !in now
        }
    }

    /** Titre de la notification (pluriel français correct). */
    fun buildTitle(count: Int): String =
        if (count <= 1) "📴 1 appareil absent"
        else "📴 $count appareils absents"

    /** Texte : noms/IP des 3 premiers + « et X autres… ». */
    fun buildNotificationText(devices: List<Device>): String {
        if (devices.isEmpty()) return ""
        val head = devices.take(3).joinToString(", ") { it.hostname.ifBlank { it.ip } }
        return if (devices.size > 3) "$head et ${devices.size - 3} autres…" else head
    }

    /** Envoie la notification « appareil absent » (no-op si liste vide). */
    fun notify(context: Context, departed: List<Device>) {
        if (departed.isEmpty()) return
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
            context, 3, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notif = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(buildTitle(departed.size))
            .setContentText(buildNotificationText(departed))
            .setAutoCancel(true)
            .setWhen(System.currentTimeMillis())
            .setShowWhen(true)
            .setContentIntent(pending)
            .build()
        runCatching { nm.notify(NOTIFICATION_ID, notif) }
    }
}

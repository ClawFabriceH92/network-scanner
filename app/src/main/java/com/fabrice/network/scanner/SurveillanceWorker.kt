package com.fabrice.network.scanner

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/**
 * Worker de surveillance (v1.9.0) : scan réseau léger (sans UI, sans ports) puis
 * détection des nouveaux appareils. Si un appareil inconnu apparaît → notification
 * push sur le canal `surveillance`. Ne tourne jamais si le toggle est OFF.
 */
class SurveillanceWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    companion object {
        const val CHANNEL_ID = "surveillance"
    }

    override suspend fun doWork(): Result {
        val ctx = applicationContext
        if (!SurveillanceScheduler.isEnabled(ctx)) {
            AppLog.i("Surveillance", "Toggle OFF — scan annulé")
            return Result.success()
        }
        return try {
            AppLog.i("Surveillance", "Scan planifié en cours…")
            val oui = OuiDatabase.load(ctx)
            val devices = NetworkScanner.scan(
                oui = oui,
                scanPorts = false,
                scanEconomy = true,
                scanFast = true
            ) { _, _ -> }

            val historyStore = HistoryStore(ctx)
            val previous = historyStore.load()
            val trusted = TrustStore(ctx).trustedKeys()
            val auditStore = AuditLogStore(ctx)
            val fresh = ScanHistory.detectNewDevices(previous, devices, trusted)

            // ⚠️ Pas de notification au tout premier scan (historique vide).
            // Respecte le même réglage « alertes nouveaux appareils » que le
            // premier plan (sinon le toggle OFF est contourné en arrière-plan).
            if (fresh.isNotEmpty() && previous.isNotEmpty() && NewDeviceNotifier.isEnabled(ctx)) {
                notifyNewDevices(ctx, fresh)
                AppLog.i("Surveillance", "${fresh.size} nouvel(aux) appareil(s) → notification")
            }
            fresh.forEach { d ->
                auditStore.append("${d.hostname.ifBlank { d.ip }} (${d.ip}) apparu")
            }

            // Appareils qui étaient là et ne répondent plus (hors confiance).
            // ⚠️ UNIQUEMENT si le scan a trouvé des appareils : un scan vide
            // (téléphone hors du réseau maison, Wi-Fi coupé, autre réseau) ferait
            // remonter TOUT l'historique comme « absent » → spam de fausses alertes.
            if (devices.isNotEmpty()) {
                val departed = DepartureAlert.detectDepartures(previous, devices, trusted)
                if (departed.isNotEmpty()) {
                    DepartureAlert.notify(ctx, departed)
                    AppLog.i("Surveillance", "${departed.size} appareil(s) absent(s) → notification")
                }
                departed.forEach { d ->
                    auditStore.append("${d.hostname.ifBlank { d.ip }} (${d.ip}) absent")
                }
            } else {
                AppLog.i("Surveillance", "Scan vide (hors réseau ?) — pas de détection de départ")
            }
            auditStore.append(
                "Scan planifié : ${devices.size} appareil(s) (${devices.count { it.alive }} en ligne)"
            )

            // Blocages programmés dus → appliquer via l'API box.
            val scheduled = runCatching { ScheduleStore.applyDue(ctx) }.getOrDefault(0)
            if (scheduled > 0) AppLog.i("Surveillance", "$scheduled action(s) de blocage programmé")

            if (devices.isNotEmpty()) historyStore.save(devices)
            AppLog.i("Surveillance", "Scan planifié terminé : ${devices.size} appareil(s)")
            Result.success()
        } catch (e: Exception) {
            AppLog.e("Surveillance", "Échec du scan planifié : ${e.message}")
            Result.retry()
        }
    }

    /** Notification « 🆕 Nouvel appareil détecté » sur le canal dédié `surveillance`. */
    private fun notifyNewDevices(context: Context, newDevices: List<Device>) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Surveillance réseau", NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pending = PendingIntent.getActivity(
            context, 2001, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val head = newDevices.take(3).joinToString(", ") { it.hostname.ifBlank { it.ip } }
        val text = if (newDevices.size > 3) "$head et ${newDevices.size - 3} autres…" else head
        val title = if (newDevices.size == 1)
            "🆕 Nouvel appareil détecté : ${newDevices.first().hostname.ifBlank { newDevices.first().ip }}"
        else "🆕 ${newDevices.size} nouveaux appareils détectés"
        val notif = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(title)
            .setContentText(text)
            .setAutoCancel(true)
            .setContentIntent(pending)
            .build()
        runCatching { nm.notify(2001, notif) }
    }
}

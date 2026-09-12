package com.fabrice.network.scanner

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.widget.Toast

/**
 * Actions des notifications « nouvel appareil » (v1.9.38) :
 *  - MARQUER CONNU : ajoute l'appareil à la liste de confiance (plus d'alerte) ;
 *  - BLOQUER : coupe son accès via l'API box (Freebox…), sans ouvrir l'app.
 * Le blocage fait du réseau → goAsync() + thread, résultat en Toast.
 */
class NotificationActionReceiver : BroadcastReceiver() {

    companion object {
        const val ACTION_TRUST = "com.fabrice.network.scanner.action.TRUST"
        const val ACTION_BLOCK = "com.fabrice.network.scanner.action.BLOCK"
        const val EXTRA_KEY = "key"
        const val EXTRA_MAC = "mac"
        const val EXTRA_NAME = "name"
        const val EXTRA_NOTIF_ID = "notif_id"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val key = intent.getStringExtra(EXTRA_KEY).orEmpty()
        val mac = intent.getStringExtra(EXTRA_MAC).orEmpty()
        val name = intent.getStringExtra(EXTRA_NAME).orEmpty().ifBlank { mac.ifBlank { key } }
        val notifId = intent.getIntExtra(EXTRA_NOTIF_ID, -1)
        fun dismiss() {
            if (notifId >= 0) runCatching {
                (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).cancel(notifId)
            }
        }
        when (intent.action) {
            ACTION_TRUST -> {
                if (key.isNotBlank()) {
                    TrustStore(context).setTrusted(key, true)
                    runCatching { AuditLogStore(context).append("$name marqué de confiance (notification)") }
                    Toast.makeText(context, context.getString(R.string.notif_trusted, name), Toast.LENGTH_SHORT).show()
                }
                dismiss()
            }
            ACTION_BLOCK -> {
                if (mac.isBlank()) { dismiss(); return }
                val pending = goAsync()
                Thread {
                    val ok = runCatching { BoxManager.detect(context)?.blockDevice(mac) ?: false }.getOrDefault(false)
                    if (ok) {
                        runCatching {
                            context.getSharedPreferences("scan_prefs", Context.MODE_PRIVATE).let { p ->
                                p.edit().putStringSet("blocked_macs", (p.getStringSet("blocked_macs", emptySet()) ?: emptySet()) + mac).apply()
                            }
                            AuditLogStore(context).append("$name ($mac) bloqué via la box (notification)")
                        }
                    }
                    android.os.Handler(android.os.Looper.getMainLooper()).post {
                        Toast.makeText(
                            context,
                            if (ok) context.getString(R.string.notif_blocked, name) else context.getString(R.string.notif_block_failed),
                            Toast.LENGTH_LONG
                        ).show()
                        dismiss()
                        pending.finish()
                    }
                }.start()
            }
        }
    }
}

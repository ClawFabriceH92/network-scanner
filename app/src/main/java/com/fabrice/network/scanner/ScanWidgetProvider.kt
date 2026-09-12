package com.fabrice.network.scanner

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.widget.RemoteViews

/**
 * Widget d'écran d'accueil (v1.9.38) : appareils du dernier scan (total /
 * en ligne), ancienneté du scan, changements notables. Tap → ouvre l'app et
 * lance un scan. Rafraîchi après chaque scan (premier plan + surveillance).
 */
class ScanWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        ids.forEach { id -> manager.updateAppWidget(id, build(context)) }
    }

    companion object {
        /** Met à jour toutes les instances du widget (no-op s'il n'y en a pas). */
        fun refresh(context: Context) {
            runCatching {
                val app = context.applicationContext
                val manager = AppWidgetManager.getInstance(app)
                val ids = manager.getAppWidgetIds(ComponentName(app, ScanWidgetProvider::class.java))
                if (ids.isEmpty()) return
                ids.forEach { manager.updateAppWidget(it, build(app)) }
            }
        }

        /** Résumé affiché (pur, testable) : (ligne principale, ligne secondaire). */
        fun summary(context: Context, devices: List<Device>?, ageMs: Long?): Pair<String, String> {
            if (devices.isNullOrEmpty() || ageMs == null) {
                return context.getString(R.string.widget_no_scan) to context.getString(R.string.widget_tap_to_scan)
            }
            val online = devices.count { it.alive }
            val main = context.getString(R.string.widget_devices, devices.size, online)
            val sub = context.getString(R.string.widget_last_scan, ScanPersistence.ageLabel(ageMs))
            return main to sub
        }

        private fun build(context: Context): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_scan)
            val (main, sub) = summary(context, runCatching { ScanPersistence.load(context) }.getOrNull(), ScanPersistence.ageMs(context))
            views.setTextViewText(R.id.widget_main, main)
            views.setTextViewText(R.id.widget_sub, sub)
            val pi = PendingIntent.getActivity(
                context, 7, LaunchActions.scanIntent(context),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            views.setOnClickPendingIntent(R.id.widget_root, pi)
            return views
        }
    }
}

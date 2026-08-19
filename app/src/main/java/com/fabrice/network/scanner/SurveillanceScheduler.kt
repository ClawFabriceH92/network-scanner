package com.fabrice.network.scanner

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit
import kotlin.math.abs

/**
 * Surveillance continue (v1.9.0) — scan planifié via WorkManager.
 *
 * OPTION DÉSACTIVÉE PAR DÉFAUT (consommation batterie). Le worker ne tourne que
 * si le toggle `surveillance_enabled` est ON ; le scheduler annule le travail
 * périodique dès qu'on repasse OFF. Intervalle configurable 1h/2h/6h (défaut 2h).
 */
object SurveillanceScheduler {

    const val PREFS = "settings"
    const val KEY_ENABLED = "surveillance_enabled"
    const val KEY_INTERVAL = "surveillance_interval"
    const val DEFAULT_INTERVAL_HOURS = 2L
    const val WORK_NAME = "surveillance_periodic_scan"

    /** Intervalles proposés (en heures). */
    val INTERVALS_HOURS: List<Long> = listOf(1L, 2L, 6L)

    fun isEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, false)

    fun intervalHours(context: Context): Long =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getLong(KEY_INTERVAL, DEFAULT_INTERVAL_HOURS)

    /**
     * Sélection d'intervalle : retourne l'intervalle valide le plus proche.
     * Pure, testable (les valeurs hors liste sont ramenées à la plus proche).
     */
    fun nearestValidInterval(hours: Long): Long =
        INTERVALS_HOURS.minByOrNull { abs(it - hours) } ?: DEFAULT_INTERVAL_HOURS

    fun setEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_ENABLED, enabled).apply()
        // Applique immédiatement : schedule() si ON, cancel() si OFF.
        if (enabled) schedule(context) else cancel(context)
    }

    fun setInterval(context: Context, hours: Long) {
        val valid = nearestValidInterval(hours)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putLong(KEY_INTERVAL, valid).apply()
        // Si la surveillance est active, replanifie avec le nouvel intervalle.
        if (isEnabled(context)) schedule(context)
    }

    /** Planifie (ou replanifie) le scan périodique. No-op si le toggle est OFF. */
    fun schedule(context: Context) {
        cancel(context)
        if (!isEnabled(context)) return
        val request = PeriodicWorkRequestBuilder<SurveillanceWorker>(
            intervalHours(context),
            TimeUnit.HOURS
        )
            .setConstraints(
                Constraints.Builder()
                    .setRequiresBatteryNotLow(true)
                    .setRequiresCharging(false)
                    .build()
            )
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            WORK_NAME,
            ExistingPeriodicWorkPolicy.REPLACE,
            request
        )
    }

    fun cancel(context: Context) {
        WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
    }
}

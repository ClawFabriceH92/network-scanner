package com.fabrice.network.scanner

/**
 * Animation de proximité de la box (v1.8.0) : à partir d'une fenêtre
 * d'échantillons RSSI consécutifs, détermine si l'on se RAPPROCHE ou
 * s'ÉLOIGNE de la box (tendance). Logique pure, testable en JVM.
 */
object ProximityIndicator {

    /** Tendance de la fenêtre d'échantillons. */
    enum class Trend { APPROACHING, LEAVING, NEUTRAL }

    /** Seuil (dBm) au-delà duquel la variation est significative. */
    const val THRESHOLD_DBM = 2

    /**
     * Tendance : delta = dernier échantillon − premier échantillon (dBm).
     * delta > +2 → on se rapproche (signal plus fort) ; delta < −2 → on
     * s'éloigne ; sinon stable.
     */
    fun tendency(samples: List<Int>): Trend {
        if (samples.size < 2) return Trend.NEUTRAL
        val delta = samples.last() - samples.first()
        return when {
            delta > THRESHOLD_DBM -> Trend.APPROACHING
            delta < -THRESHOLD_DBM -> Trend.LEAVING
            else -> Trend.NEUTRAL
        }
    }

    /** Force du signal (0-4) sur le dernier échantillon (pattern WifiQuality.level). */
    fun strength(samples: List<Int>): Int =
        WifiQuality.level(samples.lastOrNull() ?: Int.MIN_VALUE)

    /** Libellé français de la tendance. */
    fun trendLabel(trend: Trend): String = when (trend) {
        Trend.APPROACHING -> "Tu te rapproches de la box"
        Trend.LEAVING -> "Tu t'éloignes de la box"
        Trend.NEUTRAL -> "Stable"
    }

    /** Flèche affichée (an) : ↑ / ↓ / →. */
    fun arrow(trend: Trend): String = when (trend) {
        Trend.APPROACHING -> "↑"
        Trend.LEAVING -> "↓"
        Trend.NEUTRAL -> "→"
    }

    /** Emoji de statut pour la tendance. */
    fun emoji(trend: Trend): String = when (trend) {
        Trend.APPROACHING -> "🟢"
        Trend.LEAVING -> "🔴"
        Trend.NEUTRAL -> "🟡"
    }
}

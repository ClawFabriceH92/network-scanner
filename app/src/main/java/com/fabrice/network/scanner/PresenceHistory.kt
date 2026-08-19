package com.fabrice.network.scanner

/**
 * Historique de présence (v1.7.0) : pour chaque appareil, la liste des instants
 * (epoch seconds) où il a été vu. Permet d'afficher « Vu il y a X » dans la fiche.
 *
 * Logique pure — la persistance JSON est dans [PresenceHistoryStore].
 */
object PresenceHistory {

    /** Nombre max de timestamps conservés par appareil. */
    const val MAX_ENTRIES = 500

    /** Rotation : les timestamps de plus de 30 jours sont supprimés. */
    const val MAX_AGE_SECONDS = 30L * 24 * 3600

    /** Fusion de deux timestamps considérés comme identiques (fenêtre anti-doublon). */
    const val DEDUPE_WINDOW_SECONDS = 60L

    /**
     * Enregistre la présence de [devices] à l'instant [now] (epoch seconds).
     * Met à jour le registre key→timestamps : ajoute un timestamp par appareil,
     * déduplique les timestamps trop proches (< 60 s), purge ceux de plus de
     * 30 jours et borne chaque liste à [MAX_ENTRIES]. Retourne le registre mis
     * à jour (immutable, sans modifier l'original).
     */
    fun record(
        registry: Map<String, List<Long>>,
        devices: List<Device>,
        now: Long = System.currentTimeMillis() / 1000
    ): Map<String, List<Long>> {
        val cutoff = now - MAX_AGE_SECONDS
        val out = HashMap<String, List<Long>>()
        // rotation globale : purge les timestamps trop anciens
        registry.forEach { (k, v) ->
            val kept = v.filter { it >= cutoff }
            if (kept.isNotEmpty()) out[k] = kept
        }
        devices.forEach { d ->
            val key = ScanHistory.identityKey(d)
            val list = (out[key].orEmpty()).toMutableList()
            if (list.isEmpty() || now - list.last() >= DEDUPE_WINDOW_SECONDS) {
                list.add(now)
            }
            while (list.size > MAX_ENTRIES) list.removeAt(0)
            out[key] = list
        }
        return out
    }

    /** Dernier timestamp vu (epoch seconds), ou null si jamais vu. */
    fun lastSeenAt(timestamps: List<Long>): Long? = timestamps.lastOrNull()

    /** Label relatif « il y a X min / hier / il y a 3 j » pour un dernier vu. */
    fun lastSeen(timestamps: List<Long>, now: Long = System.currentTimeMillis() / 1000): String {
        val last = lastSeenAt(timestamps) ?: return "jamais vu"
        return ageLabel(now - last)
    }

    /** Libellé d'âge à partir d'un écart en secondes (réutilise le pattern ageLabel). */
    fun ageLabel(secondsAgo: Long): String {
        val s = secondsAgo.coerceAtLeast(0)
        val minutes = s / 60
        val hours = s / 3600
        val days = s / 86400
        return when {
            s < 60 -> "à l'instant"
            s < 3600 -> "il y a $minutes min"
            s < 86400 -> "il y a $hours h"
            s < 172800 -> "hier"
            else -> "il y a $days j"
        }
    }

    /** Nombre total d'apparitions d'un appareil. */
    fun count(timestamps: List<Long>): Int = timestamps.size
}

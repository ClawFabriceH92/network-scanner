package com.fabrice.network.scanner

/**
 * Occupation des canaux Wi-Fi (v1.9.36) — logique pure, testable.
 *
 * 2,4 GHz : un réseau sur le canal c (20 MHz) déborde sur c±2, donc chaque
 * réseau compte pour 1 sur son canal et 0,5 sur les canaux voisins (±1, ±2) ;
 * seuls 1, 6 et 11 ne se chevauchent pas → on ne recommande que ceux-là.
 * 5 GHz : canaux de 20 MHz sans recouvrement (on ignore la liaison de canaux),
 * recommandation parmi les canaux courants hors DFS (36–48, 149–165).
 */
object WifiChannels {

    data class Occupancy(val channel: Int, val networks: Int, val load: Double)

    val CHANNELS_24 = (1..13).toList()
    val NON_OVERLAP_24 = listOf(1, 6, 11)
    val COMMON_5 = listOf(36, 40, 44, 48, 149, 153, 157, 161, 165)

    fun is24(net: WifiScanner.WifiNetwork) = net.frequency in 2400..2500
    fun is5(net: WifiScanner.WifiNetwork) = net.frequency in 4900..5900

    /** Occupation pondérée par canal 2,4 GHz (1..13). */
    fun occupancy24(nets: List<WifiScanner.WifiNetwork>): List<Occupancy> {
        val count = HashMap<Int, Int>()
        val load = HashMap<Int, Double>()
        nets.filter { is24(it) }.mapNotNull { it.channel }.forEach { c ->
            count[c] = (count[c] ?: 0) + 1
            for (d in -2..2) {
                val k = c + d
                if (k in 1..14) load[k] = (load[k] ?: 0.0) + (if (d == 0) 1.0 else 0.5)
            }
        }
        return CHANNELS_24.map { Occupancy(it, count[it] ?: 0, load[it] ?: 0.0) }
    }

    /** Occupation par canal 5 GHz (canaux présents + canaux courants). */
    fun occupancy5(nets: List<WifiScanner.WifiNetwork>): List<Occupancy> {
        val count = HashMap<Int, Int>()
        nets.filter { is5(it) }.mapNotNull { it.channel }.forEach { c -> count[c] = (count[c] ?: 0) + 1 }
        val channels = (COMMON_5 + count.keys).distinct().sorted()
        return channels.map { Occupancy(it, count[it] ?: 0, (count[it] ?: 0).toDouble()) }
    }

    /** Meilleur canal 2,4 GHz parmi 1/6/11 (charge minimale, puis le plus bas). */
    fun best24(nets: List<WifiScanner.WifiNetwork>): Occupancy? {
        val occ = occupancy24(nets).filter { it.channel in NON_OVERLAP_24 }
        return occ.minWithOrNull(compareBy<Occupancy> { it.load }.thenBy { it.channel })
    }

    /** Meilleur canal 5 GHz parmi les canaux courants hors DFS. */
    fun best5(nets: List<WifiScanner.WifiNetwork>): Occupancy? {
        val occ = occupancy5(nets).filter { it.channel in COMMON_5 }
        return occ.minWithOrNull(compareBy<Occupancy> { it.load }.thenBy { it.channel })
    }

    /**
     * Conseil pour le réseau connecté ([currentBssid]) : null si rien à dire,
     * sinon un texte (« Ta box est sur le canal 6 (4 réseaux) : le canal 11 est libre »).
     */
    fun advice(nets: List<WifiScanner.WifiNetwork>, currentBssid: String?): String? {
        if (currentBssid.isNullOrBlank()) return null
        val me = nets.firstOrNull { it.bssid.equals(currentBssid, ignoreCase = true) } ?: return null
        val ch = me.channel ?: return null
        return if (is24(me)) {
            val occ = occupancy24(nets).firstOrNull { it.channel == ch } ?: return null
            val best = best24(nets) ?: return null
            val mine = (occ.load - 1.0).coerceAtLeast(0.0)   // sans compter notre propre réseau
            when {
                ch !in NON_OVERLAP_24 -> "Ta box est sur le canal $ch (chevauchant) : préfère 1, 6 ou 11 — le ${best.channel} est le moins chargé."
                best.channel != ch && best.load + 1.0 < occ.load -> "Ta box est sur le canal $ch (${fmt(mine)} de charge voisine) : le canal ${best.channel} est moins chargé (${fmt(best.load)})."
                else -> "Ta box est sur le canal $ch : c'est déjà le meilleur choix en 2,4 GHz."
            }
        } else if (is5(me)) {
            val occ = occupancy5(nets).firstOrNull { it.channel == ch } ?: return null
            val best = best5(nets) ?: return null
            if (best.channel != ch && best.networks + 1 < occ.networks)
                "Ta box est sur le canal $ch (${occ.networks} réseaux) : le canal ${best.channel} est plus libre (${best.networks})."
            else "Ta box est sur le canal $ch en 5 GHz : bon choix (${occ.networks - 1} autre(s) réseau(x))."
        } else null
    }

    private fun fmt(v: Double): String = if (v == v.toLong().toDouble()) v.toLong().toString() else String.format(java.util.Locale.FRENCH, "%.1f", v)
}

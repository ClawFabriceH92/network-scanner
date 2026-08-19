package com.fabrice.network.scanner

import kotlinx.coroutines.delay

/**
 * Détection et test Wake-on-LAN (v1.8.0).
 *
 * ⚠️ Limite honnête : un appareil éteint est INVISIBLE (pas de ping/ARP) — on
 * ne peut donc PAS détecter passivement le support WoL. On identifie les
 * CANDIDATS (appareils connus, absents du scan courant, avec MAC valide) et on
 * TESTE le WoL en envoyant un magic packet puis en re-pinguant après délai.
 */
object WoLDetector {

    /** Candidat au réveil : appareil connu éteint + résultat éventuel de test. */
    data class WolCandidate(
        val device: Device,
        val lastSeenLabel: String,
        val wolTested: Boolean = false,
        val wolWorks: Boolean = false
    )

    /**
     * Candidats WoL : appareils de [known] (historique/box) absents du scan
     * courant [current], avec une MAC valide (magic packet constructible).
     * `lastSeenLabel` vient de l'historique de présence ([presence]).
     *
     * @param presence registre key → timestamps (epoch s), cf. PresenceHistory
     * @param now instant de référence (epoch s) pour les libellés relatifs
     */
    fun candidates(
        known: List<Device>,
        current: List<Device>,
        presence: Map<String, List<Long>> = emptyMap(),
        now: Long = System.currentTimeMillis() / 1000
    ): List<WolCandidate> {
        val currentKeys = current.map { ScanHistory.identityKey(it) }.toSet()
        return known
            .filter { it.mac.isNotBlank() && WakeOnLan.magicPacket(it.mac) != null }
            .filter { ScanHistory.identityKey(it) !in currentKeys }
            .map { d ->
                val key = ScanHistory.identityKey(d)
                WolCandidate(
                    device = d,
                    lastSeenLabel = presence[key]?.let { PresenceHistory.lastSeen(it, now) }
                        ?: "jamais vu"
                )
            }
    }

    /**
     * Teste le WoL : envoie le magic packet (réutilise [WakeOnLan.send]), attend
     * [waitMs] (60-90 s en prod), puis re-ping l'IP via [recheck].
     * Retourne true si l'appareil répond (WoL fonctionne), false sinon.
     *
     * @param waitMs délai avant re-ping (injectable pour les tests)
     */
    suspend fun testWol(
        mac: String,
        ip: String,
        broadcastIp: String,
        waitMs: Long = 60_000,
        recheck: (String) -> Boolean
    ): Boolean {
        if (!WakeOnLan.send(mac, broadcastIp)) return false
        if (waitMs > 0) delay(waitMs)
        return recheck(ip)
    }
}

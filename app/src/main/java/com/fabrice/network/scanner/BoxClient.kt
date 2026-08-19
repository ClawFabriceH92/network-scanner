package com.fabrice.network.scanner

/**
 * Architecture multi-box : récupère les infos de la box (baux DHCP,
 * équipements) pour compléter le scan direct — les appareils silencieux que
 * le ping/ARP rate apparaissent ici (comme l'interface Freebox).
 *
 * Chaque box expose son propre client. La détection se fait par le fabricant
 * de la passerelle (OUI) : Freebox SAS → Freebox, Sagemcom → Livebox, etc.
 */
interface BoxClient {

    /** Nom court du fabricant (affiché dans l'UI). */
    val name: String

    /** URL de base de l'API locale. */
    val baseUrl: String

    /** Équipements vus par la box (baux DHCP + table ARP de la box). */
    data class BoxDevice(
        val name: String,
        val mac: String,
        val ip: String,
        val hostType: String,     // "computer", "printer", "camera"…
        val active: Boolean,
        val reachable: Boolean,
        val lastActivity: String  // date lisible ou ""
    )

    /**
     * Authentifie si nécessaire et retourne les équipements de la box.
     * Retourne null si la box n'est pas joignable ou non autorisée.
     */
    suspend fun fetchDevices(): List<BoxDevice>?

    /** Le client peut-il être utilisé tel quel (box joignable + auth dispo) ? */
    fun isAvailable(): Boolean

    /**
     * Coupe l'accès réseau/Internet d'un périphérique (blocage légal via l'API
     * box, équivalent « bloquer » de l'interface constructeur — PAS de deauth).
     * Retourne false par défaut : les implémentations qui ne le supportent pas
     * ne cassent pas les appels existants.
     */
    fun blockDevice(mac: String): Boolean = false

    /** Rétablit l'accès d'un périphérique bloqué. */
    fun unblockDevice(mac: String): Boolean = false
}

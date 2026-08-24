package com.fabrice.network.scanner

/**
 * Architecture multi-box : récupère les infos de la box (baux DHCP,
 * équipements) pour compléter le scan direct — les appareils silencieux que
 * le ping/ARP rate apparaissent ici (comme l'interface Freebox).
 *
 * Chaque box expose son propre client. La détection se fait par le fabricant
 * de la passerelle (OUI) : Freebox SAS → Freebox, Sagemcom → Livebox, etc.
 *
 * v1.8.0 : les méthodes `fetchLeases`/`fetchConnection`/`fetchBandwidth`/
 * `fetchWifi`/`fetchSystem` ont des implémentations PAR DÉFAUT (null/false) —
 * une box qui ne supporte pas un endpoint renvoie null et l'UI affiche
 * « non disponible », sans casser les clients existants.
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
        val lastActivity: String, // date lisible ou ""
        /** « WiFi » / « Ethernet » si la box l'expose, sinon null. */
        val connectionType: String? = null,
        /** Signal Wi-Fi (RSSI dBm) vu par la box, si fourni. */
        val rssi: Int? = null,
        /** Débit de liaison (Mb/s) vu par la box, si fourni. */
        val linkRateMbps: Int? = null,
        /** Octets reçus/émis par l'appareil (compteurs box), si fournis. */
        val rxBytes: Long? = null,
        val txBytes: Long? = null,
        /** Première apparition (date lisible), si fournie. */
        val firstSeen: String = ""
    )

    /**
     * Authentifie si nécessaire et retourne les équipements de la box.
     * Retourne null si la box n'est pas joignable ou non autorisée.
     */
    suspend fun fetchDevices(): List<BoxDevice>?

    /** Le client peut-il être utilisé tel quel (box joignable + auth dispo) ? */
    fun isAvailable(): Boolean

    // --- Nouveaux endpoints multi-box (v1.8.0) — null = non supporté ---

    /** Baux DHCP vus par la box. */
    suspend fun fetchLeases(): List<BoxLease>? = null

    /** Connexion WAN : IP publique, type d'accès, débit contractuel. */
    suspend fun fetchConnection(): BoxConnection? = null

    /** Débit temps réel (octets/s). */
    suspend fun fetchBandwidth(): BoxBandwidth? = null

    /** WiFi de la box : SSID, sécurité, canal, clients. */
    suspend fun fetchWifi(): BoxWifi? = null

    /** État système : firmware, uptime, température. */
    suspend fun fetchSystem(): BoxSystem? = null

    /**
     * Coupe l'accès réseau/Internet d'un périphérique (blocage légal via l'API
     * box, équivalent « bloquer » de l'interface constructeur — PAS de deauth).
     * Retourne false par défaut : les implémentations qui ne le supportent pas
     * ne cassent pas les appels existants.
     */
    fun blockDevice(mac: String): Boolean = false

    /** Rétablit l'accès d'un périphérique bloqué. */
    fun unblockDevice(mac: String): Boolean = false

    /**
     * Redémarre la box (action destructive : coupe Internet ~2 min). Nécessite
     * en général une authentification. Retourne false par défaut (non supporté).
     */
    suspend fun reboot(): Boolean = false
}

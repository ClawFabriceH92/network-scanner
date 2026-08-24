package com.fabrice.network.scanner

/**
 * Modèles de données multi-box (v1.8.0) : tout ce qu'une box peut exposer
 * au-delà de la simple liste d'équipements — baux DHCP, connexion WAN, débit
 * temps réel, WiFi de la box, état système.
 *
 * Ces types sont purs (aucun accès réseau) : ils servent de contrat entre les
 * clients box (`BoxClient`) et les écrans (`BoxScreen`).
 */

/** Bail DHCP vu par la box. */
data class BoxLease(
    val ip: String,
    val mac: String,
    val hostname: String = "",
    /** Durée du bail en secondes (null si non fournie par la box). */
    val leaseTime: Long? = null,
    val active: Boolean = true
)

/** Connexion WAN de la box : IP publique, type d'accès, débit contractuel. */
data class BoxConnection(
    val publicIp: String = "",
    /** Type d'accès : « ftth », « xdsl », « cable »… (libellé fourni par la box). */
    val connectionType: String = "",
    /** Débit descendant contractuel (bits/s) — null si non fourni. */
    val downloadRate: Long? = null,
    /** Débit montant contractuel (bits/s) — null si non fourni. */
    val uploadRate: Long? = null,
    /** État de la ligne (« up »/« connected »…) si fourni. */
    val lineStatus: String = "",
    /** Uptime de la connexion WAN en secondes, si fourni. */
    val uptimeSeconds: Long? = null,
    // Diagnostic xDSL (null hors ADSL/VDSL) :
    /** Marge de bruit (SNR) descendante en dB. */
    val snrDown: Double? = null,
    /** Marge de bruit (SNR) montante en dB. */
    val snrUp: Double? = null,
    /** Atténuation descendante en dB. */
    val attenuationDown: Double? = null,
    /** Atténuation montante en dB. */
    val attenuationUp: Double? = null
)

/** Débit temps réel (octets/seconde) mesuré à un instant donné. */
data class BoxBandwidth(
    val downloadBps: Long,
    val uploadBps: Long,
    val timestampMs: Long = System.currentTimeMillis()
)

/** Client WiFi connecté à la box. */
data class WifiClient(
    val mac: String,
    val ip: String = "",
    val hostname: String = "",
    /** RSSI (dBm) vu par la box, ou null si non fourni. */
    val rssi: Int? = null,
    val band: String = ""
)

/** WiFi de la box : SSID, sécurité, canal, bande et clients connectés. */
data class BoxWifi(
    val ssid: String = "",
    val security: String = "",
    val channel: String = "",
    val band: String = "",
    val clients: List<WifiClient> = emptyList()
)

/** État système de la box : firmware, uptime, température éventuelle. */
data class BoxSystem(
    val firmware: String = "",
    val uptimeSeconds: Long? = null,
    val temperatureC: Double? = null,
    /** Modèle de la box (ex. « NB6VAC », « Freebox Delta »). */
    val model: String = "",
    /** Numéro de série, si fourni. */
    val serial: String = ""
)

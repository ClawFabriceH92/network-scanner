package com.fabrice.network.scanner

import android.content.Context

/**
 * Détecte la box du réseau (par fabricant de la passerelle) et fournit le
 * client adapté. Complète le scan direct avec les équipements vus par la box
 * (baux DHCP) — les appareils silencieux que le ping/ARP ne voit pas.
 *
 * Fabricants connus (via OUI de la passerelle) :
 * - Freebox SAS → FreeboxBoxClient
 * - Sagemcom / Technicolor / Nokia → Livebox (Sagemcom) — à ajouter
 * - Bouygues / Bbox → Bbox API — à ajouter
 */
object BoxManager {

    /** Client sélectionné pour la box actuelle (null si non reconnue). */
    private var cachedClient: BoxClient? = null
    private var cachedGateway: String = ""

    /** Détecte et retourne le client box adapté (ou null). */
    fun detect(context: Context): BoxClient? {
        val gateway = NetworkInfoProvider.readGateway()
        if (gateway.isBlank()) return null
        if (cachedClient != null && cachedGateway == gateway) return cachedClient
        val oui = OuiDatabase.load(context)
        // Fabricant de la passerelle : on cherche la MAC de la gateway dans l'ARP
        val arp = NetworkScanner.parseArp(runCatching {
            java.io.File("/proc/net/arp").readText()
        }.getOrDefault(""))
        val gatewayMac = arp[gateway] ?: ""
        val vendor = NetworkScanner.vendorFor(gatewayMac, oui)

        val client = when {
            vendor.contains("freebox", true) || gateway == "192.168.0.254" ->
                FreeboxBoxClient(context)
            vendor.contains("sagemcom", true) ||
                vendor.contains("technicolor", true) -> null // Livebox : à implémenter
            else -> null // Box non reconnue ou SFR (pas d'API)
        }
        cachedClient = client
        cachedGateway = gateway
        return client
    }

    fun reset() {
        cachedClient = null
        cachedGateway = ""
    }
}

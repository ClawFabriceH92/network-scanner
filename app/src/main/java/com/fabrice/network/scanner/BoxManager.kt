package com.fabrice.network.scanner

import android.content.Context

/**
 * Détecte la box du réseau (par fabricant/OUi de la passerelle + passerelle)
 * et fournit le client adapté. Complète le scan direct avec les équipements
 * vus par la box (baux DHCP).
 *
 * Détection multi-box (v1.8.0) — la passerelle EST le discriminant fiable :
 * - 192.168.0.254 ou OUI « freebox » → FreeboxBoxClient (API v9)
 * - 192.168.1.254 ou OUI « bouygues/bbox » → BboxBoxClient (sysbus, communauté)
 * - 192.168.1.1   ou OUI « livebox/orange/technicolor » → LiveboxBoxClient (TR-064)
 * - OUI « sfr/numericable/neuf » → PAS d'API fiable → nom « Box SFR » + null
 */
object BoxManager {

    /** Type de box reconnu (utilisé pour l'annuaire + la sélection du client). */
    enum class BoxType(val label: String) {
        FREEBOX("Freebox"),
        BBOX("Bbox"),
        LIVEBOX("Livebox"),
        SFR("SFR")
    }

    /**
     * Classifie une passerelle + fabricant → type de box (pur, testable).
     * L'ordre compte : la passerelle prime sur le fabricant (Sagemcom fabrique
     * AUSSI des Bbox ET des Livebox — seule la gateway les distingue).
     */
    fun classify(gateway: String, vendor: String): BoxType? {
        val v = vendor.lowercase()
        return when {
            v.contains("freebox") || gateway == "192.168.0.254" -> BoxType.FREEBOX
            gateway == "192.168.1.254" -> BoxType.BBOX
            gateway == "192.168.1.1" -> BoxType.LIVEBOX
            v.contains("bouygues") || v.contains("bbox") -> BoxType.BBOX
            v.contains("livebox") || v.contains("orange") ||
                v.contains("technicolor") || v.contains("sagemcom") -> BoxType.LIVEBOX
            v.contains("sfr") || v.contains("numericable") || v.contains("neuf") -> BoxType.SFR
            else -> null
        }
    }

    /** Client sélectionné pour la box actuelle (null si non reconnue). */
    @Volatile
    private var cachedClient: BoxClient? = null
    @Volatile
    private var cachedGateway: String = ""

    /** Détecte et retourne le client box adapté (ou null). */
    @Synchronized
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

        val type = classify(gateway, vendor)
        val client = when (type) {
            BoxType.FREEBOX -> FreeboxBoxClient(context)
            BoxType.BBOX -> BboxBoxClient()
            BoxType.LIVEBOX -> LiveboxBoxClient(context)
            // SFR : pas d'API fiable — on mémorise le nom mais pas de client.
            BoxType.SFR -> null
            null -> null
        }
        cachedClient = client
        cachedGateway = gateway

        // Annuaire des boxes : mémorise le type reconnu avec un nom par défaut.
        if (type != null) {
            val prefs = context.getSharedPreferences(BoxStore.PREFS, Context.MODE_PRIVATE)
            val boxType = type.label
            if (BoxStore.getBoxName(prefs, gateway) == null) {
                BoxStore.saveBox(prefs, gateway, "Box $boxType", boxType)
            }
        }
        return client
    }

    @Synchronized
    fun reset() {
        cachedClient = null
        cachedGateway = ""
    }
}

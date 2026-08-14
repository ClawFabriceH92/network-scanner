package com.fabrice.network.scanner

import android.content.Context
import android.net.wifi.WifiManager

/**
 * Qualité du signal Wi-Fi en temps réel.
 *
 * Le RSSI (dBm) est lu via WifiManager et converti en niveau 0-4 barres
 * (seuils usuels Android) : >= -50 excellent, -51..-60 bon, -61..-70 moyen,
 * -71..-80 faible, < -80 très faible.
 */
object WifiQuality {

    /** Niveau de barres (0-4) à partir du RSSI. */
    fun level(rssi: Int): Int = when {
        rssi >= -50 -> 4
        rssi >= -60 -> 3
        rssi >= -70 -> 2
        rssi >= -80 -> 1
        else -> 0
    }

    /** Libellé du niveau. */
    fun label(rssi: Int): String = when {
        rssi == Int.MIN_VALUE -> "inconnue"
        rssi >= -50 -> "Excellente"
        rssi >= -60 -> "Bonne"
        rssi >= -70 -> "Moyenne"
        rssi >= -80 -> "Faible"
        else -> "Très faible"
    }

    /** Lit le RSSI courant (dBm). Int.MIN_VALUE si Wi-Fi indisponible. */
    fun currentRssi(context: Context): Int {
        return try {
            val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wifi.connectionInfo?.rssi ?: Int.MIN_VALUE
        } catch (e: Exception) {
            Int.MIN_VALUE
        }
    }

    /** Formatte le RSSI : "-57 dBm". */
    fun formatRssi(rssi: Int): String =
        if (rssi == Int.MIN_VALUE) "—" else "$rssi dBm"
}

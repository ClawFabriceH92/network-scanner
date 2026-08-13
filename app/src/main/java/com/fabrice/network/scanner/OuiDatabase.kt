package com.fabrice.network.scanner

import android.content.Context

/**
 * Base OUI (fabricants par préfixe MAC) embarquée dans assets/oui.txt.
 * Format : "aabbcc\tVENDOR" par ligne — chargée une seule fois en mémoire.
 */
object OuiDatabase {

    private var map: Map<String, String>? = null

    fun load(context: Context): Map<String, String> {
        map?.let { return it }
        val m = HashMap<String, String>()
        context.assets.open("oui.txt").bufferedReader(Charsets.UTF_8).useLines { lines ->
            lines.forEach { line ->
                NetworkScanner.parseOuiLine(line)?.let { (mac, vendor) -> m[mac] = vendor }
            }
        }
        map = m
        return m
    }

    fun vendorFor(mac: String, context: Context): String =
        NetworkScanner.vendorFor(mac, load(context))
}

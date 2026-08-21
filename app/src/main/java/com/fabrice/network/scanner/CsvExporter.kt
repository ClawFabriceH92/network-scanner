package com.fabrice.network.scanner

/**
 * Export CSV des appareils détectés.
 *
 * Format compatible Excel FR : séparateur `;` + BOM UTF-8 (utf-8-sig),
 * préférence Fabrice pour une ouverture sans casse d'accents.
 */
object CsvExporter {

    /** En-têtes + lignes, avec BOM UTF-8. */
    fun buildCsv(
        devices: List<Device>,
        vulnsByIp: Map<String, VulnScanner.DeviceVulns> = emptyMap()
    ): String = buildString {
        append('\uFEFF') // BOM UTF-8
        appendLine("IP;MAC;Fabricant;Nom réseau;Produit;Modèle;SNMP Nom;SNMP Description;Connexion;Système;Statut;Vulnérabilités;Score;Credential défaut")
        devices.forEach { d ->
            append(csv(d.ip)); append(';')
            append(csv(d.mac)); append(';')
            append(csv(d.vendor)); append(';')
            append(csv(d.hostname)); append(';')
            append(csv(d.product)); append(';')
            append(csv(d.model)); append(';')
            append(csv(d.snmpName ?: "")); append(';')
            append(csv(d.snmpDescr ?: "")); append(';')
            append(csv(d.connectionType ?: "")); append(';')
            append(csv(d.os)); append(';')
            append(if (d.alive) "En ligne" else "Vu récemment (ARP)"); append(';')
            val v = vulnsByIp[d.ip]
            if (v != null && !v.isEmpty) {
                append(csv(v.cves.joinToString(", ") { it.id })); append(';')
                append("${v.label} (${v.score}/100)")
            } else {
                append(csv("")); append(';')
                append(csv(""))
            }
            append(';')
            append(csv(d.defaultCred ?: ""))
            appendLine()
        }
    }

    /**
     * Échappe un champ CSV. Neutralise d'abord l'injection de formule (un champ
     * réseau non fiable — hostname, SNMP, fabricant — commençant par = + - @ est
     * interprété comme une formule par Excel/LibreOffice) en le préfixant d'une
     * apostrophe, puis applique le quoting standard (; " retours ligne).
     */
    private fun csv(value: String): String {
        val safe = if (value.isNotEmpty() && value.first() in charArrayOf('=', '+', '-', '@'))
            "'$value" else value
        if (safe.contains(';') || safe.contains('"') || safe.contains('\n') || safe.contains('\r')) {
            return "\"" + safe.replace("\"", "\"\"") + "\""
        }
        return safe
    }
}

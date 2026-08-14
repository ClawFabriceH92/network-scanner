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
        appendLine("IP;MAC;Fabricant;Nom réseau;Système;Statut;Vulnérabilités;Score")
        devices.forEach { d ->
            append(csv(d.ip)); append(';')
            append(csv(d.mac)); append(';')
            append(csv(d.vendor)); append(';')
            append(csv(d.hostname)); append(';')
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
            appendLine()
        }
    }

    /** Échappe un champ CSV (guillemets si contient ; " ou retour ligne). */
    private fun csv(value: String): String {
        if (value.contains(';') || value.contains('"') || value.contains('\n') || value.contains('\r')) {
            return "\"" + value.replace("\"", "\"\"") + "\""
        }
        return value
    }
}

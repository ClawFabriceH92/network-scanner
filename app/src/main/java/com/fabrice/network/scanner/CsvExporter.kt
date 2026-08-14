package com.fabrice.network.scanner

/**
 * Export CSV des appareils détectés.
 *
 * Format compatible Excel FR : séparateur `;` + BOM UTF-8 (utf-8-sig),
 * préférence Fabrice pour une ouverture sans casse d'accents.
 */
object CsvExporter {

    /** En-têtes + lignes, avec BOM UTF-8. */
    fun buildCsv(devices: List<Device>): String = buildString {
        append('\uFEFF') // BOM UTF-8
        appendLine("IP;MAC;Fabricant;Nom réseau;Statut")
        devices.forEach { d ->
            append(csv(d.ip)); append(';')
            append(csv(d.mac)); append(';')
            append(csv(d.vendor)); append(';')
            append(csv(d.hostname)); append(';')
            appendLine(if (d.alive) "En ligne" else "Vu récemment (ARP)")
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

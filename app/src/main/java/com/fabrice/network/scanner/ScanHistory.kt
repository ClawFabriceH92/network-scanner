package com.fabrice.network.scanner

/**
 * Historique des appareils vus sur le réseau.
 *
 * Clé d'identité : MAC si disponible, sinon IP (les appareils sans MAC ne
 * peuvent pas être suivis de façon fiable). Permet de détecter les nouveaux
 * appareils entre deux scans et de conserver les noms personnalisés.
 */
object ScanHistory {

    /** Identifiant stable d'un appareil (MAC si possible, sinon IP). */
    fun identityKey(device: Device): String =
        if (device.mac.isNotBlank()) device.mac else "ip:${device.ip}"

    /**
     * Appareils présents dans [current] mais absents de [previous] (et non
     * marqués de confiance). Les clés [trusted] sont ignorées — les fonctions
     * pures reçoivent le Set en paramètre et ne lisent jamais les prefs.
     */
    fun detectNewDevices(
        previous: List<Device>,
        current: List<Device>,
        trusted: Set<String> = emptySet()
    ): List<Device> {
        val known = previous.map { identityKey(it) }.toSet()
        return current.filter { identityKey(it) !in known && identityKey(it) !in trusted }
    }

    /**
     * Sérialise la liste d'appareils en format texte stable (une ligne par
     * appareil, champs échappés). Format versionné pour rester lisible et
     * compatible avec les tests JVM (pas de dépendance JSON).
     */
    fun serialize(devices: List<Device>): String = buildString {
        appendLine("v1")
        devices.forEach { d ->
            append(listOf(d.ip, d.mac, d.vendor, d.hostname).joinToString("|") { escape(it) })
            appendLine()
        }
    }

    /** Parse le format produit par [serialize]. */
    fun deserialize(text: String): List<Device> {
        val lines = text.lineSequence().filter { it.isNotBlank() }.toList()
        if (lines.isEmpty() || lines.first() != "v1") return emptyList()
        return lines.drop(1).mapNotNull { line ->
            val parts = splitEscaped(line)
            if (parts.size < 4) return@mapNotNull null
            Device(
                ip = unescape(parts[0]),
                mac = unescape(parts[1]),
                vendor = unescape(parts[2]),
                hostname = unescape(parts[3])
            )
        }
    }

    /** Découpe sur les | non échappés (\\|). */
    private fun splitEscaped(s: String): List<String> {
        val parts = mutableListOf<String>()
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '\\' && i + 1 < s.length && s[i + 1] == '|') {
                sb.append('\\').append('|')
                i += 2
            } else if (c == '|') {
                parts.add(sb.toString())
                sb.setLength(0)
                i += 1
            } else {
                sb.append(c)
                i += 1
            }
        }
        parts.add(sb.toString())
        return parts
    }

    private fun escape(s: String): String =
        s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n")

    private fun unescape(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '\\' && i + 1 < s.length) {
                when (s[i + 1]) {
                    '\\' -> sb.append('\\')
                    '|' -> sb.append('|')
                    'n' -> sb.append('\n')
                    else -> { sb.append(c); sb.append(s[i + 1]) }
                }
                i += 2
            } else {
                sb.append(c)
                i += 1
            }
        }
        return sb.toString()
    }
}

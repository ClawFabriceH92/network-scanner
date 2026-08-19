package com.fabrice.network.scanner

import org.json.JSONArray

/**
 * Signatures Nmap (identification produit/service façon Fing) — v1.7.0.
 *
 * L'asset `assets/nmap_signatures.json` (généré par `tools/build_nmap_signatures.py`)
 * contient des règles compactes : service, produit, gabarit de version, regex Java.
 * Il remplace avantageusement les ~20 règles maison de [ServiceFingerprint] pour
 * identifier précisément les bannières HTTP/SSH/FTP/SMTP/POP3/IMAP/Telnet/RTSP…
 *
 * Priorité d'affichage (résolution produit) : ServiceFingerprint (règles maison
 * précises) d'abord, puis NmapSignatures, puis SNMP, puis mDNS.
 */
object NmapSignatures {

    /** Une règle de signature : regex + gabarit de produit/version. */
    data class NmapRule(
        val service: String,
        val product: String,
        val version: String,   // gabarit : « {1} » = groupe 1, ou littéral
        val regex: Regex
    )

    /** Une correspondance identifiée. */
    data class NmapMatch(val service: String, val product: String, val version: String) {
        fun displayName(): String =
            listOf(product, version).filter { it.isNotBlank() }.joinToString(" ").trim()
    }

    @Volatile
    private var rules: List<NmapRule> = emptyList()

    /**
     * Parse le JSON de signatures et mémorise les règles (pour [identify]).
     * Retourne les règles parsées. Les regex invalides sont ignorées.
     */
    fun load(json: String): List<NmapRule> {
        val out = mutableListOf<NmapRule>()
        val arr = runCatching { JSONArray(json) }.getOrNull() ?: return emptyList()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val regexStr = o.optString("regex", "")
            if (regexStr.isBlank()) continue
            val regex = runCatching {
                val flags = o.optString("flags", "")
                Regex(regexStr, if (flags.contains('i')) setOf(RegexOption.IGNORE_CASE) else emptySet())
            }.getOrNull() ?: continue
            out.add(
                NmapRule(
                    service = o.optString("service", ""),
                    product = o.optString("product", ""),
                    version = o.optString("version", ""),
                    regex = regex
                )
            )
        }
        rules = out
        return out
    }

    /**
     * Identifie la première règle qui matche une des bannières fournies.
     * L'ordre du fichier prime (règles les plus spécifiques en premier).
     * Retourne null si aucune règle ne matche.
     */
    fun identify(banners: List<String>): NmapMatch? {
        for (rule in rules) {
            for (banner in banners) {
                if (banner.isBlank()) continue
                val m = rule.regex.find(banner) ?: continue
                return NmapMatch(rule.service, rule.product, resolveVersion(rule.version, m))
            }
        }
        return null
    }

    /** Remplace « {N} » par le groupe de capture N dans un gabarit de version. */
    private fun resolveVersion(template: String, m: MatchResult): String {
        if (template.isBlank()) return ""
        if (!template.contains('{')) return template
        var out = template
        for (i in 1 until m.groupValues.size) {
            out = out.replace("{$i}", m.groupValues.getOrNull(i).orEmpty())
        }
        return out
    }
}

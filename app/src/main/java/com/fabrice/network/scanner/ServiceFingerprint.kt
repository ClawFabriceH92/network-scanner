package com.fabrice.network.scanner

/**
 * Annuaire de produits : identifie le modèle d'appareil depuis le banner
 * réseau (comme Fing). Logique pure, testable — les règles sont des motifs
 * regex → libellé produit.
 *
 * Le banner est récupéré par BannerGrab (HTTP Server, SSH, FTP, SMTP, IPP,
 * JetDirect, DSM Synology…). Ce fingerprint en extrait un libellé lisible
 * du type « HP LaserJet MFP E57540 » ou « Synology DS218play ».
 */
object ServiceFingerprint {

    data class Match(val product: String, val type: String)

    /** Règles : (pattern regex sur banner, libellé produit, type appareil). */
    private val RULES: List<Triple<Regex, String, String>> = listOf(
        // --- Imprimantes (IPP / JetDirect / LPD) ---
        Triple(Regex("HP (LaserJet[^\\r\\n]*|OfficeJet[^\\r\\n]*|DeskJet[^\\r\\n]*|ENVY[^\\r\\n]*)", RegexOption.IGNORE_CASE), "HP {0}", "Imprimante"),
        Triple(Regex("LaserJet MFP ([A-Z0-9]+)", RegexOption.IGNORE_CASE), "HP LaserJet MFP {0}", "Imprimante"),
        Triple(Regex("Canon[^\\r\\n]*(iP|MG|MX|TS|G[0-9])[^\\r\\n]*", RegexOption.IGNORE_CASE), "Canon {0}", "Imprimante"),
        Triple(Regex("EPSON[^\\r\\n]*(WF|XP|ET|L[0-9])[^\\r\\n]*", RegexOption.IGNORE_CASE), "Epson {0}", "Imprimante"),
        Triple(Regex("Brother[^\\r\\n]*(HL|MFC|DCP)[^\\r\\n]*", RegexOption.IGNORE_CASE), "Brother {0}", "Imprimante"),
        Triple(Regex("Xerox[^\\r\\n]*(WorkCentre|Phaser|VersaLink)[^\\r\\n]*", RegexOption.IGNORE_CASE), "Xerox {0}", "Imprimante"),
        Triple(Regex("RICOH[^\\r\\n]*", RegexOption.IGNORE_CASE), "Ricoh {0}", "Imprimante"),

        // --- NAS Synology / QNAP ---
        Triple(Regex("DiskStation[^\\r\\n]*|DS[0-9]{2,3}play|synology[^\\r\\n]*", RegexOption.IGNORE_CASE), "Synology {0}", "NAS"),
        Triple(Regex("QNAP[^\\r\\n]*|TS-[^\\r\\n]*", RegexOption.IGNORE_CASE), "QNAP {0}", "NAS"),

        // --- Serveurs Web / routeurs (via Server header) ---
        Triple(Regex("Server:\\s*nginx/([0-9.]+)", RegexOption.IGNORE_CASE), "nginx {0}", "Ordinateur"),
        Triple(Regex("Server:\\s*Apache/([0-9.]+)", RegexOption.IGNORE_CASE), "Apache {0}", "Ordinateur"),
        Triple(Regex("Server:\\s*lighttpd/([0-9.]+)", RegexOption.IGNORE_CASE), "lighttpd {0}", "Ordinateur"),
        Triple(Regex("Server:\\s*Microsoft-IIS/([0-9.]+)", RegexOption.IGNORE_CASE), "Microsoft IIS {0}", "Ordinateur"),

        // --- Box / routeurs (banner UPnP) ---
        Triple(Regex("Freebox[^\\r\\n]*", RegexOption.IGNORE_CASE), "Freebox", "Routeur / Box"),
        Triple(Regex("Livebox[^\\r\\n]*", RegexOption.IGNORE_CASE), "Livebox", "Routeur / Box"),
        Triple(Regex("Sagemcom[^\\r\\n]*", RegexOption.IGNORE_CASE), "Sagemcom", "Routeur / Box"),
        Triple(Regex("Bbox[^\\r\\n]*", RegexOption.IGNORE_CASE), "Bbox", "Routeur / Box"),

        // --- Caméras ---
        Triple(Regex("Hikvision[^\\r\\n]*", RegexOption.IGNORE_CASE), "Hikvision", "Caméra"),
        Triple(Regex("Reolink[^\\r\\n]*", RegexOption.IGNORE_CASE), "Reolink", "Caméra"),
        Triple(Regex("Dahua[^\\r\\n]*", RegexOption.IGNORE_CASE), "Dahua", "Caméra"),

        // --- TV / média ---
        Triple(Regex("Samsung[^\\r\\n]*(TV|SmartTV)[^\\r\\n]*", RegexOption.IGNORE_CASE), "Samsung TV", "TV / Media"),
        Triple(Regex("BRAVIA[^\\r\\n]*", RegexOption.IGNORE_CASE), "Sony BRAVIA", "TV / Media"),
        Triple(Regex("Chromecast[^\\r\\n]*", RegexOption.IGNORE_CASE), "Chromecast", "TV / Media"),

        // --- Smartphones ---
        Triple(Regex("iPhone[^\\r\\n]*|iPad[^\\r\\n]*", RegexOption.IGNORE_CASE), "Apple {0}", "Smartphone"),
        Triple(Regex("Xiaomi[^\\r\\n]*", RegexOption.IGNORE_CASE), "Xiaomi", "Smartphone"),
        Triple(Regex("SM-[A-Z0-9]+", RegexOption.IGNORE_CASE), "Samsung {0}", "Smartphone"),

        // --- Autres ---
        Triple(Regex("reMarkable[^\\r\\n]*", RegexOption.IGNORE_CASE), "reMarkable", "Tablette"),
        Triple(Regex("Raspberry[^\\r\\n]*", RegexOption.IGNORE_CASE), "Raspberry Pi", "Ordinateur"),
        Triple(Regex("Synology", RegexOption.IGNORE_CASE), "Synology", "NAS")
    )

    /**
     * Cherche une correspondance produit dans le banner.
     * Retourne null si rien ne matche.
     */
    fun identify(banner: String): Match? {
        if (banner.isBlank()) return null
        for ((re, label, type) in RULES) {
            val m = re.find(banner) ?: continue
            val matched = m.groupValues
            // {0} = groupe 1 (le modèle), sinon le texte complet du match
            val product = if (label.contains("{0}")) {
                val g = matched.getOrNull(1)?.trim().orEmpty()
                if (g.isNotEmpty()) label.replace("{0}", g) else label.replace(" {0}", "")
            } else {
                label
            }
            return Match(product, type)
        }
        return null
    }
}

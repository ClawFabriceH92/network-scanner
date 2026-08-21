package com.fabrice.network.scanner

/**
 * Scan de vulnérabilités passif (par versions de services), aligné sur les
 * sources CERT : CISA KEV (vulnérabilités activement exploitées) + NVD
 * (CVE des services courants avec CVSS).
 *
 * Pipeline :
 * 1. Banner grabbing existant (HTTP Server, SSH, FTP/SMTP/POP3/IMAP) → texte brut
 * 2. Parsing du banner → (produit, version) — ex: "Server: nginx/1.18.0" → nginx 1.18.0
 * 3. Matching contre la base CVE embarquée (ranges de versions NVD)
 * 4. Score de risque par appareil + agrégat réseau
 */
object VulnScanner {

    /** Un service identifié depuis un banner. */
    data class Service(val product: String, val version: String?, val banner: String)

    /** Résultat du matching pour un appareil. */
    data class DeviceVulns(
        val services: List<Service>,
        val cves: List<CveEntry>,
        val score: Int,          // 0..100
        val label: String,       // Aucune / Faible / Modéré / Élevé / Critique
        val criticalCount: Int,
        val highCount: Int,
        val kevCount: Int,
        val defaultCred: String? = null
    ) {
        val total: Int get() = cves.size
        val isEmpty: Boolean get() = cves.isEmpty() && defaultCred == null
    }

    /** Poids sévérité pour le score. */
    private fun severityWeight(sev: String): Int = when (sev) {
        "CRITICAL" -> 50
        "HIGH" -> 30
        "MEDIUM" -> 15
        "LOW" -> 5
        else -> 0
    }

    fun labelForScore(score: Int): String = when {
        score == 0 -> "Aucune"
        score < 15 -> "Faible"
        score < 30 -> "Modéré"
        score < 50 -> "Élevé"
        else -> "Critique"
    }

    /**
     * Parse un banner de service → produit + version.
     * Formats connus (BannerGrab) :
     *   "Server: nginx/1.18.0" | "Server: Apache/2.4.41 (Ubuntu)"
     *   "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
     *   "220 ProFTPD 1.3.5e Server"
     *   "220 Microsoft ESMTP MAIL"
     */
    fun parseBanner(banner: String): List<Service> {
        if (banner.isBlank()) return emptyList()
        val b = banner.trim()
        return when {
            // HTTP Server header
            b.startsWith("Server:", ignoreCase = true) -> {
                val server = b.substringAfter(':').trim()
                parseServerHeader(server, b)
            }
            // SSH identification
            b.startsWith("SSH-") -> {
                val m = Regex("OpenSSH[_-]([0-9][0-9a-zA-Z.\\-_]*)", RegexOption.IGNORE_CASE).find(b)
                if (m != null) {
                    listOf(Service("openssh", cleanVersion(m.groupValues[1]), b))
                } else if (b.contains("dropbear", ignoreCase = true)) {
                    listOf(Service("openssh", null, b))
                } else emptyList()
            }
            // FTP / SMTP / POP3 / IMAP / Telnet text banners
            else -> parseTextBanner(b)
        }
    }

    private fun parseServerHeader(server: String, banner: String): List<Service> {
        val s = server.lowercase()
        return when {
            s.contains("nginx") -> listOf(Service("nginx", extractSlashVersion(server, "nginx"), banner))
            s.contains("apache") -> listOf(Service("apache", extractSlashVersion(server, "apache"), banner))
            s.contains("microsoft-iis") || s.contains("microsoft-httpapi") ->
                listOf(Service("iis", extractSlashVersion(server, "iis"), banner))
            s.contains("lighttpd") -> listOf(Service("lighttpd", extractSlashVersion(server, "lighttpd"), banner))
            s.contains("thttpd") -> listOf(Service("thttpd", extractSlashVersion(server, "thttpd"), banner))
            s.contains("openresty") -> listOf(Service("nginx", extractSlashVersion(server, "openresty"), banner))
            else -> emptyList()
        }
    }

    /** "nginx/1.18.0 (Ubuntu)" → "1.18.0" ; "Apache/2.4.41" → "2.4.41". */
    private fun extractSlashVersion(server: String, product: String): String? {
        val idx = server.indexOf('/')
        if (idx < 0) return null
        val after = server.substring(idx + 1).trim()
        val m = Regex("^([0-9][0-9a-zA-Z.\\-_]*)").find(after) ?: return null
        return cleanVersion(m.groupValues[1])
    }

    private fun parseTextBanner(b: String): List<Service> {
        val low = b.lowercase()
        return when {
            low.contains("proftpd") -> listOf(Service("proftpd", extractVersionAfter(b, "proftpd"), b))
            low.contains("vsftpd") -> listOf(Service("vsftpd", extractVersionAfter(b, "vsftpd"), b))
            low.contains("pure-ftpd") || low.contains("pureftpd") -> listOf(Service("pureftpd", extractVersionAfter(b, "pure-ftpd"), b))
            low.contains("postfix") -> listOf(Service("postfix", null, b))
            low.contains("exim") -> listOf(Service("exim", null, b))
            low.contains("sendmail") -> listOf(Service("sendmail", null, b))
            low.contains("dovecot") -> listOf(Service("dovecot", null, b))
            low.contains("microsoft") && low.contains("esmtp") -> listOf(Service("iis", null, b))
            else -> emptyList()
        }
    }

    /** "ProFTPD 1.3.5e Server" → "1.3.5e". */
    private fun extractVersionAfter(banner: String, product: String): String? {
        val idx = banner.indexOf(product, ignoreCase = true)
        if (idx < 0) return null
        val after = banner.substring(idx + product.length).trim()
        val m = Regex("^([0-9][0-9a-zA-Z.\\-_]*)").find(after) ?: return null
        return cleanVersion(m.groupValues[1])
    }

    /** Nettoie une version brute : "8.2p1" → "8.2p1", "1.18.0" → "1.18.0". */
    private fun cleanVersion(v: String): String = v.trim().trimEnd('/')

    /**
     * Matching : version détectée contre les CVE du produit.
     * - CVE avec ranges : match si la version tombe dans une des bornes
     * - CVE sans range (KEV produit-level) : match produit-level uniquement
     *   quand aucune version n'est détectée (on ne peut pas confirmer) —
     *   on les signale quand même avec flag kevOnly pour ne pas noyer.
     */
    fun match(services: List<Service>, db: CveDatabase, defaultCred: String? = null): DeviceVulns {
        val hits = LinkedHashMap<String, CveEntry>()

        services.forEach { svc ->
            val entries = db.entriesFor(svc.product)
            entries.forEach { cve ->
                val versionHit = svc.version != null && cve.ranges.any { inRange(svc.version, it) }
                // KEV produit-level (sans range) : alerte dès que le produit
                // est détecté — c'est l'exploitation active, le plus important.
                val productLevelOnly = cve.ranges.isEmpty() && (cve.kev || svc.version == null)
                if (versionHit || productLevelOnly) {
                    hits[cve.id] = cve
                }
            }
        }

        val cves = hits.values.sortedWith(compareByDescending<CveEntry> { severityWeight(it.severity) }
            .thenByDescending { it.kev })
        var score = 0
        var critical = 0
        var high = 0
        var kevCount = 0
        cves.forEach { c ->
            score += severityWeight(c.severity)
            if (c.severity == "CRITICAL") critical++
            if (c.severity == "HIGH") high++
            if (c.kev) kevCount++
        }
        // Bonus KEV : une vulnérabilité activement exploitée monte le score
        score += kevCount * 10
        // Credential par défaut trouvée = accès critique (+50)
        if (defaultCred != null) score += 50
        score = score.coerceAtMost(100)

        return DeviceVulns(
            services = services,
            cves = cves,
            score = score,
            label = labelForScore(score),
            criticalCount = critical,
            highCount = high,
            kevCount = kevCount,
            defaultCred = defaultCred
        )
    }

    /** Compare deux versions (format NVD CPE). Retourne <0, 0, >0. */
    fun compareVersions(a: String, b: String): Int {
        val pa = versionParts(a)
        val pb = versionParts(b)
        val n = maxOf(pa.size, pb.size)
        for (i in 0 until n) {
            val x = pa.getOrNull(i) ?: 0
            val y = pb.getOrNull(i) ?: 0
            if (x != y) return x.compareTo(y)
        }
        return 0
    }

    /** "1.18.0" → [1,18,0] ; "8.2p1" → [8,2,1] ; "1.3.5e" → [1,3,5]. */
    private fun versionParts(v: String): List<Int> {
        val clean = v.trim().replace('-', '.').replace('_', '.')
        return clean.split('.').mapNotNull { seg ->
            val num = Regex("^\\d+").find(seg)?.value
            num?.toIntOrNull()
        }
    }

    /** Teste si une version tombe dans un range NVD. */
    fun inRange(version: String, r: CveRange): Boolean {
        if (r.startIncluding != null && compareVersions(version, r.startIncluding) < 0) return false
        if (r.startExcluding != null && compareVersions(version, r.startExcluding) <= 0) return false
        if (r.endExcluding != null && compareVersions(version, r.endExcluding) >= 0) return false
        if (r.endIncluding != null && compareVersions(version, r.endIncluding) > 0) return false
        return true
    }
}

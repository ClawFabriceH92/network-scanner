package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VulnScannerTest {

    // ---------- Parsing de banner ----------

    @Test
    fun parseBanner_nginx() {
        val services = VulnScanner.parseBanner("Server: nginx/1.18.0")
        assertEquals(1, services.size)
        assertEquals("nginx", services[0].product)
        assertEquals("1.18.0", services[0].version)
    }

    @Test
    fun parseBanner_apacheWithOs() {
        val services = VulnScanner.parseBanner("Server: Apache/2.4.41 (Ubuntu)")
        assertEquals("apache", services[0].product)
        assertEquals("2.4.41", services[0].version)
    }

    @Test
    fun parseBanner_iis() {
        val services = VulnScanner.parseBanner("Server: Microsoft-IIS/10.0")
        assertEquals("iis", services[0].product)
        assertEquals("10.0", services[0].version)
    }

    @Test
    fun parseBanner_openssh() {
        val services = VulnScanner.parseBanner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
        assertEquals("openssh", services[0].product)
        assertEquals("8.2p1", services[0].version)
    }

    @Test
    fun parseBanner_proftpd() {
        val services = VulnScanner.parseBanner("220 ProFTPD 1.3.5e Server")
        assertEquals("proftpd", services[0].product)
        assertEquals("1.3.5e", services[0].version)
    }

    @Test
    fun parseBanner_esmtpNoVersion() {
        val services = VulnScanner.parseBanner("220 Microsoft ESMTP MAIL")
        assertEquals(1, services.size)
        assertEquals("iis", services[0].product)
        assertNull(services[0].version)
    }

    @Test
    fun parseBanner_blankOrUnknown() {
        assertTrue(VulnScanner.parseBanner("").isEmpty())
        assertTrue(VulnScanner.parseBanner("Weird banner here").isEmpty())
    }

    // ---------- Comparaison de versions ----------

    @Test
    fun compareVersions_basic() {
        assertTrue(VulnScanner.compareVersions("1.18.0", "1.18.0") == 0)
        assertTrue(VulnScanner.compareVersions("1.18.0", "1.18.1") < 0)
        assertTrue(VulnScanner.compareVersions("2.0", "1.99.9") > 0)
        assertTrue(VulnScanner.compareVersions("8.2p1", "8.3") < 0)
        assertTrue(VulnScanner.compareVersions("8.2p1", "8.1") > 0)
    }

    @Test
    fun compareVersions_withSuffix() {
        // "1.3.5e" vs "1.3.5" : même numéro, suffixe ignoré → égal
        assertTrue(VulnScanner.compareVersions("1.3.5e", "1.3.5") == 0)
    }

    // ---------- Ranges ----------

    @Test
    fun inRange_endExcluding() {
        val r = CveRange(endExcluding = "1.18.1")
        assertTrue(VulnScanner.inRange("1.18.0", r))
        assertFalse(VulnScanner.inRange("1.18.1", r))
        assertTrue(VulnScanner.inRange("1.17", r))
    }

    @Test
    fun inRange_startAndEnd() {
        val r = CveRange(startIncluding = "8.0", endExcluding = "8.8")
        assertTrue(VulnScanner.inRange("8.2p1", r))
        assertFalse(VulnScanner.inRange("7.9", r))
        assertFalse(VulnScanner.inRange("8.8", r))
    }

    @Test
    fun inRange_endIncluding() {
        val r = CveRange(endIncluding = "2.4.41")
        assertTrue(VulnScanner.inRange("2.4.41", r))
        assertFalse(VulnScanner.inRange("2.4.42", r))
    }

    // ---------- Matching complet ----------

    private fun dbWith(vararg cves: CveEntry): CveDatabase {
        val map = cves.groupBy { it.product }
        return CveDatabase(generated = "2026-08-14", productLabels = map.keys.associateWith { it }, byProduct = map)
    }

    private fun cve(
        id: String,
        product: String,
        sev: String = "HIGH",
        cvss: Double? = 7.5,
        kev: Boolean = false,
        vararg ranges: CveRange
    ) = CveEntry(id, product, sev, cvss, "desc", kev, false, ranges.toList())

    @Test
    fun match_versionHit() {
        val db = dbWith(cve("CVE-2021-23017", "nginx", "CRITICAL", 9.8, false, CveRange(endExcluding = "1.21.0")))
        val result = VulnScanner.match(listOf(VulnScanner.Service("nginx", "1.18.0", "Server: nginx/1.18.0")), db)
        assertEquals(1, result.cves.size)
        assertEquals("CVE-2021-23017", result.cves[0].id)
        assertEquals("Critique", result.label)
        assertTrue(result.score >= 50)
    }

    @Test
    fun match_patchedVersionNoHit() {
        val db = dbWith(cve("CVE-2021-23017", "nginx", "CRITICAL", 9.8, false, CveRange(endExcluding = "1.21.0")))
        val result = VulnScanner.match(listOf(VulnScanner.Service("nginx", "1.21.1", "Server: nginx/1.21.1")), db)
        assertTrue(result.cves.isEmpty())
        assertEquals(0, result.score)
        assertEquals("Aucune", result.label)
    }

    @Test
    fun match_kevWithoutVersion_productLevelOnly() {
        val db = dbWith(cve("CVE-2024-0001", "openssh", "CRITICAL", 9.8, kev = true))
        val result = VulnScanner.match(listOf(VulnScanner.Service("openssh", null, "SSH-2.0-OpenSSH")), db)
        // Pas de version détectée → on signale la KEV produit-level
        assertEquals(1, result.cves.size)
        assertTrue(result.kevCount >= 1)
    }

    @Test
    fun match_kevWithVersionButNoRange_isFlagged() {
        val db = dbWith(cve("CVE-2024-0001", "openssh", "CRITICAL", 9.8, kev = true))
        val result = VulnScanner.match(listOf(VulnScanner.Service("openssh", "8.2p1", "SSH-2.0-OpenSSH_8.2p1")), db)
        assertEquals(1, result.cves.size)
        assertTrue(result.cves[0].kev)
    }

    @Test
    fun match_multipleServicesAndSort() {
        val db = dbWith(
            cve("CVE-A", "nginx", "LOW", 3.0, false, CveRange(endExcluding = "9.0")),
            cve("CVE-B", "nginx", "CRITICAL", 9.8, true, CveRange(endExcluding = "9.0")),
            cve("CVE-C", "openssh", "HIGH", 7.5, false, CveRange(endExcluding = "9.0"))
        )
        val result = VulnScanner.match(
            listOf(
                VulnScanner.Service("nginx", "1.18.0", "Server: nginx/1.18.0"),
                VulnScanner.Service("openssh", "8.2p1", "SSH-2.0-OpenSSH_8.2p1")
            ),
            db
        )
        assertEquals(3, result.cves.size)
        // Tri : sévérité décroissante, KEV en tête
        assertEquals("CVE-B", result.cves[0].id)
        assertEquals("CVE-C", result.cves[1].id)
        assertEquals("CVE-A", result.cves[2].id)
        assertEquals(1, result.kevCount)
        assertTrue(result.score >= 50)
    }

    @Test
    fun score_neverAbove100() {
        val db = dbWith(
            cve("CVE-1", "nginx", "CRITICAL", 9.8, true, CveRange(endExcluding = "9.0")),
            cve("CVE-2", "nginx", "CRITICAL", 9.8, true, CveRange(endExcluding = "9.0")),
            cve("CVE-3", "nginx", "CRITICAL", 9.8, true, CveRange(endExcluding = "9.0"))
        )
        val result = VulnScanner.match(listOf(VulnScanner.Service("nginx", "1.0", "Server: nginx/1.0")), db)
        assertEquals(100, result.score)
    }

    // ---------- Chargement de la vraie base ----------

    @Test
    fun loadRealDatabase() {
        val text = javaClass.classLoader?.getResourceAsStream("cve_db.json")
            ?.bufferedReader()?.use { it.readText() } ?: return
        val db = CveDatabase.load(text)
        assertTrue(db.generated.isNotBlank())
        assertTrue(db.allCount > 300)
        assertTrue(db.entriesFor("nginx").isNotEmpty())
        assertTrue(db.entriesFor("openssh").isNotEmpty())
        // La base doit contenir des KEV (CISA) et des CVE à ranges (NVD)
        val kevCount = db.byProduct.values.flatten().count { it.kev }
        assertTrue(kevCount > 0)
        val ranged = db.byProduct.values.flatten().count { it.ranges.isNotEmpty() }
        assertTrue(ranged > 200)
    }
}

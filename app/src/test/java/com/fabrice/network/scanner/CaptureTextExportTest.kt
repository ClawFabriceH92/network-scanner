package com.fabrice.network.scanner

import com.fabrice.network.scanner.capture.CaptureState
import com.fabrice.network.scanner.capture.CaptureTextExport
import com.fabrice.network.scanner.capture.FirewallRules
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** v1.9.42 — export texte de la capture pour un LLM. */
class CaptureTextExportTest {

    private fun conn(host: String, ip: String, port: Int, app: String, out: Long, inn: Long,
                     cat: String = "", geo: String = "", blocked: Boolean = false, reason: String = "") =
        CaptureState.Conn("TCP", 50000, ip, port, 10001, app, out, inn, 3, 3, 0, 1000,
            if (blocked) "bloqué" else "actif", host, blocked, reason, cat, geo)

    private val session = CaptureTextExport.Session(
        startMs = 1_700_000_000_000, endMs = 1_700_000_090_000, packets = 120, bytesOut = 5000, bytesIn = 20000,
        blockedPackets = 4, rules = listOf(FirewallRules.Rule(FirewallRules.KIND_DOMAIN, "evil.example")),
        blockTrackers = true, allowedApps = emptySet(), ipv6 = false,
        deviceInfo = "Xiaomi 14, Android 15 (API 35), Scan Réseau 1.9.43",
        techLogs = listOf("2026-09-21 10:00:00.000 [I] Capture: Démarrage : TUN 10.111.222.1/32", "2026-09-21 10:00:01.000 [W] Capture: Connexion TCP 1.2.3.4:443 impossible")
    )

    @Test
    fun buildsMarkdownGroupedByApp() {
        val conns = listOf(
            conn("api.example.com", "93.184.216.34", 443, "Mail", 1000, 9000, geo = "🇺🇸US · Ashburn · Edgecast"),
            conn("ads.doubleclick.net", "142.250.1.1", 443, "Jeu", 500, 2000, cat = "Publicité · Google"),
            conn("", "203.0.113.9", 8080, "Jeu", 100, 100, blocked = true, reason = "règle evil.example")
        )
        val md = CaptureTextExport.build(conns, session, nowMs = 1_700_000_100_000)
        assertTrue(md.startsWith("# Capture réseau Android"))
        assertTrue(md.contains("Durée : 1 min 30 s"))
        assertTrue(md.contains("trackers/publicité bloqués, domaine evil.example · 4 paquet(s) bloqué(s)"))
        assertTrue(md.contains("1 connexion(s) vers des trackers/publicité : Publicité · Google (1)"))
        assertTrue(md.contains("Pays contactés : US (1)"))
        assertTrue(md.contains("1 connexion(s) vers des IP publiques sans nom connu"))
        // L'app la plus volumineuse en premier
        assertTrue(md.indexOf("### Mail") < md.indexOf("### Jeu"))
        assertTrue(md.contains("- api.example.com [93.184.216.34] · 443/TCP"))
        assertTrue(md.contains("BLOQUÉ (règle evil.example)"))
        assertTrue(md.contains("## Domaines contactés (2)"))
        assertTrue(md.contains("doubleclick.net"))
        assertTrue(md.contains("## Logs techniques"))
        assertTrue(md.contains("Environnement : Xiaomi 14"))
        assertTrue(md.contains("### Connexions brutes (3)"))
        assertTrue(md.contains("TCP :50000 → 93.184.216.34:443 [api.example.com] Mail(uid 10001) actif ↑1000 ↓9000 3/3pk"))
        assertTrue(md.contains("[règle evil.example]"))
        assertTrue(md.contains("### Journal du moteur de capture (2 ligne(s))"))
        assertTrue(md.contains("Connexion TCP 1.2.3.4:443 impossible"))
        assertTrue(md.indexOf("## Logs techniques") < md.indexOf("## Question suggérée"))
    }

    @Test
    fun appLogLinesFilter() {
        AppLog.clear()
        AppLog.i("Capture", "a")
        AppLog.w("Scan", "b")
        assertEquals(2, AppLog.lines().size)
        assertEquals(1, AppLog.lines(tags = setOf("Capture")).size)
        assertTrue(AppLog.lines(tags = setOf("Capture")).first().endsWith("[I] Capture: a"))
        assertTrue(AppLog.lines(sinceMs = System.currentTimeMillis() + 10_000).isEmpty())
    }

    @Test
    fun helpers() {
        assertEquals("doubleclick.net", CaptureTextExport.rootDomain("ads.g.doubleclick.net"))
        assertEquals("bbc.co.uk", CaptureTextExport.rootDomain("www.bbc.co.uk"))
        assertEquals("localhost", CaptureTextExport.rootDomain("localhost"))
        assertEquals("FR", CaptureTextExport.countryOf("🇫🇷FR · Paris · Orange"))
        assertEquals("", CaptureTextExport.countryOf(""))
        assertEquals("45 s", CaptureTextExport.formatDuration(45_000))
        assertEquals("2 h 5 min", CaptureTextExport.formatDuration(7_500_000))
    }
}

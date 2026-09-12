package com.fabrice.network.scanner

import com.fabrice.network.scanner.capture.CaptureState
import com.fabrice.network.scanner.capture.DnsSniParser
import com.fabrice.network.scanner.capture.FirewallRules
import com.fabrice.network.scanner.capture.FirewallRuntime
import com.fabrice.network.scanner.capture.GeoCache
import com.fabrice.network.scanner.capture.IpPacket
import com.fabrice.network.scanner.capture.TrackerDatabase
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v1.9.34 — pare-feu de capture, liste de trackers, IPv6, NXDOMAIN, GeoIP.
 */
class CaptureFirewallTest {

    // ---- Règles ---------------------------------------------------------

    @Test
    fun normalizeDomainStripsSchemePathAndWildcard() {
        assertEquals("doubleclick.net", FirewallRules.normalizeDomain("https://Doubleclick.NET/ads?x=1"))
        assertEquals("example.com", FirewallRules.normalizeDomain(" *.example.com. "))
        assertEquals("host.tld", FirewallRules.normalizeDomain("host.tld:8443"))
    }

    @Test
    fun hostMatchesSuffixOnly() {
        assertTrue(FirewallRules.hostMatches("ads.doubleclick.net", "doubleclick.net"))
        assertTrue(FirewallRules.hostMatches("doubleclick.net", "doubleclick.net"))
        assertFalse(FirewallRules.hostMatches("notdoubleclick.net", "doubleclick.net"))
        assertFalse(FirewallRules.hostMatches("", "doubleclick.net"))
    }

    @Test
    fun rulesJsonRoundTrip() {
        val rules = listOf(
            FirewallRules.Rule(FirewallRules.KIND_APP, "com.example.app", "Example"),
            FirewallRules.Rule(FirewallRules.KIND_DOMAIN, "tracker.io")
        )
        val back = FirewallRules.fromJson(FirewallRules.toJson(rules))
        assertEquals(rules, back)
        assertTrue(FirewallRules.fromJson("garbage").isEmpty())
        assertTrue(FirewallRules.fromJson(null).isEmpty())
    }

    @Test
    fun runtimeBlocksByUidRuleAndTracker() {
        FirewallRuntime.setForTest(
            uids = setOf(10123),
            domains = listOf("evil.example"),
            trackers = true,
            lookup = { h -> if (h.endsWith("ads.net")) "Publicité" else null }
        )
        assertTrue(FirewallRuntime.isUidBlocked(10123))
        assertFalse(FirewallRuntime.isUidBlocked(10124))
        assertFalse(FirewallRuntime.isUidBlocked(-1))
        assertEquals("règle evil.example", FirewallRuntime.domainBlockReason("cdn.evil.example"))
        assertEquals("tracker (Publicité)", FirewallRuntime.domainBlockReason("x.ads.net"))
        assertNull(FirewallRuntime.domainBlockReason("good.example"))
        // Trackers OFF → seule la règle explicite bloque
        FirewallRuntime.setForTest(emptySet(), listOf("evil.example"), false) { "Publicité" }
        assertNull(FirewallRuntime.domainBlockReason("x.ads.net"))
        FirewallRuntime.setForTest(emptySet(), emptyList(), false, null)
    }

    // ---- Trackers -------------------------------------------------------

    @Test
    fun trackerLookupUsesMostSpecificSuffix() {
        val db = TrackerDatabase.parse(
            """{"generated":"2026-09-12","domains":{"doubleclick.net":"Publicité|Google","stats.example.org":"Analytique|Ex"}}"""
        )
        assertEquals(2, db.count)
        assertEquals("2026-09-12", db.generated)
        assertEquals("Publicité · Google", db.lookup("ad.g.doubleclick.net")?.label)
        assertEquals("Analytique", db.lookup("stats.example.org")?.category)
        assertNull(db.lookup("example.org"))
        assertNull(db.lookup(""))
    }

    // ---- DNS : requête + NXDOMAIN ---------------------------------------

    private fun dnsQuery(name: String, id: Int = 0x1234): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(id ushr 8); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00)             // RD
        out.write(0); out.write(1)                   // QDCOUNT 1
        out.write(0); out.write(0); out.write(0); out.write(0); out.write(0); out.write(0)
        name.split('.').forEach { l -> out.write(l.length); out.write(l.toByteArray()) }
        out.write(0)
        out.write(0); out.write(1)                   // A
        out.write(0); out.write(1)                   // IN
        return out.toByteArray()
    }

    @Test
    fun parseDnsQuestionReadsQueryName() {
        val q = dnsQuery("ads.doubleclick.net")
        assertEquals("ads.doubleclick.net", DnsSniParser.parseDnsQuestion(q, 0, q.size))
        // Une réponse (QR=1) n'est pas une question
        val r = q.copyOf(); r[2] = (r[2].toInt() or 0x80).toByte()
        assertNull(DnsSniParser.parseDnsQuestion(r, 0, r.size))
    }

    @Test
    fun buildNxDomainKeepsIdAndQuestionSetsRcode3() {
        val q = dnsQuery("tracker.io", 0xBEEF)
        val nx = DnsSniParser.buildNxDomain(q, 0, q.size)
        assertNotNull(nx)
        nx!!
        assertEquals(0xBEEF, IpPacket.u16(nx, 0))
        val flags = IpPacket.u16(nx, 2)
        assertTrue(flags and 0x8000 != 0)             // QR
        assertEquals(3, flags and 0x000F)             // NXDOMAIN
        assertEquals(1, IpPacket.u16(nx, 4))
        assertEquals(0, IpPacket.u16(nx, 6))
        assertEquals(q.size, nx.size)                 // en-tête + question uniquement
        assertEquals("tracker.io", DnsSniParser.parseDnsQuestion(q, 0, q.size))
    }

    // ---- IPv6 -----------------------------------------------------------

    @Test
    fun buildUdpV6ProducesValidHeaderAndChecksum() {
        val payload = "hello".toByteArray()
        val p = IpPacket.buildUdp("2001:db8::1", 53, "2001:db8::2", 40000, payload, payload.size)
        assertEquals(6, IpPacket.version(p))
        assertEquals(40, IpPacket.l4Offset(p))
        assertEquals(IpPacket.PROTO_UDP, IpPacket.l4Protocol(p))
        assertEquals("2001:db8::1", IpPacket.srcIp(p))
        assertEquals("2001:db8::2", IpPacket.dstIp(p))
        assertEquals(40 + 8 + 5, IpPacket.packetEnd(p))
        assertEquals(53, IpPacket.u16(p, 40))
        assertEquals(40000, IpPacket.u16(p, 42))
        // Checksum valide ⇔ recalcul avec le champ inclus donne 0
        assertEquals(0, IpPacket.l4Checksum(p, 40, 13, IpPacket.PROTO_UDP))
    }

    @Test
    fun buildTcpV6RstIsParsable() {
        val p = IpPacket.buildTcp("2a01:e0a::1", 443, "fd00::1", 51000, 0L, 12345L,
            IpPacket.RST or IpPacket.ACK, 0, null, 0, 0)
        assertEquals(6, IpPacket.version(p))
        assertEquals(IpPacket.PROTO_TCP, IpPacket.l4Protocol(p))
        assertEquals(IpPacket.RST or IpPacket.ACK, IpPacket.u8(p, 40 + 13))
        assertEquals(12345L, IpPacket.u32(p, 40 + 8))
        assertEquals(0, IpPacket.l4Checksum(p, 40, 20, IpPacket.PROTO_TCP))
    }

    @Test
    fun v4HelpersStillWork() {
        val p = IpPacket.buildUdp("10.0.0.1", 1, "10.0.0.2", 2, ByteArray(0), 0)
        assertEquals(4, IpPacket.version(p))
        assertEquals(20, IpPacket.l4Offset(p))
        assertEquals(28, IpPacket.packetEnd(p))
        assertEquals("10.0.0.1", IpPacket.srcIp(p))
    }

    // ---- GeoIP ----------------------------------------------------------

    @Test
    fun geoPublicIpDetection() {
        assertTrue(GeoCache.isPublic("93.184.216.34"))
        assertFalse(GeoCache.isPublic("192.168.0.10"))
        assertFalse(GeoCache.isPublic("10.1.2.3"))
        assertFalse(GeoCache.isPublic("172.20.0.1"))
        assertFalse(GeoCache.isPublic("100.64.0.1"))
        assertFalse(GeoCache.isPublic("224.0.0.251"))
        assertTrue(GeoCache.isPublic("2a01:e0a:1::1"))
        assertFalse(GeoCache.isPublic("fe80::1"))
        assertFalse(GeoCache.isPublic("fd00::1"))
        assertEquals("🇫🇷", GeoCache.flag("FR"))
        assertEquals("", GeoCache.flag("fr"))
    }

    // ---- CSV connexions -------------------------------------------------

    @Test
    fun connectionsCsvHasHeaderAndRow() {
        val c = CaptureState.Conn(
            "TCP", 51000, "1.2.3.4", 443, 10001, "App", 100, 200, 3, 4,
            1_700_000_000_000, 1_700_000_001_000, "bloqué", "ads.net",
            blocked = true, blockReason = "tracker (Publicité)", category = "Publicité · X", geo = "🇺🇸US"
        )
        val csv = CsvExporter.buildConnectionsCsv(listOf(c))
        val lines = csv.trim().lines()
        assertEquals(2, lines.size)
        assertTrue(lines[0].startsWith("﻿Protocole;Hôte;IP distante"))
        assertTrue(lines[1].startsWith("TCP;ads.net;1.2.3.4;443;51000;App;Publicité · X;🇺🇸US;bloqué;tracker (Publicité);100;200;7;"))
    }
}

package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** v1.9.35 — diff structuré entre deux scans + signaux d'usurpation ARP. */
class ScanDiffTest {

    private fun dev(ip: String, mac: String, ports: List<Int> = emptyList(), gw: Boolean = false, name: String = "") =
        Device(ip = ip, mac = mac, hostname = name, ports = ports, isGateway = gw, alive = true)

    @Test
    fun emptyPreviousGivesNoChanges() {
        assertTrue(ScanDiff.compute(emptyList(), listOf(dev("192.168.0.2", "aa:aa:aa:aa:aa:01"))).isEmpty())
    }

    @Test
    fun portsOpenedAndClosedAreDetected() {
        val prev = listOf(dev("192.168.0.10", "aa:aa:aa:aa:aa:10", listOf(80, 443), name = "printer"))
        val cur = listOf(dev("192.168.0.10", "aa:aa:aa:aa:aa:10", listOf(80, 22), name = "printer"))
        val ch = ScanDiff.compute(prev, cur)
        val opened = ch.first { it.kind == ScanDiff.Kind.PORT_OPENED }
        val closed = ch.first { it.kind == ScanDiff.Kind.PORT_CLOSED }
        assertTrue(opened.detail.contains("22"))
        assertEquals(1, opened.severity)          // SSH = port sensible
        assertTrue(closed.detail.contains("443"))
        assertEquals(0, closed.severity)
    }

    @Test
    fun portsIgnoredWhenNotScanned() {
        val prev = listOf(dev("192.168.0.10", "aa:aa:aa:aa:aa:10", listOf(80)))
        val cur = listOf(dev("192.168.0.10", "aa:aa:aa:aa:aa:10", emptyList()))
        assertTrue(ScanDiff.compute(prev, cur, portsKnown = false).none { it.kind == ScanDiff.Kind.PORT_CLOSED })
    }

    @Test
    fun gatewayMacChangeIsAlert() {
        val prev = listOf(dev("192.168.0.1", "aa:aa:aa:aa:aa:01", gw = true))
        val cur = listOf(dev("192.168.0.1", "bb:bb:bb:bb:bb:02", gw = true))
        val ch = ScanDiff.arpAlerts(prev, cur)
        assertEquals(1, ch.size)
        assertEquals(ScanDiff.Kind.MAC_CHANGED, ch[0].kind)
        assertEquals(2, ch[0].severity)
        assertTrue(ch[0].message.contains("🚨"))
    }

    @Test
    fun nonGatewayMacChangeIsWarning() {
        val prev = listOf(dev("192.168.0.50", "aa:aa:aa:aa:aa:50"))
        val cur = listOf(dev("192.168.0.50", "cc:cc:cc:cc:cc:50"))
        assertEquals(1, ScanDiff.arpAlerts(prev, cur).single().severity)
    }

    @Test
    fun duplicateMacWithGatewayIsAlert() {
        val cur = listOf(
            dev("192.168.0.1", "aa:aa:aa:aa:aa:01", gw = true),
            dev("192.168.0.66", "AA:AA:AA:AA:AA:01")
        )
        val ch = ScanDiff.arpAlerts(emptyList(), cur)
        assertEquals(ScanDiff.Kind.DUPLICATE_MAC, ch.single().kind)
        assertEquals(2, ch.single().severity)
        assertTrue(ch.single().detail.contains("192.168.0.66"))
    }

    @Test
    fun ipChangeSameMacIsInfo() {
        val prev = listOf(dev("192.168.0.20", "aa:aa:aa:aa:aa:20"))
        val cur = listOf(dev("192.168.0.21", "aa:aa:aa:aa:aa:20"))
        val ch = ScanDiff.compute(prev, cur)
        assertTrue(ch.any { it.kind == ScanDiff.Kind.IP_CHANGED && it.severity == 0 })
        assertTrue(ch.none { it.kind == ScanDiff.Kind.NEW_DEVICE })
    }

    @Test
    fun summaryCountsAlertsAndWarnings() {
        val prev = listOf(dev("192.168.0.1", "aa:aa:aa:aa:aa:01", gw = true), dev("192.168.0.50", "aa:aa:aa:aa:aa:50", listOf(80)))
        val cur = listOf(dev("192.168.0.1", "bb:bb:bb:bb:bb:02", gw = true), dev("192.168.0.50", "aa:aa:aa:aa:aa:50", listOf(80, 3389)))
        val ch = ScanDiff.compute(prev, cur)
        assertEquals(2, ch.first().severity)   // trié : alerte en premier
        assertEquals("2 changements (1 alerte, 1 à vérifier)", ScanDiff.summary(ch))
        assertEquals("", ScanDiff.summary(emptyList()))
    }
}

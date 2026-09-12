package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** v1.9.36 — canaux Wi-Fi, exposition Internet, prévision toner + CSV imprimante. */
class R3FeaturesTest {

    private fun net(ssid: String, bssid: String, freq: Int) =
        WifiScanner.WifiNetwork(ssid, bssid, -60, freq, "[WPA2-PSK-CCMP][ESS]")

    // ---- Canaux Wi-Fi ---------------------------------------------------

    @Test
    fun occupancy24WeightsNeighbours() {
        val nets = listOf(net("a", "00:00:00:00:00:01", 2437))   // canal 6
        val occ = WifiChannels.occupancy24(nets).associateBy { it.channel }
        assertEquals(1.0, occ[6]!!.load, 0.001)
        assertEquals(0.5, occ[4]!!.load, 0.001)
        assertEquals(0.5, occ[8]!!.load, 0.001)
        assertEquals(0.0, occ[11]!!.load, 0.001)
        assertEquals(1, occ[6]!!.networks)
    }

    @Test
    fun best24PicksLeastLoadedNonOverlapping() {
        val nets = listOf(
            net("a", "00:00:00:00:00:01", 2412), net("b", "00:00:00:00:00:02", 2412),   // canal 1 ×2
            net("c", "00:00:00:00:00:03", 2437)                                          // canal 6
        )
        assertEquals(11, WifiChannels.best24(nets)!!.channel)
    }

    @Test
    fun best5AndAdvice() {
        val nets = listOf(
            net("me", "aa:bb:cc:dd:ee:ff", 5180),   // canal 36
            net("x", "00:00:00:00:00:10", 5180),
            net("y", "00:00:00:00:00:11", 5180)
        )
        assertEquals(40, WifiChannels.best5(nets)!!.channel)
        val advice = WifiChannels.advice(nets, "AA:BB:CC:DD:EE:FF")
        assertNotNull(advice)
        assertTrue(advice!!.contains("canal 40"))
        assertNull(WifiChannels.advice(nets, null))
    }

    @Test
    fun adviceOverlappingChannel() {
        val nets = listOf(net("me", "aa:bb:cc:dd:ee:ff", 2422))   // canal 3
        val advice = WifiChannels.advice(nets, "aa:bb:cc:dd:ee:ff")!!
        assertTrue(advice.contains("chevauchant"))
    }

    // ---- Exposition Internet -------------------------------------------

    private fun fw(ext: Int, ip: String, int: Int, proto: String = "tcp", enabled: Boolean = true) =
        BoxPortForward(ext, ip, int, proto, enabled, "", "Freebox")

    @Test
    fun newForwardsDiffAndRisk() {
        val a = fw(8080, "192.168.0.10", 80)
        val b = fw(51413, "192.168.0.20", 51413)
        val known = setOf(ExposureMonitor.signature(a))
        val fresh = ExposureMonitor.newForwards(known, listOf(a, b, fw(22, "192.168.0.5", 22, enabled = false)))
        assertEquals(listOf(b), fresh)                    // désactivée ignorée
        assertEquals(2, ExposureMonitor.risk(a))          // 80 exposé
        assertEquals(1, ExposureMonitor.risk(b))
        assertEquals(0, ExposureMonitor.risk(fw(22, "x", 22, enabled = false)))
        assertEquals("tcp:8080>192.168.0.10:80", ExposureMonitor.signature(a))
        assertTrue(ExposureMonitor.describe(a).startsWith("8080/tcp → 192.168.0.10:80"))
    }

    @Test
    fun upnpMappingConverts() {
        val m = IgdProbe.PortMapping(3389, "TCP", "192.168.0.7", 3389, "RDP", true)
        val f = ExposureMonitor.fromUpnp(m)
        assertEquals("UPnP", f.source)
        assertEquals(2, ExposureMonitor.risk(f))
        assertEquals("RDP", f.comment)
    }

    // ---- Prévision toner + CSV -----------------------------------------

    private fun snap(ts: Long, level: Int, pages: Long = 100) = PrinterStatsStore.Snapshot(
        ts, "HP E57540", "idle", pages, null, null,
        listOf(PrinterProbe.Supply("Black Cartridge", "black", "toner", level))
    )

    @Test
    fun forecastLinearDecline() {
        val day = 86_400_000L
        val h = listOf(snap(0, 80), snap(10 * day, 70), snap(20 * day, 60))
        val fc = PrinterStatsStore.tonerForecast(h, "black cartridge", nowMs = 20 * day)!!
        assertEquals(1.0, fc.percentPerDay, 0.01)
        assertEquals(60.0, fc.daysLeft, 0.5)
        assertEquals((80 * day).toDouble(), fc.emptyAtMs.toDouble(), (day / 2).toDouble())
    }

    @Test
    fun forecastRestartsAfterReplacement() {
        val day = 86_400_000L
        // Cartouche remplacée au jour 20 (niveau remonte à 100) : seule la fin compte.
        val h = listOf(snap(0, 30), snap(10 * day, 10), snap(20 * day, 100), snap(30 * day, 95))
        val fc = PrinterStatsStore.tonerForecast(h, "black cartridge", nowMs = 30 * day)!!
        assertEquals(0.5, fc.percentPerDay, 0.01)
        assertEquals(190.0, fc.daysLeft, 1.0)
    }

    @Test
    fun forecastNullWhenNotEnoughData() {
        val day = 86_400_000L
        assertNull(PrinterStatsStore.tonerForecast(listOf(snap(0, 50)), "black cartridge"))
        assertNull(PrinterStatsStore.tonerForecast(listOf(snap(0, 50), snap(3_600_000, 49)), "black cartridge"))
        assertNull(PrinterStatsStore.tonerForecast(listOf(snap(0, 50), snap(5 * day, 50)), "black cartridge"))
        assertNull(PrinterStatsStore.tonerForecast(listOf(snap(0, 50), snap(5 * day, 40)), "cyan"))
    }

    @Test
    fun printerCsvHasDynamicSupplyColumns() {
        val csv = PrinterStatsStore.buildCsv(listOf(snap(0, 80, 1234), snap(86_400_000, 75, 1300)))
        val lines = csv.trim().lines()
        assertEquals(3, lines.size)
        assertTrue(lines[0].endsWith("Date;Modèle;État;Pages;Numérisations;Copies;Black Cartridge (%)"))
        assertTrue(lines[1].contains(";HP E57540;idle;1234;;;80"))
        assertTrue(lines[2].endsWith(";75"))
    }
}

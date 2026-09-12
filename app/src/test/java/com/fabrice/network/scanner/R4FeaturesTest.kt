package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** v1.9.37 — traceurs BLE, journal des coupures Internet, test de détournement DNS. */
class R4FeaturesTest {

    // ---- Traceurs BLE ---------------------------------------------------

    private val FD5A = "0000fd5a-0000-1000-8000-00805f9b34fb"
    private val FEED = "0000feed-0000-1000-8000-00805f9b34fb"
    private val FEAA = "0000feaa-0000-1000-8000-00805f9b34fb"

    @Test
    fun classifyTrackers() {
        assertEquals("Apple Find My (AirTag / accessoire)",
            BleTrackers.classify(mapOf(0x004C to byteArrayOf(0x12, 0x19, 0x10)), emptyList(), emptyMap()))
        assertNull(BleTrackers.classify(mapOf(0x004C to byteArrayOf(0x07, 0x19)), emptyList(), emptyMap()))   // AirPods
        assertEquals("Samsung SmartTag", BleTrackers.classify(emptyMap(), listOf(FD5A), emptyMap()))
        assertEquals("Tile", BleTrackers.classify(emptyMap(), listOf(FEED), emptyMap()))
        assertEquals("Google Find My Device",
            BleTrackers.classify(emptyMap(), emptyList(), mapOf(FEAA to byteArrayOf(0x40, 0x01))))
        assertNull(BleTrackers.classify(emptyMap(), emptyList(), mapOf(FEAA to byteArrayOf(0x10, 0x01))))    // Eddystone URL
        assertNull(BleTrackers.classify(mapOf(0x0075 to byteArrayOf(0x01, 0x02)), emptyList(), emptyMap()))
        assertEquals("FD5A", BleTrackers.shortUuid(FD5A))
    }

    @Test
    fun assessFollowing() {
        val h = 3_600_000L
        assertTrue(BleTrackers.assess(listOf(BleTrackers.Sighting(0, "ssid:Maison", -60), BleTrackers.Sighting(h, "ssid:Bureau", -70))).following)
        assertTrue(BleTrackers.assess(listOf(BleTrackers.Sighting(0, "a", -60), BleTrackers.Sighting(h, "a", -60), BleTrackers.Sighting(2 * h, "a", -60))).following)
        assertFalse(BleTrackers.assess(listOf(BleTrackers.Sighting(0, "a", -60), BleTrackers.Sighting(10 * 60_000, "a", -60))).following)
        assertFalse(BleTrackers.assess(emptyList()).following)
        val a = BleTrackers.assess(listOf(BleTrackers.Sighting(0, "a", -60), BleTrackers.Sighting(2 * h, "b", -60)))
        assertEquals("vu 2 fois à 2 lieux sur 2 h", a.label)
    }

    @Test
    fun recordKeepsTrackersAndPrunes() {
        val now = 100L * 24 * 3_600_000
        val old = mapOf(
            "AA" to listOf(BleTrackers.Sighting(now - 8L * 24 * 3_600_000, "x", -50)),   // > 7 j : purgé
            "BB" to listOf(BleTrackers.Sighting(now - 3_600_000, "x", -50))
        )
        val devices = listOf(
            BluetoothScanner.BtDevice("tag", "CC", -60, "BLE", "Apple", "", "", trackerType = "Apple Find My (AirTag / accessoire)"),
            BluetoothScanner.BtDevice("phone", "DD", -60, "BLE", "Samsung", "", ""),
            BluetoothScanner.BtDevice("mine", "EE", -100, "apparié", "Apple", "", "", trackerType = "Tile")
        )
        val out = BleTrackers.record(old, devices, "ssid:Maison", now)
        assertFalse(out.containsKey("AA"))
        assertEquals(1, out["BB"]!!.size)
        assertEquals(1, out["CC"]!!.size)
        assertFalse(out.containsKey("DD"))
        assertFalse(out.containsKey("EE"))
        val back = BleTrackers.fromJson(BleTrackers.toJson(out))
        assertEquals(out, back)
    }

    // ---- Journal des coupures ------------------------------------------

    @Test
    fun outagesAndAvailability() {
        val ev = listOf(
            OutageLog.Event(0, true, 20),
            OutageLog.Event(100, false, null),
            OutageLog.Event(150, true, 25),
            OutageLog.Event(180, false, null)
        )
        val o = OutageLog.outages(ev)
        assertEquals(2, o.size)
        assertEquals(100L, o[0].startMs); assertEquals(150L, o[0].endMs)
        assertTrue(o[1].ongoing)
        assertEquals(30L, o[1].durationMs(210))
        // up 0..100 + 150..180 = 130 sur 200
        assertEquals(65.0, OutageLog.availabilityPercent(ev, 0, 200)!!, 0.01)
        // fenêtre commençant pendant la coupure : état hérité de l'événement précédent
        assertEquals(50.0, OutageLog.availabilityPercent(ev, 120, 180)!!, 0.01)
        assertNull(OutageLog.availabilityPercent(emptyList(), 0, 10))
    }

    @Test
    fun shouldRecordOnTransitionOrHeartbeat() {
        assertTrue(OutageLog.shouldRecord(null, true, 0))
        assertFalse(OutageLog.shouldRecord(OutageLog.Event(0, true, 10), true, 1000))
        assertTrue(OutageLog.shouldRecord(OutageLog.Event(0, true, 10), false, 1000))
        assertTrue(OutageLog.shouldRecord(OutageLog.Event(0, true, 10), true, OutageLog.HEARTBEAT_MS))
        assertEquals("< 1 min", OutageLog.formatDuration(30_000))
        assertEquals("12 min", OutageLog.formatDuration(12 * 60_000))
        assertEquals("2 h 5 min", OutageLog.formatDuration(125 * 60_000))
        assertEquals("1 j 2 h", OutageLog.formatDuration(26L * 3_600_000))
    }

    // ---- Détournement DNS ----------------------------------------------

    private fun dnsAnswer(id: Int, name: String, rcode: Int, ip: String?): ByteArray {
        val q = DnsHijackTest.buildQuery(id, name)
        val out = java.io.ByteArrayOutputStream()
        out.write(q, 0, q.size)
        val b = out.toByteArray()
        b[2] = 0x81.toByte(); b[3] = (0x80 or rcode).toByte()          // QR RD RA + rcode
        if (ip == null) return b
        b[7] = 1                                                         // ANCOUNT = 1
        val o2 = java.io.ByteArrayOutputStream(); o2.write(b, 0, b.size)
        o2.write(0xC0); o2.write(0x0C)                                   // ptr question
        o2.write(0); o2.write(1); o2.write(0); o2.write(1)               // A IN
        o2.write(0); o2.write(0); o2.write(0); o2.write(60)              // TTL
        o2.write(0); o2.write(4)
        ip.split('.').forEach { o2.write(it.toInt()) }
        return o2.toByteArray()
    }

    @Test
    fun buildQueryAndParseResponse() {
        val q = DnsHijackTest.buildQuery(0x1234, "example.com")
        assertEquals("example.com", com.fabrice.network.scanner.capture.DnsSniParser.parseDnsQuestion(q, 0, q.size))
        val ok = dnsAnswer(0x1234, "example.com", 0, "93.184.216.34")
        val (rcode, ips) = DnsHijackTest.parseResponse(ok, ok.size, 0x1234)!!
        assertEquals(0, rcode); assertEquals(listOf("93.184.216.34"), ips)
        val nx = dnsAnswer(0x1234, "nxabc.example.net", 3, null)
        assertEquals(3, DnsHijackTest.parseResponse(nx, nx.size, 0x1234)!!.first)
        assertNull(DnsHijackTest.parseResponse(ok, ok.size, 0x9999))     // mauvais ID
        assertTrue(DnsHijackTest.randomNxDomain().endsWith(".example.net"))
    }

    private fun res(label: String, server: String, sentinel: List<String>, nxRcode: Int?, nxIps: List<String>, lat: Int? = 10, err: String? = null) =
        DnsHijackTest.ResolverResult(server, label, lat, sentinel, nxRcode, nxIps, err)

    @Test
    fun evaluateVerdicts() {
        val ex = listOf("93.184.216.34")
        val sane = listOf(res("DNS du réseau", "192.168.0.1", ex, 3, emptyList()), res("Cloudflare", "1.1.1.1", ex, 3, emptyList()), res("Quad9", "9.9.9.9", ex, 3, emptyList()))
        assertEquals(0, DnsHijackTest.evaluate(sane).level)
        val hijack = listOf(res("DNS du réseau", "192.168.0.1", ex, 0, listOf("10.0.0.5")), res("Cloudflare", "1.1.1.1", ex, 3, emptyList()))
        val v = DnsHijackTest.evaluate(hijack)
        assertEquals(2, v.level); assertTrue(v.details.any { it.contains("NXDOMAIN") })
        val intercept = listOf(res("DNS du réseau", "192.168.0.1", ex, 3, emptyList()), res("Cloudflare", "1.1.1.1", ex, 0, listOf("10.0.0.5")))
        assertEquals(2, DnsHijackTest.evaluate(intercept).level)
        val mismatch = listOf(res("DNS du réseau", "192.168.0.1", listOf("10.0.0.9"), 3, emptyList()), res("Cloudflare", "1.1.1.1", ex, 3, emptyList()))
        assertEquals(1, DnsHijackTest.evaluate(mismatch).level)
        val forced = listOf(res("DNS du réseau", "192.168.0.1", ex, 3, emptyList()), res("Cloudflare", "1.1.1.1", emptyList(), null, emptyList(), null, "pas de réponse"))
        val f = DnsHijackTest.evaluate(forced)
        assertEquals(1, f.level); assertTrue(f.details.any { it.contains("injoignables") })
        assertNotNull(DnsHijackTest.evaluate(emptyList()))
    }
}

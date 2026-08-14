package com.fabrice.network.scanner

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FingFeaturesTest {

    // ---------- WakeOnLan ----------

    @Test
    fun magicPacket_structure() {
        val packet = WakeOnLan.magicPacket("AA:BB:CC:DD:EE:FF")
        assertNotNull(packet)
        assertEquals(6 + 16 * 6, packet!!.size)
        // 6 octets 0xFF au début
        for (i in 0 until 6) assertEquals(0xFF.toByte(), packet[i])
        // 16 répétitions du MAC
        val expected = byteArrayOf(
            0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0xEE.toByte(), 0xFF.toByte()
        )
        for (i in 0 until 16) {
            assertArrayEquals("répétition $i", expected, packet.copyOfRange(6 + i * 6, 6 + (i + 1) * 6))
        }
    }

    @Test
    fun magicPacket_acceptsDashesAndRaw() {
        assertNotNull(WakeOnLan.magicPacket("AA-BB-CC-DD-EE-FF"))
        assertNotNull(WakeOnLan.magicPacket("aabbccddeeff"))
        assertNotNull(WakeOnLan.magicPacket("aa:bb:cc:dd:ee:ff"))
    }

    @Test
    fun magicPacket_rejectsInvalid() {
        assertNull(WakeOnLan.magicPacket(""))                    // vide
        assertNull(WakeOnLan.magicPacket("AA:BB:CC"))             // trop court
        assertNull(WakeOnLan.magicPacket("GG:HH:II:JJ:KK:LL"))    // hex invalide
        assertNull(WakeOnLan.magicPacket("aa:bb:cc:dd:ee:ff:00")) // trop long
    }

    // ---------- CsvExporter ----------

    @Test
    fun csv_hasBomAndSemicolons() {
        val csv = CsvExporter.buildCsv(
            listOf(Device(ip = "192.168.0.1", mac = "aa:bb:cc:dd:ee:ff", vendor = "BOX SAS", hostname = "box"))
        )
        assertTrue(csv.startsWith('\uFEFF'))
        assertTrue(csv.contains("192.168.0.1;aa:bb:cc:dd:ee:ff;BOX SAS;box;"))
    }

    @Test
    fun csv_escapesSemicolonsInValues() {
        val csv = CsvExporter.buildCsv(
            listOf(Device(ip = "1.1.1.1", mac = "", vendor = "Vendor; Inc", hostname = "pc"))
        )
        // Le point-virgule du fabricant doit être entre guillemets
        assertTrue(csv.contains("\"Vendor; Inc\""))
    }

    // ---------- ScanHistory ----------

    @Test
    fun identityKey_prefersMac() {
        val d1 = Device(ip = "192.168.0.5", mac = "aa:bb:cc:dd:ee:ff")
        val d2 = Device(ip = "192.168.0.5", mac = "")
        assertEquals("aa:bb:cc:dd:ee:ff", ScanHistory.identityKey(d1))
        assertEquals("ip:192.168.0.5", ScanHistory.identityKey(d2))
    }

    @Test
    fun detectNewDevices_flagsUnknownOnly() {
        val previous = listOf(Device(ip = "192.168.0.1", mac = "aa:bb:cc:dd:ee:01"))
        val current = listOf(
            Device(ip = "192.168.0.1", mac = "aa:bb:cc:dd:ee:01"),
            Device(ip = "192.168.0.42", mac = "aa:bb:cc:dd:ee:02"),
            Device(ip = "192.168.0.99", mac = "")
        )
        val fresh = ScanHistory.detectNewDevices(previous, current)
        assertEquals(2, fresh.size)
        assertEquals("192.168.0.42", fresh[0].ip)
        assertEquals("192.168.0.99", fresh[1].ip)
    }

    @Test
    fun serialize_deserialize_roundTrip() {
        val devices = listOf(
            Device(ip = "192.168.0.1", mac = "aa:bb:cc:dd:ee:ff", vendor = "BOX|SAS", hostname = "box\\1"),
            Device(ip = "192.168.0.2", mac = "", vendor = "", hostname = "")
        )
        val back = ScanHistory.deserialize(ScanHistory.serialize(devices))
        assertEquals(devices, back)
    }

    @Test
    fun deserialize_rejectsUnknownVersion() {
        assertEquals(emptyList<Device>(), ScanHistory.deserialize("v99\n1.2.3.4|||"))
        assertEquals(emptyList<Device>(), ScanHistory.deserialize(""))
    }

    // ---------- PortScanner ----------

    @Test
    fun serviceName_knownAndUnknown() {
        assertEquals("HTTP", PortScanner.serviceName(80))
        assertEquals("SSH", PortScanner.serviceName(22))
        assertEquals("Ollama", PortScanner.serviceName(11434))
        assertEquals("port-1234", PortScanner.serviceName(1234))
    }

    // ---------- NetworkScanner broadcast ----------

    @Test
    fun broadcastAddress_computed() {
        assertEquals("192.168.0.255", NetworkScanner.broadcastAddress("192.168.0.190", 24))
        assertEquals("10.5.255.255", NetworkScanner.broadcastAddress("10.5.3.7", 16))
    }

    @Test
    fun ports_defaultEmpty() {
        val d = Device(ip = "1.2.3.4")
        assertTrue(d.ports.isEmpty())
        assertFalse(d.alive.not())
    }
}

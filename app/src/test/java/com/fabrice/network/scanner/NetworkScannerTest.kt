package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkScannerTest {

    @Test
    fun ipToInt_roundTrip() {
        assertEquals("192.168.0.190", NetworkScanner.intToIp(NetworkScanner.ipToInt("192.168.0.190")))
        assertEquals("10.0.0.1", NetworkScanner.intToIp(NetworkScanner.ipToInt("10.0.0.1")))
        assertEquals(0xC0A800BE, NetworkScanner.ipToInt("192.168.0.190"))
    }

    @Test
    fun networkAddress_masksCorrectly() {
        // 192.168.0.190/24 → 192.168.0.0
        assertEquals("192.168.0.0", NetworkScanner.intToIp(NetworkScanner.networkAddress("192.168.0.190", 24)))
        // 10.5.3.7/16 → 10.5.0.0
        assertEquals("10.5.0.0", NetworkScanner.intToIp(NetworkScanner.networkAddress("10.5.3.7", 16)))
    }

    @Test
    fun hostList_excludesNetworkAndBroadcast() {
        val hosts = NetworkScanner.hostList("192.168.0.190", 24)
        assertEquals(254, hosts.size)
        assertEquals("192.168.0.1", hosts.first())
        assertEquals("192.168.0.254", hosts.last())
        assertTrue("192.168.0.0" !in hosts)
        assertTrue("192.168.0.255" !in hosts)
    }

    @Test
    fun parseArp_extractsMacs() {
        val text = """
            IP address       HW type     Flags       HW address            Mask     Device
            192.168.0.254    0x1         0x2         f4:ca:e5:4d:d3:e9     *        eth0
            192.168.0.15     0x1         0x2         8c:7a:3d:c6:6c:68     *        eth0
            192.168.0.253    0x1         0x0         00:00:00:00:00:00     *        eth0
        """.trimIndent()
        val arp = NetworkScanner.parseArp(text)
        assertEquals(2, arp.size)
        assertEquals("f4:ca:e5:4d:d3:e9", arp["192.168.0.254"])
        assertEquals("8c:7a:3d:c6:6c:68", arp["192.168.0.15"])
        assertTrue("192.168.0.253" !in arp) // MAC à zéro → ignorée
    }

    @Test
    fun parseOuiLine_validAndInvalid() {
        val valid = NetworkScanner.parseOuiLine("f4cae5\tFREEBOX SAS")
        assertEquals("f4cae5" to "FREEBOX SAS", valid)
        assertNull(NetworkScanner.parseOuiLine(""))           // vide
        assertNull(NetworkScanner.parseOuiLine("abcdef"))     // sans tabulation
        assertNull(NetworkScanner.parseOuiLine("zzzzzz\tX"))  // hex invalide
    }

    @Test
    fun formatMac_formatsSixBytes() {
        val raw = byteArrayOf(
            0xE0.toByte(), 0x70, 0xEA.toByte(), 0xFB.toByte(), 0x1C, 0xEB.toByte()
        )
        assertEquals("e0:70:ea:fb:1c:eb", NetworkScanner.formatMac(raw))
    }

    @Test
    fun formatMac_rejectsInvalid() {
        assertNull(NetworkScanner.formatMac(byteArrayOf(1, 2, 3)))          // mauvaise taille
        assertNull(NetworkScanner.formatMac(ByteArray(6)))                  // tout à zéro
    }

    @Test
    fun parseArpRow_extractsIpAndMac() {
        // ipNetToMediaPhysAddress.<ifIndex=2>.192.168.0.10 → MAC
        val oid = "1.3.6.1.2.1.4.22.1.2.2.192.168.0.10"
        val raw = byteArrayOf(
            0xE0.toByte(), 0x70, 0xEA.toByte(), 0xFB.toByte(), 0x1C, 0xEB.toByte()
        )
        assertEquals(
            "192.168.0.10" to "e0:70:ea:fb:1c:eb",
            NetworkScanner.parseArpRow(oid, raw)
        )
    }

    @Test
    fun parseArpRow_rejectsWrongOidOrMac() {
        val raw = ByteArray(6) { 1 }
        assertNull(NetworkScanner.parseArpRow("1.3.6.1.2.1.1.1.0", raw))     // hors table ARP
        assertNull(NetworkScanner.parseArpRow("1.3.6.1.2.1.4.22.1.2.2.10.0.0.1", ByteArray(3))) // MAC invalide
    }

    @Test
    fun vendorFor_normalizesMac() {
        val oui = mapOf("f4cae5" to "FREEBOX SAS")
        assertEquals("FREEBOX SAS", NetworkScanner.vendorFor("f4:ca:e5:4d:d3:e9", oui))
        assertEquals("FREEBOX SAS", NetworkScanner.vendorFor("F4-CA-E5-4D-D3-E9", oui))
        assertEquals("", NetworkScanner.vendorFor("", oui))
        assertEquals("", NetworkScanner.vendorFor("00:11:22:33:44:55", oui))
    }
}

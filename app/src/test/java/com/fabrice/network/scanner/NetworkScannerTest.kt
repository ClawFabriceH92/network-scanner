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
    fun vendorFor_normalizesMac() {
        val oui = mapOf("f4cae5" to "FREEBOX SAS")
        assertEquals("FREEBOX SAS", NetworkScanner.vendorFor("f4:ca:e5:4d:d3:e9", oui))
        assertEquals("FREEBOX SAS", NetworkScanner.vendorFor("F4-CA-E5-4D-D3-E9", oui))
        assertEquals("", NetworkScanner.vendorFor("", oui))
        assertEquals("", NetworkScanner.vendorFor("00:11:22:33:44:55", oui))
    }
}

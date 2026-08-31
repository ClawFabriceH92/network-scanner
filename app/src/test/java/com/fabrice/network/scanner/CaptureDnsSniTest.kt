package com.fabrice.network.scanner

import com.fabrice.network.scanner.capture.DnsSniParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests des parseurs de noms d'hôtes de la capture : SNI (ClientHello TLS) et
 * réponses DNS (A). On construit des messages minimaux mais valides.
 */
class CaptureDnsSniTest {

    private fun bytes(list: List<Int>): ByteArray = ByteArray(list.size) { list[it].toByte() }

    @Test
    fun parsesSniFromClientHello() {
        val name = "example.com"
        val out = ArrayList<Int>()
        // Record TLS : handshake, version, longueur (67).
        out.addAll(listOf(0x16, 0x03, 0x01, 0x00, 0x43))
        // ClientHello : type(1) + longueur(3 = 63).
        out.addAll(listOf(0x01, 0x00, 0x00, 0x3F))
        out.addAll(listOf(0x03, 0x03))               // client version
        repeat(32) { out.add(0x00) }                 // random
        out.add(0x00)                                // session id length
        out.addAll(listOf(0x00, 0x02, 0x00, 0x2F))   // cipher suites (len 2 + 1 suite)
        out.addAll(listOf(0x01, 0x00))               // compression (len 1 + null)
        out.addAll(listOf(0x00, 0x14))               // extensions length (20)
        out.addAll(listOf(0x00, 0x00))               // ext type server_name
        out.addAll(listOf(0x00, 0x10))               // ext length (16)
        out.addAll(listOf(0x00, 0x0E))               // server_name_list length (14)
        out.add(0x00)                                // name type host_name
        out.addAll(listOf(0x00, 0x0B))               // name length (11)
        name.forEach { out.add(it.code) }
        val data = bytes(out)
        assertEquals("example.com", DnsSniParser.parseSni(data, 0, data.size))
    }

    @Test
    fun parsesDnsAResponse() {
        val out = ArrayList<Int>()
        // En-tête : id, flags(réponse), qd=1, an=1, ns=0, ar=0.
        out.addAll(listOf(0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00))
        // Question example.com IN A.
        out.addAll(listOf(0x07, 'e'.code, 'x'.code, 'a'.code, 'm'.code, 'p'.code, 'l'.code, 'e'.code,
            0x03, 'c'.code, 'o'.code, 'm'.code, 0x00, 0x00, 0x01, 0x00, 0x01))
        // Réponse : pointeur vers la question, A, IN, ttl, rdlen=4, 93.184.216.34.
        out.addAll(listOf(0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 93, 184, 216, 34))
        val data = bytes(out)
        val res = DnsSniParser.parseDnsResponses(data, data.size)
        assertTrue(res.contains("93.184.216.34" to "example.com"))
    }

    @Test
    fun sniRejectsNonHandshakeRecord() {
        // 0x17 = application_data, pas un handshake.
        assertNull(DnsSniParser.parseSni(bytes(listOf(0x17, 0x03, 0x03, 0x00, 0x00)), 0, 5))
    }
}

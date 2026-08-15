package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Tests de la brique NBNS : encodage du nom NetBIOS (premier niveau),
 * structure de la requête NBSTAT et parsing d'une réponse (nom unique + MAC).
 */
class NbnsResolverTest {

    // ---------- encodeNetbiosName ----------

    @Test
    fun encodeNetbiosName_firstLevelEncoding() {
        val name = ByteArray(16)
        name[0] = '*'.code.toByte() // 0x2A
        val encoded = NbnsResolver.encodeNetbiosName(name)
        assertEquals(32, encoded.size)
        // 0x2A → high nibble 2 → 'C', low nibble 10 → 'K'
        assertEquals('C'.code.toByte(), encoded[0])
        assertEquals('K'.code.toByte(), encoded[1])
        // 0x00 → 'A', 'A'
        assertEquals('A'.code.toByte(), encoded[2])
        assertEquals('A'.code.toByte(), encoded[3])
    }

    @Test
    fun encodeNetbiosName_coversFullByteRange() {
        // 0xFF → high 15 → 'P' (0x41+15), low 15 → 'P'
        val name = ByteArray(16)
        name[0] = 0xFF.toByte()
        val encoded = NbnsResolver.encodeNetbiosName(name)
        assertEquals('P'.code.toByte(), encoded[0])
        assertEquals('P'.code.toByte(), encoded[1])
    }

    // ---------- buildNbstatQuery ----------

    @Test
    fun buildNbstatQuery_structure() {
        val q = NbnsResolver.buildNbstatQuery()
        assertEquals(50, q.size)
        val qd = ((q[4].toInt() and 0xFF) shl 8) or (q[5].toInt() and 0xFF)
        assertEquals(1, qd) // une seule question
        // Le nom commence par la longueur 0x20
        assertEquals(0x20, q[12].toInt() and 0xFF)
        // QTYPE NBSTAT (0x0021) juste avant QCLASS
        val qtype = ((q[46].toInt() and 0xFF) shl 8) or (q[47].toInt() and 0xFF)
        assertEquals(0x0021, qtype)
        val qclass = ((q[48].toInt() and 0xFF) shl 8) or (q[49].toInt() and 0xFF)
        assertEquals(0x0001, qclass)
    }

    // ---------- parseNbstatResponse ----------

    @Test
    fun parseNbstatResponse_extractsUniqueNameAndMac() {
        val mac = byteArrayOf(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        val resp = nbstatResponse("DESKTOP-ABC123", 0x00, 0x0400, mac)
        val info = NbnsResolver.parseNbstatResponse(resp)
        assertNotNull(info)
        assertEquals("DESKTOP-ABC123", info!!.name)
        assertEquals("00:11:22:33:44:55", info.mac)
    }

    @Test
    fun parseNbstatResponse_acceptsFileServerSuffix() {
        val resp = nbstatResponse("NAS-SRV", 0x20, 0x0400, null)
        val info = NbnsResolver.parseNbstatResponse(resp)
        assertNotNull(info)
        assertEquals("NAS-SRV", info!!.name)
    }

    @Test
    fun parseNbstatResponse_ignoresGroupNames() {
        // bit group 0x8000 → nom de groupe, pas un nom machine
        val mac = byteArrayOf(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        val resp = nbstatResponse("WORKGROUP", 0x00, 0x8000, mac)
        val info = NbnsResolver.parseNbstatResponse(resp)
        assertNotNull(info)
        assertEquals("", info!!.name)
        assertEquals("00:11:22:33:44:55", info.mac)
    }

    @Test
    fun parseNbstatResponse_skipsNonWorkstationSuffix() {
        // suffix 0x03 (Messenger) → pas un nom machine, et pas de MAC → null
        val resp = nbstatResponse("DESKTOP", 0x03, 0x0400, null)
        assertNull(NbnsResolver.parseNbstatResponse(resp))
    }

    @Test
    fun parseNbstatResponse_trimsPadding() {
        val resp = nbstatResponse("PC", 0x00, 0x0400, null)
        val info = NbnsResolver.parseNbstatResponse(resp)
        assertNotNull(info)
        assertEquals("PC", info!!.name)
    }

    @Test
    fun parseNbstatResponse_garbageReturnsNull() {
        assertNull(NbnsResolver.parseNbstatResponse(ByteArray(3)))
        assertNull(NbnsResolver.parseNbstatResponse(ByteArray(0)))
    }

    // ---------- helper ----------

    private fun nbstatResponse(name: String, suffix: Int, flags: Int, mac: ByteArray?): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add(v.toByte()) }
        // En-tête DNS-like : ID, flags réponse, QDCOUNT=0, ANCOUNT=1
        u16(0x1234); u16(0x8400); u16(0); u16(1); u16(0); u16(0)
        // Réponse : nom en pointeur de compression, TYPE NBSTAT, CLASS IN, TTL
        out.add(0xC0.toByte()); out.add(0x0C.toByte())
        u16(0x0021); u16(0x0001)
        u16(0); u16(0) // TTL (4 octets à zéro)
        // RDATA : 1 octet nb de noms + 18 octets par nom + stats éventuelles
        val rdlen = 1 + 18 + (mac?.size ?: 0)
        u16(rdlen)
        out.add(1) // 1 nom
        val nameBytes = ByteArray(16)
        val raw = name.toByteArray(Charsets.US_ASCII)
        System.arraycopy(raw, 0, nameBytes, 0, minOf(raw.size, 15))
        for (i in raw.size until 15) nameBytes[i] = ' '.code.toByte()
        nameBytes[15] = suffix.toByte()
        out.addAll(nameBytes.toList())
        u16(flags)
        if (mac != null) out.addAll(mac.toList())
        return out.toByteArray()
    }
}

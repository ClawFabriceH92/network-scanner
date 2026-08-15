package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Tests de la brique mDNS : construction de requête, parsing d'une réponse DNS
 * (PTR/TXT/SRV avec décompression) et agrégation en MdnsInfo (modèle/nom/type).
 */
class MdnsResolverTest {

    // ---------- buildQuery ----------

    @Test
    fun buildQuery_setsQuestionCount() {
        val q = MdnsResolver.buildQuery(listOf("_ipp._tcp.local", "_smb._tcp.local"))
        val qd = ((q[4].toInt() and 0xFF) shl 8) or (q[5].toInt() and 0xFF)
        assertEquals(2, qd)
    }

    // ---------- parseMessage ----------

    @Test
    fun parseMessage_extractsPtrRecord() {
        val resp = ptrResponse("_googlecast._tcp.local", "Salon._googlecast._tcp.local")
        val records = MdnsResolver.parseMessage(resp)
        assertEquals(1, records.size)
        assertEquals("_googlecast._tcp.local", records[0].name)
        assertEquals(12, records[0].type)
        assertEquals(MdnsResolver.RecordData.Ptr("Salon._googlecast._tcp.local"), records[0].data)
    }

    @Test
    fun parseMessage_handlesCompressedName() {
        // Nom de la réponse via pointeur 0xC00C (réponse typique mDNS)
        val resp = compressedPtrResponse("Salon._airplay._tcp.local")
        val records = MdnsResolver.parseMessage(resp)
        assertEquals(1, records.size)
        assertEquals(MdnsResolver.RecordData.Ptr("Salon._airplay._tcp.local"), records[0].data)
    }

    @Test
    fun parseMessage_garbageReturnsEmpty() {
        assertEquals(emptyList<MdnsResolver.DnsRecord>(), MdnsResolver.parseMessage(ByteArray(3)))
        assertEquals(emptyList<MdnsResolver.DnsRecord>(), MdnsResolver.parseMessage(ByteArray(0)))
    }

    // ---------- extract ----------

    @Test
    fun extract_buildsModelNameAndHint() {
        val rec = MdnsResolver.MutableRecord()
        rec.txt["md"] = "Chromecast"
        rec.txt["fn"] = "Salon"
        rec.serviceTypes.add("_googlecast")
        val info = MdnsResolver.extract(rec)
        assertEquals("Chromecast", info.model)
        assertEquals("Salon", info.name)
        assertEquals("TV / Media", info.deviceHint)
    }

    @Test
    fun extract_printerModelFromTxt() {
        val rec = MdnsResolver.MutableRecord()
        rec.txt["ty"] = "HP LaserJet MFP M28w"
        rec.serviceTypes.add("_ipp")
        val info = MdnsResolver.extract(rec)
        assertEquals("HP LaserJet MFP M28w", info.model)
        assertEquals("Imprimante", info.deviceHint)
    }

    @Test
    fun deviceHint_mapsServiceTypes() {
        assertEquals("Imprimante", MdnsResolver.deviceHint(setOf("_ipp")))
        assertEquals("TV / Media", MdnsResolver.deviceHint(setOf("_googlecast")))
        assertEquals("NAS", MdnsResolver.deviceHint(setOf("_smb")))
        assertEquals("Enceinte", MdnsResolver.deviceHint(setOf("_sonos")))
        assertEquals("Ordinateur", MdnsResolver.deviceHint(setOf("_workstation")))
        assertEquals("", MdnsResolver.deviceHint(setOf("_inconnu")))
    }

    // ---------- helpers ----------

    private fun dnsName(vararg labels: String): ByteArray {
        val out = ArrayList<Byte>()
        for (l in labels) {
            val b = l.toByteArray(Charsets.UTF_8)
            out.add(b.size.toByte())
            out.addAll(b.toList())
        }
        out.add(0)
        return out.toByteArray()
    }

    private fun ptrResponse(name: String, target: String): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add(v.toByte()) }
        u16(0); u16(0x8400); u16(0); u16(1); u16(0); u16(0) // en-tête, 1 réponse
        val nb = dnsName(*name.split(".").toTypedArray())
        val tb = dnsName(*target.split(".").toTypedArray())
        out.addAll(nb.toList())
        u16(12); u16(1) // TYPE PTR, CLASS IN
        u16(0); u16(120) // TTL
        u16(tb.size)
        out.addAll(tb.toList())
        return out.toByteArray()
    }

    private fun compressedPtrResponse(target: String): ByteArray {
        val out = ArrayList<Byte>()
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add(v.toByte()) }
        // Question : _airplay._tcp.local (pour permettre le pointeur 0xC00C)
        u16(0); u16(0x8400); u16(0); u16(1); u16(0); u16(0)
        val tb = dnsName(*target.split(".").toTypedArray())
        // Réponse : nom = pointeur 0xC00C, puis PTR vers la cible
        out.add(0xC0.toByte()); out.add(0x0C.toByte())
        u16(12); u16(1)
        u16(0); u16(120)
        u16(tb.size)
        out.addAll(tb.toList())
        return out.toByteArray()
    }
}

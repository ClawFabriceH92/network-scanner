package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class PrinterProbeTest {

    // ---- Constructeur de réponse IPP factice (pour tester le parseur) ----

    private fun ByteArrayOutputStream.u16(v: Int) {
        write((v ushr 8) and 0xFF); write(v and 0xFF)
    }

    private fun ByteArrayOutputStream.textAttr(tag: Int, name: String, value: String) {
        write(tag)
        val n = name.toByteArray(Charsets.US_ASCII); u16(n.size); write(n)
        val v = value.toByteArray(Charsets.UTF_8); u16(v.size); write(v)
    }

    /** Valeur additionnelle (même attribut 1setOf) : name-length = 0. */
    private fun ByteArrayOutputStream.addText(tag: Int, value: String) {
        write(tag); u16(0)
        val v = value.toByteArray(Charsets.UTF_8); u16(v.size); write(v)
    }

    private fun ByteArrayOutputStream.intAttr(tag: Int, name: String, value: Int) {
        write(tag)
        val n = name.toByteArray(Charsets.US_ASCII); u16(n.size); write(n)
        u16(4); write((value ushr 24) and 0xFF); write((value ushr 16) and 0xFF)
        write((value ushr 8) and 0xFF); write(value and 0xFF)
    }

    private fun ByteArrayOutputStream.addInt(tag: Int, value: Int) {
        write(tag); u16(0)
        u16(4); write((value ushr 24) and 0xFF); write((value ushr 16) and 0xFF)
        write((value ushr 8) and 0xFF); write(value and 0xFF)
    }

    private fun sampleResponse(): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(0x01); o.write(0x01)          // version 1.1
        o.write(0x00); o.write(0x00)          // status successful-ok
        o.write(0x00); o.write(0x00); o.write(0x00); o.write(0x01) // request-id
        o.write(0x04)                         // printer-attributes-tag
        o.textAttr(0x41, "printer-make-and-model", "HP Color LaserJet MFP E57540")
        o.intAttr(0x23, "printer-state", 3)   // enum idle
        o.textAttr(0x41, "printer-location", "Bureau")
        o.textAttr(0x42, "marker-names", "Black Cartridge")
        o.addText(0x42, "Cyan Cartridge")
        o.intAttr(0x21, "marker-levels", 80)
        o.addInt(0x21, 60)
        o.write(0x03)                         // end-of-attributes
        return o.toByteArray()
    }

    @Test
    fun parseIppResponse_extractsModelAndState() {
        val info = PrinterProbe.parseIppResponse(sampleResponse())!!
        assertEquals("HP Color LaserJet MFP E57540", info.makeAndModel)
        assertEquals("Prête", info.state)
        assertEquals("Bureau", info.location)
        assertTrue(info.hasData)
    }

    @Test
    fun parseIppResponse_zipsSupplies() {
        val info = PrinterProbe.parseIppResponse(sampleResponse())!!
        assertEquals(2, info.supplies.size)
        assertEquals("Black Cartridge", info.supplies[0].name)
        assertEquals(80, info.supplies[0].levelPercent)
        assertEquals("Cyan Cartridge", info.supplies[1].name)
        assertEquals(60, info.supplies[1].levelPercent)
    }

    @Test
    fun parseIppResponse_rejectsGarbage() {
        assertNull(PrinterProbe.parseIppResponse(byteArrayOf(1, 2, 3)))
    }

    @Test
    fun stateLabel_knownStates() {
        assertEquals("Prête", PrinterProbe.stateLabel(3))
        assertEquals("Impression en cours", PrinterProbe.stateLabel(4))
        assertEquals("Arrêtée", PrinterProbe.stateLabel(5))
        assertEquals("", PrinterProbe.stateLabel(null))
    }

    @Test
    fun buildRequest_isWellFormedIpp() {
        val req = PrinterProbe.buildGetPrinterAttributes("ipp://192.168.0.10/ipp/print")
        // version 1.1, operation-id Get-Printer-Attributes (0x000B), se termine
        // par le tag end-of-attributes (0x03).
        assertEquals(0x01, req[0].toInt())
        assertEquals(0x01, req[1].toInt())
        assertEquals(0x00, req[2].toInt())
        assertEquals(0x0B, req[3].toInt())
        assertEquals(0x03, req.last().toInt())
    }
}

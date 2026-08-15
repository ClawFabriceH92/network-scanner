package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests de l'enrichissement du moteur : détection des MAC aléatoires et
 * remontée des champs Produit/Modèle dans l'export CSV.
 */
class DeviceEnrichmentTest {

    // ---------- isRandomizedMac ----------

    @Test
    fun isRandomizedMac_locallyAdministered() {
        // Bit 0x02 (U/L) à 1 → adresse privée/aléatoire
        assertTrue(NetworkScanner.isRandomizedMac("02:00:00:00:00:00"))
        assertTrue(NetworkScanner.isRandomizedMac("06:11:22:33:44:55"))
        assertTrue(NetworkScanner.isRandomizedMac("aa:bb:cc:dd:ee:ff")) // 0xAA & 0x02 = 2
    }

    @Test
    fun isRandomizedMac_universallyAdministered() {
        assertFalse(NetworkScanner.isRandomizedMac("00:11:22:33:44:55"))
        assertFalse(NetworkScanner.isRandomizedMac("f4:ca:e5:4d:d3:e9")) // Freebox : 0xF4 & 0x02 = 0
        assertFalse(NetworkScanner.isRandomizedMac("8c:7a:3d:c6:6c:68"))
    }

    @Test
    fun isRandomizedMac_invalid() {
        assertFalse(NetworkScanner.isRandomizedMac(""))
        assertFalse(NetworkScanner.isRandomizedMac("zz:zz:zz:zz:zz:zz"))
        assertFalse(NetworkScanner.isRandomizedMac("12:34"))
    }

    @Test
    fun isRandomizedMac_acceptsDashes() {
        assertTrue(NetworkScanner.isRandomizedMac("02-00-00-00-00-00"))
        assertFalse(NetworkScanner.isRandomizedMac("00-11-22-33-44-55"))
    }

    // ---------- CSV : Produit / Modèle ----------

    @Test
    fun csv_includesProductAndModelColumns() {
        val csv = CsvExporter.buildCsv(
            listOf(
                Device(ip = "192.168.0.1", hostname = "box",
                    product = "Freebox Server", model = "Freebox V8")
            )
        )
        assertTrue(csv.contains("Produit;Modèle"))
        assertTrue(csv.contains("Freebox Server;Freebox V8"))
    }

    @Test
    fun csv_deviceWithoutProductHasEmptyColumns() {
        val csv = CsvExporter.buildCsv(listOf(Device(ip = "192.168.0.2", hostname = "pc")))
        assertTrue(csv.contains("pc;;;")) // hostname puis Produit/Modèle vides
    }

    @Test
    fun device_defaultsForNewFields() {
        val d = Device(ip = "1.2.3.4")
        assertEquals("", d.product)
        assertEquals("", d.model)
        assertEquals("", d.mdnsName)
        assertFalse(d.isRandomizedMac)
        assertTrue(d.mdnsServices.isEmpty())
    }
}

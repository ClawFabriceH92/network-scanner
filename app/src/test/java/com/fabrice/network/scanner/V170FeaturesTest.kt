package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests Feature 2 (NewDeviceNotifier — texte/titre purs) et Feature 3 (GeoIP
 * parse) + colonne CSV « Credential défaut ».
 */
class V170FeaturesTest {

    // ---------- NewDeviceNotifier ----------

    @Test
    fun notifier_title_singularAndPlural() {
        assertEquals("🆕 1 nouvel appareil détecté", NewDeviceNotifier.buildTitle(1))
        assertEquals("🆕 3 nouveaux appareils détectés", NewDeviceNotifier.buildTitle(3))
    }

    @Test
    fun notifier_text_oneDevice() {
        val text = NewDeviceNotifier.buildNotificationText(
            listOf(Device(ip = "192.168.0.10", hostname = "printer"))
        )
        assertEquals("printer", text)
    }

    @Test
    fun notifier_text_threeDevices() {
        val text = NewDeviceNotifier.buildNotificationText(
            listOf(
                Device(ip = "192.168.0.10", hostname = "a"),
                Device(ip = "192.168.0.11"),
                Device(ip = "192.168.0.12", hostname = "c")
            )
        )
        assertEquals("a, 192.168.0.11, c", text)
    }

    @Test
    fun notifier_text_moreThanThree_truncates() {
        val text = NewDeviceNotifier.buildNotificationText(
            (1..5).map { Device(ip = "192.168.0.$it") }
        )
        assertEquals("192.168.0.1, 192.168.0.2, 192.168.0.3 et 2 autres…", text)
    }

    @Test
    fun notifier_text_empty() {
        assertEquals("", NewDeviceNotifier.buildNotificationText(emptyList()))
    }

    // ---------- GeoIP ----------

    @Test
    fun geoIp_parseValid() {
        val g = NetworkInfoProvider.parseGeoIp(
            """{"ip":"1.2.3.4","city":"Paris","region":"Île-de-France","country":"FR","org":"AS1234 Orange"}"""
        )
        assertEquals("Paris", g!!.city)
        assertEquals("Île-de-France", g.region)
        assertEquals("FR", g.country)
        assertEquals("AS1234 Orange", g.org)
    }

    @Test
    fun geoIp_parseInvalid_returnsNull() {
        assertNull(NetworkInfoProvider.parseGeoIp("not json"))
        assertNull(NetworkInfoProvider.parseGeoIp(""))
    }

    // ---------- CSV : colonne Credential défaut ----------

    @Test
    fun csv_includesDefaultCredColumn() {
        val csv = CsvExporter.buildCsv(
            listOf(
                Device(ip = "192.168.0.1", defaultCred = "admin/admin"),
                Device(ip = "192.168.0.2")
            )
        )
        assertTrue(csv.contains("Credential défaut"))
        assertTrue(csv.contains("admin/admin"))
    }

    @Test
    fun vuln_defaultCred_bumpsScore() {
        val db = CveDatabase("", emptyMap(), emptyMap())
        val v = VulnScanner.match(emptyList(), db, defaultCred = "admin/admin")
        assertEquals(50, v.score)
        assertEquals("Critique", v.label)
        assertEquals("admin/admin", v.defaultCred)
        assertTrue(!v.isEmpty)
    }
}

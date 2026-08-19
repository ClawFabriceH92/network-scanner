package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests Feature 7 — Test des mots de passe par défaut : parse de l'asset,
 * combosFor (fabricant prioritaire, max 8), checkDevice (trouvé, non trouvé,
 * limite 8, anti-lockout 2×403) et ports web.
 */
class DefaultCredsTest {

    private val json = """
        {"generic":[["admin","admin"],["admin","1234"],["admin","password"],["root","root"],["admin",""],["user","user"],["admin","1111"],["admin","12345"],["admin","admin123"],["support","support"]],
         "vendors":{"hikvision":[["admin","12345"]],"dahua":[["admin","admin"]],"tp-link":[["admin","admin"]]}}
    """.trimIndent()

    @Test
    fun load_parses() {
        val n = DefaultCredsChecker.load(json)
        assertTrue(n > 10)
    }

    @Test
    fun combosFor_vendorFirst_max8() {
        DefaultCredsChecker.load(json)
        val d = Device(ip = "192.168.0.5", vendor = "Hikvision Digital Technology", ports = listOf(80))
        val combos = DefaultCredsChecker.combosFor(d)
        assertEquals(8, combos.size)
        assertEquals("admin" to "12345", combos[0]) // hikvision d'abord
    }

    @Test
    fun combosFor_genericOnly_max8() {
        DefaultCredsChecker.load(json)
        val d = Device(ip = "192.168.0.5", vendor = "Unknown Corp", ports = listOf(80))
        val combos = DefaultCredsChecker.combosFor(d)
        assertEquals(8, combos.size)
        assertEquals("admin" to "admin", combos[0]) // générique d'abord
    }

    @Test
    fun vendorKey_matches() {
        assertEquals(
            "hikvision",
            DefaultCredsChecker.vendorKey(Device(ip = "x", vendor = "Hikvision Digital Technology"))
        )
        assertEquals(
            "tplink",
            DefaultCredsChecker.vendorKey(Device(ip = "x", hostname = "TP-LINK_5G"))
        )
        assertNull(DefaultCredsChecker.vendorKey(Device(ip = "x", vendor = "Some Unknown Corp")))
    }

    @Test
    fun webPort_picksFirstWebPort() {
        assertEquals(80, DefaultCredsChecker.webPort(Device(ip = "x", ports = listOf(22, 80))))
        assertEquals(443, DefaultCredsChecker.webPort(Device(ip = "x", ports = listOf(443, 8443))))
        assertEquals(8443, DefaultCredsChecker.webPort(Device(ip = "x", ports = listOf(8443))))
        assertNull(DefaultCredsChecker.webPort(Device(ip = "x", ports = listOf(22, 23))))
    }

    @Test
    fun checkDevice_foundOnSecondTry() {
        DefaultCredsChecker.load(json)
        val d = Device(ip = "192.168.0.5", vendor = "Unknown", ports = listOf(80))
        var calls = 0
        val found = DefaultCredsChecker.checkDevice(d) { _, _, _, _ ->
            calls++
            if (calls == 2) 200 else 401
        }
        assertEquals("admin/1234", found)
        assertEquals(2, calls)
    }

    @Test
    fun checkDevice_notFound() {
        DefaultCredsChecker.load(json)
        val d = Device(ip = "192.168.0.5", vendor = "Unknown", ports = listOf(80))
        var calls = 0
        val found = DefaultCredsChecker.checkDevice(d) { _, _, _, _ -> calls++; 401 }
        assertNull(found)
        assertEquals(8, calls) // limite 8 combos
    }

    @Test
    fun checkDevice_antiLockout_2x403() {
        DefaultCredsChecker.load(json)
        val d = Device(ip = "192.168.0.5", vendor = "Unknown", ports = listOf(80))
        var calls = 0
        val found = DefaultCredsChecker.checkDevice(d) { _, _, _, _ -> calls++; 403 }
        assertNull(found)
        assertEquals(2, calls) // stop après 2×403
    }

    @Test
    fun checkDevice_noWebPort_skips() {
        DefaultCredsChecker.load(json)
        val d = Device(ip = "192.168.0.5", vendor = "Unknown", ports = listOf(22))
        var calls = 0
        assertNull(DefaultCredsChecker.checkDevice(d) { _, _, _, _ -> calls++; 200 })
        assertEquals(0, calls)
    }
}

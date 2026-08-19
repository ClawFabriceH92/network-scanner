package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests Feature 4 — Historique de présence : enregistrement, déduplication,
 * bornes (500), rotation (>30 j) et libellés relatifs de dernier vu.
 */
class PresenceHistoryTest {

    private val d1 = Device(ip = "192.168.0.10", mac = "aa:bb:cc:dd:ee:01")
    private val d2 = Device(ip = "192.168.0.11") // sans MAC → clé ip:

    @Test
    fun record_addsTimestamp() {
        val now = 1_000_000L
        val r = PresenceHistory.record(emptyMap(), listOf(d1), now)
        assertEquals(listOf(now), r["aa:bb:cc:dd:ee:01"])
    }

    @Test
    fun record_dedupesCloseTimestamps() {
        val now = 1_000_000L
        val r1 = PresenceHistory.record(emptyMap(), listOf(d1), now)
        // +30 s → trop proche (< 60 s) → pas de nouvel horodatage
        val r2 = PresenceHistory.record(r1, listOf(d1), now + 30)
        assertEquals(1, r2["aa:bb:cc:dd:ee:01"]!!.size)
        // +120 s → nouvel horodatage
        val r3 = PresenceHistory.record(r2, listOf(d1), now + 120)
        assertEquals(2, r3["aa:bb:cc:dd:ee:01"]!!.size)
    }

    @Test
    fun record_capsAt500() {
        var reg = emptyMap<String, List<Long>>()
        var now = 0L
        repeat(600) {
            now += 100 // > 60 s d'écart à chaque fois
            reg = PresenceHistory.record(reg, listOf(d1), now)
        }
        assertEquals(500, reg["aa:bb:cc:dd:ee:01"]!!.size)
    }

    @Test
    fun record_rotatesOldTimestamps() {
        val old = 1_000_000L
        val reg0 = PresenceHistory.record(emptyMap(), listOf(d1), old)
        // 31 jours plus tard : l'entrée de d1 (> 30 j) est purgée
        val now = old + 31L * 86400
        val reg = PresenceHistory.record(reg0, listOf(d2), now)
        assertNull(reg["aa:bb:cc:dd:ee:01"])
        assertEquals(listOf(now), reg["ip:192.168.0.11"])
    }

    @Test
    fun lastSeen_labels() {
        val now = 1_000_000L
        assertEquals("à l'instant", PresenceHistory.lastSeen(listOf(now), now))
        assertEquals("il y a 5 min", PresenceHistory.lastSeen(listOf(now - 300), now))
        assertEquals("il y a 2 h", PresenceHistory.lastSeen(listOf(now - 7200), now))
        assertEquals("hier", PresenceHistory.lastSeen(listOf(now - 86400), now))
        assertEquals("il y a 3 j", PresenceHistory.lastSeen(listOf(now - 259200), now))
        assertEquals("jamais vu", PresenceHistory.lastSeen(emptyList(), now))
    }

    @Test
    fun identityKey_usesMacElseIp() {
        assertEquals("aa:bb:cc:dd:ee:01", ScanHistory.identityKey(d1))
        assertEquals("ip:192.168.0.11", ScanHistory.identityKey(d2))
    }

    @Test
    fun ageLabel_boundaries() {
        assertEquals("à l'instant", PresenceHistory.ageLabel(59))
        assertEquals("il y a 1 min", PresenceHistory.ageLabel(60))
        assertEquals("il y a 1 h", PresenceHistory.ageLabel(3600))
        assertEquals("hier", PresenceHistory.ageLabel(86400))
        assertTrue(PresenceHistory.ageLabel(-5).contains("instant"))
    }
}

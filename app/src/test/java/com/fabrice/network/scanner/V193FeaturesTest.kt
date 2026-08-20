package com.fabrice.network.scanner

import android.content.SharedPreferences
import com.fabrice.network.scanner.ui.layoutPositions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.sqrt

/**
 * Tests v1.9.3 : alerte de départ (détection pure), appareils de confiance
 * (TrustStore via FakePrefs), timeline d'audit (rotation + JSON), blocage
 * programmé (dueNow/add/remove/toggle + JSON) et carte réseau (layoutPositions).
 */
class V193FeaturesTest {

    // ---------- Fake SharedPreferences (JVM, sans Robolectric) ----------

    private class FakePrefs : SharedPreferences {
        private val map = HashMap<String, Any>()

        private inner class EditorImpl : SharedPreferences.Editor {
            private val ops = HashMap<String, Any?>()
            override fun putString(key: String, value: String?): SharedPreferences.Editor { ops[key] = value; return this }
            override fun putStringSet(key: String, values: Set<String>?): SharedPreferences.Editor { ops[key] = values; return this }
            override fun putInt(key: String, value: Int): SharedPreferences.Editor { ops[key] = value; return this }
            override fun putLong(key: String, value: Long): SharedPreferences.Editor { ops[key] = value; return this }
            override fun putFloat(key: String, value: Float): SharedPreferences.Editor { ops[key] = value; return this }
            override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor { ops[key] = value; return this }
            override fun remove(key: String): SharedPreferences.Editor { ops[key] = null; return this }
            override fun clear(): SharedPreferences.Editor { ops.clear(); return this }
            override fun commit(): Boolean { apply(); return true }
            override fun apply() {
                ops.forEach { (k, v) -> if (v == null) map.remove(k) else map[k] = v!! }
                ops.clear()
            }
        }

        override fun getAll(): MutableMap<String, *> = HashMap(map)
        override fun getString(key: String, defValue: String?): String? = map[key] as? String ?: defValue
        override fun getStringSet(key: String, defValues: Set<String>?): Set<String>? =
            map[key] as? Set<String> ?: defValues
        override fun getInt(key: String, defValue: Int): Int = map[key] as? Int ?: defValue
        override fun getLong(key: String, defValue: Long): Long = map[key] as? Long ?: defValue
        override fun getFloat(key: String, defValue: Float): Float = map[key] as? Float ?: defValue
        override fun getBoolean(key: String, defValue: Boolean): Boolean = map[key] as? Boolean ?: defValue
        override fun contains(key: String): Boolean = map.containsKey(key)
        override fun edit(): SharedPreferences.Editor = EditorImpl()
        override fun registerOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?
        ) {}
        override fun unregisterOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?
        ) {}
    }

    // ---------- DepartureAlert : détection pure ----------

    @Test
    fun departure_basic() {
        val prev = listOf(Device(ip = "192.168.0.5", mac = "aa:bb:cc:dd:ee:ff", hostname = "Surface Films"))
        val d = DepartureAlert.detectDepartures(prev, emptyList())
        assertEquals(1, d.size)
        assertEquals("aa:bb:cc:dd:ee:ff", d[0].mac)
    }

    @Test
    fun departure_ignoresSelfGatewayMaclessTrusted() {
        val prev = listOf(
            Device(ip = "192.168.0.1", mac = "11:11:11:11:11:11", isSelf = true),
            Device(ip = "192.168.0.2", mac = "22:22:22:22:22:22", isGateway = true),
            Device(ip = "192.168.0.3", mac = ""), // MAC-less → clé non fiable
            Device(ip = "192.168.0.4", mac = "44:44:44:44:44:44"),
            Device(ip = "192.168.0.5", mac = "55:55:55:55:55:55")
        )
        val trusted = setOf("44:44:44:44:44:44")
        val d = DepartureAlert.detectDepartures(prev, emptyList(), trusted)
        assertEquals(listOf("55:55:55:55:55:55"), d.map { it.mac })
    }

    @Test
    fun departure_stillPresentNotFlagged() {
        val prev = listOf(Device(ip = "192.168.0.5", mac = "aa:bb:cc:dd:ee:ff"))
        val cur = listOf(Device(ip = "192.168.0.5", mac = "aa:bb:cc:dd:ee:ff"))
        assertTrue(DepartureAlert.detectDepartures(prev, cur).isEmpty())
    }

    @Test
    fun departure_emptyPrevious() {
        assertTrue(DepartureAlert.detectDepartures(emptyList(), emptyList()).isEmpty())
    }

    @Test
    fun departure_titleAndText() {
        assertEquals("📴 1 appareil absent", DepartureAlert.buildTitle(1))
        assertEquals("📴 3 appareils absents", DepartureAlert.buildTitle(3))
        val devices = listOf(
            Device(ip = "192.168.0.5", hostname = "Surface Films"),
            Device(ip = "192.168.0.6", hostname = "PC"),
            Device(ip = "192.168.0.7", hostname = "NAS"),
            Device(ip = "192.168.0.8")
        )
        val text = DepartureAlert.buildNotificationText(devices)
        assertTrue(text.startsWith("Surface Films, PC, NAS"))
        assertTrue(text.contains("et 1 autres"))
    }

    // ---------- TrustStore : set de confiance ----------

    @Test
    fun trustStore_toggleAndKeys() {
        val store = TrustStore(FakePrefs())
        assertFalse(store.isTrusted("aa:bb:cc:dd:ee:ff"))
        assertTrue(store.toggle("aa:bb:cc:dd:ee:ff"))
        assertTrue(store.isTrusted("aa:bb:cc:dd:ee:ff"))
        store.setTrusted("11:22:33:44:55:66", true)
        assertEquals(setOf("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"), store.trustedKeys())
        assertFalse(store.toggle("aa:bb:cc:dd:ee:ff"))
        assertEquals(setOf("11:22:33:44:55:66"), store.trustedKeys())
    }

    @Test
    fun trustStore_doesNotLeakUntrustedKeys() {
        val store = TrustStore(FakePrefs())
        store.setTrusted("aa:bb:cc:dd:ee:ff", true)
        store.setTrusted("11:22:33:44:55:66", false)
        assertEquals(setOf("aa:bb:cc:dd:ee:ff"), store.trustedKeys())
    }

    // ---------- AuditLog : rotation + JSON ----------

    @Test
    fun auditLog_rotation500Fifo() {
        var list = emptyList<AuditLog.Event>()
        repeat(600) { i -> list = AuditLog.recordEvent(list, "event_$i", i.toLong()) }
        assertEquals(500, list.size)
        assertEquals("event_100", list.first().message) // 0..99 sorties
        assertEquals(599L, list.last().ts)
    }

    @Test
    fun auditLog_jsonRoundTrip() {
        val events = listOf(
            AuditLog.Event(1000L, "apparu"),
            AuditLog.Event(2000L, "absente")
        )
        val parsed = AuditLog.parse(AuditLog.toJson(events))
        assertEquals(2, parsed.size)
        assertEquals(1000L, parsed[0].ts)
        assertEquals("apparu", parsed[0].message)
        assertEquals("absente", parsed[1].message)
    }

    @Test
    fun auditLog_parseGarbageReturnsEmpty() {
        assertTrue(AuditLog.parse("{not json").isEmpty())
        assertTrue(AuditLog.parse("").isEmpty())
    }

    // ---------- ScheduleStore : dueNow + add/remove/toggle + JSON ----------

    @Test
    fun schedule_dueNow() {
        // Lundi uniquement (bit 1 = 2)
        val s = ScheduleStore.Schedule(
            mac = "aa:bb",
            startMinutes = 60,
            endMinutes = 120,
            days = ScheduleStore.dayBit(2)
        )
        val monBit = ScheduleStore.dayBit(2)
        assertTrue(ScheduleStore.dueNow(s, 90, monBit))     // dans la fenêtre, lundi
        assertFalse(ScheduleStore.dueNow(s, 30, monBit))    // avant
        assertFalse(ScheduleStore.dueNow(s, 120, monBit))   // fin exclusive
        assertFalse(ScheduleStore.dueNow(s, 90, ScheduleStore.dayBit(3))) // mauvais jour
    }

    @Test
    fun schedule_dueNow_overnight() {
        // 23:00 → 01:00
        val s = ScheduleStore.Schedule(mac = "aa", startMinutes = 1380, endMinutes = 60, days = 127)
        val bit = ScheduleStore.dayBit(2)
        assertTrue(ScheduleStore.dueNow(s, 1430, bit))  // 23:50
        assertTrue(ScheduleStore.dueNow(s, 30, bit))    // 00:30
        assertFalse(ScheduleStore.dueNow(s, 600, bit))  // 10:00
    }

    @Test
    fun schedule_dueNow_inactive() {
        val s = ScheduleStore.Schedule(mac = "aa", startMinutes = 0, endMinutes = 1439, days = 127, active = false)
        assertFalse(ScheduleStore.dueNow(s, 500, ScheduleStore.dayBit(2)))
    }

    @Test
    fun schedule_addReplaceRemoveToggle() {
        val s1 = ScheduleStore.Schedule(mac = "AA:BB:CC", startMinutes = 60, endMinutes = 120)
        val s2 = ScheduleStore.Schedule(mac = "DD:EE:FF", startMinutes = 0, endMinutes = 60)
        var list = ScheduleStore.add(emptyList(), s1)
        list = ScheduleStore.add(list, s2)
        assertEquals(2, list.size)
        // Remplace la même MAC (insensible à la casse)
        list = ScheduleStore.add(list, s1.copy(startMinutes = 300))
        assertEquals(2, list.size)
        assertEquals(300, list.first { it.mac == "AA:BB:CC" }.startMinutes)
        // Toggle
        list = ScheduleStore.toggle(list, "dd:ee:ff")
        assertFalse(list.first { it.mac == "DD:EE:FF" }.active)
        // Remove
        list = ScheduleStore.remove(list, "AA:BB:CC")
        assertEquals(1, list.size)
        assertEquals("DD:EE:FF", list[0].mac)
    }

    @Test
    fun schedule_jsonRoundTrip() {
        val list = listOf(
            ScheduleStore.Schedule("aa:bb:cc", 60, 120, 127, true),
            ScheduleStore.Schedule("dd:ee:ff", 1380, 60, 62, false)
        )
        val parsed = ScheduleStore.parse(ScheduleStore.toJson(list))
        assertEquals(2, parsed.size)
        assertEquals("aa:bb:cc", parsed[0].mac)
        assertEquals(60, parsed[0].startMinutes)
        assertEquals(62, parsed[1].days)
        assertFalse(parsed[1].active)
    }

    @Test
    fun schedule_parseGarbageReturnsEmpty() {
        assertTrue(ScheduleStore.parse("").isEmpty())
        assertTrue(ScheduleStore.parse("nope").isEmpty())
    }

    // ---------- Carte réseau : layoutPositions ----------

    @Test
    fun mapLayout_countAndRadius() {
        val devices = (0 until 5).map { Device(ip = "192.168.0.${it + 1}") }
        val cx = 300f; val cy = 300f; val r = 100f
        val pos = layoutPositions(devices, cx, cy, r)
        assertEquals(5, pos.size)
        pos.forEach { p ->
            val d = sqrt((p.x - cx) * (p.x - cx) + (p.y - cy) * (p.y - cy))
            assertEquals(r, d, 0.001f)
        }
        // Premier nœud en haut (-90°)
        assertEquals(cx, pos[0].x, 0.001f)
        assertEquals(cy - r, pos[0].y, 0.001f)
    }

    @Test
    fun mapLayout_evenSpacing() {
        val devices = (0 until 3).map { Device(ip = "192.168.0.${it + 1}") }
        val pos = layoutPositions(devices, 100f, 100f, 50f)
        // 3 nœuds → angles 120° ; les distances entre nœuds consécutifs sont égales
        val d01 = sqrt((pos[1].x - pos[0].x) * (pos[1].x - pos[0].x) + (pos[1].y - pos[0].y) * (pos[1].y - pos[0].y))
        val d12 = sqrt((pos[2].x - pos[1].x) * (pos[2].x - pos[1].x) + (pos[2].y - pos[1].y) * (pos[2].y - pos[1].y))
        assertEquals(d01, d12, 0.001f)
    }

    @Test
    fun mapLayout_empty() {
        assertTrue(layoutPositions(emptyList(), 0f, 0f, 100f).isEmpty())
    }
}

package com.fabrice.network.scanner

import android.content.SharedPreferences
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests v1.6.0 : GatewayWatcher, BoxStore (annuaire des boxes) et SnmpScanner
 * (encodage/décodage BER pur + format uptime).
 */
class V160FeaturesTest {

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

    // ---------- GatewayWatcher ----------

    @Test
    fun gatewayWatcher_remembersAndDetectsChange() {
        val prefs = FakePrefs()
        assertNull(GatewayWatcher.lastGateway(prefs))
        // Premier appel : pas de valeur mémorisée → changement détecté
        assertTrue(GatewayWatcher.remember(prefs, "192.168.0.254"))
        assertEquals("192.168.0.254", GatewayWatcher.lastGateway(prefs))
        // Même passerelle : pas de changement
        assertFalse(GatewayWatcher.remember(prefs, "192.168.0.254"))
        // Nouvelle passerelle : changement détecté
        assertTrue(GatewayWatcher.remember(prefs, "192.168.1.1"))
        assertEquals("192.168.1.1", GatewayWatcher.lastGateway(prefs))
    }

    @Test
    fun gatewayWatcher_ignoresBlankGateway() {
        val prefs = FakePrefs()
        assertFalse(GatewayWatcher.remember(prefs, ""))
        assertNull(GatewayWatcher.lastGateway(prefs))
    }

    @Test
    fun gatewayWatcher_clearResets() {
        val prefs = FakePrefs()
        GatewayWatcher.remember(prefs, "10.0.0.1")
        GatewayWatcher.clear(prefs)
        assertNull(GatewayWatcher.lastGateway(prefs))
    }

    // ---------- BoxStore ----------

    @Test
    fun boxStore_saveAndRead() {
        val prefs = FakePrefs()
        BoxStore.saveBox(prefs, "192.168.0.254", "Box Freebox", "Freebox")
        assertEquals("Box Freebox", BoxStore.getBoxName(prefs, "192.168.0.254"))
        assertEquals("Freebox", BoxStore.getBoxType(prefs, "192.168.0.254"))
        assertNull(BoxStore.getBoxName(prefs, "192.168.1.1"))
    }

    @Test
    fun boxStore_setBoxNameKeepsType() {
        val prefs = FakePrefs()
        BoxStore.saveBox(prefs, "192.168.0.254", "Box Freebox", "Freebox")
        BoxStore.setBoxName(prefs, "192.168.0.254", "Freebox du salon")
        assertEquals("Freebox du salon", BoxStore.getBoxName(prefs, "192.168.0.254"))
        assertEquals("Freebox", BoxStore.getBoxType(prefs, "192.168.0.254"))
    }

    @Test
    fun boxStore_boxesAreKeyedByGateway() {
        val prefs = FakePrefs()
        BoxStore.saveBox(prefs, "192.168.0.254", "Freebox maison", "Freebox")
        BoxStore.saveBox(prefs, "192.168.1.254", "Livebox bureau", "Livebox")
        assertEquals("Freebox maison", BoxStore.getBoxName(prefs, "192.168.0.254"))
        assertEquals("Livebox bureau", BoxStore.getBoxName(prefs, "192.168.1.254"))
    }

    @Test
    fun boxStore_corruptJsonReturnsNull() {
        val prefs = FakePrefs()
        prefs.edit().putString(BoxStore.boxKey("192.168.0.254"), "{not json").apply()
        assertNull(BoxStore.getBoxName(prefs, "192.168.0.254"))
        assertNull(BoxStore.getBoxType(prefs, "192.168.0.254"))
    }

    // ---------- SnmpScanner : encodeLength ----------

    @Test
    fun snmp_encodeLength_shortAndLongForm() {
        assertArrayEquals(byteArrayOf(0x00), SnmpScanner.encodeLength(0))
        assertArrayEquals(byteArrayOf(0x7F), SnmpScanner.encodeLength(127))
        assertArrayEquals(byteArrayOf(0x81.toByte(), 0x80.toByte()), SnmpScanner.encodeLength(128))
        assertArrayEquals(byteArrayOf(0x82.toByte(), 0x01, 0x2C), SnmpScanner.encodeLength(300))
    }

    // ---------- SnmpScanner : encodeOid / decodeOid ----------

    @Test
    fun snmp_encodeOid_matchesKnownVector() {
        // .1.3.6.1.2.1.1.1.0 → 06 08 2b 06 01 02 01 01 01 00
        val expected = byteArrayOf(
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00
        )
        assertArrayEquals(expected, SnmpScanner.encodeOid(".1.3.6.1.2.1.1.1.0"))
        assertArrayEquals(expected, SnmpScanner.encodeOid("1.3.6.1.2.1.1.1.0"))
    }

    @Test
    fun snmp_decodeOid_roundTrip() {
        val content = byteArrayOf(0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00)
        assertEquals("1.3.6.1.2.1.1.1.0", SnmpScanner.decodeOid(content))
    }

    @Test
    fun snmp_decodeOid_multibyteSubIds() {
        // OID 1.3.6.1.4.1.8072 (sub-id 8072 = 63*128+8 → multi-octet 0xBF 0x08)
        val content = byteArrayOf(0x2b, 0x06, 0x01, 0x04, 0x01, 0xBF.toByte(), 0x08)
        assertEquals("1.3.6.1.4.1.8072", SnmpScanner.decodeOid(content))
    }

    // ---------- SnmpScanner : parseVarbind ----------

    @Test
    fun snmp_parseVarbind_extractsOidAndOctetString() {
        // varbind = SEQUENCE { OID 1.3.6.1.2.1.1.1.0, OCTET STRING "Linux box" }
        val oidTlv = SnmpScanner.encodeOid("1.3.6.1.2.1.1.1.0") // 10 octets
        val valueTlv = byteArrayOf(0x04, 0x09) + "Linux box".toByteArray() // 11 octets
        val varbind = byteArrayOf(0x30, 0x15) + oidTlv + valueTlv
        val vb = SnmpScanner.parseVarbind(varbind)
        assertEquals("1.3.6.1.2.1.1.1.0", vb!!.oid)
        assertEquals("Linux box", vb.textOrNull())
    }

    // ---------- SnmpScanner : parseResponse ----------

    @Test
    fun snmp_parseResponse_extractsSystemFields() {
        val response = tlv(
            0x30,
            int(0) + tlv(0x04, "public".toByteArray()) +
                tlv(
                    0xA2,
                    int(1) + int(0) + int(0) +
                        tlv(
                            0x30,
                            varbind(SnmpScanner.OID_SYS_DESCR, octet("Linux box 4.19")) +
                                varbind(SnmpScanner.OID_SYS_NAME, octet("router1")) +
                                varbind(SnmpScanner.OID_SYS_LOCATION, octet("Salon")) +
                                varbind(SnmpScanner.OID_SYS_UPTIME, tlv(0x43, SnmpScanner.encodeInteger(366100L)))
                        )
                )
        )
        val result = SnmpScanner.parseResponse(response)
        assertEquals("Linux box 4.19", result!!.descr)
        assertEquals("router1", result.name)
        assertEquals("Salon", result.location)
        assertEquals(3661L, result.uptimeSeconds)
    }

    @Test
    fun snmp_parseResponse_rejectsGarbage() {
        assertNull(SnmpScanner.parseResponse(ByteArray(0)))
        assertNull(SnmpScanner.parseResponse(byteArrayOf(0x01, 0x02, 0x03)))
    }

    @Test
    fun snmp_parseResponse_errorStatusReturnsNull() {
        // error-status = 1 (tooBig) → parseResponse retourne null
        val response = tlv(
            0x30,
            int(0) + tlv(0x04, "public".toByteArray()) +
                tlv(0xA2, int(1) + int(1) + int(0) + tlv(0x30, ByteArray(0)))
        )
        assertNull(SnmpScanner.parseResponse(response))
    }

    // ---------- SnmpScanner : formatUptime ----------

    @Test
    fun snmp_formatUptime() {
        // 366100 centièmes = 3661 s → « 1h 1m 1s »
        assertEquals("1h 1m 1s", SnmpScanner.formatUptime(3661))
        assertEquals("0s", SnmpScanner.formatUptime(0))
        assertEquals("1m 5s", SnmpScanner.formatUptime(65))
        assertEquals("1j 1h 1m", SnmpScanner.formatUptime(90_061))
        assertEquals("2j 0h 0m", SnmpScanner.formatUptime(172_800))
    }

    // ---------- CsvExporter : colonnes SNMP ----------

    @Test
    fun csv_includesSnmpColumns() {
        val csv = CsvExporter.buildCsv(
            listOf(Device(ip = "192.168.0.1", snmpName = "router1", snmpDescr = "Cisco IOS"))
        )
        assertTrue(csv.contains("SNMP Nom;SNMP Description"))
        assertTrue(csv.contains("router1;Cisco IOS"))
    }

    // ---------- Helpers de construction BER (miroir de l'encodage prod) ----------

    private fun tlv(tag: Int, content: ByteArray): ByteArray =
        byteArrayOf(tag.toByte()) + SnmpScanner.encodeLength(content.size) + content

    private fun int(value: Long): ByteArray = tlv(0x02, SnmpScanner.encodeInteger(value))

    private fun octet(s: String): ByteArray = tlv(0x04, s.toByteArray())

    private fun varbind(oid: String, valueTlv: ByteArray): ByteArray =
        tlv(0x30, SnmpScanner.encodeOid(oid) + valueTlv)
}

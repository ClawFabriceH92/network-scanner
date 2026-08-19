package com.fabrice.network.scanner

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests v1.9.0 : verrouillage PIN (hash + blocage), logs (ring buffer), historique
 * des débits (rotation JSON), NFC (UID hex + NDEF + dédup), surveillance (intervalle),
 * options techniques (défauts) et rapport PDF (synthèse + recommandations).
 */
class V190FeaturesTest {

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

    // ---------- AppLock : hash + vérification + blocage ----------

    @Test
    fun appLock_hashIsSha256HexNeverPlaintext() {
        val hash = AppLock.hashPin("1234")
        assertEquals(64, hash.length)
        assertTrue(hash.all { it in '0'..'9' || it in 'a'..'f' })
        assertFalse(hash.contains("1234"))
        // Vecteur connu : SHA-256("1234")
        assertEquals("03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4", hash)
        // Déterministe
        assertEquals(hash, AppLock.hashPin("1234"))
    }

    @Test
    fun appLock_matchesGoodAndBadPin() {
        val hash = AppLock.hashPin("4321")
        assertTrue(AppLock.matches("4321", hash))
        assertFalse(AppLock.matches("1234", hash))
        assertFalse(AppLock.matches("4321", "")) // hash vide → jamais match
    }

    @Test
    fun appLock_lockoutAfterFiveFailures() {
        var s = AppLock.Attempts(0, 0L)
        val now = 1_000_000L
        repeat(4) { s = s.onFailure(now) }
        assertEquals(4, s.count)
        assertFalse(s.isLocked(now))
        // 5e échec → reset + verrouillage 30 s
        s = s.onFailure(now)
        assertEquals(0, s.count)
        assertTrue(s.isLocked(now))
        assertEquals(30_000L, s.remainingMs(now))
        assertFalse(s.isLocked(now + 30_000L))
    }

    @Test
    fun appLock_successResetsAttempts() {
        var s = AppLock.Attempts(3, 0L).onFailure(1000L)
        s = s.onSuccess()
        assertEquals(0, s.count)
        assertEquals(0L, s.lockedUntil)
    }

    // ---------- AppLog : ring buffer ----------

    @Test
    fun appLog_boundedTo500Fifo() {
        AppLog.clear()
        for (i in 0..600) AppLog.i("Scan", "log_$i")
        assertEquals(500, AppLog.size())
        val dump = AppLog.dump()
        assertFalse(dump.contains("log_0"))
        assertTrue(dump.contains("log_600"))
    }

    @Test
    fun appLog_dumpFormatContainsLevelTagAndMessage() {
        AppLog.clear()
        AppLog.e("TestTag", "erreur critique")
        val dump = AppLog.dump()
        assertTrue(dump.contains("[E] TestTag: erreur critique"))
        assertTrue(dump.contains("=== NetworkScanner logs"))
    }

    // ---------- SpeedHistoryStore : rotation + JSON ----------

    @Test
    fun speedHistory_rotationBoundsTo200() {
        val existing = (0 until 200).map { SpeedHistoryStore.Entry(it.toLong(), 1.0, 1.0, 10) }
        val rotated = SpeedHistoryStore.rotate(
            existing,
            SpeedHistoryStore.Entry(999L, 5.0, 5.0, 5)
        )
        assertEquals(200, rotated.size)
        assertEquals(1L, rotated.first().ts)   // l'entrée la plus ancienne (0) sort
        assertEquals(999L, rotated.last().ts)
    }

    @Test
    fun speedHistory_jsonRoundTrip() {
        val entries = listOf(
            SpeedHistoryStore.Entry(1000L, 50.5, 10.2, 12),
            SpeedHistoryStore.Entry(2000L, 60.0, 8.0, 9)
        )
        val parsed = SpeedHistoryStore.parse(SpeedHistoryStore.toJson(entries))
        assertEquals(2, parsed.size)
        assertEquals(1000L, parsed[0].ts)
        assertEquals(50.5, parsed[0].downMbps, 0.001)
        assertEquals(10.2, parsed[0].upMbps, 0.001)
        assertEquals(12, parsed[0].latencyMs)
    }

    @Test
    fun speedHistory_parseGarbageReturnsEmpty() {
        assertTrue(SpeedHistoryStore.parse("{not json").isEmpty())
        assertTrue(SpeedHistoryStore.parse("").isEmpty())
    }

    // ---------- NfcReader.uidToHex + NdefParser ----------

    @Test
    fun nfc_uidToHex() {
        assertEquals("", NfcReader.uidToHex(null))
        assertEquals("", NfcReader.uidToHex(byteArrayOf()))
        assertEquals(
            "04A1B2C3D4E5",
            NfcReader.uidToHex(
                byteArrayOf(0x04, 0xA1.toByte(), 0xB2.toByte(), 0xC3.toByte(), 0xD4.toByte(), 0xE5.toByte())
            )
        )
    }

    @Test
    fun ndef_parseUri() {
        // code 0x04 = https://
        val payload = byteArrayOf(0x04) + "example.com".toByteArray()
        assertEquals("https://example.com", NdefParser.parseUri(payload))
        assertEquals(null, NdefParser.parseUri(byteArrayOf()))
    }

    @Test
    fun ndef_parseText() {
        // statut 0x02 (langue 2 octets) + "fr" + texte
        val payload = byteArrayOf(0x02) + "fr".toByteArray() + "Bonjour".toByteArray()
        assertEquals("Bonjour", NdefParser.parseText(payload))
        assertEquals(null, NdefParser.parseText(byteArrayOf()))
    }

    @Test
    fun ndef_parseRecords() {
        val uri = NdefParser.Record(0x01.toShort(), byteArrayOf(0x55), byteArrayOf(0x03) + "example.org".toByteArray())
        val text = NdefParser.Record(0x01.toShort(), byteArrayOf(0x54), byteArrayOf(0x02) + "en".toByteArray() + "Hi".toByteArray())
        assertEquals("http://example.org · Hi", NdefParser.parse(listOf(uri, text)))
        // TNF non well-known → ignoré
        val unknown = NdefParser.Record(0x02.toShort(), byteArrayOf(0x55), byteArrayOf(0x03) + "x".toByteArray())
        assertEquals("", NdefParser.parse(listOf(unknown)))
    }

    // ---------- NfcHistoryStore : dédup + rotation ----------

    @Test
    fun nfcHistory_dedupByUid() {
        val e1 = NfcReader.NfcLogEntry("AAA", listOf("NfcA"), "hello", 1000L)
        val e2 = NfcReader.NfcLogEntry("AAA", listOf("NfcA", "IsoDep"), "world", 2000L)
        val l1 = NfcHistoryStore.rotate(emptyList(), e1)
        assertEquals(1, l1.size)
        assertEquals(1, l1[0].views)
        val l2 = NfcHistoryStore.rotate(l1, e2)
        assertEquals(1, l2.size)
        assertEquals(2, l2[0].views)
        assertEquals(2000L, l2[0].lastTs)
        assertEquals(listOf("NfcA", "IsoDep"), l2[0].techs)
        assertEquals("world", l2[0].payload)
    }

    @Test
    fun nfcHistory_rotation200() {
        var list = emptyList<NfcHistoryStore.HistoryEntry>()
        repeat(201) { i ->
            list = NfcHistoryStore.rotate(
                list,
                NfcReader.NfcLogEntry("UID$i", emptyList(), null, i.toLong())
            )
        }
        assertEquals(200, list.size)
        assertEquals("UID1", list.first().uid)
        assertEquals("UID200", list.last().uid)
    }

    @Test
    fun nfcHistory_jsonRoundTrip() {
        val entries = listOf(
            NfcHistoryStore.HistoryEntry("ABC", listOf("NfcA", "Ndef"), "hi", 3, 100L, 300L)
        )
        val parsed = NfcHistoryStore.parse(NfcHistoryStore.toJson(entries))
        assertEquals(1, parsed.size)
        assertEquals("ABC", parsed[0].uid)
        assertEquals(listOf("NfcA", "Ndef"), parsed[0].techs)
        assertEquals("hi", parsed[0].payload)
        assertEquals(3, parsed[0].views)
        assertEquals(100L, parsed[0].firstTs)
        assertEquals(300L, parsed[0].lastTs)
    }

    // ---------- SurveillanceScheduler : sélection d'intervalle ----------

    @Test
    fun surveillance_nearestValidInterval() {
        assertEquals(1L, SurveillanceScheduler.nearestValidInterval(1L))
        assertEquals(2L, SurveillanceScheduler.nearestValidInterval(2L))
        assertEquals(6L, SurveillanceScheduler.nearestValidInterval(6L))
        assertEquals(1L, SurveillanceScheduler.nearestValidInterval(0L))
        assertEquals(2L, SurveillanceScheduler.nearestValidInterval(3L))
        assertEquals(6L, SurveillanceScheduler.nearestValidInterval(5L))
        assertEquals(6L, SurveillanceScheduler.nearestValidInterval(100L))
    }

    // ---------- TechOptions : défauts (pure via FakePrefs) ----------

    @Test
    fun techOptions_defaults() {
        val prefs = FakePrefs()
        assertTrue(TechOptions.scanFastFrom(prefs))
        assertFalse(TechOptions.scanEconomyFrom(prefs))
        assertFalse(TechOptions.largeTextFrom(prefs))
    }

    @Test
    fun techOptions_readWrite() {
        val prefs = FakePrefs()
        prefs.edit().putBoolean(TechOptions.KEY_SCAN_FAST, false).apply()
        prefs.edit().putBoolean(TechOptions.KEY_SCAN_ECONOMY, true).apply()
        prefs.edit().putBoolean(TechOptions.KEY_A11Y_LARGE, true).apply()
        assertFalse(TechOptions.scanFastFrom(prefs))
        assertTrue(TechOptions.scanEconomyFrom(prefs))
        assertTrue(TechOptions.largeTextFrom(prefs))
    }

    // ---------- PdfAuditReport : synthèse + recommandations ----------

    private fun vulns(critical: Int, high: Int) = VulnScanner.DeviceVulns(
        services = emptyList(),
        cves = emptyList(),
        score = 50,
        label = "Critique",
        criticalCount = critical,
        highCount = high,
        kevCount = 0
    )

    @Test
    fun pdf_buildSummary_counts() {
        val devices = listOf(
            Device(ip = "192.168.0.1", defaultCred = "admin/admin"),
            Device(ip = "192.168.0.2")
        )
        val vulnsByIp = mapOf("192.168.0.2" to vulns(critical = 1, high = 2))
        val data = PdfAuditReport.buildData(devices, vulnsByIp, "192.168.0.5", "192.168.0.0/24")
        assertEquals(1, data.defaultCredCount)
        val summary = PdfAuditReport.buildSummary(data)
        assertTrue(summary.contains("2 appareil(s)"))
        assertTrue(summary.contains("1 vulnérabilité(s) critique(s)"))
        assertTrue(summary.contains("1 credential(s) par défaut"))
    }

    @Test
    fun pdf_buildRecommendations_orderedAndBounded() {
        val devices = listOf(
            Device(ip = "192.168.0.1", hostname = "box", isGateway = true, defaultCred = "admin/admin"),
            Device(ip = "192.168.0.20", hostname = "pc", defaultCred = null),
            Device(ip = "192.168.0.30", hostname = "nas", defaultCred = null)
        )
        val vulnsByIp = mapOf(
            "192.168.0.1" to vulns(critical = 1, high = 0),
            "192.168.0.20" to vulns(critical = 2, high = 1),
            "192.168.0.30" to vulns(critical = 0, high = 3)
        )
        val data = PdfAuditReport.buildData(devices, vulnsByIp, "192.168.0.5", "192.168.0.0/24")
        val recs = PdfAuditReport.buildRecommendations(data)
        assertTrue(recs.size <= 5)
        // Priorité max = credential par défaut en premier
        assertTrue(recs[0].contains("admin/admin"))
        // Les vulnérabilités critiques de l'appareil le plus touché passent avant
        assertTrue(recs.any { it.contains("2 vulnérabilité(s) critique(s)") })
    }

    @Test
    fun pdf_buildRecommendations_firmwareForVulnerableGateway() {
        val devices = listOf(Device(ip = "192.168.0.1", hostname = "box", isGateway = true))
        val vulnsByIp = mapOf("192.168.0.1" to vulns(critical = 1, high = 0))
        val data = PdfAuditReport.buildData(devices, vulnsByIp, "192.168.0.5", "192.168.0.0/24")
        val recs = PdfAuditReport.buildRecommendations(data)
        // La box (gateway) a une vulnérabilité → firmware recommandé
        assertTrue(recs.any { it.contains("firmware de la box") })
    }

    @Test
    fun pdf_buildRecommendations_emptyWhenNoFindings() {
        val data = PdfAuditReport.buildData(
            listOf(Device(ip = "192.168.0.1")),
            emptyMap(),
            "192.168.0.5",
            "192.168.0.0/24"
        )
        assertTrue(PdfAuditReport.buildRecommendations(data).isEmpty())
    }
}

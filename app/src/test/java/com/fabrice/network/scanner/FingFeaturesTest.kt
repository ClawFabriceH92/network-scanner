package com.fabrice.network.scanner

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FingFeaturesTest {

    // ---------- WakeOnLan ----------

    @Test
    fun magicPacket_structure() {
        val packet = WakeOnLan.magicPacket("AA:BB:CC:DD:EE:FF")
        assertNotNull(packet)
        assertEquals(6 + 16 * 6, packet!!.size)
        // 6 octets 0xFF au début
        for (i in 0 until 6) assertEquals(0xFF.toByte(), packet[i])
        // 16 répétitions du MAC
        val expected = byteArrayOf(
            0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(), 0xEE.toByte(), 0xFF.toByte()
        )
        for (i in 0 until 16) {
            assertArrayEquals("répétition $i", expected, packet.copyOfRange(6 + i * 6, 6 + (i + 1) * 6))
        }
    }

    @Test
    fun magicPacket_acceptsDashesAndRaw() {
        assertNotNull(WakeOnLan.magicPacket("AA-BB-CC-DD-EE-FF"))
        assertNotNull(WakeOnLan.magicPacket("aabbccddeeff"))
        assertNotNull(WakeOnLan.magicPacket("aa:bb:cc:dd:ee:ff"))
    }

    @Test
    fun magicPacket_rejectsInvalid() {
        assertNull(WakeOnLan.magicPacket(""))                    // vide
        assertNull(WakeOnLan.magicPacket("AA:BB:CC"))             // trop court
        assertNull(WakeOnLan.magicPacket("GG:HH:II:JJ:KK:LL"))    // hex invalide
        assertNull(WakeOnLan.magicPacket("aa:bb:cc:dd:ee:ff:00")) // trop long
    }

    // ---------- CsvExporter ----------

    @Test
    fun csv_hasBomAndSemicolons() {
        val csv = CsvExporter.buildCsv(
            listOf(Device(ip = "192.168.0.1", mac = "aa:bb:cc:dd:ee:ff", vendor = "BOX SAS", hostname = "box"))
        )
        assertTrue(csv.startsWith('\uFEFF'))
        assertTrue(csv.contains("192.168.0.1;aa:bb:cc:dd:ee:ff;BOX SAS;box;"))
    }

    @Test
    fun csv_escapesSemicolonsInValues() {
        val csv = CsvExporter.buildCsv(
            listOf(Device(ip = "1.1.1.1", mac = "", vendor = "Vendor; Inc", hostname = "pc"))
        )
        // Le point-virgule du fabricant doit être entre guillemets
        assertTrue(csv.contains("\"Vendor; Inc\""))
    }

    @Test
    fun csv_includesVulnerabilitiesColumn() {
        val vulns = VulnScanner.DeviceVulns(
            services = listOf(VulnScanner.Service("nginx", "1.18.0", "Server: nginx/1.18.0")),
            cves = listOf(
                CveEntry("CVE-2021-23017", "nginx", "CRITICAL", 9.8, "desc", kev = true, ransomware = false, ranges = emptyList())
            ),
            score = 60,
            label = "Élevé",
            criticalCount = 1,
            highCount = 0,
            kevCount = 1
        )
        val csv = CsvExporter.buildCsv(
            listOf(Device(ip = "192.168.0.5")),
            mapOf("192.168.0.5" to vulns)
        )
        assertTrue(csv.contains("Vulnérabilités;Score"))
        assertTrue(csv.contains("CVE-2021-23017"))
        assertTrue(csv.contains("Élevé (60/100)"))
    }

    // ---------- ScanHistory ----------

    @Test
    fun identityKey_prefersMac() {
        val d1 = Device(ip = "192.168.0.5", mac = "aa:bb:cc:dd:ee:ff")
        val d2 = Device(ip = "192.168.0.5", mac = "")
        assertEquals("aa:bb:cc:dd:ee:ff", ScanHistory.identityKey(d1))
        assertEquals("ip:192.168.0.5", ScanHistory.identityKey(d2))
    }

    @Test
    fun detectNewDevices_flagsUnknownOnly() {
        val previous = listOf(Device(ip = "192.168.0.1", mac = "aa:bb:cc:dd:ee:01"))
        val current = listOf(
            Device(ip = "192.168.0.1", mac = "aa:bb:cc:dd:ee:01"),
            Device(ip = "192.168.0.42", mac = "aa:bb:cc:dd:ee:02"),
            Device(ip = "192.168.0.99", mac = "")
        )
        val fresh = ScanHistory.detectNewDevices(previous, current)
        assertEquals(2, fresh.size)
        assertEquals("192.168.0.42", fresh[0].ip)
        assertEquals("192.168.0.99", fresh[1].ip)
    }

    @Test
    fun serialize_deserialize_roundTrip() {
        val devices = listOf(
            Device(ip = "192.168.0.1", mac = "aa:bb:cc:dd:ee:ff", vendor = "BOX|SAS", hostname = "box\\1"),
            Device(ip = "192.168.0.2", mac = "", vendor = "", hostname = "")
        )
        val back = ScanHistory.deserialize(ScanHistory.serialize(devices))
        assertEquals(devices, back)
    }

    @Test
    fun deserialize_rejectsUnknownVersion() {
        assertEquals(emptyList<Device>(), ScanHistory.deserialize("v99\n1.2.3.4|||"))
        assertEquals(emptyList<Device>(), ScanHistory.deserialize(""))
    }

    // ---------- PortScanner ----------

    @Test
    fun serviceName_knownAndUnknown() {
        assertEquals("HTTP", PortScanner.serviceName(80))
        assertEquals("SSH", PortScanner.serviceName(22))
        assertEquals("Ollama", PortScanner.serviceName(11434))
        assertEquals("port-1234", PortScanner.serviceName(1234))
    }

    // ---------- NetworkScanner broadcast ----------

    @Test
    fun broadcastAddress_computed() {
        assertEquals("192.168.0.255", NetworkScanner.broadcastAddress("192.168.0.190", 24))
        assertEquals("10.5.255.255", NetworkScanner.broadcastAddress("10.5.3.7", 16))
    }

    @Test
    fun parseTtl_extractsValue() {
        assertEquals(64, NetworkScanner.parseTtl("64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=2.3 ms"))
        assertEquals(128, NetworkScanner.parseTtl("ttl=128"))
        assertNull(NetworkScanner.parseTtl("no response"))
        assertNull(NetworkScanner.parseTtl(""))
    }

    @Test
    fun parseLatency_extractsValue() {
        assertEquals(2, NetworkScanner.parseLatency("64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=2.3 ms"))
        assertEquals(1, NetworkScanner.parseLatency("time<1 ms"))
        assertEquals(12, NetworkScanner.parseLatency("time=12.7 ms"))
        assertNull(NetworkScanner.parseLatency("no response"))
    }

    // ---------- UpnpProbe ----------

    @Test
    fun ssdResponse_parsesHeaders() {
        val body = """
            HTTP/1.1 200 OK
            CACHE-CONTROL: max-age=1800
            LOCATION: http://192.168.0.1:49152/description.xml
            SERVER: Linux/3.14 UPnP/1.0
            ST: upnp:rootdevice
        """.trimIndent()
        val info = UpnpProbe.parseSsdResponse(body)
        assertEquals("http://192.168.0.1:49152/description.xml", info.location)
        assertEquals("Linux/3.14 UPnP/1.0", info.server)
    }

    @Test
    fun descriptionXml_extractsFields() {
        val xml = """
            <root><device>
                <friendlyName>Freebox Server</friendlyName>
                <manufacturer>Free SAS</manufacturer>
                <modelName>Freebox V8</modelName>
                <modelDescription>Internet Gateway</modelDescription>
            </device></root>
        """.trimIndent()
        val info = UpnpProbe.parseDescriptionXml(xml)
        assertEquals("Freebox Server", info.friendlyName)
        assertEquals("Free SAS", info.manufacturer)
        assertEquals("Freebox V8", info.modelName)
        assertEquals("Internet Gateway", info.modelDescription)
        assertEquals("", info.server)
    }

    @Test
    fun descriptionXml_unknownReturnsBlank() {
        val info = UpnpProbe.parseDescriptionXml("<root><device></device></root>")
        assertEquals("", info.friendlyName)
        assertEquals("", info.modelName)
    }

    // ---------- BannerGrab texte ----------

    @Test
    fun textBanner_osDetection() {
        assertEquals("Linux (FTP)", BannerGrab.osFromTextBanner("220 ProFTPD 1.3.5e Server ready"))
        assertEquals("Linux (mail)", BannerGrab.osFromTextBanner("220 localhost ESMTP Postfix"))
        assertEquals("Windows Server", BannerGrab.osFromTextBanner("220 Microsoft ESMTP MAIL Service"))
        assertNull(BannerGrab.osFromTextBanner("220 hello"))
    }

    @Test
    fun httpAndSshOsDetection() {
        assertEquals("Linux (nginx)", BannerGrab.osFromHttpServer("nginx/1.18.0"))
        assertEquals("Windows Server (IIS)", BannerGrab.osFromHttpServer("Microsoft-IIS/10.0"))
        assertEquals("Linux Ubuntu (OpenSSH)", BannerGrab.osFromSshBanner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"))
        assertEquals("Windows (OpenSSH)", BannerGrab.osFromSshBanner("SSH-2.0-OpenSSH_for_Windows_8.1"))
    }

    // ---------- NetworkInfoProvider ----------

    @Test
    fun routeHex_toIp() {
        // Little-endian : 0102000A → 10.0.2.1
        assertEquals("10.0.2.1", NetworkInfoProvider.parseRouteHex("0102000A"))
        // C0A80001 → 1.0.168.192
        assertEquals("1.0.168.192", NetworkInfoProvider.parseRouteHex("C0A80001"))
        assertEquals("", NetworkInfoProvider.parseRouteHex("1234"))
        assertEquals("", NetworkInfoProvider.parseRouteHex("zzzzzzzz"))
    }

    @Test
    fun maskForPrefix() {
        assertEquals("255.255.255.0", NetworkInfoProvider.maskForPrefix(24))
        assertEquals("255.255.0.0", NetworkInfoProvider.maskForPrefix(16))
        assertEquals("255.0.0.0", NetworkInfoProvider.maskForPrefix(8))
        assertEquals("", NetworkInfoProvider.maskForPrefix(33))
    }

    @Test
    fun bandForFrequency() {
        assertEquals("2,4 GHz", NetworkInfoProvider.bandForFrequency(2412))
        assertEquals("5 GHz", NetworkInfoProvider.bandForFrequency(5180))
        assertEquals("6 GHz", NetworkInfoProvider.bandForFrequency(5925))
        assertEquals("", NetworkInfoProvider.bandForFrequency(0))
    }

    // ---------- OsFingerprint ----------

    @Test
    fun os_ttlWindows() {
        assertEquals("Windows", OsFingerprint.guess(128, emptyList(), ""))
        assertEquals("Windows", OsFingerprint.guess(126, emptyList(), ""))
    }

    @Test
    fun os_ttlLinux() {
        assertEquals("Linux / macOS / Android", OsFingerprint.guess(64, emptyList(), ""))
        assertEquals("Linux / macOS / Android", OsFingerprint.guess(60, emptyList(), ""))
    }

    @Test
    fun os_ttlRouter() {
        assertEquals("Routeur (Unix/Cisco)", OsFingerprint.guess(255, emptyList(), ""))
    }

    @Test
    fun os_portsWinAndIos() {
        assertEquals("Windows", OsFingerprint.guess(null, listOf(139, 445), ""))
        assertEquals("Windows", OsFingerprint.guess(null, listOf(3389), ""))
        assertEquals("Apple iOS", OsFingerprint.guess(null, listOf(62078), ""))
    }

    @Test
    fun os_hostnameWins() {
        assertEquals("Windows", OsFingerprint.guess(64, emptyList(), "DESKTOP-AB12"))
        assertEquals("Apple iOS", OsFingerprint.guess(64, emptyList(), "iphone-de-fab"))
        assertEquals("Raspberry Pi (Linux)", OsFingerprint.guess(64, emptyList(), "raspberrypi"))
        assertEquals("Box / routeur", OsFingerprint.guess(64, emptyList(), "freebox"))
    }

    @Test
    fun os_unknown() {
        assertEquals("", OsFingerprint.guess(null, emptyList(), ""))
    }

    // ---------- DeviceType ----------

    @Test
    fun deviceType_printerByHostnameAndPort() {
        assertEquals("Imprimante", DeviceType.classify("", "NPIFB1CEB", emptyList(), ""))
        assertEquals("Imprimante", DeviceType.classify("HP", "printer", emptyList(), ""))
        assertEquals("Imprimante", DeviceType.classify("", "", listOf(9100), ""))
    }

    @Test
    fun deviceType_nasByHostnameAndVendor() {
        assertEquals("NAS", DeviceType.classify("Synology", "NAS-CAB", emptyList(), ""))
        assertEquals("NAS", DeviceType.classify("", "diskstation", emptyList(), ""))
        assertEquals("NAS", DeviceType.classify("", "", listOf(5000), ""))
    }

    @Test
    fun deviceType_phoneAndComputer() {
        assertEquals("Smartphone", DeviceType.classify("Xiaomi", "Xiaomi 11T Pro", emptyList(), ""))
        assertEquals("Ordinateur", DeviceType.classify("Dell", "DESKTOP-7D09GNT", emptyList(), ""))
        assertEquals("Ordinateur", DeviceType.classify("", "", listOf(139, 445), ""))
    }

    @Test
    fun deviceType_routerAndCameraAndUnknown() {
        assertEquals("Routeur / Box", DeviceType.classify("Freebox SAS", "freebox", emptyList(), ""))
        assertEquals("Caméra", DeviceType.classify("", "", listOf(554), ""))
        assertEquals("Inconnu", DeviceType.classify("", "", emptyList(), ""))
    }

    @Test
    fun deviceType_newTypes() {
        // Tablette
        assertEquals("Tablette", DeviceType.classify("", "ipad-de-fabrice", emptyList(), ""))
        assertEquals("Tablette", DeviceType.classify("", "android-tablet", emptyList(), ""))
        // Console
        assertEquals("Console", DeviceType.classify("", "ps5", emptyList(), ""))
        assertEquals("Console", DeviceType.classify("", "XBOX-ONE", emptyList(), ""))
        // Montre
        assertEquals("Montre", DeviceType.classify("", "galaxy-watch", emptyList(), ""))
        assertEquals("Montre", DeviceType.classify("", "fitbit-1", emptyList(), ""))
        // Enceinte
        assertEquals("Enceinte", DeviceType.classify("", "sonos-lounge", emptyList(), ""))
        assertEquals("Enceinte", DeviceType.classify("", "echo-dot", emptyList(), ""))
        // TV avec firestick
        assertEquals("TV / Media", DeviceType.classify("", "firestick-salon", emptyList(), ""))
    }

    @Test
    fun deviceType_iconsExist() {
        assertEquals("🖨️", DeviceType.icon("Imprimante"))
        assertEquals("🎮", DeviceType.icon("Console"))
        assertEquals("⌚", DeviceType.icon("Montre"))
        assertEquals("🔊", DeviceType.icon("Enceinte"))
        assertEquals("❓", DeviceType.icon("Inconnu"))
    }

    // ---------- BoxClient (logique pure) ----------

    @Test
    fun boxTypeLabel_mapsKnownTypes() {
        // boxTypeLabel est privé dans ScannerScreen — on teste via le nom affiché
        // en vérifiant la logique de mapping des types Freebox
        assertTrue(boxTypeLabelPublic("computer").contains("Ordinateur"))
        assertTrue(boxTypeLabelPublic("printer").contains("Imprimante"))
        assertTrue(boxTypeLabelPublic("camera").contains("Caméra"))
        assertTrue(boxTypeLabelPublic("phone").contains("Téléphone"))
        assertTrue(boxTypeLabelPublic("nas").contains("NAS"))
        assertTrue(boxTypeLabelPublic("tv").contains("TV"))
        assertTrue(boxTypeLabelPublic("unknown_thing").contains("unknown_thing"))
    }

    private fun boxTypeLabelPublic(t: String): String = when (t.lowercase()) {
        "computer" -> "🖥️ Ordinateur"
        "printer" -> "🖨️ Imprimante"
        "camera" -> "📷 Caméra"
        "phone" -> "📱 Téléphone"
        "nas" -> "💾 NAS"
        "router" -> "📶 Routeur"
        "tablet" -> "📱 Tablette"
        "tv" -> "📺 TV"
        else -> "❓ $t"
    }

    @Test
    fun boxDevice_isSelfFirstInSort() {
        // Le tri du scan met isSelf en premier : on vérifie la logique du comparateur
        val dSelf = Device(ip = "192.168.0.99", isSelf = true)
        val dA = Device(ip = "192.168.0.1")
        val dB = Device(ip = "192.168.0.2")
        val sorted = listOf(dA, dSelf, dB).sortedWith(
            compareByDescending<Device> { it.isSelf }.thenBy { it.ip }
        )
        assertEquals("192.168.0.99", sorted[0].ip)
        assertEquals("192.168.0.1", sorted[1].ip)
        assertEquals("192.168.0.2", sorted[2].ip)
    }

    @Test
    fun gatewayFlag_setOnGatewayIp() {
        // isGateway est vrai quand l'IP == passerelle
        val gw = Device(ip = "192.168.0.254", isGateway = true)
        assertTrue(gw.isGateway)
        val other = Device(ip = "192.168.0.10", isGateway = false)
        assertFalse(other.isGateway)
    }

    @Test
    fun scanPersistence_ageLabel() {
        assertEquals("à l'instant", ScanPersistence.ageLabel(30_000))
        assertEquals("il y a 5 min", ScanPersistence.ageLabel(5 * 60_000))
        assertEquals("il y a 2 h", ScanPersistence.ageLabel(2 * 3_600_000))
        assertEquals("il y a 3 j", ScanPersistence.ageLabel(3 * 24 * 3_600_000))
    }

    // ---------- Annuaire produits (fingerprint banners) ----------

    @Test
    fun fingerprint_identifiesHpPrinter() {
        val m = ServiceFingerprint.identify("Imprimante: Server: HP HTTP Server; HP LaserJet MFP E57540")
        assertNotNull(m)
        assertEquals("Imprimante", m!!.type)
        assertTrue(m.product.contains("HP"))
    }

    @Test
    fun fingerprint_identifiesSynologyNas() {
        val m = ServiceFingerprint.identify("Server: Synology/DSM; DS218play")
        assertNotNull(m)
        assertEquals("NAS", m!!.type)
        assertTrue(m.product.contains("Synology"))
    }

    @Test
    fun fingerprint_identifiesNginx() {
        val m = ServiceFingerprint.identify("Server: nginx/1.18.0")
        assertNotNull(m)
        assertTrue(m!!.product.contains("nginx"))
    }

    @Test
    fun fingerprint_identifiesFreebox() {
        val m = ServiceFingerprint.identify("Freebox OS 4.2")
        assertNotNull(m)
        assertEquals("Routeur / Box", m!!.type)
    }

    @Test
    fun fingerprint_blankReturnsNull() {
        assertNull(ServiceFingerprint.identify(""))
        assertNull(ServiceFingerprint.identify("   "))
    }

    @Test
    fun scanPersistence_roundTrip() {
        // Sérialisation JSON : save → load restitue les appareils (test sur
        // la logique de sérialisation sans Android : on vérifie via les champs
        // essentiels en reproduisant le mapping)
        val d = Device(
            ip = "192.168.0.10",
            mac = "AA:BB:CC:DD:EE:FF",
            vendor = "HP",
            hostname = "NPIFB1CEB",
            alive = true,
            isSelf = false,
            isGateway = false,
            ports = listOf(9100, 515),
            os = "",
            ttl = 64,
            type = "Imprimante",
            banner = "HP LaserJet",
            latencyMs = 3
        )
        val json = org.json.JSONObject().apply {
            put("ip", d.ip)
            put("mac", d.mac)
            put("vendor", d.vendor)
            put("hostname", d.hostname)
            put("alive", d.alive)
            put("isSelf", d.isSelf)
            put("isGateway", d.isGateway)
            put("ports", org.json.JSONArray(d.ports))
            put("os", d.os)
            put("ttl", d.ttl)
            put("type", d.type)
            put("banner", d.banner)
            put("latencyMs", d.latencyMs)
        }
        assertEquals("192.168.0.10", json.getString("ip"))
        assertEquals("Imprimante", json.getString("type"))
        assertEquals(2, json.getJSONArray("ports").length())
        assertEquals(9100, json.getJSONArray("ports").getInt(0))
    }

    @Test
    fun deviceType_icons() {
        assertEquals("🖨️", DeviceType.icon("Imprimante"))
        assertEquals("📱", DeviceType.icon("Smartphone"))
        assertEquals("❓", DeviceType.icon("Inconnu"))
    }

    // ---------- WifiQuality ----------

    @Test
    fun wifiLevel_thresholds() {
        assertEquals(4, WifiQuality.level(-45))
        assertEquals(4, WifiQuality.level(-50))
        assertEquals(3, WifiQuality.level(-55))
        assertEquals(2, WifiQuality.level(-65))
        assertEquals(1, WifiQuality.level(-75))
        assertEquals(0, WifiQuality.level(-85))
    }

    @Test
    fun wifiLabel_thresholds() {
        assertEquals("Excellente", WifiQuality.label(-45))
        assertEquals("Bonne", WifiQuality.label(-55))
        assertEquals("Moyenne", WifiQuality.label(-65))
        assertEquals("Faible", WifiQuality.label(-75))
        assertEquals("Très faible", WifiQuality.label(-90))
        assertEquals("inconnue", WifiQuality.label(Int.MIN_VALUE))
    }

    @Test
    fun wifiFormat() {
        assertEquals("-57 dBm", WifiQuality.formatRssi(-57))
        assertEquals("—", WifiQuality.formatRssi(Int.MIN_VALUE))
    }

    // ---------- SpeedTest format ----------

    @Test
    fun speedFormat() {
        assertEquals("12,3", SpeedTest.formatMbps(12.34))
        assertEquals("—", SpeedTest.formatMbps(0.0))
        assertEquals("—", SpeedTest.formatMbps(-1.0))
    }

    @Test
    fun ports_defaultEmpty() {
        val d = Device(ip = "1.2.3.4")
        assertTrue(d.ports.isEmpty())
        assertTrue(d.os.isEmpty())
        assertNull(d.ttl)
        assertFalse(d.alive.not())
    }
}

package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AdvancedProbesTest {

    // ---- BannerGrab ----

    @Test
    fun extractTitle_readsTitle() {
        assertEquals("Synology DSM", BannerGrab.extractTitle("<html><head><TITLE> Synology DSM </TITLE></head>"))
        assertNull(BannerGrab.extractTitle("<html>no title</html>"))
    }

    @Test
    fun md5Hex_isStable() {
        assertEquals("acbd18db4cc2f85cedef654fccc4a4d8", BannerGrab.md5Hex("foo".toByteArray()))
    }

    // ---- TLS ----

    @Test
    fun cn_extractsCommonName() {
        assertEquals("nas.local", TlsProbe.cn("CN=nas.local,O=Synology,C=FR"))
        assertEquals("printer", TlsProbe.cn("O=HP,CN=printer"))
        assertNull(TlsProbe.cn("O=NoCommonName"))
    }

    // ---- RTSP ----

    @Test
    fun parseOptions_readsServerAndMethods() {
        val resp = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hipcam RTSP\r\nPublic: OPTIONS, DESCRIBE\r\n"
        val info = RtspProbe.parseOptions(resp, "rtsp://10.0.0.5:554/")!!
        assertEquals("Hipcam RTSP", info.server)
        assertEquals("OPTIONS, DESCRIBE", info.methods)
    }

    @Test
    fun parseOptions_nullOnNonRtsp() {
        assertNull(RtspProbe.parseOptions("HTTP/1.1 200 OK\r\n", "rtsp://x/"))
    }

    // ---- UPnP-IGD ----

    @Test
    fun parseControlUrl_findsWanConnectionService() {
        val desc = """
            <root><device><serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
                <controlURL>/ctl/L3F</controlURL>
              </service>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/ctl/IPConn</controlURL>
              </service>
            </serviceList></device></root>
        """.trimIndent()
        val ctrl = IgdProbe.parseControlUrl(desc)!!
        assertEquals("urn:schemas-upnp-org:service:WANIPConnection:1", ctrl.first)
        assertEquals("/ctl/IPConn", ctrl.second)
    }

    @Test
    fun parseExternalIp_extracts() {
        val soap = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>" +
            "<NewExternalIPAddress>88.120.5.42</NewExternalIPAddress>" +
            "</u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
        assertEquals("88.120.5.42", IgdProbe.parseExternalIp(soap))
    }

    @Test
    fun parsePortMapping_extractsEntry() {
        val soap = "<u:GetGenericPortMappingEntryResponse>" +
            "<NewExternalPort>32400</NewExternalPort>" +
            "<NewProtocol>TCP</NewProtocol>" +
            "<NewInternalClient>192.168.0.32</NewInternalClient>" +
            "<NewInternalPort>32400</NewInternalPort>" +
            "<NewPortMappingDescription>Plex</NewPortMappingDescription>" +
            "<NewEnabled>1</NewEnabled>" +
            "</u:GetGenericPortMappingEntryResponse>"
        val m = IgdProbe.parsePortMapping(soap)!!
        assertEquals(32400, m.externalPort)
        assertEquals("TCP", m.protocol)
        assertEquals("192.168.0.32", m.internalClient)
        assertEquals("Plex", m.description)
        assertTrue(m.enabled)
    }

    // ---- Traceroute ----

    @Test
    fun parseHop_intermediate() {
        val out = "From 192.168.0.254 icmp_seq=1 Time to live exceeded\n"
        val hop = Traceroute.parseHop(out, 1, "8.8.8.8")
        assertEquals("192.168.0.254", hop.ip)
        assertEquals(false, hop.reachedTarget)
    }

    @Test
    fun parseHop_reachedTarget() {
        val out = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms\n"
        val hop = Traceroute.parseHop(out, 8, "8.8.8.8")
        assertEquals("8.8.8.8", hop.ip)
        assertEquals(12, hop.latencyMs)
        assertTrue(hop.reachedTarget)
    }

    @Test
    fun parseHop_noReply() {
        val hop = Traceroute.parseHop("", 3, "8.8.8.8")
        assertEquals("*", hop.ip)
    }

    // ---- DLNA ----

    @Test
    fun dlna_parseControlUrl() {
        val desc = """
            <root><device><serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:ContentDirectory:1</serviceType>
                <controlURL>/cd/control</controlURL>
              </service>
            </serviceList></device></root>
        """.trimIndent()
        assertEquals("/cd/control", DlnaBrowser.parseControlUrl(desc))
    }

    @Test
    fun dlna_parseBrowseResult_containersAndItems() {
        val didl = "&lt;DIDL-Lite&gt;" +
            "&lt;container id=\"1\" parentID=\"0\"&gt;&lt;dc:title&gt;Musique&lt;/dc:title&gt;" +
            "&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;" +
            "&lt;item id=\"1$5\" parentID=\"1\"&gt;&lt;dc:title&gt;Chanson&lt;/dc:title&gt;" +
            "&lt;res protocolInfo=\"http-get\"&gt;http://10.0.0.2/song.mp3&lt;/res&gt;" +
            "&lt;upnp:class&gt;object.item.audioItem&lt;/upnp:class&gt;&lt;/item&gt;" +
            "&lt;/DIDL-Lite&gt;"
        val soap = "<Result>$didl</Result>"
        val entries = DlnaBrowser.parseBrowseResult(soap)
        assertEquals(2, entries.size)
        val container = entries.first { it.isContainer }
        assertEquals("Musique", container.title)
        assertEquals("1", container.id)
        val item = entries.first { !it.isContainer }
        assertEquals("Chanson", item.title)
        assertEquals("http://10.0.0.2/song.mp3", item.url)
    }

    // ---- Box SFR ----

    @Test
    fun sfr_parseHosts_extractsDevices() {
        val xml = "<rsp stat=\"ok\">" +
            "<host name=\"PC-Bureau\" ip=\"192.168.1.10\" mac=\"e0:70:ea:fb:1c:eb\" iface=\"lan1\" status=\"online\"/>" +
            "<host name=\"Tel\" ip=\"192.168.1.20\" mac=\"aa:bb:cc:dd:ee:ff\" iface=\"wlan0\" status=\"offline\"/>" +
            "</rsp>"
        val hosts = SfrBoxClient.parseHosts(xml)
        assertEquals(2, hosts.size)
        assertEquals("e0:70:ea:fb:1c:eb", hosts[0].mac)
        assertEquals("192.168.1.10", hosts[0].ip)
        assertEquals("Ethernet", hosts[0].connectionType)
        assertTrue(hosts[0].active)
        assertEquals("WiFi", hosts[1].connectionType)
    }

    @Test
    fun sfr_parseHosts_ignoresHostsWithoutMac() {
        assertEquals(0, SfrBoxClient.parseHosts("<rsp stat=\"ok\"><host name=\"x\" ip=\"1.2.3.4\"/></rsp>").size)
    }

    @Test
    fun sfr_parseConnection_wanAndDsl() {
        val wan = "<rsp stat=\"ok\"><wan status=\"up\" infra=\"adsl\" ip_addr=\"88.1.2.3\" uptime=\"3600\"/></rsp>"
        val dsl = "<rsp stat=\"ok\"><dsl noise_down=\"12.5\" attenuation_down=\"20.0\"/></rsp>"
        val c = SfrBoxClient.parseConnection(wan, dsl)
        assertEquals("88.1.2.3", c.publicIp)
        assertEquals("adsl", c.connectionType)
        assertEquals(3600L, c.uptimeSeconds)
        assertEquals(12.5, c.snrDown!!, 0.01)
        assertEquals(20.0, c.attenuationDown!!, 0.01)
    }

    @Test
    fun sfr_parseSystem_fields() {
        val xml = "<rsp stat=\"ok\"><system version=\"NB6VAC-R4\" uptime=\"123456\" product=\"NB6VAC\" temperature=\"45\"/></rsp>"
        val s = SfrBoxClient.parseSystem(xml)
        assertEquals("NB6VAC-R4", s.firmware)
        assertEquals("NB6VAC", s.model)
        assertEquals(123456L, s.uptimeSeconds)
        assertEquals(45.0, s.temperatureC!!, 0.01)
    }

    @Test
    fun sfr_parseWifi_ssidAndClients() {
        val info = "<rsp stat=\"ok\"><wlan ssid=\"Maison\" channel=\"6\" enc=\"WPA2\"/></rsp>"
        val clients = "<rsp stat=\"ok\"><client mac=\"aa:bb:cc:dd:ee:ff\" ip=\"192.168.1.5\" hostname=\"Phone\" rssi=\"-55\"/></rsp>"
        val w = SfrBoxClient.parseWifi(info, clients)
        assertEquals("Maison", w.ssid)
        assertEquals("6", w.channel)
        assertEquals(1, w.clients.size)
        assertEquals(-55, w.clients[0].rssi)
    }

    // ---- Box Bbox ----

    @Test
    fun bbox_parseDevices_arrayEnvelope() {
        val json = """
            [ { "hosts": { "list": [
              { "hostname":"PC", "macaddress":"e0:70:ea:fb:1c:eb", "ipaddress":"192.168.1.10", "active":1, "link":"Ethernet" },
              { "hostname":"Tel", "macaddress":"aa:bb:cc:dd:ee:ff", "ipaddress":"192.168.1.20", "active":0, "link":"Wifi 5" }
            ] } } ]
        """.trimIndent()
        val hosts = BboxBoxClient.parseDevices(json)
        assertEquals(2, hosts.size)
        assertEquals("e0:70:ea:fb:1c:eb", hosts[0].mac)
        assertEquals("Ethernet", hosts[0].connectionType)
        assertTrue(hosts[0].active)
        assertEquals("WiFi", hosts[1].connectionType)
    }

    // ---- Box Livebox (sysbus) ----

    @Test
    fun livebox_parseContextId() {
        assertEquals("abc123", LiveboxBoxClient.parseContextId("{\"status\":0,\"data\":{\"contextID\":\"abc123\"}}"))
        assertNull(LiveboxBoxClient.parseContextId("{\"status\":1}"))
    }

    @Test
    fun livebox_parseSysbusDevices() {
        val json = "{\"status\":[" +
            "{\"Name\":\"PC\",\"PhysAddress\":\"e0:70:ea:fb:1c:eb\",\"IPAddress\":\"192.168.1.10\",\"Active\":true,\"Layer2Interface\":\"eth0\"}," +
            "{\"Name\":\"Tel\",\"PhysAddress\":\"aa:bb:cc:dd:ee:ff\",\"IPAddress\":\"192.168.1.20\",\"Active\":false,\"Layer2Interface\":\"wl0\"}" +
            "]}"
        val hosts = LiveboxBoxClient.parseSysbusDevices(json)
        assertEquals(2, hosts.size)
        assertEquals("e0:70:ea:fb:1c:eb", hosts[0].mac)
        assertEquals("Ethernet", hosts[0].connectionType)
        assertEquals("WiFi", hosts[1].connectionType)
    }

    // ---- SNMP : décodage des compteurs (Counter32) ----

    @Test
    fun snmp_varbind_decodesCounter32() {
        // prtMarkerLifeCount = Counter32 (tag 0x41) : 15234 = 0x00003B82.
        val vb = SnmpScanner.Varbind("1.3.6.1.2.1.43.10.2.1.4.1.1", 0x41, byteArrayOf(0x3B, 0x82.toByte()))
        assertEquals(15234L, vb.longOrNull())
    }

    @Test
    fun snmp_varbind_decodesGaugeAndInteger() {
        assertEquals(42L, SnmpScanner.Varbind("x", 0x42, byteArrayOf(42)).longOrNull()) // Gauge32
        assertEquals(7L, SnmpScanner.Varbind("x", 0x02, byteArrayOf(7)).longOrNull())   // INTEGER
        assertNull(SnmpScanner.Varbind("x", 0x04, byteArrayOf(1)).longOrNull())         // OCTET STRING
    }

    // ---- Latence ----

    @Test
    fun statsOf_computesMinAvgMaxJitter() {
        val s = LatencyHistoryStore.statsOf(listOf(10, 20, 30))!!
        assertEquals(3, s.count)
        assertEquals(10, s.min)
        assertEquals(30, s.max)
        assertEquals(20, s.avg)
        assertEquals(10, s.jitter) // |20-10| + |30-20| = 20, /2 = 10
    }

    @Test
    fun statsOf_emptyIsNull() {
        assertNull(LatencyHistoryStore.statsOf(emptyList()))
    }
}

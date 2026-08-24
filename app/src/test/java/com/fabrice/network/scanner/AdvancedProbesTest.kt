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

package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests de la brique WS-Discovery : construction du Probe SOAP et parsing des
 * ProbeMatches (XAddrs + Types + type d'appareil déduit).
 */
class WsdResolverTest {

    @Test
    fun buildProbe_isValidSoap() {
        val xml = String(WsdResolver.buildProbe("urn:uuid:test-1234"), Charsets.UTF_8)
        assertTrue(xml.contains("http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"))
        assertTrue(xml.contains("urn:uuid:test-1234"))
        assertTrue(xml.contains("<wsd:Probe/>"))
    }

    @Test
    fun buildProbe_generatesUniqueMessageId() {
        val a = String(WsdResolver.buildProbe(), Charsets.UTF_8)
        val b = String(WsdResolver.buildProbe(), Charsets.UTF_8)
        assertTrue(a != b) // MessageID distincts par défaut
    }

    @Test
    fun parseProbeMatch_extractsPrinterTypesAndXAddrs() {
        val info = WsdResolver.parseProbeMatch(probeMatches("wsdp:Device wsdp:Printer"))
        assertEquals(listOf("http://192.168.1.10:80/wsd/device"), info.xAddrs)
        assertEquals(listOf("wsdp:Device", "wsdp:Printer"), info.types)
        assertEquals("Imprimante", info.deviceHint)
    }

    @Test
    fun parseProbeMatch_computerHint() {
        val info = WsdResolver.parseProbeMatch(probeMatches("wsdp:Device wsdp:Computer"))
        assertEquals("Ordinateur", info.deviceHint)
    }

    @Test
    fun parseProbeMatch_multipleMatches() {
        val xml = """<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<soap:Body><wsd:ProbeMatches>
<wsd:ProbeMatch><wsd:Types>wsdp:Printer</wsd:Types><wsd:XAddrs>http://192.168.1.10:80/x</wsd:XAddrs></wsd:ProbeMatch>
<wsd:ProbeMatch><wsd:Types>wsdp:Device</wsd:Types><wsd:XAddrs>http://192.168.1.11:80/y</wsd:XAddrs></wsd:ProbeMatch>
</wsd:ProbeMatches></soap:Body></soap:Envelope>"""
        val info = WsdResolver.parseProbeMatch(xml)
        assertEquals(2, info.xAddrs.size)
        assertEquals("Imprimante", info.deviceHint)
    }

    @Test
    fun parseProbeMatch_blankReturnsEmpty() {
        assertEquals(WsdResolver.WsdInfo(), WsdResolver.parseProbeMatch(""))
        assertEquals(WsdResolver.WsdInfo(), WsdResolver.parseProbeMatch("not xml at all"))
    }

    private fun probeMatches(types: String): String = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<soap:Body><wsd:ProbeMatches>
<wsd:ProbeMatch>
<wsa:EndpointReference><wsa:Address>urn:uuid:98190dc2-0890-4ef8-ac9a-5940995e6119</wsa:Address></wsa:EndpointReference>
<wsd:Types>$types</wsd:Types>
<wsd:XAddrs>http://192.168.1.10:80/wsd/device</wsd:XAddrs>
<wsd:MetadataVersion>10</wsd:MetadataVersion>
</wsd:ProbeMatch>
</wsd:ProbeMatches></soap:Body></soap:Envelope>"""
}

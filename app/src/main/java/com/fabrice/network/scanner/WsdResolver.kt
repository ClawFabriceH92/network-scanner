package com.fabrice.network.scanner

import java.net.DatagramPacket
import java.net.InetAddress
import java.net.MulticastSocket
import java.util.UUID

/**
 * Découverte WS-Discovery (WSD) — PC Windows récents, imprimantes réseau,
 * scanners et certains NAS. Envoie un Probe SOAP en multicast sur
 * 239.255.255.250:3702 et parse les ProbeMatches reçus en retour.
 *
 * Le parsing (parseProbeMatch) est PUR et testable (DocumentBuilder du JDK) ;
 * seul discover() fait de l'I/O et ne lève jamais d'exception. Le MulticastLock
 * de l'appelant couvre cet appel (le scan tourne déjà sous withMulticastLock).
 */
object WsdResolver {

    data class WsdInfo(
        val xAddrs: List<String> = emptyList(),
        val types: List<String> = emptyList()
    ) {
        val hasInfo: Boolean get() = xAddrs.isNotEmpty() || types.isNotEmpty()

        /** Type d'appareil déduit des types WSD annoncés (aligné sur DeviceType). */
        val deviceHint: String
            get() = when {
                types.any { it.contains("Printer", ignoreCase = true) ||
                    it.contains("ScanDevice", ignoreCase = true) ||
                    it.contains("Scanner", ignoreCase = true) } -> "Imprimante"
                types.any { it.contains("Computer", ignoreCase = true) } -> "Ordinateur"
                else -> ""
            }
    }

    private const val WSD_ADDR = "239.255.255.250"
    private const val WSD_PORT = 3702

    private const val PROBE_ACTION = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"
    private const val PROBE_TO = "urn:schemas-xmlsoap-org:ws:2005:04:discovery"

    /**
     * Construit le Probe SOAP (gabarit standard WS-Discovery), avec un
     * MessageID unique par défaut. Testable en injectant un messageId fixe.
     */
    fun buildProbe(messageId: String = "urn:uuid:${UUID.randomUUID()}"): ByteArray {
        return ("""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<soap:Header>
<wsa:To>$PROBE_TO</wsa:To>
<wsa:Action>$PROBE_ACTION</wsa:Action>
<wsa:MessageID>$messageId</wsa:MessageID>
</soap:Header>
<soap:Body>
<wsd:Probe/>
</soap:Body>
</soap:Envelope>""").toByteArray(Charsets.UTF_8)
    }

    /**
     * Parse un message ProbeMatches (SOAP) et en extrait les XAddrs et les
     * Types de chaque ProbeMatch. Retourne un WsdInfo vide en cas d'échec.
     */
    fun parseProbeMatch(xml: String): WsdInfo {
        if (xml.isBlank()) return WsdInfo()
        return try {
            val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
            factory.isNamespaceAware = true
            // Durcissement : le XML provient de paquets UDP LAN non fiables
            // (239.255.255.250:3702). Interdire tout DOCTYPE neutralise d'un coup
            // le « billion laughs » (expansion d'entités) et les XXE.
            runCatching {
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            }
            runCatching {
                factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
            }
            runCatching {
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            }
            factory.isExpandEntityReferences = false
            val builder = factory.newDocumentBuilder()
            val doc = builder.parse(org.xml.sax.InputSource(java.io.StringReader(xml)))

            val xAddrs = mutableListOf<String>()
            val types = mutableListOf<String>()
            val matches = doc.getElementsByTagNameNS("*", "ProbeMatch")
            for (i in 0 until matches.length) {
                val el = matches.item(i) as? org.w3c.dom.Element ?: continue
                val xAddrNodes = el.getElementsByTagNameNS("*", "XAddrs")
                for (j in 0 until xAddrNodes.length) {
                    xAddrNodes.item(j).textContent?.trim()
                        ?.takeIf { it.isNotBlank() }?.let { xAddrs.add(it) }
                }
                val typesNodes = el.getElementsByTagNameNS("*", "Types")
                for (j in 0 until typesNodes.length) {
                    typesNodes.item(j).textContent?.trim()
                        ?.split(Regex("\\s+"))?.forEach { if (it.isNotBlank()) types.add(it) }
                }
            }
            WsdInfo(xAddrs = xAddrs.distinct(), types = types.distinct())
        } catch (e: Exception) {
            WsdInfo()
        }
    }

    /** Fusionne deux infos pour une même IP (union des listes). */
    private fun WsdInfo.merge(other: WsdInfo): WsdInfo = WsdInfo(
        xAddrs = (xAddrs + other.xAddrs).distinct(),
        types = (types + other.types).distinct()
    )

    /**
     * Lance la découverte WS-Discovery et écoute les réponses pendant
     * [timeoutMs]. Retourne les infos par IP source (jamais d'exception).
     */
    fun discover(timeoutMs: Int = 2_500): Map<String, WsdInfo> {
        val perIp = HashMap<String, WsdInfo>()
        var socket: MulticastSocket? = null
        try {
            // Socket non lié → reuseAddress avant bind (le port 3702 peut être
            // partagé par d'autres services). On rejoint le groupe multicast.
            socket = MulticastSocket(null as java.net.SocketAddress?).apply {
                reuseAddress = true
                bind(java.net.InetSocketAddress(WSD_PORT))
                soTimeout = 400
                runCatching { joinGroup(InetAddress.getByName(WSD_ADDR)) }
            }

            val probe = buildProbe()
            runCatching {
                socket.send(DatagramPacket(probe, probe.size, InetAddress.getByName(WSD_ADDR), WSD_PORT))
            }

            val buffer = ByteArray(16384)
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(packet)
                } catch (e: java.net.SocketTimeoutException) {
                    continue
                }
                val ip = packet.address?.hostAddress ?: continue
                val body = String(packet.data, 0, packet.length, Charsets.UTF_8)
                val info = parseProbeMatch(body)
                if (info.hasInfo) {
                    perIp[ip] = perIp[ip]?.merge(info) ?: info
                }
            }
        } catch (e: Exception) {
            // pas de réseau ou port occupé : on rend ce qu'on a déjà reçu.
        } finally {
            runCatching { socket?.leaveGroup(InetAddress.getByName(WSD_ADDR)) }
            runCatching { socket?.close() }
        }
        return perIp
    }
}

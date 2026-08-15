package com.fabrice.network.scanner

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.net.URL

/**
 * Découverte UPnP/SSDP (comme Fing) : interroge les appareils du réseau qui
 * annoncent leurs services UPnP (boxes, NAS, imprimantes, TV, enceintes…).
 *
 * 1. Envoi d'un M-SEARCH multicast sur 239.255.255.250:1900.
 * 2. Les appareils répondent avec des en-têtes dont LOCATION (URL du XML de
 *    description) et SERVER.
 * 3. Fetch du XML de description pour extraire : friendlyName, manufacturer,
 *    modelName, modelDescription, serialNumber…
 */
object UpnpProbe {

    data class UpnpInfo(
        val location: String = "",
        val server: String = "",
        val friendlyName: String = "",
        val manufacturer: String = "",
        val modelName: String = "",
        val modelDescription: String = ""
    ) {
        val hasInfo: Boolean
            get() = friendlyName.isNotBlank() || manufacturer.isNotBlank() || modelName.isNotBlank()
    }

    /** Cibles SSDP interrogées en une seule salve multicast (fusionnées par IP). */
    private val SEARCH_TARGETS = listOf(
        "upnp:rootdevice",
        "ssdp:all",
        "urn:schemas-upnp-org:device:MediaServer:1",
        "urn:schemas-upnp-org:device:MediaRenderer:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
    )

    /**
     * Envoie les M-SEARCH et écoute les réponses pendant [listenMs].
     * Retourne les infos par IP source (les appareils qui ont répondu).
     * Nécessite un MulticastLock côté appelant (Android).
     */
    fun discover(listenMs: Int = 2_500): Map<String, UpnpInfo> {
        val found = HashMap<String, UpnpInfo>()
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = listenMs
                // Plusieurs ST : rootdevice + ssdp:all + MediaServer/MediaRenderer/
                // InternetGatewayDevice → couvre NAS, TV, enceintes, boxes, IoT.
                for (st in SEARCH_TARGETS) {
                    val request = (
                        "M-SEARCH * HTTP/1.1\r\n" +
                            "HOST: 239.255.255.250:1900\r\n" +
                            "MAN: \"ssdp:discover\"\r\n" +
                            "MX: 2\r\n" +
                            "ST: $st\r\n" +
                            "\r\n"
                        ).toByteArray(Charsets.UTF_8)
                    runCatching {
                        socket.send(
                            DatagramPacket(request, request.size, InetAddress.getByName("239.255.255.250"), 1900)
                        )
                    }
                }
                val buffer = ByteArray(8192)
                val deadline = System.currentTimeMillis() + listenMs
                while (System.currentTimeMillis() < deadline) {
                    try {
                        val packet = DatagramPacket(buffer, buffer.size)
                        socket.receive(packet)
                        val ip = packet.address.hostAddress ?: continue
                        val body = String(packet.data, 0, packet.length, Charsets.UTF_8)
                        val info = parseSsdResponse(body)
                        // Fusionne : la réponse la plus complète gagne
                        val merged = found[ip]?.let { it.merge(info) } ?: info
                        found[ip] = merged
                    } catch (e: java.net.SocketTimeoutException) {
                        break
                    }
                }
            }
            found
        } catch (e: Exception) {
            found
        }
    }

    /** Parse une réponse SSDP (en-têtes HTTP). Testable. */
    fun parseSsdResponse(body: String): UpnpInfo {
        var location = ""
        var server = ""
        body.lineSequence().forEach { line ->
            when {
                line.startsWith("LOCATION:", ignoreCase = true) -> location = line.substringAfter(':').trim()
                line.startsWith("SERVER:", ignoreCase = true) -> server = line.substringAfter(':').trim()
            }
        }
        return UpnpInfo(location = location, server = server)
    }

    /**
     * Récupère et parse le XML de description UPnP (LOCATION).
     * Retourne null si le fetch ou le parse échoue.
     */
    fun fetchDescription(location: String, timeoutMs: Int = 2_000): UpnpInfo? {
        if (location.isBlank()) return null
        return try {
            val url = URL(location)
            val host = url.host
            val port = if (url.port > 0) url.port else if (url.protocol == "https") 443 else 80
            Socket().use { socket ->
                socket.connect(java.net.InetSocketAddress(host, port), timeoutMs)
                socket.soTimeout = timeoutMs
                val path = if (url.path.isBlank()) "/" else url.path
                val query = url.query?.let { "?$it" } ?: ""
                socket.getOutputStream().write(
                    "GET $path$query HTTP/1.0\r\nHost: $host\r\n\r\n".toByteArray(Charsets.UTF_8)
                )
                socket.getOutputStream().flush()
                val text = socket.getInputStream().bufferedReader().use { it.readText() }
                // On ne garde que le corps (après la 1re ligne vide)
                val body = text.substringAfter("\r\n\r\n", text)
                parseDescriptionXml(body)
            }
        } catch (e: Exception) {
            null
        }
    }

    /** Extrait les champs utiles du XML de description UPnP. Testable. */
    fun parseDescriptionXml(xml: String): UpnpInfo {
        fun tag(name: String): String {
            val m = Regex("<$name>([^<]*)</$name>", RegexOption.IGNORE_CASE).find(xml)
            return m?.groupValues?.get(1)?.trim() ?: ""
        }
        return UpnpInfo(
            friendlyName = tag("friendlyName"),
            manufacturer = tag("manufacturer"),
            modelName = tag("modelName"),
            modelDescription = tag("modelDescription")
        )
    }

    private fun UpnpInfo.merge(other: UpnpInfo): UpnpInfo = UpnpInfo(
        location = location.ifBlank { other.location },
        server = server.ifBlank { other.server },
        friendlyName = friendlyName.ifBlank { other.friendlyName },
        manufacturer = manufacturer.ifBlank { other.manufacturer },
        modelName = modelName.ifBlank { other.modelName },
        modelDescription = modelDescription.ifBlank { other.modelDescription }
    )
}

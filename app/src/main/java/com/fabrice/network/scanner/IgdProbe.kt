package com.fabrice.network.scanner

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URL

/**
 * UPnP-IGD (Internet Gateway Device) : interroge le routeur pour l'IP publique
 * (WAN) et surtout la liste des **redirections de ports** (port forwarding) —
 * précieux pour repérer des services exposés sur Internet.
 *
 * Découverte SSDP → description XML → contrôle SOAP (GetExternalIPAddress +
 * GetGenericPortMappingEntry en boucle). Tout en best-effort, jamais bloquant.
 */
object IgdProbe {

    data class PortMapping(
        val externalPort: Int,
        val protocol: String,
        val internalClient: String,
        val internalPort: Int,
        val description: String,
        val enabled: Boolean
    )

    data class IgdInfo(
        val externalIp: String,
        val mappings: List<PortMapping>
    )

    private const val SSDP_ADDR = "239.255.255.250"
    private const val SSDP_PORT = 1900
    private val SERVICE_TYPES = listOf(
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1"
    )

    /** Découvre l'IGD et retourne IP publique + redirections, ou null. */
    fun discover(timeoutMs: Int = 2_500, maxMappings: Int = 64): IgdInfo? {
        val location = runCatching { ssdpSearch(timeoutMs) }.getOrNull() ?: return null
        val desc = runCatching { httpGet(location, timeoutMs) }.getOrNull() ?: return null
        val ctrl = parseControlUrl(desc) ?: return null
        val controlUrl = runCatching { URL(URL(location), ctrl.second).toString() }.getOrNull() ?: return null
        val serviceType = ctrl.first

        val externalIp = runCatching {
            val soap = soapCall(controlUrl, serviceType, "GetExternalIPAddress", "", timeoutMs)
            soap?.let { parseExternalIp(it) }
        }.getOrNull().orEmpty()

        val mappings = mutableListOf<PortMapping>()
        for (i in 0 until maxMappings) {
            val resp = runCatching {
                soapCall(
                    controlUrl, serviceType, "GetGenericPortMappingEntry",
                    "<NewPortMappingIndex>$i</NewPortMappingIndex>", timeoutMs
                )
            }.getOrNull() ?: break
            val m = parsePortMapping(resp) ?: break
            mappings.add(m)
        }
        if (externalIp.isBlank() && mappings.isEmpty()) return null
        return IgdInfo(externalIp, mappings)
    }

    /** M-SEARCH SSDP ciblé IGD → première URL LOCATION trouvée. */
    private fun ssdpSearch(timeoutMs: Int): String? {
        for (st in SERVICE_TYPES) {
            val loc = runCatching { ssdpSearchOne(st, timeoutMs) }.getOrNull()
            if (!loc.isNullOrBlank()) return loc
        }
        return null
    }

    private fun ssdpSearchOne(st: String, timeoutMs: Int): String? {
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMs
            val msg = "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: $SSDP_ADDR:$SSDP_PORT\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: 2\r\n" +
                "ST: $st\r\n\r\n"
            val data = msg.toByteArray()
            socket.send(DatagramPacket(data, data.size, InetAddress.getByName(SSDP_ADDR), SSDP_PORT))
            val buf = ByteArray(2048)
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val pkt = DatagramPacket(buf, buf.size)
                socket.receive(pkt)
                val resp = String(pkt.data, 0, pkt.length)
                val loc = resp.lineSequence().firstOrNull { it.startsWith("LOCATION:", ignoreCase = true) }
                    ?.substringAfter(':')?.trim()
                if (!loc.isNullOrBlank()) return loc
            }
        }
        return null
    }

    /** Extrait (serviceType, controlURL) du service WAN*Connection de la desc. */
    fun parseControlUrl(descXml: String): Pair<String, String>? {
        val serviceRe = Regex("<service>(.*?)</service>", RegexOption.DOT_MATCHES_ALL)
        for (m in serviceRe.findAll(descXml)) {
            val block = m.groupValues[1]
            val type = Regex("<serviceType>(.*?)</serviceType>").find(block)?.groupValues?.get(1)?.trim()
                ?: continue
            if (type in SERVICE_TYPES) {
                val ctrl = Regex("<controlURL>(.*?)</controlURL>").find(block)?.groupValues?.get(1)?.trim()
                if (!ctrl.isNullOrBlank()) return type to ctrl
            }
        }
        return null
    }

    /** Extrait l'IP externe d'une réponse SOAP GetExternalIPAddress. */
    fun parseExternalIp(soap: String): String? =
        Regex("<NewExternalIPAddress>(.*?)</NewExternalIPAddress>").find(soap)
            ?.groupValues?.get(1)?.trim()?.ifBlank { null }

    /** Parse une entrée de redirection de port (réponse SOAP). null si absente. */
    fun parsePortMapping(soap: String): PortMapping? {
        fun tag(name: String): String? =
            Regex("<$name>(.*?)</$name>").find(soap)?.groupValues?.get(1)?.trim()
        val extPort = tag("NewExternalPort")?.toIntOrNull() ?: return null
        return PortMapping(
            externalPort = extPort,
            protocol = tag("NewProtocol").orEmpty(),
            internalClient = tag("NewInternalClient").orEmpty(),
            internalPort = tag("NewInternalPort")?.toIntOrNull() ?: 0,
            description = tag("NewPortMappingDescription").orEmpty(),
            enabled = tag("NewEnabled") == "1"
        )
    }

    private fun soapCall(
        controlUrl: String,
        serviceType: String,
        action: String,
        argsXml: String,
        timeoutMs: Int
    ): String? {
        val body = "<?xml version=\"1.0\"?>" +
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
            "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
            "<s:Body><u:$action xmlns:u=\"$serviceType\">$argsXml</u:$action></s:Body></s:Envelope>"
        val conn = URL(controlUrl).openConnection() as HttpURLConnection
        return try {
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "text/xml; charset=\"utf-8\"")
            conn.setRequestProperty("SOAPAction", "\"$serviceType#$action\"")
            conn.outputStream.use { it.write(body.toByteArray()); it.flush() }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }
        } catch (e: Exception) {
            null
        } finally {
            runCatching { conn.disconnect() }
        }
    }

    private fun httpGet(url: String, timeoutMs: Int): String? {
        val conn = URL(url).openConnection() as HttpURLConnection
        return try {
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            if (conn.responseCode != 200) return null
            conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } catch (e: Exception) {
            null
        } finally {
            runCatching { conn.disconnect() }
        }
    }
}

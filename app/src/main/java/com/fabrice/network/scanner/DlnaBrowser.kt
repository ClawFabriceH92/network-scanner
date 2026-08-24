package com.fabrice.network.scanner

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

/**
 * Navigateur DLNA / UPnP-AV : découvre les serveurs multimédia (MediaServer /
 * ContentDirectory) et parcourt leur contenu (dossiers + fichiers), sans lire
 * les flux (juste titres + URLs à ouvrir dans un lecteur).
 *
 * SSDP → description → SOAP ContentDirectory#Browse → parsing DIDL-Lite.
 */
object DlnaBrowser {

    data class Server(val name: String, val controlUrl: String)

    data class Entry(
        val id: String,
        val title: String,
        val isContainer: Boolean,
        val url: String,
        val cls: String
    )

    private const val SSDP_ADDR = "239.255.255.250"
    private const val SSDP_PORT = 1900
    private const val CONTENT_DIRECTORY = "urn:schemas-upnp-org:service:ContentDirectory:1"

    /** Découvre les serveurs DLNA du réseau. */
    fun discover(timeoutMs: Int = 2_500): List<Server> {
        val locations = runCatching { ssdpSearch(timeoutMs) }.getOrDefault(emptyList())
        val servers = mutableListOf<Server>()
        val seen = HashSet<String>()
        for (loc in locations) {
            val desc = runCatching { httpGet(loc, timeoutMs) }.getOrNull() ?: continue
            val ctrl = parseControlUrl(desc) ?: continue
            val controlUrl = runCatching { URL(URL(loc), ctrl).toString() }.getOrNull() ?: continue
            if (!seen.add(controlUrl)) continue
            val name = parseFriendlyName(desc) ?: "Serveur DLNA"
            servers.add(Server(name, controlUrl))
        }
        return servers
    }

    /** Parcourt les enfants directs d'un conteneur ([objectId] « 0 » = racine). */
    fun browse(controlUrl: String, objectId: String = "0", timeoutMs: Int = 4_000): List<Entry> {
        val args = "<ObjectID>$objectId</ObjectID>" +
            "<BrowseFlag>BrowseDirectChildren</BrowseFlag>" +
            "<Filter>*</Filter><StartingIndex>0</StartingIndex>" +
            "<RequestedCount>500</RequestedCount><SortCriteria></SortCriteria>"
        val soap = runCatching {
            soapCall(controlUrl, CONTENT_DIRECTORY, "Browse", args, timeoutMs)
        }.getOrNull() ?: return emptyList()
        return parseBrowseResult(soap)
    }

    // ---------------------------------------------------------------- SSDP

    private fun ssdpSearch(timeoutMs: Int): List<String> {
        val out = mutableListOf<String>()
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMs
            val msg = "M-SEARCH * HTTP/1.1\r\nHOST: $SSDP_ADDR:$SSDP_PORT\r\n" +
                "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: $CONTENT_DIRECTORY\r\n\r\n"
            val data = msg.toByteArray()
            socket.send(DatagramPacket(data, data.size, InetAddress.getByName(SSDP_ADDR), SSDP_PORT))
            val buf = ByteArray(2048)
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    socket.receive(pkt)
                    val resp = String(pkt.data, 0, pkt.length)
                    resp.lineSequence().firstOrNull { it.startsWith("LOCATION:", ignoreCase = true) }
                        ?.substringAfter(':')?.trim()
                        ?.let { if (it.isNotBlank() && it !in out) out.add(it) }
                } catch (e: Exception) {
                    break
                }
            }
        }
        return out
    }

    // ------------------------------------------------------------- Parsing

    /** controlURL du service ContentDirectory dans la description. Testable. */
    fun parseControlUrl(descXml: String): String? {
        val serviceRe = Regex("<service>(.*?)</service>", RegexOption.DOT_MATCHES_ALL)
        for (m in serviceRe.findAll(descXml)) {
            val block = m.groupValues[1]
            val type = Regex("<serviceType>(.*?)</serviceType>").find(block)?.groupValues?.get(1)?.trim()
            if (type == CONTENT_DIRECTORY) {
                return Regex("<controlURL>(.*?)</controlURL>").find(block)?.groupValues?.get(1)?.trim()
            }
        }
        return null
    }

    fun parseFriendlyName(descXml: String): String? =
        Regex("<friendlyName>(.*?)</friendlyName>").find(descXml)?.groupValues?.get(1)?.trim()?.ifBlank { null }

    /**
     * Parse la réponse SOAP Browse : extrait le DIDL-Lite (échappé) du <Result>,
     * le déséchappe, puis lit conteneurs et items. Fonction pure — testable.
     */
    fun parseBrowseResult(soap: String): List<Entry> {
        val resultRaw = Regex("<Result>(.*?)</Result>", RegexOption.DOT_MATCHES_ALL)
            .find(soap)?.groupValues?.get(1) ?: return emptyList()
        val didl = unescapeXml(resultRaw)
        val entries = mutableListOf<Entry>()
        // Conteneurs (dossiers)
        Regex("<container\\b([^>]*)>(.*?)</container>", RegexOption.DOT_MATCHES_ALL)
            .findAll(didl).forEach { m ->
                val id = attr(m.groupValues[1], "id")
                val body = m.groupValues[2]
                entries.add(
                    Entry(id, tag(body, "dc:title") ?: "(sans titre)", true, "", tag(body, "upnp:class").orEmpty())
                )
            }
        // Items (fichiers)
        Regex("<item\\b([^>]*)>(.*?)</item>", RegexOption.DOT_MATCHES_ALL)
            .findAll(didl).forEach { m ->
                val id = attr(m.groupValues[1], "id")
                val body = m.groupValues[2]
                val res = Regex("<res\\b[^>]*>(.*?)</res>", RegexOption.DOT_MATCHES_ALL)
                    .find(body)?.groupValues?.get(1)?.trim().orEmpty()
                entries.add(
                    Entry(id, tag(body, "dc:title") ?: "(sans titre)", false, res, tag(body, "upnp:class").orEmpty())
                )
            }
        return entries
    }

    private fun attr(attrs: String, name: String): String =
        Regex("$name=\"([^\"]*)\"").find(attrs)?.groupValues?.get(1).orEmpty()

    private fun tag(xml: String, name: String): String? =
        Regex("<$name\\b[^>]*>(.*?)</$name>", RegexOption.DOT_MATCHES_ALL)
            .find(xml)?.groupValues?.get(1)?.trim()?.ifBlank { null }

    /** Déséchappe les entités XML de base. */
    fun unescapeXml(s: String): String =
        s.replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", "\"").replace("&apos;", "'")
            .replace("&amp;", "&")

    // --------------------------------------------------------------- Réseau

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
            val stream = if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
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

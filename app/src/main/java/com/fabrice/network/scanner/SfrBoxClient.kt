package com.fabrice.network.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Client box SFR / RED / Neufbox (Sagemcom NB4/NB5/NB6/NB6V/NB6VAC).
 *
 * API REST locale documentée : `http://<box>/api/1.0/?method=<methode>`.
 * `lan.getHostsList` est PUBLIC (aucune authentification requise depuis le
 * firmware 3.0.7) et renvoie la liste des équipements au format XML :
 *
 *   <rsp stat="ok"><host name="…" ip="…" mac="…" iface="lan1|wlan0" status="online"/>…</rsp>
 *
 * C'est ce qui permet de récupérer les MAC de tout le réseau sur une box SFR.
 */
class SfrBoxClient(private val gateway: String) : BoxClient {

    override val name = "SFR"
    override val baseUrl = "http://$gateway/api/1.0"

    override fun isAvailable(): Boolean = gateway.isNotBlank()

    override suspend fun fetchDevices(): List<BoxClient.BoxDevice>? =
        withContext(Dispatchers.IO) {
            val xml = httpGet("$baseUrl/?method=lan.getHostsList") ?: return@withContext null
            val hosts = parseHosts(xml)
            hosts.ifEmpty { if (xml.contains("<rsp")) emptyList() else null }
        }

    override suspend fun fetchConnection(): BoxConnection? =
        withContext(Dispatchers.IO) {
            val wan = httpGet("$baseUrl/?method=wan.getInfo") ?: return@withContext null
            val dsl = httpGet("$baseUrl/?method=dsl.getInfo")
            parseConnection(wan, dsl)
        }

    override suspend fun fetchSystem(): BoxSystem? =
        withContext(Dispatchers.IO) {
            val xml = httpGet("$baseUrl/?method=system.getInfo") ?: return@withContext null
            parseSystem(xml)
        }

    override suspend fun fetchWifi(): BoxWifi? =
        withContext(Dispatchers.IO) {
            val info = httpGet("$baseUrl/?method=wlan.getInfo") ?: return@withContext null
            val clients = httpGet("$baseUrl/?method=wlan.getClientList")
            parseWifi(info, clients)
        }

    companion object {
        /**
         * Vrai si l'hôte répond à l'API SFR (signature `<rsp …>` de la Neufbox).
         * Sert à distinguer une box SFR d'une Livebox sur la même passerelle
         * (192.168.1.1). À appeler depuis un thread IO.
         */
        fun respondsToApi(gateway: String, timeoutMs: Int = 1_500): Boolean {
            if (gateway.isBlank()) return false
            val xml = httpGetStatic("http://$gateway/api/1.0/?method=lan.getHostsList", timeoutMs)
            return xml != null && xml.contains("<rsp")
        }

        private fun httpGetStatic(url: String, timeoutMs: Int): String? {
            val conn = URL(url).openConnection() as HttpURLConnection
            return try {
                conn.connectTimeout = timeoutMs
                conn.readTimeout = timeoutMs
                conn.setRequestProperty("User-Agent", "NetworkScanner/1.0")
                if (conn.responseCode != 200) return null
                conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            } catch (e: Exception) {
                null
            } finally {
                runCatching { conn.disconnect() }
            }
        }

        /**
         * Parse la réponse XML `lan.getHostsList` → liste d'équipements.
         * Robuste : extrait chaque élément `<host …/>` et ses attributs, quelle
         * que soit l'imbrication. Fonction pure — testable.
         */
        fun parseHosts(xml: String): List<BoxClient.BoxDevice> {
            val out = mutableListOf<BoxClient.BoxDevice>()
            Regex("<host\\b([^>]*)/?>", RegexOption.DOT_MATCHES_ALL).findAll(xml).forEach { m ->
                val attrs = m.groupValues[1]
                val mac = attr(attrs, "mac")
                if (mac.isBlank()) return@forEach
                val iface = attr(attrs, "iface").lowercase()
                val connectionType = when {
                    iface.startsWith("wlan") || iface.contains("wifi") -> "WiFi"
                    iface.startsWith("lan") || iface.contains("eth") -> "Ethernet"
                    else -> null
                }
                val status = attr(attrs, "status").lowercase()
                val alive = status == "online" || status == "1" || attr(attrs, "alive").isNotBlank()
                out.add(
                    BoxClient.BoxDevice(
                        name = attr(attrs, "name"),
                        mac = mac,
                        ip = attr(attrs, "ip"),
                        hostType = attr(attrs, "type"),
                        active = alive,
                        reachable = alive,
                        lastActivity = "",
                        connectionType = connectionType
                    )
                )
            }
            return out
        }

        private fun attr(attrs: String, name: String): String =
            Regex("$name=\"([^\"]*)\"").find(attrs)?.groupValues?.get(1).orEmpty()

        /** Valeur d'un attribut XML n'importe où dans la réponse (1er match). */
        private fun anyAttr(xml: String, vararg names: String): String {
            for (n in names) {
                val v = Regex("\\b$n=\"([^\"]*)\"").find(xml)?.groupValues?.get(1)
                if (!v.isNullOrBlank()) return v
            }
            return ""
        }

        /**
         * Parse wan.getInfo (+ dsl.getInfo) → BoxConnection. Défensif : plusieurs
         * noms d'attributs possibles. Fonction pure — testable.
         */
        fun parseConnection(wanXml: String, dslXml: String?): BoxConnection {
            val mode = anyAttr(wanXml, "infra", "mode", "wan_mode", "type").lowercase()
            val ip = anyAttr(wanXml, "ip_addr", "ipaddr", "ip", "wan_ip_addr")
            val status = anyAttr(wanXml, "status", "wan_status", "state")
            val uptime = anyAttr(wanXml, "uptime", "wan_uptime").toLongOrNull()
            val down = anyAttr(wanXml, "rate_down", "down_rate", "downstream").toLongOrNull()
            val up = anyAttr(wanXml, "rate_up", "up_rate", "upstream").toLongOrNull()
            val snrDown = dslXml?.let { anyAttr(it, "noise_down", "snr_down", "attn_down_snr").toDoubleOrNull() }
            val snrUp = dslXml?.let { anyAttr(it, "noise_up", "snr_up").toDoubleOrNull() }
            val attnDown = dslXml?.let { anyAttr(it, "attenuation_down", "attn_down").toDoubleOrNull() }
            val attnUp = dslXml?.let { anyAttr(it, "attenuation_up", "attn_up").toDoubleOrNull() }
            return BoxConnection(
                publicIp = ip,
                connectionType = mode,
                downloadRate = down,
                uploadRate = up,
                lineStatus = status,
                uptimeSeconds = uptime,
                snrDown = snrDown,
                snrUp = snrUp,
                attenuationDown = attnDown,
                attenuationUp = attnUp
            )
        }

        /** Parse wlan.getInfo (+ getClientList) → BoxWifi. Défensif. Testable. */
        fun parseWifi(infoXml: String, clientsXml: String?): BoxWifi {
            val clients = mutableListOf<WifiClient>()
            if (clientsXml != null) {
                Regex("<client\\b([^>]*)/?>", RegexOption.DOT_MATCHES_ALL).findAll(clientsXml).forEach { m ->
                    val a = m.groupValues[1]
                    val mac = attr(a, "mac")
                    if (mac.isBlank()) return@forEach
                    clients.add(
                        WifiClient(
                            mac = mac,
                            ip = attr(a, "ip"),
                            hostname = attr(a, "hostname").ifBlank { attr(a, "name") },
                            rssi = attr(a, "rssi").ifBlank { attr(a, "signal") }.toIntOrNull()
                        )
                    )
                }
            }
            return BoxWifi(
                ssid = anyAttr(infoXml, "ssid"),
                security = anyAttr(infoXml, "enc", "encryption", "security"),
                channel = anyAttr(infoXml, "channel"),
                band = anyAttr(infoXml, "band"),
                clients = clients
            )
        }

        /** Parse system.getInfo → BoxSystem. Défensif. Fonction pure — testable. */
        fun parseSystem(xml: String): BoxSystem {
            val temp = anyAttr(xml, "temperature", "temp").toDoubleOrNull()
            return BoxSystem(
                firmware = anyAttr(xml, "version", "firmware_version", "fw_version"),
                uptimeSeconds = anyAttr(xml, "uptime").toLongOrNull(),
                temperatureC = temp,
                model = anyAttr(xml, "product", "model", "product_name"),
                serial = anyAttr(xml, "serial", "serial_number")
            )
        }
    }

    private fun httpGet(url: String, timeoutMs: Int = 4_000): String? =
        httpGetStatic(url, timeoutMs)
}

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
    }

    private fun httpGet(url: String, timeoutMs: Int = 4_000): String? =
        httpGetStatic(url, timeoutMs)
}

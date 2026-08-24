package com.fabrice.network.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Client Bbox Bouygues — API REST locale `http://<box>/api/v1/…`.
 *
 * `GET /api/v1/hosts` est accessible en lecture sur le réseau local SANS
 * authentification et renvoie la liste des équipements en JSON :
 *
 *   [ { "hosts": { "list": [ { "hostname":"…", "macaddress":"…",
 *        "ipaddress":"…", "active":1, "link":"Wifi 5" }, … ] } } ]
 *
 * C'est ce qui permet de récupérer les MAC de tout le réseau sur une Bbox.
 */
class BboxBoxClient(private val gateway: String = GATEWAY) : BoxClient {

    companion object {
        /** Passerelle par défaut des Bbox (détection dans BoxManager). */
        const val GATEWAY = "192.168.1.254"

        /**
         * Vrai si l'hôte répond à l'API Bbox (signature JSON `hosts`/`list`).
         * Distingue une Bbox d'une autre box sur 192.168.1.254. Thread IO.
         */
        fun respondsToApi(gateway: String, timeoutMs: Int = 1_500): Boolean {
            val json = httpGet("http://$gateway/api/v1/hosts", timeoutMs) ?: return false
            return json.contains("\"hosts\"") || json.contains("macaddress")
        }

        /**
         * Parse la réponse `/api/v1/hosts` → équipements. Robuste à la forme
         * (tableau `[{"hosts":{"list":[…]}}]` ou objet `{"hosts":{"list":[…]}}`).
         * Fonction pure — testable.
         */
        fun parseDevices(json: String): List<BoxClient.BoxDevice> {
            val hostsObj = extractHostsObject(json) ?: return emptyList()
            val list = hostsObj.optJSONArray("list") ?: return emptyList()
            val out = mutableListOf<BoxClient.BoxDevice>()
            for (i in 0 until list.length()) {
                val e = list.optJSONObject(i) ?: continue
                val mac = e.optString("macaddress", e.optString("macAddress", "")).trim()
                if (mac.isBlank()) continue
                val link = e.optString("link", e.optString("devicetype", "")).lowercase()
                val connectionType = when {
                    link.contains("wifi") || link.contains("wireless") || link.contains("wl") -> "WiFi"
                    link.contains("eth") || link.contains("cable") || link.contains("wired") -> "Ethernet"
                    else -> null
                }
                // active : 1/0 (Int) ou true/false selon firmware.
                val active = when (val a = e.opt("active")) {
                    is Int -> a == 1
                    is Boolean -> a
                    is String -> a == "1" || a.equals("true", true)
                    else -> true
                }
                out.add(
                    BoxClient.BoxDevice(
                        name = e.optString("hostname", e.optString("name", "")),
                        mac = mac,
                        ip = e.optString("ipaddress", e.optString("ip", "")),
                        hostType = e.optString("devicetype", ""),
                        active = active,
                        reachable = active,
                        lastActivity = "",
                        connectionType = connectionType
                    )
                )
            }
            return out
        }

        /** Trouve l'objet `hosts` quelle que soit l'enveloppe (array/objet). */
        private fun extractHostsObject(json: String): JSONObject? {
            val trimmed = json.trimStart()
            val container: JSONObject? = if (trimmed.startsWith("[")) {
                runCatching { JSONArray(json).optJSONObject(0) }.getOrNull()
            } else {
                runCatching { JSONObject(json) }.getOrNull()
            }
            return container?.optJSONObject("hosts")
        }

        private fun httpGet(url: String, timeoutMs: Int): String? {
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
    }

    override val name = "Bbox"
    override val baseUrl = "http://$gateway/api/v1"

    override fun isAvailable(): Boolean = gateway.isNotBlank()

    override suspend fun fetchDevices(): List<BoxClient.BoxDevice>? =
        withContext(Dispatchers.IO) {
            val json = httpGet("$baseUrl/hosts", 5_000) ?: return@withContext null
            val devices = parseDevices(json)
            devices.ifEmpty { if (json.contains("\"hosts\"")) emptyList() else null }
        }

    override suspend fun fetchConnection(): BoxConnection? =
        withContext(Dispatchers.IO) {
            val json = httpGet("$baseUrl/wan/ip", 4_000) ?: return@withContext null
            runCatching {
                val wan = extractFirst(json, "wan") ?: return@runCatching null
                val ipObj = wan.optJSONObject("ip")
                val ip = ipObj?.optString("address", "") ?: ""
                val status = ipObj?.optString("state", "") ?: ""
                val type = wan.optJSONObject("link")?.optString("type", "") ?: ""
                // xDSL (si ligne ADSL/VDSL) : /api/v1/wan/xdsl.
                val xdslJson = httpGet("$baseUrl/wan/xdsl", 4_000)
                var snrDown: Double? = null; var snrUp: Double? = null
                var attnDown: Double? = null; var attnUp: Double? = null
                if (xdslJson != null) runCatching {
                    val xdsl = extractFirst(xdslJson, "wan")?.optJSONObject("xdsl")
                    xdsl?.optJSONObject("down")?.let {
                        snrDown = it.optDouble("snr").takeIf { v -> !v.isNaN() }
                        attnDown = it.optDouble("attenuation").takeIf { v -> !v.isNaN() }
                    }
                    xdsl?.optJSONObject("up")?.let {
                        snrUp = it.optDouble("snr").takeIf { v -> !v.isNaN() }
                        attnUp = it.optDouble("attenuation").takeIf { v -> !v.isNaN() }
                    }
                }
                BoxConnection(
                    publicIp = ip,
                    connectionType = type,
                    lineStatus = status,
                    snrDown = snrDown, snrUp = snrUp,
                    attenuationDown = attnDown, attenuationUp = attnUp
                )
            }.getOrNull()
        }

    override suspend fun fetchSystem(): BoxSystem? =
        withContext(Dispatchers.IO) {
            val json = httpGet("$baseUrl/device", 4_000) ?: return@withContext null
            runCatching {
                val d = extractFirst(json, "device") ?: return@runCatching null
                BoxSystem(
                    firmware = d.optJSONObject("main")?.optString("version", "")
                        ?: d.optString("version", ""),
                    uptimeSeconds = d.optLong("uptime").takeIf { it > 0 },
                    temperatureC = d.optJSONObject("temperature")?.optDouble("current")
                        ?.takeIf { !it.isNaN() },
                    model = d.optString("modelname", d.optString("model", "")),
                    serial = d.optString("serialnumber", "")
                )
            }.getOrNull()
        }

    private fun extractFirst(json: String, key: String): JSONObject? {
        val trimmed = json.trimStart()
        val container = if (trimmed.startsWith("[")) {
            runCatching { JSONArray(json).optJSONObject(0) }.getOrNull()
        } else runCatching { JSONObject(json) }.getOrNull()
        return container?.optJSONObject(key)
    }
}

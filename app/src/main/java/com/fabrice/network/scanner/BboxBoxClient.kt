package com.fabrice.network.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Client Bbox Bouygues — API « sysbus » locale (http://192.168.1.254).
 *
 * ⚠️ L'API sysbus n'est PAS documentée officiellement : les endpoints listés
 * ci-dessous viennent de la communauté (forums LaFibre, scripts domotique).
 * Chaque appel est protégé par runCatching et renvoie null en cas d'échec.
 * Les champs parsés sont défensifs (plusieurs clés possibles) et DOIVENT être
 * confirmés sur une vraie Bbox avant de prétendre que ça marche.
 *
 * Auth : la sysbus peut exiger un token (POST /sysbus/ avec le password de
 * l'interface d'admin). Non géré ici : sans token, `fetchDevices()` renvoie
 * null (l'UI affiche « non disponible »).
 */
class BboxBoxClient : BoxClient {

    companion object {
        /** Passerelle par défaut des Bbox (détection dans BoxManager). */
        const val GATEWAY = "192.168.1.254"

        /**
         * Parse une réponse JSON sysbus (factice ou réelle) → équipements.
         * Format défensif : cherche `result` puis un tableau d'équipements sous
         * plusieurs clés possibles (`devices`, `hosts`, `results`), et lit les
         * champs sous plusieurs noms (camelCase ou PascalCase). ⚠️ À confirmer
         * sur box réelle.
         */
        fun parseDevices(json: String): List<BoxClient.BoxDevice> {
            val root = runCatching { JSONObject(json) }.getOrNull() ?: return emptyList()
            val result = root.optJSONObject("result") ?: root
            val array = listOf("devices", "hosts", "results", "list")
                .firstNotNullOfOrNull { result.optJSONArray(it) }
                ?: return emptyList()
            val out = mutableListOf<BoxClient.BoxDevice>()
            for (i in 0 until array.length()) {
                val e = array.optJSONObject(i) ?: continue
                val mac = e.optString("MACAddress", e.optString("mac", e.optString("MAC", "")))
                val ip = e.optString("IPAddress", e.optString("ip", ""))
                val name = e.optString("Name", e.optString("name", e.optString("HostName", e.optString("hostname", ""))))
                val active = e.optBoolean("Active", e.optBoolean("active", true))
                val rawType = e.optString("ConnectionType", e.optString("connectionType", e.optString("InterfaceType", ""))).lowercase()
                val connectionType = when {
                    rawType.contains("eth") || rawType.contains("wired") || rawType.contains("cable") -> "Ethernet"
                    rawType.contains("wifi") || rawType.contains("wireless") || rawType.contains("wlan") || rawType.contains("802.11") -> "WiFi"
                    else -> null
                }
                out.add(
                    BoxClient.BoxDevice(
                        name = name,
                        mac = mac,
                        ip = ip,
                        hostType = "",
                        active = active,
                        reachable = active,
                        lastActivity = "",
                        connectionType = connectionType
                    )
                )
            }
            return out
        }

        /**
         * Parse une réponse JSON sysbus « connexion » → BoxConnection (défensif).
         * ⚠️ L'endpoint de connexion Bbox n'est pas documenté de façon fiable —
         * ce parseur sert surtout à tester la structure, il n'est pas garanti
         * contre une vraie box.
         */
        fun parseConnection(json: String): BoxConnection? {
            val root = runCatching { JSONObject(json) }.getOrNull() ?: return null
            val r = root.optJSONObject("result") ?: root
            val ip = r.optString("IPAddress", r.optString("ip", r.optString("IPv4Address", "")))
            val type = r.optString("ConnectionType", r.optString("type", ""))
            return BoxConnection(
                publicIp = ip,
                connectionType = type
            )
        }
    }

    override val name = "Bbox"
    override val baseUrl = "http://192.168.1.254"

    /** GET simple sur la sysbus, corps de réponse en String (null si échec). */
    private fun get(path: String, timeoutMs: Int = 5_000): String? {
        return try {
            val conn = URL(baseUrl + path).openConnection() as HttpURLConnection
            conn.requestMethod = "GET"
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.setRequestProperty("User-Agent", "NetworkScanner/1.0")
            if (conn.responseCode in 200..299) {
                val text = conn.inputStream.bufferedReader().use { it.readText() }
                conn.disconnect()
                text
            } else {
                conn.disconnect()
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    override fun isAvailable(): Boolean {
        // La sysbus répond sur /sysbus/ si la Bbox est joignable.
        return get("/sysbus/") != null
    }

    override suspend fun fetchDevices(): List<BoxClient.BoxDevice>? =
        withContext(Dispatchers.IO) {
            // Endpoints communauté à confirmer : Devices:get est le plus souvent
            // cité ; on tente plusieurs formes et on parse de façon défensive.
            val candidates = listOf(
                "/sysbus/Devices:get",
                "/sysbus/Hosts:getHosts",
                "/sysbus/NMC:getLANDevices"
            )
            for (path in candidates) {
                val text = get(path) ?: continue
                val devices = parseDevices(text)
                if (devices.isNotEmpty()) return@withContext devices
            }
            null
        }

    override suspend fun fetchConnection(): BoxConnection? =
        withContext(Dispatchers.IO) {
            // ⚠️ Pas d'endpoint connexion fiable documenté côté Bbox — on tente
            // une forme, et on renvoie null sinon (honnête : « non disponible »).
            val text = get("/sysbus/NeMo:Intf:getMIBs") ?: return@withContext null
            parseConnection(text)
        }
}

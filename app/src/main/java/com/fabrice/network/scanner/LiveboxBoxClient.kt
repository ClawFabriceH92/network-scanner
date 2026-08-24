package com.fabrice.network.scanner

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

/**
 * Client Livebox Orange — protocole TR-064 (SOAP/XML sur http://192.168.1.1/ws).
 *
 * ⚠️ TR-064 est un standard mais l'implémentation Livebox est communautaire :
 * les endpoints listés (service Hosts:1, actions GetHostNumberOfEntries /
 * GetGenericHostEntry) sont ceux documentés par la communauté. Chaque appel
 * est protégé et renvoie null en cas d'échec. Auth : Basic « admin » + le
 * « mot de passe device » (à configurer dans les réglages box de l'app,
 * stocké en SharedPreferences `box_prefs`).
 */
class LiveboxBoxClient(private val context: Context) : BoxClient {

    companion object {
        /** Passerelle par défaut des Livebox (détection dans BoxManager). */
        const val GATEWAY = "192.168.1.1"
        const val PREFS = "box_prefs"
        const val PASSWORD_KEY = "livebox_device_password"
        const val SERVICE_HOSTS = "urn:dslforum-org:service:Hosts:1"

        /** Extrait la valeur d'une balise XML (ex: <NewMACAddress>aa:bb</NewMACAddress>). */
        private fun tagValue(xml: String, name: String): String =
            Regex("<$name[^>]*>(.*?)</$name>", RegexOption.DOT_MATCHES_ALL)
                .find(xml)?.groupValues?.get(1)?.trim().orEmpty()

        /**
         * Parse la réponse `GetGenericHostEntry` (XML factice ou réel) → un
         * équipement. Champs courts : NewMACAddress, NewIPAddress, NewHostName,
         * NewActive, NewInterfaceType. ⚠️ Noms à confirmer sur box réelle.
         */
        fun parseHostEntry(xml: String): BoxClient.BoxDevice? {
            val mac = tagValue(xml, "NewMACAddress")
            val ip = tagValue(xml, "NewIPAddress")
            if (mac.isBlank() && ip.isBlank()) return null
            val active = tagValue(xml, "NewActive").equals("1", true)
            val rawType = tagValue(xml, "NewInterfaceType").lowercase()
            val connectionType = when {
                rawType.contains("eth") || rawType.contains("wired") -> "Ethernet"
                rawType.contains("802.11") || rawType.contains("wifi") || rawType.contains("wireless") -> "WiFi"
                else -> null
            }
            return BoxClient.BoxDevice(
                name = tagValue(xml, "NewHostName"),
                mac = mac,
                ip = ip,
                hostType = "",
                active = active,
                reachable = active,
                lastActivity = "",
                connectionType = connectionType
            )
        }

        /** Parse le compteur d'hôtes (GetHostNumberOfEntries → NewHostNumberOfEntries). */
        fun parseHostCount(xml: String): Int =
            tagValue(xml, "NewHostNumberOfEntries").toIntOrNull() ?: 0

        // --- API « sysbus » (Livebox 4+, JSON) --------------------------------

        /** Extrait le contextID d'une réponse createContext. Testable. */
        fun parseContextId(json: String): String? =
            runCatching {
                JSONObject(json).optJSONObject("data")?.optString("contextID", "")?.ifBlank { null }
            }.getOrNull()

        /**
         * Parse la liste d'appareils sysbus (`Devices:get`) : tableau `status`
         * d'objets { PhysAddress, IPAddress, Name, Active, Layer2Interface }.
         * Fonction pure — testable.
         */
        fun parseSysbusDevices(json: String): List<BoxClient.BoxDevice> {
            val arr = runCatching { JSONObject(json).optJSONArray("status") }.getOrNull()
                ?: return emptyList()
            val out = mutableListOf<BoxClient.BoxDevice>()
            for (i in 0 until arr.length()) {
                val e = arr.optJSONObject(i) ?: continue
                val mac = e.optString("PhysAddress", "").trim()
                if (mac.isBlank()) continue
                val l2 = e.optString("Layer2Interface", "").lowercase()
                val connectionType = when {
                    l2.startsWith("eth") || l2.contains("wired") -> "Ethernet"
                    l2.startsWith("wl") || l2.contains("wifi") || l2.contains("wireless") -> "WiFi"
                    else -> null
                }
                val active = e.optBoolean("Active", false)
                out.add(
                    BoxClient.BoxDevice(
                        name = e.optString("Name", ""),
                        mac = mac,
                        ip = e.optString("IPAddress", ""),
                        hostType = e.optString("DeviceType", ""),
                        active = active,
                        reachable = active,
                        lastActivity = "",
                        connectionType = connectionType
                    )
                )
            }
            return out
        }
    }

    override val name = "Livebox"
    override val baseUrl = "http://192.168.1.1"

    private fun password(): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(PASSWORD_KEY, null)

    /** Le mot de passe device est-il configuré ? (prérequis TR-064) */
    fun isPasswordConfigured(): Boolean = !password().isNullOrBlank()

    /** Stocke le mot de passe device (réglages box de l'app). */
    fun setPassword(value: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(PASSWORD_KEY, value).apply()
    }

    /**
     * Appel SOAP TR-064 sur /ws. Retourne le corps de réponse (String) ou null.
     */
    private fun tr064(action: String, args: String = "", timeoutMs: Int = 6_000): String? {
        val pwd = password() ?: return null
        val body = buildString {
            append("<?xml version=\"1.0\"?>")
            append("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" ")
            append("s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">")
            append("<s:Body><u:$action xmlns:u=\"$SERVICE_HOSTS\">$args</u:$action></s:Body>")
            append("</s:Envelope>")
        }
        return try {
            val conn = URL("$baseUrl/ws").openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "text/xml; charset=utf-8")
            conn.setRequestProperty("SOAPAction", "$SERVICE_HOSTS#$action")
            val cred = Base64.getEncoder().encodeToString("admin:$pwd".toByteArray())
            conn.setRequestProperty("Authorization", "Basic $cred")
            conn.outputStream.use { it.write(body.toByteArray()) }
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

    override fun isAvailable(): Boolean = isPasswordConfigured()

    /** POST sur /ws (API sysbus JSON). Retourne (corps, Set-Cookie) ou null. */
    private fun wsPost(headers: Map<String, String>, body: String, timeoutMs: Int = 6_000): Pair<String, String?>? {
        return try {
            val conn = URL("$baseUrl/ws").openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/x-sah-ws-4-call+json")
            headers.forEach { (k, v) -> if (v.isNotBlank()) conn.setRequestProperty(k, v) }
            conn.outputStream.use { it.write(body.toByteArray()) }
            if (conn.responseCode !in 200..299) { conn.disconnect(); return null }
            val text = conn.inputStream.bufferedReader().use { it.readText() }
            val cookie = conn.headerFields["Set-Cookie"]?.joinToString("; ") { it.substringBefore(";") }
            conn.disconnect()
            text to cookie
        } catch (e: Exception) {
            null
        }
    }

    /** Récupère les appareils via l'API sysbus (Livebox 4+). null si échec. */
    private fun sysbusFetchDevices(pwd: String): List<BoxClient.BoxDevice>? {
        val (ctxJson, cookie) = wsPost(
            headers = mapOf("Authorization" to "X-Sah-Login"),
            body = "{\"service\":\"sah.Device.Information\",\"method\":\"createContext\"," +
                "\"parameters\":{\"applicationName\":\"so_sdkut\",\"username\":\"admin\",\"password\":\"$pwd\"}}"
        ) ?: return null
        val ctx = parseContextId(ctxJson) ?: return null
        val devJson = wsPost(
            headers = mapOf(
                "X-Context" to ctx,
                "Authorization" to "X-Sah $ctx",
                "Cookie" to (cookie ?: "")
            ),
            body = "{\"service\":\"Devices\",\"method\":\"get\"," +
                "\"parameters\":{\"expression\":\"lan and not self\"}}"
        )?.first ?: return null
        return parseSysbusDevices(devJson)
    }

    override suspend fun fetchDevices(): List<BoxClient.BoxDevice>? =
        withContext(Dispatchers.IO) {
            val pwd = password() ?: return@withContext null
            // 1. API sysbus (Livebox 4+, JSON) — méthode fiable actuelle.
            runCatching { sysbusFetchDevices(pwd) }.getOrNull()
                ?.takeIf { it.isNotEmpty() }
                ?.let { return@withContext it }
            // 2. Repli TR-064 (Livebox 2/3 ou si sysbus indisponible).
            val countXml = tr064("GetHostNumberOfEntries") ?: return@withContext null
            val count = parseHostCount(countXml)
            val out = mutableListOf<BoxClient.BoxDevice>()
            // TR-064 (service Hosts:1) : NewIndex est 1-based, de 1 à count inclus.
            // Un for (0 until count) rate le dernier hôte et gaspille une requête
            // sur l'index 0 invalide.
            for (i in 1..count) {
                val entryXml = tr064("GetGenericHostEntry", "<NewIndex>$i</NewIndex>")
                    ?: continue
                parseHostEntry(entryXml)?.let { out.add(it) }
            }
            out
        }

    override suspend fun fetchConnection(): BoxConnection? =
        withContext(Dispatchers.IO) {
            // TR-064 exposerait l'IP publique via le service WANIPConnection
            // (GetExternalIPAddress), distinct du service Hosts — non implémenté
            // ici (best-effort) : null → l'UI affiche « non disponible ».
            null
        }

    override suspend fun fetchSystem(): BoxSystem? =
        withContext(Dispatchers.IO) {
            // Pas d'action TR-064 fiable pour firmware/uptime → null (honnête).
            null
        }
}

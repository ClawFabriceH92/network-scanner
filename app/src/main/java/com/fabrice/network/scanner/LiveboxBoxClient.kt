package com.fabrice.network.scanner

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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

    override suspend fun fetchDevices(): List<BoxClient.BoxDevice>? =
        withContext(Dispatchers.IO) {
            val pwd = password() ?: return@withContext null
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

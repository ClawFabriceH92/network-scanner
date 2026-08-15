package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Client Freebox OS API v9 : baux DHCP + équipements (comme l'interface
 * Freebox). Procédure d'autorisation standard :
 * 1. POST /login/authorize → track_id + app_token (l'utilisateur valide sur
 *    l'écran de la box ou l'interface)
 * 2. GET /login/authorize/<track> → statut granted
 * 3. POST /login/session → session_token (HMAC-SHA1(challenge, app_token))
 * 4. GET /dhcp/leases + /lan/browser/pub avec X-Fbx-App-Auth
 *
 * Le token d'app est persisté en SharedPreferences (clé app_token_freebox).
 */
class FreeboxBoxClient(private val context: Context) : BoxClient {

    override val name = "Freebox"
    override val baseUrl = "http://192.168.0.254/api/v9" // cleartext autorisé par networkSecurityConfig

    private val prefs by lazy {
        context.getSharedPreferences("box_tokens", Context.MODE_PRIVATE)
    }

    private fun appToken(): String? = prefs.getString("app_token_freebox", null)

    private fun http(
        method: String,
        path: String,
        body: JSONObject? = null,
        token: String? = null,
        timeoutMs: Int = 10_000
    ): JSONObject? {
        return try {
            val conn = URL(baseUrl + path).openConnection() as HttpURLConnection
            conn.requestMethod = method
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("User-Agent", "NetworkScanner/1.0")
            token?.let { conn.setRequestProperty("X-Fbx-App-Auth", it) }
            if (body != null) {
                conn.doOutput = true
                conn.outputStream.use { it.write(body.toString().toByteArray()) }
            }
            if (conn.responseCode in 200..299) {
                val text = conn.inputStream.bufferedReader().use { it.readText() }
                conn.disconnect()
                JSONObject(text)
            } else {
                conn.disconnect()
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    override fun isAvailable(): Boolean {
        // La box est joignable si on est sur son réseau local
        val gateway = NetworkInfoProvider.readGateway()
        return gateway.isNotBlank() && (gateway == "192.168.0.254" || appToken() != null)
    }

    /** Lance la procédure d'autorisation (l'utilisateur valide sur la box). */
    fun requestAuthorization(): String? {
        val body = JSONObject().apply {
            put("app_id", "fr.fabrice.networkscanner")
            put("app_name", "NetworkScanner")
            put("app_version", "1.0")
            put("device_name", "Android")
        }
        val d = http("POST", "/login/authorize/", body)?.optJSONObject("result") ?: return null
        val track = d.optInt("track_id", -1)
        val token = d.optString("app_token", "")
        if (track < 0 || token.isEmpty()) return null
        prefs.edit().putString("pending_track", track.toString())
            .putString("pending_token", token).apply()
        return token
    }

    /** Vérifie si l'autorisation a été accordée (à poller). */
    fun authorizationStatus(): String? {
        val track = prefs.getString("pending_track", null) ?: return null
        val d = http("GET", "/login/authorize/$track")?.optJSONObject("result") ?: return null
        val status = d.optString("status", "pending")
        if (status == "granted") {
            val token = prefs.getString("pending_token", null)
            if (token != null) {
                prefs.edit().putString("app_token_freebox", token)
                    .remove("pending_track").remove("pending_token").apply()
            }
        }
        return status
    }

    private fun sessionToken(): String? {
        val token = appToken() ?: return null
        val challenge = http("GET", "/login/")?.optJSONObject("result")?.optString("challenge", "")
            ?: return null
        val pwd = hmacSha1(token, challenge)
        val body = JSONObject().apply {
            put("app_id", "fr.fabrice.networkscanner")
            put("password", pwd)
        }
        return http("POST", "/login/session/", body)?.optJSONObject("result")
            ?.optString("session_token", null)
    }

    override suspend fun fetchDevices(): List<BoxClient.BoxDevice>? =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            val session = sessionToken() ?: return@withContext null
            val d = http("GET", "/lan/browser/pub/", token = session) ?: return@withContext null
            if (!d.optBoolean("success", false)) return@withContext null
            val arr = d.optJSONArray("result") ?: return@withContext null
            val out = mutableListOf<BoxClient.BoxDevice>()
            for (i in 0 until arr.length()) {
                val e = arr.getJSONObject(i)
                val name = e.optString("name", "")
                var mac = ""
                e.optJSONArray("l2ident")?.let { ids ->
                    for (j in 0 until ids.length()) {
                        val id = ids.getJSONObject(j).optString("id", "")
                        if (id.contains(":")) { mac = id; break }
                    }
                }
                var ip = ""
                e.optJSONArray("l3connectivity")?.let { conns ->
                    for (j in 0 until conns.length()) {
                        val ipv4 = conns.getJSONObject(j).optString("ipv4", "")
                        if (ipv4.count { it == '.' } == 3) { ip = ipv4; break }
                    }
                }
                out.add(
                    BoxClient.BoxDevice(
                        name = name,
                        mac = mac,
                        ip = ip,
                        hostType = e.optString("host_type", ""),
                        active = e.optBoolean("active", false),
                        reachable = e.optBoolean("reachable", false),
                        lastActivity = e.optLong("last_activity", 0)
                            .let { if (it > 0) java.text.SimpleDateFormat("dd/MM/yyyy HH:mm", java.util.Locale.FRENCH).format(java.util.Date(it * 1000)) else "" }
                    )
                )
            }
            out
        }

    private fun hmacSha1(key: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key.toByteArray(), "HmacSHA1"))
        return mac.doFinal(data.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}

package com.fabrice.network.scanner

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
 * Le token d'app est persisté en SharedPreferences, keyé par la passerelle
 * (`freebox_app_token_<gateway>`) pour réutiliser le bon token quand on
 * revient sur le même réseau.
 */
class FreeboxBoxClient(private val context: Context) : BoxClient {

    companion object {
        /** Préfixe des clés de token d'app (`freebox_app_token_<gateway>`). */
        const val TOKEN_PREFIX = "freebox_app_token_"
        private const val PREFS = "box_prefs"

        /** Efface tous les tokens d'app (utilisé au changement de passerelle). */
        fun clearTokens(context: Context) {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val editor = prefs.edit()
            prefs.all.keys.filter { it.startsWith(TOKEN_PREFIX) }.forEach { editor.remove(it) }
            editor.remove("pending_track").remove("pending_token")
            editor.apply()
        }
    }

    override val name = "Freebox"

    /** Hôte de la box (passerelle courante ; repli sur l'adresse Freebox usuelle). */
    private fun gatewayHost(): String = NetworkInfoProvider.readGateway().ifBlank { "192.168.0.254" }

    /** Base d'API par défaut si la découverte échoue. */
    private fun defaultBase(): String = "http://${gatewayHost()}/api/v9"

    @Volatile
    private var apiBaseCache: String? = null

    // Affiché à titre indicatif ; les requêtes utilisent la base découverte.
    override val baseUrl: String get() = apiBaseCache ?: defaultBase()

    /**
     * Découvre dynamiquement la base d'API Freebox via `GET /api_version`
     * (renvoie `api_base_url` = « /api/ » et `api_version` = « 13.0 »…). Corrige
     * le problème du numéro de version figé (l'API échouait si la box n'était
     * pas exactement en v9). Résultat mis en cache.
     */
    private fun discoverApiBase(): String {
        apiBaseCache?.let { return it }
        val host = gatewayHost()
        val discovered = runCatching {
            val conn = URL("http://$host/api_version").openConnection() as HttpURLConnection
            conn.connectTimeout = 5_000
            conn.readTimeout = 5_000
            conn.setRequestProperty("User-Agent", "NetworkScanner/1.0")
            if (conn.responseCode !in 200..299) { conn.disconnect(); return@runCatching null }
            val text = conn.inputStream.bufferedReader().use { it.readText() }
            conn.disconnect()
            val o = JSONObject(text)
            val apiBaseUrl = o.optString("api_base_url", "/api/").ifBlank { "/api/" }
            val major = o.optString("api_version", "9.0").substringBefore('.').toIntOrNull() ?: 9
            "http://$host${apiBaseUrl.trimEnd('/')}/v$major"
        }.getOrNull()
        val base = discovered ?: defaultBase()
        apiBaseCache = base
        return base
    }

    private val prefs by lazy {
        context.getSharedPreferences("box_prefs", Context.MODE_PRIVATE)
    }

    /** Clé du token d'app pour la passerelle courante. */
    private fun tokenKey(): String = TOKEN_PREFIX + NetworkInfoProvider.readGateway()

    private fun appToken(): String? = prefs.getString(tokenKey(), null)

    private fun http(
        method: String,
        path: String,
        body: JSONObject? = null,
        token: String? = null,
        timeoutMs: Int = 10_000
    ): JSONObject? {
        return try {
            val conn = URL(discoverApiBase() + path).openConnection() as HttpURLConnection
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
                prefs.edit().putString(tokenKey(), token)
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
                // Parsing défensif (optJSONObject ?: continue) : un firmware ou
                // une réponse inattendue ne doit pas lever de JSONException non
                // rattrapée hors du withContext (cf. BboxBoxClient.parseDevices).
                val e = arr.optJSONObject(i) ?: continue
                val name = e.optString("name", "")
                var mac = ""
                e.optJSONArray("l2ident")?.let { ids ->
                    for (j in 0 until ids.length()) {
                        val id = ids.optJSONObject(j)?.optString("id", "") ?: ""
                        if (id.contains(":")) { mac = id; break }
                    }
                }
                var ip = ""
                e.optJSONArray("l3connectivity")?.let { conns ->
                    for (j in 0 until conns.length()) {
                        val ipv4 = conns.optJSONObject(j)?.optString("ipv4", "") ?: ""
                        if (ipv4.count { it == '.' } == 3) { ip = ipv4; break }
                    }
                }
                // Connexion (WiFi vs Ethernet) : l'endpoint liste ne fournit pas
                // toujours `interfaces` (disponible sur le détail
                // /lan/browser/pub/{id}/). Lecture défensive — null si absent.
                // ⚠️ À confirmer sur box réelle.
                var connectionType: String? = null
                e.optJSONArray("interfaces")?.let { ifs ->
                    for (j in 0 until ifs.length()) {
                        when (ifs.optJSONObject(j)?.optString("type", "")?.lowercase()) {
                            "ethernet", "eth", "wired" -> { connectionType = "Ethernet"; break }
                            "wifi", "wireless", "wlan" -> { connectionType = "WiFi"; break }
                        }
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
                            .let { if (it > 0) java.text.SimpleDateFormat("dd/MM/yyyy HH:mm", java.util.Locale.FRENCH).format(java.util.Date(it * 1000)) else "" },
                        connectionType = connectionType
                    )
                )
            }
            out
        }

    // -------------------------------------------------------------------------
    // Endpoints multi-box (v1.8.0) — chaque appel protégé, null si échec.
    // Endpoints Freebox OS v9 documentés ; ⚠️ à confirmer sur box réelle.
    // -------------------------------------------------------------------------

    override suspend fun fetchLeases(): List<BoxLease>? =
        withContext(Dispatchers.IO) {
            val session = sessionToken() ?: return@withContext null
            val d = http("GET", "/dhcp/leases/", token = session) ?: return@withContext null
            if (!d.optBoolean("success", false)) return@withContext null
            val arr = d.optJSONArray("result") ?: return@withContext null
            val out = mutableListOf<BoxLease>()
            for (i in 0 until arr.length()) {
                val e = arr.getJSONObject(i)
                out.add(
                    BoxLease(
                        ip = e.optString("ip", ""),
                        mac = e.optString("mac", ""),
                        hostname = e.optString("hostname", ""),
                        leaseTime = if (e.has("lease_time")) e.optLong("lease_time") else null,
                        active = true
                    )
                )
            }
            out
        }

    override suspend fun fetchConnection(): BoxConnection? =
        withContext(Dispatchers.IO) {
            val session = sessionToken() ?: return@withContext null
            val d = http("GET", "/connection/", token = session) ?: return@withContext null
            if (!d.optBoolean("success", false)) return@withContext null
            val r = d.optJSONObject("result") ?: return@withContext null
            BoxConnection(
                publicIp = r.optString("ipv4", "").ifBlank { r.optString("ipv6", "") },
                connectionType = r.optString("type", ""),
                downloadRate = if (r.has("rate_down")) r.optLong("rate_down") else null,
                uploadRate = if (r.has("rate_up")) r.optLong("rate_up") else null
            )
        }

    override suspend fun fetchBandwidth(): BoxBandwidth? =
        withContext(Dispatchers.IO) {
            val session = sessionToken() ?: return@withContext null
            val d = http("GET", "/connection/bandwidth/", token = session) ?: return@withContext null
            if (!d.optBoolean("success", false)) return@withContext null
            val r = d.optJSONObject("result") ?: return@withContext null
            // Freebox renvoie rate_down / rate_up en octets/s (B/s).
            BoxBandwidth(
                downloadBps = r.optLong("rate_down", 0),
                uploadBps = r.optLong("rate_up", 0)
            )
        }

    override suspend fun fetchWifi(): BoxWifi? =
        withContext(Dispatchers.IO) {
            val session = sessionToken() ?: return@withContext null
            // Liste des points d'accès WiFi, puis détail du premier AP.
            // ⚠️ Structure exacte (config.ssid / channel / stations) à confirmer
            // sur box réelle — on lit de façon défensive plusieurs clés.
            val list = http("GET", "/wifi/", token = session) ?: return@withContext null
            val aps = list.optJSONArray("result") ?: return@withContext null
            if (aps.length() == 0) return@withContext null
            val first = aps.getJSONObject(0)
            val apId = first.optString("id", "")
            var ssid = ""
            var security = ""
            var channel = ""
            var band = ""
            var clients: List<WifiClient> = emptyList()
            if (apId.isNotBlank()) {
                val ap = http("GET", "/wifi/ap/$apId/", token = session)?.optJSONObject("result")
                if (ap != null) {
                    val cfg = ap.optJSONObject("config")
                    ssid = cfg?.optString("ssid", "") ?: ap.optString("name", "")
                    security = cfg?.optString("security", "")
                        ?: ap.optString("security", "")
                    channel = ap.optString("channel", "")
                    band = ap.optString("band", "")
                }
                // Stations connectées (clients WiFi) — endpoint dédié.
                val stations = http("GET", "/wifi/ap/$apId/stations/", token = session)
                    ?.optJSONArray("result")
                if (stations != null) {
                    val tmp = mutableListOf<WifiClient>()
                    for (i in 0 until stations.length()) {
                        val s = stations.getJSONObject(i)
                        tmp.add(
                            WifiClient(
                                mac = s.optString("mac", ""),
                                ip = s.optString("ip", ""),
                                hostname = s.optString("hostname", ""),
                                rssi = if (s.has("rssi")) s.optInt("rssi") else null,
                                band = s.optString("band", "")
                            )
                        )
                    }
                    clients = tmp
                }
            }
            BoxWifi(ssid = ssid, security = security, channel = channel, band = band, clients = clients)
        }

    override suspend fun fetchSystem(): BoxSystem? =
        withContext(Dispatchers.IO) {
            val session = sessionToken() ?: return@withContext null
            val d = http("GET", "/sys/", token = session) ?: return@withContext null
            if (!d.optBoolean("success", false)) return@withContext null
            val r = d.optJSONObject("result") ?: return@withContext null
            // Freebox expose firmware_version et uptime (chaîne « 3 jours 5 h ») ;
            // pas d'uptime en secondes ni de température unique → null.
            BoxSystem(
                firmware = r.optString("firmware_version", "")
            )
        }

    private fun hmacSha1(key: String, data: String): String {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key.toByteArray(), "HmacSHA1"))
        return mac.doFinal(data.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    /**
     * Coupe/restaure l'accès d'un périphérique (blocage légal via l'API box,
     * équivalent du « bloquer » de Freebox Companion — PAS de deauth).
     *
     * ⚠️ Endpoint à confirmer sur box réelle : on cherche l'id de l'équipement
     * dans `/lan/browser/pub/` (par MAC dans l2ident) puis `PUT /lan/browser/pub/<id>`
     * avec `{"blocked": true|false}`. Si la box n'expose pas ce champ, la méthode
     * retourne false (à tester physiquement). Le blocage n'est pas toujours
     * persistant (reboot de la box = retour à la normale).
     */
    override fun blockDevice(mac: String): Boolean = setBlocked(mac, true)

    override fun unblockDevice(mac: String): Boolean = setBlocked(mac, false)

    override suspend fun reboot(): Boolean = withContext(Dispatchers.IO) {
        val session = sessionToken() ?: return@withContext false
        val r = http("POST", "/system/reboot/", token = session)
        r?.optBoolean("success", false) == true
    }

    private fun setBlocked(mac: String, blocked: Boolean): Boolean {
        return try {
            val normalized = mac.replace("-", ":").lowercase()
            val session = sessionToken() ?: return false
            val d = http("GET", "/lan/browser/pub/", token = session) ?: return false
            val arr = d.optJSONArray("result") ?: return false
            var id = ""
            for (i in 0 until arr.length()) {
                val e = arr.getJSONObject(i)
                var m = ""
                e.optJSONArray("l2ident")?.let { ids ->
                    for (j in 0 until ids.length()) {
                        val v = ids.getJSONObject(j).optString("id", "")
                        if (v.contains(":")) { m = v; break }
                    }
                }
                if (m.lowercase() == normalized) {
                    id = e.optString("id", "")
                    break
                }
            }
            if (id.isBlank()) return false
            val body = JSONObject().put("blocked", blocked)
            val r = http("PUT", "/lan/browser/pub/$id", body, token = session)
            r?.optBoolean("success", false) == true
        } catch (e: Exception) {
            false
        }
    }
}

package com.fabrice.network.scanner

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

/**
 * Test des mots de passe par défaut sur les services web (v1.7.0, feature 7).
 *
 * Pour chaque appareil avec un service web (80/443/8080/8443), on tente un
 * nombre LIMITÉ de combos par défaut (Basic Auth + formulaires simples) et on
 * alerte si un combo fonctionne.
 *
 * ⚠️ Limites (volontaires) :
 *  - Basic Auth + formulaires simples seulement ; CSRF/JS = « non testé ».
 *  - Jamais plus de 8 combos par appareil (légal, non intrusif).
 *  - Anti-lockout : on s'arrête après 2 réponses 403.
 *  - Ne JAMAIS tester hors du subnet détecté (le scan ne le fait pas).
 */
object DefaultCredsChecker {

    /** Nombre max de combos testés par appareil. */
    const val MAX_COMBOS = 8

    /** Codes HTTP considérés comme un succès d'authentification. */
    private val SUCCESS_CODES = setOf(200, 204, 302, 301)

    /** Ports web testables. */
    private val WEB_PORTS = listOf(80, 443, 8080, 8443)

    /** Clés fabricant reconnues (normalisées : sans tiret/underscore). */
    private val VENDOR_KEYS = listOf(
        "hikvision", "dahua", "mikrotik", "ubiquiti", "synology", "tplink",
        "netgear", "dlink", "cisco", "foscam", "axis"
    )

    @Volatile private var generic: List<Pair<String, String>> = emptyList()
    @Volatile private var vendorCreds: Map<String, List<Pair<String, String>>> = emptyMap()

    /**
     * Parse l'asset `default_creds.json` :
     * `{"generic":[[u,p],...], "vendors":{"hikvision":[[u,p],...]}}`.
     * Retourne le nombre total de combos chargés.
     */
    fun load(json: String): Int {
        val obj = runCatching { JSONObject(json) }.getOrNull() ?: return 0
        val g = mutableListOf<Pair<String, String>>()
        obj.optJSONArray("generic")?.let { arr -> for (i in 0 until arr.length()) {
            val pair = arr.optJSONArray(i) ?: continue
            if (pair.length() >= 2) g.add(pair.optString(0, "") to pair.optString(1, ""))
        } }
        val v = mutableMapOf<String, List<Pair<String, String>>>()
        obj.optJSONObject("vendors")?.let { vendors ->
            val keys = vendors.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                val list = mutableListOf<Pair<String, String>>()
                vendors.optJSONArray(k)?.let { arr -> for (i in 0 until arr.length()) {
                    val pair = arr.optJSONArray(i) ?: continue
                    if (pair.length() >= 2) list.add(pair.optString(0, "") to pair.optString(1, ""))
                } }
                v[normalize(k)] = list
            }
        }
        generic = g
        vendorCreds = v
        return g.size + v.values.sumOf { it.size }
    }

    /** Clé fabricant déduite du device (vendor/hostname/produit/banner). */
    fun vendorKey(device: Device): String? {
        val hay = normalize("${device.vendor} ${device.hostname} ${device.product} ${device.banner}")
        return VENDOR_KEYS.firstOrNull { hay.contains(it) }
    }

    /** Normalise une chaîne pour la comparaison de fabricant (minuscule, sans -/_). */
    private fun normalize(s: String): String =
        s.lowercase().replace("-", "").replace("_", "")

    /** Combos à tester pour un device : fabricant d'abord puis génériques, max 8. */
    fun combosFor(device: Device): List<Pair<String, String>> {
        val list = mutableListOf<Pair<String, String>>()
        vendorKey(device)?.let { vendorCreds[it]?.forEach { p -> list.add(p) } }
        generic.forEach { p -> list.add(p) }
        return list.take(MAX_COMBOS)
    }

    /** Port web à tester pour un device, ou null si aucun. */
    fun webPort(device: Device): Int? = WEB_PORTS.firstOrNull { it in device.ports }

    /**
     * Teste un combo Basic Auth sur `http://ip:port/`. True si le code est un
     * succès (200/204/302), false sinon (401/403/erreur réseau silencieuse).
     */
    fun testBasicAuth(ip: String, port: Int, user: String, pass: String, timeoutMs: Int = 1_500): Boolean {
        val code = basicAuthStatus(ip, port, user, pass, timeoutMs) ?: return false
        return code in SUCCESS_CODES
    }

    /** Comme [testBasicAuth] mais retourne le code HTTP (null si erreur réseau). */
    fun basicAuthStatus(ip: String, port: Int, user: String, pass: String, timeoutMs: Int = 1_500): Int? {
        var conn: HttpURLConnection? = null
        return try {
            // Schéma selon le port : 443/8443 → https (sinon la requête http vers
            // un port TLS échoue et l'appareil n'est jamais réellement testé).
            val scheme = if (port == 443 || port == 8443) "https" else "http"
            conn = URL("$scheme://$ip:$port/").openConnection() as HttpURLConnection
            if (conn is javax.net.ssl.HttpsURLConnection) {
                // Équipements LAN (caméras/routeurs) : certificats auto-signés
                // fréquents → validation permissive, limitée à ce scan LAN de nos
                // propres équipements (jamais un endpoint Internet).
                (conn as javax.net.ssl.HttpsURLConnection).sslSocketFactory = lanTrustAllFactory()
                (conn as javax.net.ssl.HttpsURLConnection).hostnameVerifier =
                    javax.net.ssl.HostnameVerifier { _, _ -> true }
            }
            conn.instanceFollowRedirects = false
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.requestMethod = "GET"
            conn.setRequestProperty("User-Agent", "NetworkScanner/1.0")
            val cred = "$user:$pass"
            val encoded = Base64.getEncoder().encodeToString(cred.toByteArray(Charsets.UTF_8))
            conn.setRequestProperty("Authorization", "Basic $encoded")
            conn.responseCode
        } catch (e: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }

    /**
     * SSLSocketFactory permissive réservée au scan des équipements du réseau
     * LOCAL de l'utilisateur (certificats auto-signés courants sur caméras/box).
     * N'est jamais utilisée pour des connexions Internet.
     */
    @Volatile private var lanFactory: javax.net.ssl.SSLSocketFactory? = null

    private fun lanTrustAllFactory(): javax.net.ssl.SSLSocketFactory {
        lanFactory?.let { return it }
        val trustAll = arrayOf<javax.net.ssl.TrustManager>(
            object : javax.net.ssl.X509TrustManager {
                override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
            }
        )
        val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, java.security.SecureRandom())
        return ctx.socketFactory.also { lanFactory = it }
    }

    /**
     * Itère les combos (max 8) jusqu'à trouver un accès. Le fetcher retourne le
     * code HTTP (ou null en cas d'erreur réseau) — injectable pour les tests.
     *
     * Test STRICT (v1.9.3) pour éliminer les faux positifs :
     *  1. Le serveur doit RÉELLEMENT demander une authentification : une requête
     *     SANS credentials doit répondre 401. Sinon (200/302/…), il n'y a pas de
     *     Basic Auth → AUCUN test → aucun badge (ex: imprimantes qui retournent
     *     200 à tout le monde).
     *  2. Succès = code HTTP 200/204/301/302 DIFFÉRENT du baseline (401) —
     *     c'est-à-dire que les credentials ont réellement changé la réponse.
     * Anti-lockout : stop après 2 réponses 403. Retourne "user/pass" si trouvé,
     * null sinon.
     */
    fun checkDevice(
        device: Device,
        fetcher: (ip: String, port: Int, user: String, pass: String) -> Int?
    ): String? {
        val port = webPort(device) ?: return null

        // 1. Baseline : le serveur exige-t-il une auth ? (401 sans credentials)
        val baseline = fetcher(device.ip, port, "", "")
        if (baseline != 401) return null

        // 2. Test des combos — succès seulement si code ≠ baseline et ≠ 401.
        var forbidden = 0
        for ((u, p) in combosFor(device)) {
            when (fetcher(device.ip, port, u, p)) {
                403 -> { forbidden++; if (forbidden >= 2) return null }
                in SUCCESS_CODES -> return "$u/$p"
                else -> { /* 401 / null / autre : échec d'authentification */ }
            }
        }
        return null
    }
}

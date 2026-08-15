package com.fabrice.network.scanner

import android.content.SharedPreferences
import java.net.HttpURLConnection
import java.net.URL

/**
 * Repli en ligne pour la résolution du fabricant à partir d'une adresse MAC.
 *
 * Utilisé uniquement quand la base OUI embarquée ne connaît pas le préfixe.
 * L'API gratuite https://api.macvendors.com/<mac> renvoie le nom du fabricant
 * en texte brut (HTTP 200), ou HTTP 404 si le préfixe est inconnu. Rate limit
 * d'environ 1 req/s : on met donc en cache par préfixe OUI (6 premiers
 * caractères) — en mémoire pour la durée d'un scan, et dans les
 * SharedPreferences pour les scans suivants. Une valeur vide (« ») signifie
 * « inconnu » et n'est jamais re-interrogée.
 */
object VendorLookup {

    /** Préfixe des clés de cache dans les SharedPreferences. */
    const val CACHE_KEY_PREFIX = "vendor_cache_"

    /** Timeout réseau (connexion + lecture) en millisecondes. */
    private const val TIMEOUT_MS = 4_000

    private val USER_AGENT = "NetworkScanner/${BuildConfig.VERSION_NAME}"

    /**
     * Résout le fabricant d'une MAC.
     *
     * Ordre de résolution : cache mémoire → SharedPreferences → API en ligne.
     * Un résultat vide est mis en cache (« ») pour ne pas re-tenter le même
     * préfixe. Retourne null si la MAC est invalide ou inconnue de l'API.
     *
     * @param mac  adresse MAC (séparateurs :, - ou brut).
     * @param cache cache en mémoire (Map préfixe → fabricant, « » = inconnu).
     * @param prefs SharedPreferences facultatif (cache persistant).
     * @param fetcher fonction de requête HTTP, injectable pour les tests.
     */
    fun lookup(
        mac: String,
        cache: MutableMap<String, String>,
        prefs: SharedPreferences? = null,
        fetcher: (String) -> String? = ::httpFetch
    ): String? {
        val prefix = NetworkScanner.macPrefix(mac) ?: return null

        // 1. Cache en mémoire (présence = déjà résolu, même si inconnu).
        if (cache.containsKey(prefix)) {
            return cache[prefix]?.takeIf { it.isNotBlank() }
        }

        // 2. Cache persistant (SharedPreferences), chargé dans le cache mémoire.
        val key = CACHE_KEY_PREFIX + prefix
        if (prefs != null && prefs.contains(key)) {
            val cached = prefs.getString(key, null) ?: ""
            cache[prefix] = cached
            return cached.takeIf { it.isNotBlank() }
        }

        // 3. Requête en ligne (échec silencieux → null, jamais d'exception).
        val result = try {
            fetcher(mac)
        } catch (e: Exception) {
            null
        }
        val value = result ?: ""
        cache[prefix] = value
        prefs?.edit()?.putString(key, value)?.apply()
        return result
    }

    /** Parse la réponse HTTP de l'API macvendors.com. */
    fun parseMacvendorsResponse(code: Int, body: String): String? {
        if (code != 200) return null
        val trimmed = body.trim()
        return trimmed.takeIf { it.isNotEmpty() }
    }

    /** Requête HTTP brute vers l'API (texte brut en 200, 404 sinon). */
    private fun httpFetch(mac: String): String? {
        return try {
            val conn = URL("https://api.macvendors.com/$mac").openConnection() as HttpURLConnection
            try {
                conn.connectTimeout = TIMEOUT_MS
                conn.readTimeout = TIMEOUT_MS
                conn.setRequestProperty("User-Agent", USER_AGENT)
                val code = conn.responseCode
                val body = if (code == 200) {
                    conn.inputStream.bufferedReader().use { it.readText() }
                } else {
                    ""
                }
                parseMacvendorsResponse(code, body)
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            null
        }
    }
}

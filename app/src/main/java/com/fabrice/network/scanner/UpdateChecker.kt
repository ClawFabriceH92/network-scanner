package com.fabrice.network.scanner

import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL

/**
 * Vérifie la présence d'une nouvelle version de l'app sur GitHub Releases
 * (auto-update, pattern Vigie).
 *
 * L'API GitHub est interrogée sans token (60 req/h/IP, largement suffisant) ;
 * on retient la release la PLUS HAUTE ayant un asset `.apk`, en ignorant les
 * drafts, et on compare sa version à [BuildConfig.VERSION_NAME] segment par
 * segment (comparaison numérique, pas lexicale : 0.10.0 > 0.9.0).
 */
object UpdateChecker {

    const val RELEASES_URL =
        "https://api.github.com/repos/ClawFabriceH92/network-scanner/releases?per_page=5"

    /** Version disponible + URL de téléchargement de l'APK. */
    data class UpdateInfo(val version: String, val url: String)

    /**
     * Dernière erreur réseau/API rencontrée par [check] (null si aucune).
     * Permet à l'UI de distinguer « à jour » (check ok, pas de MAJ) d'une
     * vraie erreur (⚠️ API indisponible), jamais un faux « ✅ À jour ».
     */
    @Volatile
    var lastError: String? = null
        private set

    /** Vérifie les releases GitHub et retourne la MAJ dispo (ou null). */
    fun check(): UpdateInfo? {
        lastError = null
        val text = try {
            val conn = URL(RELEASES_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = 10_000
            conn.readTimeout = 20_000
            conn.setRequestProperty("User-Agent", "NetworkScanner/${BuildConfig.VERSION_NAME}")
            if (conn.responseCode != 200) {
                lastError = "HTTP ${conn.responseCode}"
                conn.disconnect()
                return null
            }
            val t = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            conn.disconnect()
            t
        } catch (e: Exception) {
            lastError = e.message ?: e.javaClass.simpleName
            return null
        }
        return parseReleases(text, BuildConfig.VERSION_NAME)
    }

    /**
     * Parse un tableau JSON de releases GitHub et retourne la version la plus
     * haute (avec asset `.apk`, non-draft) supérieure à [currentVersion].
     * Retourne null si le JSON est invalide ou si aucune MAJ n'est trouvée.
     * Fonction pure — testable en JVM.
     */
    fun parseReleases(json: String, currentVersion: String): UpdateInfo? {
        return try {
            val arr = JSONArray(json)
            var best: UpdateInfo? = null
            for (i in 0 until arr.length()) {
                val rel = arr.optJSONObject(i) ?: continue
                if (rel.optBoolean("draft", false)) continue
                val tag = rel.optString("tag_name", "").removePrefix("v").trim()
                if (tag.isBlank()) continue
                val assets = rel.optJSONArray("assets") ?: continue
                var apkUrl: String? = null
                for (j in 0 until assets.length()) {
                    val a = assets.optJSONObject(j) ?: continue
                    if (a.optString("name", "").endsWith(".apk")) {
                        apkUrl = a.optString("browser_download_url", "")
                        if (apkUrl.isNotBlank()) break
                    }
                }
                if (apkUrl.isNullOrBlank()) continue
                if (shouldUpdate(currentVersion, tag)) {
                    if (best == null || shouldUpdate(best.version, tag)) {
                        best = UpdateInfo(tag, apkUrl)
                    }
                }
            }
            best
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Comparaison de versions segment par segment (Int), PAS lexicale :
     * `0.10.0 > 0.9.0`, `1.6.0 < 1.6.1`. Les segments non numériques valent 0.
     */
    fun shouldUpdate(current: String, remote: String): Boolean {
        val a = current.split('.')
        val b = remote.split('.')
        val n = maxOf(a.size, b.size)
        for (i in 0 until n) {
            val x = a.getOrElse(i) { "0" }.toIntOrNull() ?: 0
            val y = b.getOrElse(i) { "0" }.toIntOrNull() ?: 0
            if (x != y) return y > x
        }
        return false
    }
}

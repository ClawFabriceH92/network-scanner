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

    /**
     * Lien DIRECT et STABLE vers l'APK de la dernière version : la release
     * rolling `latest` contient une copie de l'APK sous un nom fixe
     * (`network-scanner-latest.apk`). Permet un bouton « Télécharger » qui marche
     * toujours, sans dépendre de la comparaison de versions.
     */
    const val LATEST_APK_URL =
        "https://github.com/ClawFabriceH92/network-scanner/releases/download/latest/network-scanner-latest.apk"

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
                val assets = rel.optJSONArray("assets") ?: continue
                var apkUrl: String? = null
                var apkName = ""
                for (j in 0 until assets.length()) {
                    val a = assets.optJSONObject(j) ?: continue
                    val name = a.optString("name", "")
                    if (name.endsWith(".apk")) {
                        apkUrl = a.optString("browser_download_url", "")
                        apkName = name
                        if (apkUrl.isNotBlank()) break
                    }
                }
                if (apkUrl.isNullOrBlank()) continue
                // Version : depuis le tag s'il est numérique (releases « vX.Y.Z »),
                // sinon depuis le NOM de l'APK (release rolling « latest » dont le
                // tag n'est pas un numéro : network-scanner-vX.Y.Z.apk). Sans
                // version exploitable, la release est ignorée.
                val tag = rel.optString("tag_name", "").removePrefix("v").trim()
                val version = versionFrom(tag) ?: versionFrom(apkName) ?: continue
                if (shouldUpdate(currentVersion, version)) {
                    if (best == null || shouldUpdate(best.version, version)) {
                        best = UpdateInfo(version, apkUrl)
                    }
                }
            }
            best
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Extrait un numéro de version (« 1.9.5 ») d'une chaîne — tag (« v1.9.5 »,
     * « 1.9.5 ») ou nom d'APK (« network-scanner-v1.9.5.apk ») — ou null si
     * aucune séquence de type X.Y(.Z…) n'est trouvée (ex. tag « latest »).
     */
    fun versionFrom(s: String): String? =
        Regex("\\d+(?:\\.\\d+)+").find(s)?.value

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

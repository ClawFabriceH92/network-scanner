package com.fabrice.network.scanner

import java.net.HttpURLConnection
import java.net.URL

/**
 * Analyse « réseau public » (portail captif) — v1.7.0, feature 5bis.
 *
 * Quand l'app est connectée à un Wi-Fi public (hôtel, SNCF, gare, café), on
 * détecte un éventuel portail captif et on alerte sur les risques du réseau.
 */
object PublicWifiAnalyzer {

    enum class CaptiveStatus { NONE, CAPTIVE, UNKNOWN }

    /** Résultat de la détection de portail captif. */
    data class CaptivePortalStatus(
        val status: CaptiveStatus,
        val portalUrl: String? = null,
        val portalHttps: Boolean = false,
        val portalHost: String = ""
    )

    /** Réponse brute injectable (pour les tests JUnit). */
    data class PortalFetch(
        val code: Int,
        val finalUrl: String? = null,
        val body: String? = null
    )

    /** Risques + recommandations pour un réseau public. */
    data class PublicWifiVuln(
        val score: Int,
        val label: String,
        val risks: List<String>,
        val recommendations: List<String>
    )

    private const val CHECK_URL = "http://connectivitycheck.gstatic.com/generate_204"

    /**
     * Détecte un portail captif sur le réseau CONNECTÉ via
     * `http://connectivitycheck.gstatic.com/generate_204` :
     *  - HTTP 204 → pas de portail (connexion normale)
     *  - Redirection 3xx / 200 avec page de login → portail captif
     *  - Erreur réseau → UNKNOWN
     */
    fun detectCaptivePortal(timeoutMs: Int = 4_000): CaptivePortalStatus =
        detectCaptivePortal { httpFetch(timeoutMs) }

    /** Variante testable : le fetch est injecté. */
    fun detectCaptivePortal(fetcher: () -> PortalFetch?): CaptivePortalStatus {
        val f = fetcher() ?: return CaptivePortalStatus(CaptiveStatus.UNKNOWN)
        if (f.code == 204) return CaptivePortalStatus(CaptiveStatus.NONE)
        val finalUrl = f.finalUrl
        val redirected = finalUrl != null && finalUrl.isNotBlank() &&
            !finalUrl.contains("gstatic.com/generate_204")
        if (redirected) {
            return captive(finalUrl)
        }
        if (f.code == 200 && isLoginPage(f.body)) {
            return captive(finalUrl)
        }
        return CaptivePortalStatus(CaptiveStatus.NONE)
    }

    private fun captive(url: String?): CaptivePortalStatus {
        val u = url ?: ""
        val https = u.startsWith("https://")
        val host = runCatching { URL(u).host }.getOrDefault("")
        return CaptivePortalStatus(CaptiveStatus.CAPTIVE, u, https, host)
    }

    private fun isLoginPage(body: String?): Boolean {
        if (body.isNullOrBlank()) return false
        val b = body.lowercase()
        return listOf(
            "type=\"password\"", "type=password", "type='password'",
            "name=\"password\"", "name=password", "name='password'",
            "password", "login", "sign in", "signin", "captive", "authenticate",
            "authorize", "connexion", "identifiant", "mot de passe"
        ).any { b.contains(it) }
    }

    /**
     * Analyse un réseau public (SSID + sécurité + portail captif) → score,
     * label, risques et recommandations. Logique pure.
     */
    fun analyzePublicNetwork(
        ssid: String?,
        security: WifiScanner.WifiSecurity,
        captive: CaptivePortalStatus
    ): PublicWifiVuln {
        var score = 0
        val risks = mutableListOf<String>()
        val isOpen = security == WifiScanner.WifiSecurity.OPEN
        val hasCaptive = captive.status == CaptiveStatus.CAPTIVE

        if (isOpen && hasCaptive) {
            score = maxOf(score, 75)
            risks.add("Trafic en clair sur le portail")
            risks.add("Login/CB visibles par tous si portail HTTP")
            risks.add("Pas d'isolation client/client (probable)")
            risks.add("Evil twin possible — vérifie le nom exact du réseau")
        } else if (isOpen) {
            score = maxOf(score, 60)
            risks.add("Réseau ouvert : trafic en clair")
        }
        if (hasCaptive) {
            if (!captive.portalHttps) {
                risks.add("Le portail est en HTTP : ton identifiant/mot de passe circule en clair")
                score = maxOf(score, 70)
            } else {
                risks.add("Portail HTTPS — vérifie le certificat")
                score = maxOf(score, 50)
            }
        }
        if (WifiVulnAnalyzer.isPublicSsid(ssid.orEmpty())) {
            risks.add("Réseau public partagé")
            score = maxOf(score, 40)
        }
        val recommendations = listOf(
            "Utilise un VPN (WireGuard/Proton)",
            "Ne saisis aucun identifiant sans VPN",
            "Vérifie le nom exact du réseau (evil twin)"
        )
        return PublicWifiVuln(
            score = score.coerceAtMost(100),
            label = WifiVulnAnalyzer.labelForScore(score),
            risks = risks.distinct(),
            recommendations = recommendations
        )
    }

    /**
     * Soupçon d'evil twin : 2+ réseaux visibles avec le MÊME SSID (et des BSSID
     * différents) → true.
     */
    fun evilTwinHint(scanResults: List<WifiScanner.WifiNetwork>): Boolean {
        return scanResults
            .filter { it.ssid.isNotBlank() && it.bssid.isNotBlank() }
            .groupBy { it.ssid }
            .values
            .any { list -> list.map { it.bssid.lowercase() }.toSet().size >= 2 }
    }

    private fun httpFetch(timeoutMs: Int): PortalFetch? {
        return try {
            val conn = URL(CHECK_URL).openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = true
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.setRequestProperty("User-Agent", "NetworkScanner/1.0")
            val code = conn.responseCode
            val finalUrl = conn.url?.toString()
            val body = if (code == 200) {
                runCatching { conn.inputStream.bufferedReader().use { it.readText() } }
                    .getOrDefault("")
            } else ""
            conn.disconnect()
            PortalFetch(code, finalUrl, body)
        } catch (e: Exception) {
            null
        }
    }
}

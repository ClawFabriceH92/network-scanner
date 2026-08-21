package com.fabrice.network.scanner

/**
 * Analyse de vulnérabilité Wi-Fi (v1.7.0) — cœur de la feature, logique pure.
 *
 * Score 0..100 basé sur la sécurité ANNONCÉE (capabilities) + heuristiques SSID
 * (réseau public/portail captif, SSID par défaut). Ce n'est PAS un pentest
 * (capture de handshake / WPS PIN = root + aircrack-ng, hors de portée de l'app).
 */
object WifiVulnAnalyzer {

    data class WifiVuln(val score: Int, val label: String, val risks: List<String>)

    /** Analyse la sécurité d'un réseau → score + label + risques. */
    fun analyze(sec: WifiScanner.WifiSecurity, ssid: String): WifiVuln {
        var score: Int
        var label: String
        val risks = mutableListOf<String>()
        when (sec) {
            WifiScanner.WifiSecurity.OPEN -> {
                score = 100; label = "Critique"
                risks.add("Réseau ouvert : trafic en clair")
            }
            WifiScanner.WifiSecurity.WEP -> {
                score = 95; label = "Critique"
                risks.add("WEP cassé depuis 2001 (outils grand public)")
            }
            WifiScanner.WifiSecurity.WPA_TKIP -> {
                score = 70; label = "Élevé"
                risks.add("WPA2-TKIP : KRACK + brute force offline")
            }
            WifiScanner.WifiSecurity.WPA2_CCMP -> {
                score = 45; label = "Modéré"
                risks.add("KRACK partiel (patches 2017), attaque PMKID possible")
            }
            WifiScanner.WifiSecurity.WPA2_WPA3_MIXED -> {
                score = 25; label = "Faible"
                risks.add("Transition : les clients peuvent se rétrograder en WPA2")
            }
            WifiScanner.WifiSecurity.WPA3_SAE -> {
                score = 10; label = "Faible"
                risks.add("Dragonblood : attaques marginales, patchées")
            }
            WifiScanner.WifiSecurity.WPA2_ENTERPRISE -> {
                score = 30; label = "Modéré"
                risks.add("Dépend du mode EAP")
            }
            WifiScanner.WifiSecurity.WPA3_ENTERPRISE -> {
                score = 10; label = "Faible"
                risks.add("Dragonblood : attaques marginales, patchées")
            }
            WifiScanner.WifiSecurity.OWE -> {
                score = 15; label = "Faible"
                risks.add("Enhanced Open")
            }
            WifiScanner.WifiSecurity.UNKNOWN -> {
                score = 50; label = "Modéré"
                risks.add("Chiffrement non identifié")
            }
        }
        // Heuristique SSID : réseau public / portail captif (FON, hotspot…)
        if (isPublicSsid(ssid)) {
            if (score < 60) score = 60
            risks.add("Réseau public/portail captif")
        }
        // Heuristique SSID : nom par défaut du constructeur
        if (isDefaultSsid(ssid)) {
            if (score < 20) score = 20
            risks.add("SSID par défaut")
        }
        // Libellé dérivé d'UNE seule source (le score final) → texte et couleur
        // du badge cohérents avec labelForScore et la rampe UI (plus de « 50 /
        // Modéré » sur fond « Élevé »).
        val finalScore = score.coerceAtMost(100)
        return WifiVuln(finalScore, labelForScore(finalScore), risks.distinct())
    }

    /** SSID typique d'un réseau public / partagé / portail captif. */
    fun isPublicSsid(ssid: String): Boolean {
        val s = ssid.uppercase()
        return listOf(
            "FON", "FREE_WIFI", "FREE WIFI", "SFR WIFI", "SNCF", "TRAIN", "GARE",
            "HOTEL", "CAFE", "AIRPORT", "GUEST", "WIFI_GRATUIT", "CAFÉ"
        ).any { s.contains(it) } || s.startsWith("FREEBOX-") || s.startsWith("BBOX-")
    }

    /** SSID par défaut d'un constructeur (jamais renommé). */
    fun isDefaultSsid(ssid: String): Boolean {
        val s = ssid.uppercase().replace(" ", "").replace("-", "")
        return s.startsWith("DEFAULT") || s.startsWith("TPLINK") ||
            s.startsWith("NETGEAR") || s.startsWith("DLINK") || s.startsWith("LIVEBOX")
    }

    /** Libellé de risque à partir d'un score (cohérent avec la rampe UI). */
    fun labelForScore(score: Int): String = when {
        score < 25 -> "Faible"
        score < 50 -> "Modéré"
        score < 75 -> "Élevé"
        else -> "Critique"
    }
}

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

    /**
     * Analyse DÉTAILLÉE pour décider AVANT de se connecter (utile pour les Wi-Fi
     * captifs/publics). Combine le chiffrement annoncé, le WPS, l'evil-twin
     * (plusieurs bornes au même nom) et des risques/recommandations précis.
     * Pure et testable ; ne se connecte à rien.
     */
    data class DetailedWifiVuln(
        val score: Int,
        val label: String,
        val risks: List<String>,
        val recommendations: List<String>,
        val evilTwin: Boolean,
        val wps: Boolean,
        val publicOrOpen: Boolean
    )

    fun analyzeDetailed(
        net: WifiScanner.WifiNetwork,
        all: List<WifiScanner.WifiNetwork>
    ): DetailedWifiVuln {
        val base = analyze(net.security, net.ssid)
        val risks = base.risks.toMutableList()
        val recs = mutableListOf<String>()
        val isOpen = net.security == WifiScanner.WifiSecurity.OPEN
        val isPublic = isPublicSsid(net.ssid)
        val wps = net.capabilities.uppercase().contains("WPS")
        val evilTwin = all.asSequence()
            .filter { it.ssid.isNotBlank() && it.ssid == net.ssid }
            .map { it.bssid.lowercase() }
            .filter { it.isNotBlank() }
            .toSet().size >= 2

        if (evilTwin) risks.add(
            "⚠️ Plusieurs bornes annoncent ce nom (BSSID différents) : evil twin possible — " +
                "un faux point d'accès peut usurper ce réseau et intercepter tout ton trafic."
        )
        if (wps) risks.add(
            "WPS actif : le PIN à 8 chiffres est vulnérable (pixie-dust / brute-force hors-ligne) → " +
                "la clé Wi-Fi peut être retrouvée."
        )
        if (isOpen) {
            risks.add("Trafic NON chiffré : à portée, quiconque peut lire ce que tu envoies en HTTP, tes requêtes DNS, tes e-mails non sécurisés.")
            risks.add("Vol de session possible (cookies), et attaques MITM / SSL-strip sur les sites mal configurés.")
            risks.add("Le portail peut détourner le DNS : redirections et pages d'hameçonnage possibles.")
            risks.add("Pas d'isolation client-à-client garantie : les autres appareils connectés peuvent te scanner.")
        }

        if (isOpen || isPublic) {
            recs.add("Active un VPN AVANT de te connecter (WireGuard / Proton / Mullvad).")
            recs.add("Vérifie le nom EXACT du réseau auprès du personnel (méfie-toi des sosies).")
            recs.add("Sur le portail : n'entre AUCUN identifiant si l'URL n'est pas en https:// (cadenas).")
            recs.add("Ne réutilise pas de mot de passe ; évite banque/paiements sans VPN.")
            recs.add("Après usage : « oublier le réseau » pour éviter la reconnexion auto (risque evil-twin).")
        } else {
            recs.add("Si c'est TON réseau : passe en WPA3 (ou WPA2-CCMP), renomme un SSID par défaut, désactive le WPS.")
        }
        return DetailedWifiVuln(base.score, base.label, risks.distinct(), recs, evilTwin, wps, isOpen || isPublic)
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

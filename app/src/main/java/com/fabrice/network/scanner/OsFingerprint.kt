package com.fabrice.network.scanner

/**
 * Estimation du système d'exploitation d'un appareil (fingerprinting léger).
 *
 * Méthodes non intrusives, sans root :
 * 1. TTL de la réponse ICMP (ping) — valeur initiale caractéristique par OS :
 *    Windows ≈ 128, Linux/macOS/Unix ≈ 64, routeurs Cisco/Solaris ≈ 255.
 * 2. Ports ouverts — combinaisons typiques (445/3389 = Windows, 62078 = iPhone…).
 * 3. Hostname — indices explicites (DESKTOP-xxx, iphone, android-xxx…).
 */
object OsFingerprint {

    /**
     * Devine l'OS. [ttl] = TTL restant vu dans la réponse ping (null si inconnu).
     * [service] = résultat du banner grab (en-tête Server HTTP ou bannière SSH),
     * la source la plus fiable.
     * Priorité : banner grab > hostname explicite > ports discriminants > TTL.
     */
    fun guess(ttl: Int?, ports: List<Int>, hostname: String, service: String? = null): String {
        fromService(service)?.let { return it }
        fromHostname(hostname)?.let { return it }
        fromPorts(ports)?.let { return it }
        return fromTtl(ttl)
    }

    /** OS précis déduit du banner grab (HTTP Server / SSH / services texte). */
    private fun fromService(service: String?): String? {
        if (service.isNullOrBlank()) return null
        // Les déductions spécialisées d'abord (plus précises)
        if (service.startsWith("SSH-")) {
            BannerGrab.osFromSshBanner(service)?.let { return it }
        }
        if (service.contains("Server:", ignoreCase = true)) {
            BannerGrab.osFromHttpServer(service)?.let { return it }
        }
        // Sinon banner texte générique (FTP/SMTP/POP3/IMAP/Telnet)
        BannerGrab.osFromTextBanner(service)?.let { return it }
        val s = service.lowercase()
        return when {
            s.contains("microsoft-iis") || s.contains("microsoft-httpapi") -> "Windows Server"
            s.contains("synology") || s.contains("thttpd") -> "Synology DSM"
            (s.contains("ubuntu") || s.contains("debian")) && s.contains("openssh") -> "Linux"
            s.contains("openssh_for_windows") -> "Windows (OpenSSH)"
            s.contains("raspbian") || s.contains("raspberry") -> "Raspberry Pi (Linux)"
            s.contains("dropbear") -> "Routeur (Dropbear)"
            s.contains("nginx") || s.contains("apache") || s.contains("openresty") ||
                s.contains("caddy") || s.contains("lighttpd") -> "Linux (serveur web)"
            s.contains("openssh") -> "Linux/Unix (SSH)"
            else -> null
        }
    }

    /** Indices explicites dans le nom réseau. */
    private fun fromHostname(hostname: String): String? {
        val h = hostname.lowercase()
        return when {
            h.contains("iphone") || h.contains("ipad") || h.contains("ipod") -> "Apple iOS"
            h.contains("macbook") || h.contains("imac") || h.contains("macmini") ||
                h.contains("macpro") || h.contains("mac ") || h.startsWith("mac-") -> "macOS"
            h.contains("android") || h.startsWith("android-") -> "Android"
            h.startsWith("desktop-") || h.contains("windows") || h.contains("win-") -> "Windows"
            h.contains("raspberry") || h.contains("raspbian") -> "Raspberry Pi (Linux)"
            h.contains("linux") || h.contains("debian") || h.contains("ubuntu") ||
                h.contains("fedora") -> "Linux"
            h.contains("esp32") || h.contains("esp_") || h.contains("shelly") ||
                h.contains("tuya") || h.contains("tasmota") -> "IoT (ESP)"
            h.contains("freebox") || h.contains("livebox") || h.contains("bbox") ||
                h.contains("router") || h.contains("routeur") -> "Box / routeur"
            h.contains("printer") || h.contains("imprimante") || h.contains("canon") ||
                h.contains("hp ") || h.contains("epson") -> "Imprimante"
            // Pas de "samsung" nu (téléphones/imprimantes Samsung) : exiger un
            // indice TV réel.
            h.contains("tv") || h.contains("television") || h.contains("bravia") -> "TV / Media"
            h.contains("cam") || h.contains("camera") || h.contains("webcam") -> "Caméra"
            else -> null
        }
    }

    /** Combinaisons de ports typiques. */
    private fun fromPorts(ports: List<Int>): String? {
        val s = ports.toSet()
        return when {
            62078 in s -> "Apple iOS"
            s.containsAll(setOf(139, 445)) || 3389 in s -> "Windows"
            9100 in s || (631 in s && 515 in s) -> "Imprimante"
            22 in s && 53 in s -> "Linux (serveur)"
            22 in s && 80 in s && 443 in s -> "Linux"
            else -> null
        }
    }

    /** TTL initial caractéristique (approximé par paliers). */
    private fun fromTtl(ttl: Int?): String = when {
        ttl == null -> ""
        ttl >= 240 -> "Routeur (Unix/Cisco)"
        ttl >= 120 -> "Windows"
        ttl >= 55 -> "Linux / macOS / Android"
        else -> ""
    }
}

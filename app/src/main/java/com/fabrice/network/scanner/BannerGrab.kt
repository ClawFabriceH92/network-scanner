package com.fabrice.network.scanner

import java.net.InetSocketAddress
import java.net.Socket

/**
 * « Banner grab » : lecture des bannières de services ouverts pour préciser
 * le système d'exploitation (comme Fing).
 *
 * Deux sources fiables sans root :
 * 1. HTTP : requête GET / → en-tête « Server » (Microsoft-IIS = Windows
 *    Server, nginx = Linux, Apache = Linux/macOS, thttpd = NAS Synology…).
 * 2. SSH  : bannière d'identification (OpenSSH_for_Windows = Windows,
 *    OpenSSH_8.2p1 Ubuntu = Ubuntu, Dropbear = embarqué…).
 */
object BannerGrab {

    /** Ports web à tester pour le grab HTTP (dans l'ordre de préférence). */
    val HTTP_PORTS = listOf(80, 8080, 8443, 443)

    /** Autres services à banner-grabber : port → libellé. */
    val OTHER_SERVICES = listOf(
        21 to "FTP",
        25 to "SMTP",
        23 to "Telnet",
        110 to "POP3",
        143 to "IMAP"
    )

    /**
     * Envoie une requête HTTP minimale et retourne la valeur de l'en-tête
     * « Server », ou null si le service ne répond pas / n'est pas HTTP.
     */
    fun httpServerHeader(ip: String, port: Int, timeoutMs: Int = 1_500): String? {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, port), timeoutMs)
                socket.soTimeout = timeoutMs
                socket.getOutputStream().write(
                    "GET / HTTP/1.0\r\nHost: $ip\r\nUser-Agent: NetworkScanner/0.2.6\r\n\r\n".toByteArray()
                )
                socket.getOutputStream().flush()
                val reader = socket.getInputStream().bufferedReader()
                var line = reader.readLine() ?: return null
                var server: String? = null
                var guard = 0
                while (line != null && line.isNotBlank() && guard < 30) {
                    if (line.startsWith("Server:", ignoreCase = true)) {
                        server = line.substringAfter(':').trim()
                        break
                    }
                    line = reader.readLine() ?: break
                    guard++
                }
                server?.takeIf { it.isNotBlank() }
            }
        } catch (e: Exception) {
            null
        }
    }

    /** Lit la bannière d'identification SSH (première ligne du serveur). */
    fun sshBanner(ip: String, port: Int = 22, timeoutMs: Int = 1_500): String? {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, port), timeoutMs)
                socket.soTimeout = timeoutMs
                val banner = socket.getInputStream().bufferedReader().readLine() ?: return null
                banner.trim().takeIf { it.startsWith("SSH-") }
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Lit la première ligne (bannière) d'un service texte (FTP, SMTP, POP3,
     * IMAP…). Retourne la ligne brute, ou null si le service ne parle pas.
     */
    fun textBanner(ip: String, port: Int, timeoutMs: Int = 1_500): String? {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, port), timeoutMs)
                socket.soTimeout = timeoutMs
                val line = socket.getInputStream().bufferedReader().readLine() ?: return null
                line.trim().takeIf { it.isNotBlank() }
            }
        } catch (e: Exception) {
            null
        }
    }

    /** Déduit un OS à partir d'un banner texte (FTP/SMTP/POP3/IMAP/Telnet). */
    fun osFromTextBanner(banner: String?): String? {
        if (banner.isNullOrBlank()) return null
        val b = banner.lowercase()
        return when {
            b.contains("microsoft") || b.contains("esmtp") && b.contains("microsoft") -> "Windows Server"
            b.contains("proftpd") || b.contains("vsftpd") || b.contains("pure-ftpd") ||
                b.contains("wu-ftpd") -> "Linux (FTP)"
            b.contains("postfix") || b.contains("exim") || b.contains("sendmail") ||
                b.contains("dovecot") -> "Linux (mail)"
            b.contains("synology") || b.contains("dsm") -> "Synology DSM"
            b.contains("dropbear") -> "Routeur / embarqué"
            b.contains("freebox") || b.contains("livebox") || b.contains("technicolor") ->
                "Box / routeur"
            else -> null
        }
    }

    /** Déduit un OS à partir de l'en-tête Server HTTP. Testable. */
    fun osFromHttpServer(server: String?): String? {
        if (server.isNullOrBlank()) return null
        val s = server.lowercase()
        return when {
            s.contains("microsoft-iis") || s.contains("microsoft-httpapi") -> "Windows Server (IIS)"
            s.contains("thttpd") || s.contains("lighttpd") -> "NAS / embarqué"
            s.contains("synology") -> "Synology DSM"
            s.contains("openresty") -> "Linux (OpenResty)"
            s.contains("nginx") -> "Linux (nginx)"
            s.contains("apache") -> if (s.contains("ubuntu")) "Ubuntu (Apache)" else "Linux / macOS (Apache)"
            s.contains("caddy") -> "Linux (Caddy)"
            s.contains("node.js") -> "Linux (Node.js)"
            else -> null
        }
    }

    /** Déduit un OS à partir de la bannière SSH. Testable. */
    fun osFromSshBanner(banner: String?): String? {
        if (banner.isNullOrBlank()) return null
        val b = banner.lowercase()
        return when {
            b.contains("openssh_for_windows") -> "Windows (OpenSSH)"
            b.contains("ubuntu") -> "Linux Ubuntu (OpenSSH)"
            b.contains("debian") -> "Linux Debian (OpenSSH)"
            b.contains("raspbian") || b.contains("raspberry") -> "Raspberry Pi (Linux)"
            b.contains("dropbear") -> "Routeur / embarqué (Dropbear)"
            b.contains("openssh") && b.contains("freebsd") -> "FreeBSD (OpenSSH)"
            b.contains("openssh") -> "Linux/Unix (OpenSSH)"
            else -> null
        }
    }
}

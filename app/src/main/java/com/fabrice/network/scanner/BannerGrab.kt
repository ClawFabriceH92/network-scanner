package com.fabrice.network.scanner

import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

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

    /** Ports imprimante à sonder : JetDirect 9100, IPP 631, LPD 515. */
    val PRINTER_PORTS = listOf(9100, 631, 515)

    /**
     * Sonde une imprimante (JetDirect 9100 / IPP 631) et retourne le modèle
     * annoncé dans la bannière — ex: « HP E57540 » ou « 9100: PRINTER ... ».
     * Sur IPP (631), envoie une requête HTTP et lit l'en-tête Server qui
     * contient souvent le modèle (ex: Server: HP HTTP Server; HP LaserJet...).
     */
    fun printerBanner(ip: String, timeoutMs: Int = 1_500): String? {
        // 1) IPP (631) : requête HTTP OPTIONS/GET → en-tête Server riche
        val ipp = httpServerHeaderRaw(ip, 631, timeoutMs)
        if (!ipp.isNullOrBlank()) return ipp
        // 2) JetDirect (9100) : le port parle parfois en texte
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, 9100), timeoutMs)
                socket.soTimeout = timeoutMs
                socket.getOutputStream().write("\r\n".toByteArray())
                socket.getOutputStream().flush()
                val line = socket.getInputStream().bufferedReader().readLine() ?: return null
                val t = line.trim()
                if (t.isNotBlank() && !t.contains("PJL")) return t
            }
        } catch (e: Exception) {
            // port fermé ou muet → on passe
        }
        return null
    }

    /** Comme httpServerHeader mais retourne TOUT le premier bloc de réponse. */
    private fun httpServerHeaderRaw(ip: String, port: Int, timeoutMs: Int): String? {
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
                var sb = StringBuilder()
                var guard = 0
                while (line != null && line.isNotBlank() && guard < 10) {
                    sb.append(line).append('\n')
                    if (line.startsWith("Server:", ignoreCase = true)) {
                        // l'en-tête Server est le plus informatif — on s'arrête là
                        return line.substringAfter(':').trim()
                    }
                    line = reader.readLine() ?: break
                    guard++
                }
                sb.toString().trim().takeIf { it.isNotBlank() }
            }
        } catch (e: Exception) {
            null
        }
    }

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

    /**
     * Récupère le <title> de la page web d'un hôte (identifie l'UI d'un NAS,
     * routeur, caméra…). Essaie les ports web ouverts. Retourne « » si aucun.
     */
    fun httpTitle(ip: String, ports: List<Int>, timeoutMs: Int = 1_500): String {
        for (port in HTTP_PORTS) {
            if (port in ports) {
                val body = runCatching { httpBody(ip, port, timeoutMs) }.getOrNull()
                val title = body?.let { extractTitle(it) }
                if (!title.isNullOrBlank()) return title
            }
        }
        return ""
    }

    /** Extrait le contenu de la balise <title> d'un HTML. Testable. */
    fun extractTitle(html: String): String? {
        val m = Regex("<title[^>]*>(.*?)</title>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
            .find(html) ?: return null
        return m.groupValues[1].replace(Regex("\\s+"), " ").trim().take(80).ifBlank { null }
    }

    /** Empreinte MD5 (hex) du favicon d'un hôte web, ou « » si absent. */
    fun faviconHash(ip: String, ports: List<Int>, timeoutMs: Int = 1_500): String {
        val port = HTTP_PORTS.firstOrNull { it in ports } ?: return ""
        return try {
            val scheme = if (port == 443 || port == 8443) "https" else "http"
            val url = URL("$scheme://$ip:$port/favicon.ico")
            val conn = url.openConnection() as java.net.HttpURLConnection
            if (conn is javax.net.ssl.HttpsURLConnection) {
                val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
                ctx.init(null, arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
                    override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
                    override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
                    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
                }), java.security.SecureRandom())
                conn.sslSocketFactory = ctx.socketFactory
                conn.setHostnameVerifier { _, _ -> true }
            }
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            if (conn.responseCode != 200) { conn.disconnect(); return "" }
            val bytes = conn.inputStream.use { it.readBytes() }
            conn.disconnect()
            if (bytes.isEmpty()) "" else md5Hex(bytes)
        } catch (e: Exception) {
            ""
        }
    }

    /** MD5 hexadécimal de données brutes. */
    fun md5Hex(data: ByteArray): String {
        val md = java.security.MessageDigest.getInstance("MD5")
        return md.digest(data).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    /** GET brut d'une page web (corps limité à ~64 Ko). */
    private fun httpBody(ip: String, port: Int, timeoutMs: Int): String? {
        val scheme = if (port == 443 || port == 8443) "https" else "http"
        val conn = URL("$scheme://$ip:$port/").openConnection() as java.net.HttpURLConnection
        return try {
            if (conn is javax.net.ssl.HttpsURLConnection) {
                val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
                ctx.init(null, arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
                    override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
                    override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
                    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
                }), java.security.SecureRandom())
                conn.sslSocketFactory = ctx.socketFactory
                conn.setHostnameVerifier { _, _ -> true }
            }
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.instanceFollowRedirects = true
            conn.setRequestProperty("User-Agent", "NetworkScanner")
            val stream = if (conn.responseCode in 200..399) conn.inputStream else conn.errorStream
            stream?.bufferedReader(Charsets.UTF_8)?.use { r ->
                val buf = CharArray(65_536)
                val n = r.read(buf)
                if (n > 0) String(buf, 0, n) else ""
            }
        } catch (e: Exception) {
            null
        } finally {
            runCatching { conn.disconnect() }
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

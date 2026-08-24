package com.fabrice.network.scanner

import java.net.InetSocketAddress
import java.net.Socket

/**
 * Sonde RTSP (port 554) — caméras IP et serveurs de flux. Envoie une requête
 * OPTIONS et lit l'en-tête `Server`, puis expose l'URL de flux à ouvrir dans un
 * lecteur (VLC…). Pas de flux vidéo décodé (hors scope), juste l'identification.
 */
object RtspProbe {

    data class RtspInfo(
        val server: String,
        val url: String,
        val methods: String = ""
    )

    /** Interroge le service RTSP sur [port]. null si ce n'est pas du RTSP. */
    fun probe(ip: String, port: Int = 554, timeoutMs: Int = 1_500): RtspInfo? {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, port), timeoutMs)
                socket.soTimeout = timeoutMs
                val url = "rtsp://$ip:$port/"
                val req = "OPTIONS $url RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: NetworkScanner\r\n\r\n"
                socket.getOutputStream().write(req.toByteArray())
                socket.getOutputStream().flush()
                val reader = socket.getInputStream().bufferedReader()
                val head = StringBuilder()
                var line = reader.readLine()
                var guard = 0
                while (line != null && line.isNotBlank() && guard < 20) {
                    head.append(line).append('\n'); line = reader.readLine(); guard++
                }
                parseOptions(head.toString(), url)
            }
        } catch (e: Exception) {
            null
        }
    }

    /** Parse la réponse RTSP OPTIONS. null si la 1re ligne n'est pas du RTSP. */
    fun parseOptions(response: String, url: String): RtspInfo? {
        val lines = response.lineSequence().toList()
        val first = lines.firstOrNull()?.trim() ?: return null
        if (!first.startsWith("RTSP/")) return null
        fun header(name: String): String = lines.firstOrNull {
            it.startsWith("$name:", ignoreCase = true)
        }?.substringAfter(':')?.trim().orEmpty()
        return RtspInfo(
            server = header("Server"),
            url = url,
            methods = header("Public")
        )
    }
}

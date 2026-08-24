package com.fabrice.network.scanner

import java.net.InetSocketAddress
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Lecture du certificat TLS d'un service (HTTPS, etc.) — identité et posture de
 * sécurité de l'appareil : nom (CN), émetteur, date d'expiration, auto-signé,
 * expiré. On accepte tous les certificats (on ne fait que les LIRE, pas valider
 * une connexion sensible).
 */
object TlsProbe {

    /** Ports TLS courants à sonder. */
    val TLS_PORTS = listOf(443, 8443, 9443, 8006, 5001, 636)

    data class TlsInfo(
        val port: Int,
        val subject: String,
        val issuer: String,
        val notAfterMs: Long,
        val selfSigned: Boolean,
        val expired: Boolean
    )

    /** Sonde le premier port TLS ouvert parmi [ports] et lit son certificat. */
    fun probe(ip: String, ports: List<Int>, timeoutMs: Int = 2_000): TlsInfo? {
        for (p in ports) {
            if (p in TLS_PORTS) {
                val info = runCatching { probePort(ip, p, timeoutMs) }.getOrNull()
                if (info != null) return info
            }
        }
        return null
    }

    /** Ouvre une session TLS et extrait les infos du certificat serveur. */
    fun probePort(ip: String, port: Int, timeoutMs: Int = 2_000): TlsInfo? {
        val ctx = SSLContext.getInstance("TLS")
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) {}
            override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        ctx.init(null, trustAll, java.security.SecureRandom())
        val socket = ctx.socketFactory.createSocket() as SSLSocket
        return try {
            socket.connect(InetSocketAddress(ip, port), timeoutMs)
            socket.soTimeout = timeoutMs
            socket.startHandshake()
            val certs = socket.session.peerCertificates
            val cert = certs.firstOrNull() as? X509Certificate ?: return null
            val subjectDn = cert.subjectX500Principal.name
            val issuerDn = cert.issuerX500Principal.name
            val notAfter = cert.notAfter.time
            TlsInfo(
                port = port,
                subject = cn(subjectDn) ?: subjectDn,
                issuer = cn(issuerDn) ?: issuerDn,
                notAfterMs = notAfter,
                selfSigned = subjectDn == issuerDn,
                expired = notAfter < System.currentTimeMillis()
            )
        } catch (e: Exception) {
            null
        } finally {
            runCatching { socket.close() }
        }
    }

    /** Extrait le CN d'un DN X.500 (« CN=host,O=… » → « host »). Testable. */
    fun cn(dn: String): String? {
        val m = Regex("CN=([^,]+)").find(dn) ?: return null
        return m.groupValues[1].trim().ifBlank { null }
    }
}

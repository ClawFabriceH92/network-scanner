package com.fabrice.network.scanner

import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Scan de ports TCP (découverte de services).
 *
 * Stratégie : test de connexion TCP (connect timeout court) sur une liste de
 * ports connus. Les ports ouverts indiquent le type de service (SSH, HTTP,
 * RDP…). Chaque appareil est scanné en parallèle, chaque port aussi.
 */
object PortScanner {

    /** Ports courants à tester, avec le nom du service le plus fréquent. */
    val COMMON_PORTS = listOf(
        21 to "FTP",
        22 to "SSH",
        23 to "Telnet",
        25 to "SMTP",
        53 to "DNS",
        80 to "HTTP",
        443 to "HTTPS",
        445 to "SMB",
        554 to "RTSP",
        631 to "IPP",
        993 to "IMAPS",
        3389 to "RDP",
        5900 to "VNC",
        8080 to "HTTP-alt",
        8443 to "HTTPS-alt",
        11434 to "Ollama"
    )

    fun serviceName(port: Int): String =
        COMMON_PORTS.firstOrNull { it.first == port }?.second ?: "port-$port"

    /** Teste si un port TCP est ouvert sur une IP. */
    fun isPortOpen(ip: String, port: Int, timeoutMs: Int = 400): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, port), timeoutMs)
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Scanne tous les ports connus sur une IP. Retourne la liste des ports ouverts.
     * Parallélisé (un thread par port), timeout global.
     */
    fun scanPorts(ip: String, timeoutMs: Int = 400): List<Int> {
        val open = ConcurrentHashMap.newKeySet<Int>()
        val executor = Executors.newFixedThreadPool(COMMON_PORTS.size)
        try {
            COMMON_PORTS.forEach { (port, _) ->
                executor.execute {
                    if (isPortOpen(ip, port, timeoutMs)) open.add(port)
                }
            }
            executor.shutdown()
            executor.awaitTermination(30, TimeUnit.SECONDS)
        } finally {
            if (!executor.isShutdown) executor.shutdownNow()
        }
        return open.sorted()
    }
}

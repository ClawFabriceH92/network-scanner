package com.fabrice.network.scanner

import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Scan de ports TCP (découverte de services).
 *
 * Deux modes :
 * - STANDARD : 16 ports les plus courants (rapide, ~1-2 s/appareil)
 * - ÉLARGI   : ~60 ports courants + gestion/médias/IoT (plus lent mais
 *   découvre les services rarement sur les ports standard)
 *
 * Chaque appareil est scanné en parallèle, chaque port aussi.
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

    /** Ports supplémentaires du mode élargi (gestion, mail, médias, IoT). */
    val EXTRA_PORTS = listOf(
        20 to "FTP-data",
        69 to "TFTP",
        110 to "POP3",
        111 to "RPC",
        135 to "MS-RPC",
        137 to "NetBIOS",
        138 to "NetBIOS-DGM",
        139 to "NetBIOS-SSN",
        143 to "IMAP",
        161 to "SNMP",
        162 to "SNMP-trap",
        179 to "BGP",
        389 to "LDAP",
        4433 to "HTTPS-alt2",
        5000 to "UPnP/Alt",
        5001 to "NAS-Alt",
        5060 to "SIP",
        515 to "LPD",
        5353 to "mDNS",
        548 to "AFP",
        636 to "LDAPS",
        873 to "rsync",
        8888 to "HTTP-alt3",
        9000 to "App",
        9090 to "Admin",
        9100 to "Printer",
        9200 to "Elastic",
        9418 to "Git",
        9999 to "App-alt",
        10000 to "Webmin",
        11211 to "Memcached",
        12345 to "Remote",
        20000 to "App",
        27017 to "MongoDB",
        32400 to "Plex",
        49152 to "UPnP-Alt",
        22_222 to "Synology"
    )

    /** Tous les ports connus (standard + élargi). */
    val ALL_PORTS: List<Pair<Int, String>> = COMMON_PORTS + EXTRA_PORTS

    fun serviceName(port: Int): String =
        ALL_PORTS.firstOrNull { it.first == port }?.second ?: "port-$port"

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
     * Scanne les ports donnés sur une IP. Retourne la liste des ports ouverts.
     * Parallélisé (un thread par port), timeout global.
     */
    fun scanPorts(
        ip: String,
        ports: List<Int> = COMMON_PORTS.map { it.first },
        timeoutMs: Int = 400
    ): List<Int> {
        if (ports.isEmpty()) return emptyList()
        val open = ConcurrentHashMap.newKeySet<Int>()
        val executor = Executors.newFixedThreadPool(ports.size.coerceAtMost(64))
        try {
            ports.forEach { port ->
                executor.execute {
                    if (isPortOpen(ip, port, timeoutMs)) open.add(port)
                }
            }
            executor.shutdown()
            executor.awaitTermination(30, TimeUnit.SECONDS)
        } finally {
            // isTerminated (isShutdown est déjà vrai après shutdown()) : force
            // réellement l'arrêt si awaitTermination expire.
            if (!executor.isTerminated) executor.shutdownNow()
        }
        return open.sorted()
    }
}

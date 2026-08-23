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

    /**
     * Ports typiques des applications conteneurisées (Docker en mode bridge :
     * le conteneur n'a pas d'IP propre, seuls ses ports PUBLIÉS sont visibles
     * sur l'IP de l'hôte). Sans ça, un Portainer/Jellyfin/Home Assistant…
     * n'apparaissait pas car son port n'était dans aucune liste.
     */
    val CONTAINER_PORTS = listOf(
        81 to "NPM-Admin",
        2375 to "Docker-API",
        2376 to "Docker-API-TLS",
        3000 to "Grafana/App",
        3001 to "Uptime-Kuma",
        3306 to "MySQL",
        5432 to "PostgreSQL",
        5601 to "Kibana",
        6379 to "Redis",
        6767 to "Bazarr",
        7878 to "Radarr",
        8000 to "HTTP-alt4",
        8081 to "HTTP-admin",
        8086 to "InfluxDB",
        8096 to "Jellyfin",
        8112 to "Deluge",
        8123 to "Home-Assistant",
        8200 to "Vault/Duplicati",
        8384 to "Syncthing",
        8686 to "Lidarr",
        8920 to "Emby",
        8989 to "Sonarr",
        9091 to "Transmission",
        9117 to "Jackett",
        9443 to "Portainer",
        9696 to "Prowlarr",
        1880 to "Node-RED",
        1883 to "MQTT",
        19999 to "Netdata"
    )

    /** Tous les ports connus (standard + élargi + conteneurs). */
    val ALL_PORTS: List<Pair<Int, String>> =
        (COMMON_PORTS + EXTRA_PORTS + CONTAINER_PORTS).distinctBy { it.first }

    fun serviceName(port: Int): String =
        ALL_PORTS.firstOrNull { it.first == port }?.second ?: "port-$port"

    /** Ports servant une interface web en HTTPS. */
    val HTTPS_WEB_PORTS = setOf(443, 8443, 9443, 5001, 4433, 636)

    /** Ports servant une interface web en HTTP (admin, apps self-hosted…). */
    val HTTP_WEB_PORTS = setOf(
        80, 81, 3000, 3001, 5000, 8000, 8080, 8081, 8086, 8096, 8112, 8123,
        8200, 8384, 8686, 8888, 8920, 8989, 7878, 6767, 9000, 9090, 9091,
        9117, 9696, 10000, 19999, 20000, 32400
    )

    /** Vrai si le port sert (très probablement) une interface web / un site. */
    fun isWebPort(port: Int): Boolean =
        port in HTTPS_WEB_PORTS || port in HTTP_WEB_PORTS

    /**
     * URL à ouvrir pour un port web, ou null si ce n'est pas un port web.
     * Ex. (192.168.0.180, 5000) → "http://192.168.0.180:5000".
     */
    fun webUrl(ip: String, port: Int): String? {
        val https = port in HTTPS_WEB_PORTS
        val http = port in HTTP_WEB_PORTS
        if (!https && !http) return null
        val scheme = if (https) "https" else "http"
        val suffix = if (port == 80 || port == 443) "" else ":$port"
        return "$scheme://$ip$suffix"
    }

    /**
     * Ports de « ping TCP » : sonde de vivacité pour les hôtes qui filtrent
     * l'ICMP (conteneurs Docker, serveurs/VM pare-feu, IoT). Ciblés parce que
     * très souvent exposés par un service : web (dont les ports typiques des
     * apps conteneurisées : 3000/5000/8000/9000), admin distante, partages.
     */
    val TCP_PING_PORTS = listOf(
        // Web / serveurs web conteneurisés (le cas le plus fréquent)
        80, 443, 8080, 8443, 8000, 8081, 81, 5000, 5001, 8096, 8123, 9443,
        3000, 9000, 32400,
        // Administration / partages / API
        22, 445, 3389, 53, 2375
    )

    /**
     * Vrai dès qu'AU MOINS un des ports est ouvert (court-circuite au premier
     * succès). Sert de sonde de vivacité TCP : une connexion acceptée prouve
     * que l'hôte est vivant même s'il ne répond pas au ping.
     */
    fun isAnyPortOpen(ip: String, ports: List<Int> = TCP_PING_PORTS, timeoutMs: Int = 300): Boolean {
        for (port in ports) {
            if (isPortOpen(ip, port, timeoutMs)) return true
        }
        return false
    }

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

    /**
     * Scan COMPLET des 65535 ports d'UN hôte (scan approfondi à la demande).
     *
     * Découvre les services sur des ports arbitraires — typiquement les
     * conteneurs Docker en mode bridge dont les ports publiés ne figurent dans
     * aucune liste prédéfinie. Réservé à une IP unique (déclenché depuis la
     * fiche appareil) : lancer ça sur tout le sous-réseau serait bien trop long.
     *
     * Fortement parallélisé, timeout court. `onProgress(done, total)` est appelé
     * périodiquement pour la barre de progression.
     */
    fun scanAllPorts(
        ip: String,
        timeoutMs: Int = 250,
        range: IntRange = 1..65535,
        onProgress: (done: Int, total: Int) -> Unit = { _, _ -> }
    ): List<Int> {
        val total = range.count()
        val open = ConcurrentHashMap.newKeySet<Int>()
        val done = java.util.concurrent.atomic.AtomicInteger(0)
        val executor = Executors.newFixedThreadPool(256)
        try {
            range.forEach { port ->
                executor.execute {
                    if (isPortOpen(ip, port, timeoutMs)) open.add(port)
                    val d = done.incrementAndGet()
                    if (d % 1000 == 0 || d == total) onProgress(d, total)
                }
            }
            executor.shutdown()
            executor.awaitTermination(5, TimeUnit.MINUTES)
        } finally {
            if (!executor.isTerminated) executor.shutdownNow()
        }
        return open.sorted()
    }
}

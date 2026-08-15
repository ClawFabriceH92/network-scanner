package com.fabrice.network.scanner

import android.content.SharedPreferences
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Un périphérique détecté sur le réseau. */
data class Device(
    val ip: String,
    val mac: String = "",
    val vendor: String = "",
    val hostname: String = "",
    val alive: Boolean = true,
    val isSelf: Boolean = false,
    val isGateway: Boolean = false,
    val ports: List<Int> = emptyList(),
    val os: String = "",
    val ttl: Int? = null,
    val type: String = "Inconnu",
    val banner: String = "",
    val latencyMs: Int? = null,
    val upnp: UpnpProbe.UpnpInfo? = null,
    val smbShares: List<SmbShareScanner.SmbShare> = emptyList()
)

/** Résultat d'un ping : vivant ? + TTL de la réponse (pour l'OS) + latence. */
data class PingResult(val alive: Boolean, val ttl: Int?, val latencyMs: Int? = null)

/**
 * Scanner réseau local (type Fing).
 *
 * Stratégie (validée par tests sur réseau réel) :
 * 1. Détection du sous-réseau (NetworkInterface + masque)
 * 2. Ping sweep parallèle (binaire /system/bin/ping, fiable sans root)
 * 3. Fusion avec la table ARP (/proc/net/arp) — attrape les appareils qui
 *    ne répondent pas à l'ICMP mais ont un échange ARP récent. Double lecture
 *    espacée de ~500 ms car la table ARP Android ne garde que les échanges
 *    récents (beaucoup de MAC manquent sur une seule lecture).
 * 4. Reverse DNS pour le hostname
 * 5. Fabricant via la base OUI embarquée (assets/oui.txt), avec repli en
 *    ligne (api.macvendors.com) si le préfixe est inconnu localement.
 */
object NetworkScanner {

    fun ipToInt(ip: String): Long {
        val parts = ip.split(".").map { it.toLong() }
        return (parts[0] shl 24) or (parts[1] shl 16) or (parts[2] shl 8) or parts[3]
    }

    fun intToIp(value: Long): String =
        "${(value shr 24) and 0xFF}.${(value shr 16) and 0xFF}.${(value shr 8) and 0xFF}.${value and 0xFF}"

    /** Adresse réseau d'une IP + préfixe. */
    fun networkAddress(ip: String, prefix: Int): Long =
        if (prefix >= 32) ipToInt(ip) else (ipToInt(ip) and (0xFFFFFFFFL shl (32 - prefix)))

    /** Liste des adresses hôtes d'un sous-réseau (exclut réseau + broadcast). */
    fun hostList(ip: String, prefix: Int): List<String> {
        val net = networkAddress(ip, prefix)
        val size = 1L shl (32 - prefix)
        if (size <= 2) return emptyList()
        return (1 until size - 1).map { intToIp(net + it) }
    }

    /** Parse la table ARP : "IP MAC" pour les entrées valides. */
    fun parseArp(text: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        val ipRegex = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        text.lineSequence().forEach { line ->
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size >= 4 && ipRegex.matches(parts[0]) &&
                parts[3] != "00:00:00:00:00:00" && parts[3] != "incomplete"
            ) {
                result[parts[0]] = parts[3].lowercase()
            }
        }
        return result
    }

    /** Lit la table ARP système et la parse (vide si le fichier est indisponible). */
    private fun readArp(): Map<String, String> =
        parseArp(runCatching { java.io.File("/proc/net/arp").readText() }.getOrDefault(""))

    /** Fusionne deux tables ARP (IP → MAC) ; la seconde est prioritaire en cas de conflit. */
    fun mergeArp(first: Map<String, String>, second: Map<String, String>): Map<String, String> {
        val merged = HashMap<String, String>(first)
        merged.putAll(second)
        return merged
    }

    /** Parse une ligne de la base OUI : "f4cae5\tVENDOR". */
    fun parseOuiLine(line: String): Pair<String, String>? {
        val idx = line.indexOf('\t')
        if (idx <= 0) return null
        val mac = line.substring(0, idx)
        if (mac.length != 6 || !mac.all { it.isDigit() || it in 'a'..'f' }) return null
        return mac to line.substring(idx + 1)
    }

    /** Préfixe OUI (6 hex) d'une MAC normalisée, ou null si la MAC est invalide. */
    fun macPrefix(mac: String): String? {
        val clean = mac.replace(":", "").replace("-", "").lowercase()
        if (clean.length < 6) return null
        val prefix = clean.substring(0, 6)
        if (!prefix.all { it.isDigit() || it in 'a'..'f' }) return null
        return prefix
    }

    /** Normalise un MAC (aa:bb:cc:dd:ee:ff → aabbcc) et cherche le fabricant. */
    fun vendorFor(mac: String, oui: Map<String, String>): String {
        val prefix = macPrefix(mac) ?: return ""
        return oui[prefix] ?: ""
    }

    /** Détecte l'IP locale + préfixe du réseau actif (Android). */
    fun detectSubnet(): Pair<String, Int>? {
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: return null
        for (iface in interfaces) {
            if (!iface.isUp || iface.isLoopback) continue
            for (addr in iface.interfaceAddresses) {
                val ipv4 = addr.address as? Inet4Address ?: continue
                if (ipv4.isLoopbackAddress) continue
                val prefix = addr.networkPrefixLength
                if (prefix in 16..30) return ipv4.hostAddress to prefix.toInt()
            }
        }
        return null
    }

    /** Adresse de broadcast d'un sous-réseau (IP + préfixe). */
    fun broadcastAddress(ip: String, prefix: Int): String {
        val net = networkAddress(ip, prefix)
        val size = (1L shl (32 - prefix)) - 1
        return intToIp(net or size)
    }

    /**
     * Scan complet du réseau local. Ping parallèle (64 threads), puis fusion
     * avec l'ARP (triple lecture), reverse DNS, lookup fabricant et scan de
     * ports pour les appareils en ligne.
     *
     * @param prefs SharedPreferences facultatif servant de cache persistant pour
     *   le lookup fabricant en ligne (clé « vendor_cache_<prefixe6> »). Passé
     *   par la couche UI ; null en test ou hors contexte Android.
     * @param portsToScan Liste des ports à tester (défaut : PortScanner.COMMON_PORTS).
     */
    suspend fun scan(
        oui: Map<String, String>,
        scanPorts: Boolean = true,
        prefs: SharedPreferences? = null,
        portsToScan: List<Int> = PortScanner.COMMON_PORTS.map { it.first },
        onProgress: (done: Int, total: Int) -> Unit
    ): List<Device> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val subnet = detectSubnet() ?: return@withContext emptyList()
        val (ip, prefix) = subnet
        val hosts = hostList(ip, prefix)
        if (hosts.isEmpty()) return@withContext emptyList()

        val alive = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
        val ttlMap = java.util.concurrent.ConcurrentHashMap<String, Int>()
        val latencyMap = java.util.concurrent.ConcurrentHashMap<String, Int>()
        val executor = Executors.newFixedThreadPool(64)
        try {
            hosts.forEachIndexed { index, host ->
                executor.execute {
                    val r = pingHost(host)
                    if (r.alive) {
                        alive.add(host)
                        if (r.ttl != null) ttlMap[host] = r.ttl
                        if (r.latencyMs != null) latencyMap[host] = r.latencyMs
                    }
                    if (index % 64 == 0 || index == hosts.size - 1) {
                        onProgress(alive.size, hosts.size)
                    }
                }
            }
            executor.shutdown()
            executor.awaitTermination(120, TimeUnit.SECONDS)
        } finally {
            if (!executor.isShutdown) executor.shutdownNow()
        }

        // Découverte UPnP/SSDP : une seule requête multicast, réponses par IP
        val upnpByIp = UpnpProbe.discover()

        // Fusion ping + table ARP — TRIPLE lecture espacée : la table ARP
        // Android ne contient que les échanges récents, et un appareil qui
        // filtre ICMP n'apparaît qu'après un échange ARP. Trois lectures à
        // ~700 ms captent plus de MAC que deux (périphériques cachés).
        val arp = mergeArp(mergeArp(readArp(), run {
            kotlinx.coroutines.delay(700)
            readArp()
        }), run {
            kotlinx.coroutines.delay(700)
            readArp()
        })
        val allIps = (alive + arp.keys).toSortedSet()

        // Cache en mémoire des fabricants résolus en ligne : évite d'interroger
        // deux fois le même préfixe OUI au cours d'un même scan.
        val vendorCache = HashMap<String, String>()

        val localIp = ip
        val gatewayIp = NetworkInfoProvider.readGateway()
        allIps.map { host ->
            val mac = arp[host] ?: ""
            var vendor = vendorFor(mac, oui)
            // Repli en ligne si la base locale ne connaît pas le préfixe.
            if (vendor.isBlank() && mac.isNotBlank()) {
                vendor = VendorLookup.lookup(mac, vendorCache, prefs) ?: ""
            }
            val hostname = reverseDns(host)
            val ports = if (scanPorts && alive.contains(host)) {
                PortScanner.scanPorts(host, portsToScan)
            } else emptyList()
            // Banner grab : interroge les services ouverts (HTTP/SSH/FTP/SMTP…)
            // pour préciser l'OS réel et enrichir la fiche appareil.
            val banner = if (alive.contains(host)) grabService(host, ports) else ""
            val os = OsFingerprint.guess(ttlMap[host], ports, hostname, banner.ifBlank { null })
            // Partages SMB (dossiers partagés, y compris cachés $) — seulement si
            // le port 445 est ouvert, jamais bloquant (runCatching).
            val smbShares = if (alive.contains(host) && 445 in ports) {
                runCatching { SmbShareScanner.scanShares(host, timeoutMs = 1_500) }
                    .getOrDefault(emptyList())
            } else emptyList()
            // Infos UPnP éventuelles (friendlyName, fabricant, modèle…)
            var upnp = upnpByIp[host]
            if (upnp != null && upnp.location.isNotBlank() && !upnp.hasInfo) {
                upnp = UpnpProbe.fetchDescription(upnp.location)
            }
            Device(
                ip = host,
                mac = mac,
                vendor = vendor,
                hostname = hostname,
                alive = alive.contains(host),
                isSelf = host == localIp,
                isGateway = host == gatewayIp,
                ports = ports,
                ttl = ttlMap[host],
                os = os,
                type = DeviceType.classify(vendor, hostname, ports, os),
                banner = banner,
                latencyMs = latencyMap[host],
                upnp = upnp,
                smbShares = smbShares
            )
            // Tri : le périphérique qui lance le scan (isSelf) TOUT EN HAUT,
            // puis les autres par IP.
        }.sortedWith(
            compareByDescending<Device> { it.isSelf }
                .thenBy { it.ip }
        )
    }

    /**
     * Interroge les services ouverts pour lire une bannière identifiante.
     * Priorité : HTTP (en-tête Server) puis SSH puis services texte (FTP…).
     * Retourne la bannière brute (« Server: nginx/1.18 », « SSH-2.0-… »…).
     */
    private fun grabService(host: String, ports: List<Int>): String {
        // HTTP : essaie les ports web connus parmi ceux ouverts
        for (port in BannerGrab.HTTP_PORTS) {
            if (port in ports) {
                BannerGrab.httpServerHeader(host, port)?.let { return "Server: $it" }
            }
        }
        // SSH : bannière d'identification
        if (22 in ports) {
            BannerGrab.sshBanner(host)?.let { return it }
        }
        // Services texte : FTP, SMTP, POP3, IMAP, Telnet
        for ((port, _) in BannerGrab.OTHER_SERVICES) {
            if (port in ports) {
                BannerGrab.textBanner(host, port)?.let { return it }
            }
        }
        // Imprimantes : IPP (631) / JetDirect (9100) → le modèle de l'imprimante
        // (ex: « HP LaserJet MFP E57540 ») — c'est ce qui permet d'identifier
        // l'appareil précisément comme Fing.
        if (BannerGrab.PRINTER_PORTS.any { it in ports }) {
            BannerGrab.printerBanner(host)?.let { return "Imprimante: $it" }
        }
        return ""
    }

    private fun pingHost(host: String): PingResult {
        return try {
            val process = ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "1", host)
                .redirectErrorStream(true)
                .start()
            val ok = process.waitFor(3, TimeUnit.SECONDS) && process.exitValue() == 0
            val output = runCatching {
                val text = process.inputStream.bufferedReader().use { it.readText() }
                text
            }.getOrDefault("")
            runCatching { process.destroy() }
            val ttl = parseTtl(output)
            val latency = parseLatency(output)
            PingResult(ok, ttl, latency)
        } catch (e: Exception) {
            PingResult(false, null)
        }
    }

    /** Extrait le TTL de la sortie ping (« ttl=64 »). */
    fun parseTtl(pingOutput: String): Int? =
        Regex("ttl=(\\d+)").find(pingOutput)?.groupValues?.get(1)?.toIntOrNull()

    /** Extrait la latence de la sortie ping (« time=2.34 ms », « time<1 ms »). */
    fun parseLatency(pingOutput: String): Int? {
        val m = Regex("time[=<]([0-9.]+)").find(pingOutput) ?: return null
        val v = m.groupValues[1].toDoubleOrNull() ?: return null
        return if (v < 1) 1 else v.toInt()
    }

    private fun reverseDns(host: String): String {
        return try {
            val name = InetAddress.getByName(host).hostName ?: ""
            if (name == host) "" else name
        } catch (e: Exception) {
            ""
        }
    }
}

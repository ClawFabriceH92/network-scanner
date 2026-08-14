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
    val ports: List<Int> = emptyList(),
    val os: String = "",
    val ttl: Int? = null,
    val type: String = "Inconnu"
)

/** Résultat d'un ping : vivant ? + TTL de la réponse (pour l'OS). */
data class PingResult(val alive: Boolean, val ttl: Int?)

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
     * avec l'ARP (double lecture), reverse DNS, lookup fabricant et scan de
     * ports pour les appareils en ligne.
     *
     * @param prefs SharedPreferences facultatif servant de cache persistant pour
     *   le lookup fabricant en ligne (clé « vendor_cache_<prefixe6> »). Passé
     *   par la couche UI ; null en test ou hors contexte Android.
     */
    suspend fun scan(
        oui: Map<String, String>,
        scanPorts: Boolean = true,
        prefs: SharedPreferences? = null,
        onProgress: (done: Int, total: Int) -> Unit
    ): List<Device> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val subnet = detectSubnet() ?: return@withContext emptyList()
        val (ip, prefix) = subnet
        val hosts = hostList(ip, prefix)
        if (hosts.isEmpty()) return@withContext emptyList()

        val alive = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
        val ttlMap = java.util.concurrent.ConcurrentHashMap<String, Int>()
        val executor = Executors.newFixedThreadPool(64)
        try {
            hosts.forEachIndexed { index, host ->
                executor.execute {
                    val r = pingHost(host)
                    if (r.alive) {
                        alive.add(host)
                        if (r.ttl != null) ttlMap[host] = r.ttl
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

        // Fusion ping + table ARP (double lecture espacée de ~500 ms : la table
        // ARP Android ne contient que les échanges récents, on capte ainsi plus
        // de MAC que sur une seule lecture).
        val arp = mergeArp(readArp(), run {
            kotlinx.coroutines.delay(500)
            readArp()
        })
        val allIps = (alive + arp.keys).toSortedSet()

        // Cache en mémoire des fabricants résolus en ligne : évite d'interroger
        // deux fois le même préfixe OUI au cours d'un même scan.
        val vendorCache = HashMap<String, String>()

        val localIp = ip
        allIps.map { host ->
            val mac = arp[host] ?: ""
            var vendor = vendorFor(mac, oui)
            // Repli en ligne si la base locale ne connaît pas le préfixe.
            if (vendor.isBlank() && mac.isNotBlank()) {
                vendor = VendorLookup.lookup(mac, vendorCache, prefs) ?: ""
            }
            val hostname = reverseDns(host)
            val ports = if (scanPorts && alive.contains(host)) PortScanner.scanPorts(host) else emptyList()
            val os = OsFingerprint.guess(ttlMap[host], ports, hostname)
            Device(
                ip = host,
                mac = mac,
                vendor = vendor,
                hostname = hostname,
                alive = alive.contains(host),
                isSelf = host == localIp,
                ports = ports,
                ttl = ttlMap[host],
                os = os,
                type = DeviceType.classify(vendor, hostname, ports, os)
            )
        }.sortedBy { it.ip }
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
            PingResult(ok, ttl)
        } catch (e: Exception) {
            PingResult(false, null)
        }
    }

    /** Extrait le TTL de la sortie ping (« ttl=64 »). */
    fun parseTtl(pingOutput: String): Int? =
        Regex("ttl=(\\d+)").find(pingOutput)?.groupValues?.get(1)?.toIntOrNull()

    private fun reverseDns(host: String): String {
        return try {
            val name = InetAddress.getByName(host).hostName ?: ""
            if (name == host) "" else name
        } catch (e: Exception) {
            ""
        }
    }
}

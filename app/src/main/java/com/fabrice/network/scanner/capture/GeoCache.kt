package com.fabrice.network.scanner.capture

import com.fabrice.network.scanner.NetworkInfoProvider
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Cache GeoIP des IP distantes de la capture (v1.9.34) — OPT-IN : chaque IP
 * publique inconnue est envoyée à ipinfo.io (comme l'écran Réseau pour l'IP
 * WAN). Résolution en série sur un thread dédié, au plus une requête toutes
 * les [MIN_INTERVAL_MS], cache mémoire process-wide.
 */
object GeoCache {

    data class Geo(val country: String, val city: String, val org: String) {
        val label: String
            get() = listOf(flag(country) + country, city, org).filter { it.isNotBlank() }.joinToString(" · ")
    }

    private const val MIN_INTERVAL_MS = 250L
    private val cache = ConcurrentHashMap<String, Geo>()
    private val queue = ConcurrentLinkedQueue<String>()
    private val queued = ConcurrentHashMap.newKeySet<String>()
    private val workerRunning = AtomicBoolean(false)

    fun get(ip: String): Geo? = cache[ip]

    /** Pays (code ISO) déjà connus pour un ensemble d'IP. */
    fun countries(ips: Collection<String>): List<String> =
        ips.mapNotNull { cache[it]?.country }.filter { it.isNotBlank() }.distinct().sorted()

    /** Planifie la résolution de [ip] si publique et inconnue (no-op sinon). */
    fun request(ip: String) {
        if (ip.isBlank() || cache.containsKey(ip) || !isPublic(ip)) return
        if (!queued.add(ip)) return
        queue.add(ip)
        if (workerRunning.compareAndSet(false, true)) {
            Thread({ drain() }, "geo-lookup").apply { isDaemon = true }.start()
        }
    }

    private fun drain() {
        try {
            while (true) {
                val ip = queue.poll() ?: break
                val info = runCatching { NetworkInfoProvider.fetchGeoIp(ip, 4_000) }.getOrNull()
                cache[ip] = if (info == null) Geo("", "", "")
                else Geo(info.country, info.city, info.org.substringAfter(' ').ifBlank { info.org })
                queued.remove(ip)
                try { Thread.sleep(MIN_INTERVAL_MS) } catch (e: InterruptedException) { break }
            }
        } finally {
            workerRunning.set(false)
            if (queue.isNotEmpty() && workerRunning.compareAndSet(false, true)) drain()
        }
    }

    /** Drapeau emoji d'un code pays ISO-3166 alpha-2 (vide si inconnu). */
    fun flag(cc: String): String {
        if (cc.length != 2 || !cc.all { it in 'A'..'Z' }) return ""
        val a = 0x1F1E6 + (cc[0] - 'A'); val b = 0x1F1E6 + (cc[1] - 'A')
        return String(Character.toChars(a)) + String(Character.toChars(b))
    }

    /** IP routable sur Internet (exclut privées, loopback, link-local, multicast, ULA). */
    fun isPublic(ip: String): Boolean {
        if (ip.contains(':')) {
            val l = ip.lowercase()
            return !(l == "::1" || l.startsWith("fe80") || l.startsWith("fc") || l.startsWith("fd") ||
                l.startsWith("ff") || l == "::")
        }
        val p = ip.split('.').mapNotNull { it.toIntOrNull() }
        if (p.size != 4) return false
        return !(p[0] == 10 || p[0] == 127 || p[0] == 0 ||
            (p[0] == 172 && p[1] in 16..31) || (p[0] == 192 && p[1] == 168) ||
            (p[0] == 169 && p[1] == 254) || (p[0] == 100 && p[1] in 64..127) || p[0] >= 224)
    }
}

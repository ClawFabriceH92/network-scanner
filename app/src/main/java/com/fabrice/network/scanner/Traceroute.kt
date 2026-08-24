package com.fabrice.network.scanner

import java.util.concurrent.TimeUnit

/**
 * Traceroute « maison » via le binaire ping système (TTL croissant), sans root.
 * Chaque saut est sondé avec `ping -t <ttl>` : le routeur intermédiaire répond
 * « TTL exceeded » en révélant son IP. S'arrête en atteignant la cible.
 */
object Traceroute {

    data class Hop(val ttl: Int, val ip: String, val latencyMs: Int?, val reachedTarget: Boolean)

    /** Trace la route vers [target] (max [maxHops] sauts). Bloquant (IO). */
    fun trace(target: String, maxHops: Int = 20, timeoutSec: Int = 2): List<Hop> {
        val hops = mutableListOf<Hop>()
        for (ttl in 1..maxHops) {
            val out = runCatching { pingTtl(target, ttl, timeoutSec) }.getOrDefault("")
            val hop = parseHop(out, ttl, target)
            hops.add(hop)
            if (hop.reachedTarget) break
        }
        return hops
    }

    private fun pingTtl(target: String, ttl: Int, timeoutSec: Int): String {
        val proc = ProcessBuilder("/system/bin/ping", "-c", "1", "-t", "$ttl", "-W", "$timeoutSec", target)
            .redirectErrorStream(true)
            .start()
        val output = runCatching {
            proc.inputStream.bufferedReader().use { it.readText() }
        }.getOrDefault("")
        runCatching { proc.waitFor(timeoutSec.toLong() + 1, TimeUnit.SECONDS) }
        runCatching { proc.destroy() }
        return output
    }

    /**
     * Parse la sortie ping d'un saut. Cas gérés :
     * - réponse de la cible (« 64 bytes from <target>: … time=X ») → reachedTarget
     * - saut intermédiaire (« From <ip> icmp_seq=1 Time to live exceeded »)
     * - pas de réponse → ip « * »
     * Fonction pure — testable.
     */
    fun parseHop(output: String, ttl: Int, target: String): Hop {
        val time = Regex("time[=<]([0-9.]+)").find(output)?.groupValues?.get(1)?.toDoubleOrNull()?.toInt()
        // Réponse directe de la cible.
        val fromTarget = Regex("bytes from ([0-9.]+)").find(output)?.groupValues?.get(1)
        if (fromTarget != null && !output.contains("Time to live exceeded", ignoreCase = true)) {
            return Hop(ttl, fromTarget, time, reachedTarget = fromTarget == target || target.isBlank())
        }
        // Saut intermédiaire (TTL dépassé).
        val exceeded = Regex("From ([0-9.]+).*(?:Time to live exceeded|ttl)", RegexOption.IGNORE_CASE)
            .find(output)?.groupValues?.get(1)
        if (exceeded != null) return Hop(ttl, exceeded, time, reachedTarget = false)
        return Hop(ttl, "*", null, reachedTarget = false)
    }
}

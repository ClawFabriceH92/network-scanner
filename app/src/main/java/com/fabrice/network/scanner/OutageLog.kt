package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Journal des coupures Internet (v1.9.37).
 *
 * À chaque passage de la surveillance (et à chaque scan manuel), une sonde
 * TCP vers des serveurs publics dit si Internet répond alors que le Wi-Fi
 * local est là. Les TRANSITIONS (up→down, down→up) sont journalisées et
 * notifiées ; un battement de cœur est ajouté toutes les 6 h pour que la
 * disponibilité reste calculable. Résolution = intervalle de surveillance.
 * Logique de calcul pure (outages / availabilityPercent), testable.
 */
object OutageLog {

    data class Event(val ts: Long, val up: Boolean, val latencyMs: Int?)
    data class Outage(val startMs: Long, val endMs: Long?) {
        val ongoing get() = endMs == null
        fun durationMs(nowMs: Long): Long = (endMs ?: nowMs) - startMs
    }
    /** Transition détectée par [check] : DOWN (coupure) ou UP (rétablissement). */
    data class Transition(val down: Boolean, val outageMs: Long)

    const val MAX_EVENTS = 2000
    const val HEARTBEAT_MS = 6L * 3600_000

    private val PROBES = listOf("1.1.1.1" to 443, "8.8.8.8" to 53, "9.9.9.9" to 443)

    /** Coupures (du plus ancien au plus récent) d'après les transitions d'état. */
    fun outages(events: List<Event>): List<Outage> {
        val out = mutableListOf<Outage>()
        var downSince: Long? = null
        events.sortedBy { it.ts }.forEach { e ->
            if (!e.up && downSince == null) downSince = e.ts
            if (e.up && downSince != null) { out.add(Outage(downSince!!, e.ts)); downSince = null }
        }
        downSince?.let { out.add(Outage(it, null)) }
        return out
    }

    /**
     * Disponibilité (%) sur [sinceMs, nowMs] : l'état d'un événement persiste
     * jusqu'au suivant. null si aucun événement dans la fenêtre ni avant.
     */
    fun availabilityPercent(events: List<Event>, sinceMs: Long, nowMs: Long): Double? {
        val sorted = events.sortedBy { it.ts }
        if (sorted.isEmpty() || nowMs <= sinceMs) return null
        var state: Boolean? = sorted.lastOrNull { it.ts <= sinceMs }?.up
        var cursor = sinceMs
        var upMs = 0L; var knownMs = 0L
        for (e in sorted.filter { it.ts > sinceMs && it.ts <= nowMs }) {
            if (state != null) { knownMs += e.ts - cursor; if (state) upMs += e.ts - cursor }
            state = e.up; cursor = e.ts
        }
        if (state != null) { knownMs += nowMs - cursor; if (state) upMs += nowMs - cursor }
        if (knownMs <= 0) return null
        return upMs * 100.0 / knownMs
    }

    /** Faut-il journaliser ? Sur changement d'état, ou battement de cœur > 6 h. */
    fun shouldRecord(last: Event?, up: Boolean, nowMs: Long): Boolean =
        last == null || last.up != up || nowMs - last.ts >= HEARTBEAT_MS

    fun formatDuration(ms: Long): String {
        val min = ms / 60_000
        return when {
            min < 1 -> "< 1 min"
            min < 60 -> "$min min"
            min < 24 * 60 -> "${min / 60} h ${min % 60} min"
            else -> "${min / (24 * 60)} j ${(min % (24 * 60)) / 60} h"
        }
    }

    // ---- Sonde ----------------------------------------------------------

    /** Latence (ms) du premier serveur public joignable en TCP, ou null (Internet coupé). */
    fun probe(timeoutMs: Int = 2_500): Int? {
        for ((host, port) in PROBES) {
            val t0 = System.currentTimeMillis()
            val ok = runCatching {
                Socket().use { it.connect(InetSocketAddress(host, port), timeoutMs); true }
            }.getOrDefault(false)
            if (ok) return (System.currentTimeMillis() - t0).toInt()
        }
        return null
    }

    // ---- Persistance ----------------------------------------------------

    private fun file(context: Context) = File(context.filesDir, "outage_log.json")

    fun load(context: Context): List<Event> = runCatching {
        val f = file(context)
        if (!f.exists()) return emptyList()
        val arr = JSONArray(f.readText())
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            Event(o.optLong("ts"), o.optBoolean("up"), if (o.isNull("lat")) null else o.optInt("lat"))
        }
    }.getOrDefault(emptyList())

    fun save(context: Context, events: List<Event>) {
        val arr = JSONArray()
        events.takeLast(MAX_EVENTS).forEach { e ->
            arr.put(JSONObject().put("ts", e.ts).put("up", e.up).put("lat", e.latencyMs ?: JSONObject.NULL))
        }
        runCatching { file(context).writeText(arr.toString()) }
    }

    fun clear(context: Context) = save(context, emptyList())

    /**
     * Sonde Internet, journalise si nécessaire et retourne la transition
     * éventuelle (coupure ou rétablissement avec sa durée).
     */
    fun check(context: Context, nowMs: Long = System.currentTimeMillis()): Transition? {
        val latency = probe()
        val up = latency != null
        val events = load(context)
        val last = events.lastOrNull()
        if (!shouldRecord(last, up, nowMs)) return null
        save(context, events + Event(nowMs, up, latency))
        if (last == null || last.up == up) return null
        return if (up) {
            val downSince = outages(events).lastOrNull { it.ongoing }?.startMs ?: last.ts
            Transition(down = false, outageMs = nowMs - downSince)
        } else Transition(down = true, outageMs = 0)
    }
}

package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Historique de latence par appareil : à chaque scan on enregistre la latence
 * mesurée (ping). Permet d'afficher min/moyenne/max et la gigue (jitter) dans le
 * temps. Un fichier JSON par appareil (clé d'identité), borné.
 */
class LatencyHistoryStore(context: Context) {

    private val dir = java.io.File(context.filesDir, "latency").apply { mkdirs() }

    data class Sample(val timestamp: Long, val latencyMs: Int)

    data class Stats(val count: Int, val min: Int, val avg: Int, val max: Int, val jitter: Int)

    private fun fileFor(key: String): java.io.File {
        val safe = key.replace(Regex("[^A-Za-z0-9_.-]"), "_")
        return java.io.File(dir, "$safe.json")
    }

    /** Ajoute un échantillon si l'appareil a une latence mesurée. */
    fun record(device: Device, now: Long) {
        val ms = device.latencyMs ?: return
        val key = ScanHistory.identityKey(device)
        val samples = load(key).toMutableList()
        samples.add(Sample(now, ms))
        while (samples.size > MAX_SAMPLES) samples.removeAt(0)
        save(key, samples)
    }

    fun load(key: String): List<Sample> {
        val f = fileFor(key)
        if (!f.exists()) return emptyList()
        return try {
            val arr = JSONArray(f.readText())
            (0 until arr.length()).map {
                val o = arr.getJSONObject(it)
                Sample(o.optLong("ts"), o.optInt("ms"))
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Statistiques agrégées, ou null si aucun échantillon. */
    fun stats(key: String): Stats? = statsOf(load(key).map { it.latencyMs })

    private fun save(key: String, samples: List<Sample>) {
        val arr = JSONArray()
        samples.forEach { arr.put(JSONObject().put("ts", it.timestamp).put("ms", it.latencyMs)) }
        runCatching { fileFor(key).writeText(arr.toString()) }
    }

    companion object {
        const val MAX_SAMPLES = 200

        /**
         * Calcule min/moyenne/max + gigue (moyenne des écarts absolus successifs).
         * Fonction pure — testable. null si la liste est vide.
         */
        fun statsOf(values: List<Int>): Stats? {
            if (values.isEmpty()) return null
            val min = values.min()
            val max = values.max()
            val avg = values.sum() / values.size
            val jitter = if (values.size < 2) 0 else {
                var sum = 0
                for (i in 1 until values.size) sum += kotlin.math.abs(values[i] - values[i - 1])
                sum / (values.size - 1)
            }
            return Stats(values.size, min, avg, max, jitter)
        }
    }
}

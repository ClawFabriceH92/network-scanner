package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Historique des débits (v1.9.0) : fichier `filesDir/speed_history.json`
 * (JSONArray d'entrées `{ts, downMbps, upMbps, latencyMs}`), borné à 200
 * entrées (rotation FIFO). La logique pure (rotate / toJson / parse) est
 * testable en JVM sans Context.
 */
object SpeedHistoryStore {

    data class Entry(
        val ts: Long,
        val downMbps: Double,
        val upMbps: Double,
        val latencyMs: Int
    )

    const val MAX_ENTRIES = 200

    /** Ajoute [newEntry] et borne à [max] (FIFO — les plus anciennes sortent). */
    fun rotate(existing: List<Entry>, newEntry: Entry, max: Int = MAX_ENTRIES): List<Entry> {
        val list = existing.toMutableList()
        list.add(newEntry)
        while (list.size > max) list.removeAt(0)
        return list
    }

    fun toJson(entries: List<Entry>): String {
        val arr = JSONArray()
        entries.forEach { e ->
            arr.put(
                JSONObject().apply {
                    put("ts", e.ts)
                    put("downMbps", e.downMbps)
                    put("upMbps", e.upMbps)
                    put("latencyMs", e.latencyMs)
                }
            )
        }
        return arr.toString()
    }

    fun parse(raw: String): List<Entry> = try {
        val arr = JSONArray(raw)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            Entry(
                ts = o.getLong("ts"),
                downMbps = o.getDouble("downMbps"),
                upMbps = o.getDouble("upMbps"),
                latencyMs = o.getInt("latencyMs")
            )
        }
    } catch (e: Exception) {
        emptyList()
    }

    // --- Persistance fichier (Android) ---

    private fun file(context: Context) = File(context.filesDir, "speed_history.json")

    fun append(context: Context, entry: Entry) =
        write(context, rotate(load(context), entry))

    fun load(context: Context): List<Entry> =
        parse(file(context).takeIf { it.exists() }?.readText().orEmpty())

    fun clear(context: Context) = write(context, emptyList())

    private fun write(context: Context, entries: List<Entry>) {
        runCatching { file(context).writeText(toJson(entries)) }
    }
}

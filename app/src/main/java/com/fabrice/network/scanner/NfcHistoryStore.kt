package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Historique NFC local (v1.9.0) : fichier `filesDir/nfc_history.json` (JSONArray),
 * borné 200 entrées (rotation FIFO). Dédup par UID : chaque tag vu à nouveau
 * incrémente `views` + met à jour `lastTs` (pattern SpeedHistoryStore).
 */
object NfcHistoryStore {

    data class HistoryEntry(
        val uid: String,
        val techs: List<String>,
        val payload: String?,
        val views: Int,
        val firstTs: Long,
        val lastTs: Long
    )

    const val MAX_ENTRIES = 200

    /** Dédup par UID (incrémente views) + rotation FIFO à [max]. Pure, testable. */
    fun rotate(
        existing: List<HistoryEntry>,
        new: NfcReader.NfcLogEntry,
        max: Int = MAX_ENTRIES
    ): List<HistoryEntry> {
        val list = existing.toMutableList()
        val idx = if (new.uid.isBlank()) -1 else list.indexOfFirst { it.uid == new.uid }
        if (idx >= 0) {
            val old = list.removeAt(idx)
            list.add(
                old.copy(
                    views = old.views + 1,
                    lastTs = new.ts,
                    techs = (old.techs + new.techs).distinct(),
                    payload = new.payload ?: old.payload
                )
            )
        } else {
            list.add(HistoryEntry(new.uid, new.techs, new.payload, 1, new.ts, new.ts))
        }
        while (list.size > max) list.removeAt(0)
        return list
    }

    fun toJson(entries: List<HistoryEntry>): String {
        val arr = JSONArray()
        entries.forEach { e ->
            arr.put(
                JSONObject().apply {
                    put("uid", e.uid)
                    put("techs", JSONArray(e.techs))
                    put("payload", e.payload ?: JSONObject.NULL)
                    put("views", e.views)
                    put("firstTs", e.firstTs)
                    put("lastTs", e.lastTs)
                }
            )
        }
        return arr.toString()
    }

    fun parse(raw: String): List<HistoryEntry> = try {
        val arr = JSONArray(raw)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            val techs = mutableListOf<String>()
            val t = o.optJSONArray("techs")
            if (t != null) for (j in 0 until t.length()) techs.add(t.getString(j))
            HistoryEntry(
                uid = o.optString("uid", ""),
                techs = techs,
                payload = if (o.isNull("payload")) null else o.optString("payload"),
                views = o.optInt("views", 1),
                firstTs = o.optLong("firstTs", 0),
                lastTs = o.optLong("lastTs", 0)
            )
        }
    } catch (e: Exception) {
        emptyList()
    }

    // --- Persistance fichier (Android) ---

    private fun file(context: Context) = File(context.filesDir, "nfc_history.json")

    fun record(context: Context, entry: NfcReader.NfcLogEntry) =
        write(context, rotate(load(context), entry))

    /** Historique, récent en premier. */
    fun all(context: Context): List<HistoryEntry> = load(context).asReversed()

    fun clear(context: Context) = write(context, emptyList())

    private fun load(context: Context): List<HistoryEntry> =
        parse(file(context).takeIf { it.exists() }?.readText().orEmpty())

    private fun write(context: Context, entries: List<HistoryEntry>) {
        runCatching { file(context).writeText(toJson(entries)) }
    }
}

package com.fabrice.network.scanner

import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Journal d'audit horodaté (v1.9.3) : événements du scan
 * (« 07:32 Surface Films connectée », « Inconnu 192.168.1.97 apparu »,
 * « Surface Films absente »…), borné à 500 entrées (rotation FIFO).
 *
 * Logique pure (recordEvent / toJson / parse) testable en JVM ; la persistance
 * fichier est dans [AuditLogStore].
 */
object AuditLog {

    data class Event(val ts: Long, val message: String)

    const val MAX_ENTRIES = 500

    /** Ajoute [message] à [list] et borne à [MAX_ENTRIES] (FIFO). Pure. */
    fun recordEvent(list: List<Event>, message: String, ts: Long = System.currentTimeMillis()): List<Event> {
        val out = list.toMutableList()
        out.add(Event(ts, message))
        while (out.size > MAX_ENTRIES) out.removeAt(0)
        return out
    }

    /** Sérialise la liste en JSONArray (champs ts + message). */
    fun toJson(events: List<Event>): String {
        val arr = JSONArray()
        events.forEach { e ->
            arr.put(
                JSONObject().apply {
                    put("ts", e.ts)
                    put("message", e.message)
                }
            )
        }
        return arr.toString()
    }

    /** Parse le JSON produit par [toJson] (garbage → liste vide). */
    fun parse(raw: String): List<Event> = try {
        val arr = JSONArray(raw)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            Event(o.getLong("ts"), o.getString("message"))
        }
    } catch (e: Exception) {
        emptyList()
    }

    /** Heure courte (« 07:32 ») pour la liste chronologique. */
    fun formatTime(ts: Long): String =
        SimpleDateFormat("HH:mm", Locale.FRENCH).format(Date(ts))

    /** Horodatage complet (jour + heure) pour l'export. */
    fun formatFull(ts: Long): String =
        SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.FRENCH).format(Date(ts))
}

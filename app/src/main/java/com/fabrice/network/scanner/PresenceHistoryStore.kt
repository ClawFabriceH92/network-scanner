package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Persistance de l'historique de présence : fichier `filesDir/presence_history.json`
 * (JSONObject : key → [ts, ts, ts…]). Voir [PresenceHistory] pour la logique pure.
 */
class PresenceHistoryStore(context: Context) {

    private val file: File = File(context.filesDir, "presence_history.json")

    /** Charge le registre key → timestamps (vide si fichier absent/corrompu). */
    fun load(): Map<String, List<Long>> {
        return runCatching {
            val json = JSONObject(file.readText())
            val out = mutableMapOf<String, List<Long>>()
            val keys = json.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                val arr = json.getJSONArray(key)
                val list = mutableListOf<Long>()
                for (i in 0 until arr.length()) list.add(arr.getLong(i))
                out[key] = list
            }
            out
        }.getOrDefault(emptyMap())
    }

    /** Sauvegarde le registre (chaque liste bornée à [PresenceHistory.MAX_ENTRIES]). */
    fun save(registry: Map<String, List<Long>>) {
        runCatching {
            val json = JSONObject()
            registry.forEach { (k, v) ->
                val arr = JSONArray()
                v.takeLast(PresenceHistory.MAX_ENTRIES).forEach { arr.put(it) }
                json.put(k, arr)
            }
            file.writeText(json.toString())
        }
    }
}

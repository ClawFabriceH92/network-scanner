package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * « Déjà vu ? » pour TOUS les périphériques Bluetooth (v1.9.40) : pour chaque
 * adresse, première/dernière observation, nombre de scans, lieux (profils
 * réseau) et dernier nom. Logique pure ; persistance dans [BtSeenStore].
 *
 * Limite : un appareil qui randomise son adresse BLE (téléphones, AirTag…)
 * réapparaît sous une nouvelle adresse et passe donc pour « nouveau ».
 */
object BtSeen {

    data class Info(
        val firstSeen: Long,
        val lastSeen: Long,
        val count: Int,
        val places: List<String>,
        val name: String
    ) {
        /** Vu uniquement lors du scan courant. */
        val isNew: Boolean get() = count <= 1

        fun label(nowMs: Long = System.currentTimeMillis()): String {
            if (isNew) return "🆕 Jamais vu avant ce scan"
            val fmt = SimpleDateFormat("dd/MM", Locale.FRENCH)
            val sb = StringBuilder("Vu ${count}× depuis le ${fmt.format(Date(firstSeen))}")
            if (places.size > 1) sb.append(" · ${places.size} lieux")
            val gapMin = (nowMs - lastSeen) / 60_000
            if (gapMin >= 60 * 24) sb.append(" · dernier il y a ${gapMin / (60 * 24)} j")
            else if (gapMin >= 60) sb.append(" · dernier il y a ${gapMin / 60} h")
            return sb.toString()
        }
    }

    const val RETENTION_MS = 90L * 24 * 3600_000

    /** Ajoute les appareils de ce scan (lieu [place]) ; purge > 90 j. Pure. */
    fun record(
        existing: Map<String, Info>,
        devices: List<BluetoothScanner.BtDevice>,
        place: String,
        nowMs: Long
    ): Map<String, Info> {
        val out = HashMap<String, Info>()
        existing.forEach { (mac, i) -> if (nowMs - i.lastSeen <= RETENTION_MS) out[mac] = i }
        devices.forEach { d ->
            val prev = out[d.mac]
            val places = (prev?.places.orEmpty() + place).filter { it.isNotBlank() }.distinct()
            out[d.mac] = if (prev == null) Info(nowMs, nowMs, 1, places, d.name)
            else Info(prev.firstSeen, nowMs, prev.count + 1, places, d.name.ifBlank { prev.name })
        }
        return out
    }

    fun toJson(map: Map<String, Info>): String {
        val o = JSONObject()
        map.forEach { (mac, i) ->
            o.put(mac, JSONObject()
                .put("first", i.firstSeen).put("last", i.lastSeen).put("count", i.count)
                .put("places", JSONArray(i.places)).put("name", i.name))
        }
        return o.toString()
    }

    fun fromJson(json: String?): Map<String, Info> {
        if (json.isNullOrBlank()) return emptyMap()
        return runCatching {
            val o = JSONObject(json)
            val out = HashMap<String, Info>()
            o.keys().forEach { mac ->
                val e = o.getJSONObject(mac)
                val pl = e.optJSONArray("places")
                out[mac] = Info(
                    e.optLong("first"), e.optLong("last"), e.optInt("count", 1),
                    if (pl == null) emptyList() else (0 until pl.length()).map { pl.getString(it) },
                    e.optString("name", "")
                )
            }
            out
        }.getOrDefault(emptyMap())
    }
}

/** Persistance « déjà vu » (filesDir/bt_seen.json). */
class BtSeenStore(context: Context) {
    private val file = File(context.filesDir, "bt_seen.json")

    fun load(): Map<String, BtSeen.Info> =
        BtSeen.fromJson(runCatching { file.takeIf { it.exists() }?.readText() }.getOrNull())

    fun recordScan(devices: List<BluetoothScanner.BtDevice>, place: String, nowMs: Long = System.currentTimeMillis()): Map<String, BtSeen.Info> {
        val map = BtSeen.record(load(), devices, place, nowMs)
        runCatching { file.writeText(BtSeen.toJson(map)) }
        return map
    }
}

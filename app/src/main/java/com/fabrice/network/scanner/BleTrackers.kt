package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Détection des traceurs Bluetooth (v1.9.37) : AirTag / accessoires Find My,
 * Samsung SmartTag, Tile, Chipolo, Google Find My Device — d'après les trames
 * d'annonce BLE (données constructeur + UUID de service). Logique pure.
 *
 * Un traceur « qui te suit » = vu à plusieurs LIEUX (profils réseau) ou de
 * façon répétée sur une longue durée, sans être un appareil apparié.
 * Limite connue : un AirTag séparé de son propriétaire change d'adresse
 * toutes les 24 h (15 min quand le propriétaire est proche) — le suivi par
 * adresse ne couvre donc qu'une journée, ce qui suffit pour un trajet.
 */
object BleTrackers {

    /** Type de traceur, ou null si la trame n'en est pas un. */
    fun classify(
        manufacturer: Map<Int, ByteArray>,
        serviceUuids: List<String>,
        serviceData: Map<String, ByteArray>
    ): String? {
        val uuids = serviceUuids.map { shortUuid(it) }
        // Apple : type 0x12 = Offline Finding (réseau Find My : AirTag, accessoires).
        manufacturer[0x004C]?.let { d ->
            if (d.isNotEmpty() && (d[0].toInt() and 0xFF) == 0x12) return "Apple Find My (AirTag / accessoire)"
        }
        if ("FD5A" in uuids) return "Samsung SmartTag"
        if ("FEED" in uuids || "FD84" in uuids) return "Tile"
        if ("FE33" in uuids) return "Chipolo"
        // Google Find My Device Network : service data 0xFEAA, frame 0x40/0x41.
        serviceData.entries.firstOrNull { shortUuid(it.key) == "FEAA" }?.value?.let { d ->
            if (d.isNotEmpty() && (d[0].toInt() and 0xFF) in setOf(0x40, 0x41)) return "Google Find My Device"
        }
        manufacturer[0x0075]?.let { d ->
            // Samsung : certaines SmartTag n'annoncent que les données constructeur (type 0x42 + 0x09).
            if (d.size >= 2 && (d[0].toInt() and 0xFF) == 0x42 && (d[1].toInt() and 0xFF) == 0x09) return "Samsung SmartTag"
        }
        return null
    }

    /** « 0000fd5a-0000-1000-8000-00805f9b34fb » → « FD5A ». */
    fun shortUuid(uuid: String): String {
        val u = uuid.replace("-", "").uppercase()
        return if (u.length >= 8) u.substring(4, 8) else u
    }

    // ---- Suivi dans le temps ---------------------------------------------

    data class Sighting(val ts: Long, val place: String, val rssi: Int)

    data class Assessment(
        val sightings: Int,
        val places: Int,
        val spanMinutes: Long,
        val following: Boolean
    ) {
        val label: String
            get() = buildString {
                append("vu $sightings fois")
                if (places > 1) append(" à $places lieux")
                if (spanMinutes >= 60) append(" sur ${spanMinutes / 60} h") else if (spanMinutes > 0) append(" sur $spanMinutes min")
            }
    }

    /**
     * Un traceur « suit » l'utilisateur s'il a été vu à ≥ 2 lieux distincts,
     * ou ≥ 3 fois sur ≥ 1 h. Pure.
     */
    fun assess(sightings: List<Sighting>): Assessment {
        if (sightings.isEmpty()) return Assessment(0, 0, 0, false)
        val places = sightings.map { it.place }.filter { it.isNotBlank() }.distinct().size
        val span = (sightings.maxOf { it.ts } - sightings.minOf { it.ts }) / 60_000
        val following = places >= 2 || (sightings.size >= 3 && span >= 60)
        return Assessment(sightings.size, places, span, following)
    }

    const val RETENTION_MS = 7L * 24 * 3600_000

    fun toJson(map: Map<String, List<Sighting>>): String {
        val o = JSONObject()
        map.forEach { (mac, list) ->
            val arr = JSONArray()
            list.forEach { s -> arr.put(JSONObject().put("ts", s.ts).put("place", s.place).put("rssi", s.rssi)) }
            o.put(mac, arr)
        }
        return o.toString()
    }

    fun fromJson(json: String?): Map<String, List<Sighting>> {
        if (json.isNullOrBlank()) return emptyMap()
        return runCatching {
            val o = JSONObject(json)
            val out = HashMap<String, List<Sighting>>()
            o.keys().forEach { mac ->
                val arr = o.optJSONArray(mac) ?: return@forEach
                out[mac] = (0 until arr.length()).map { i ->
                    val e = arr.getJSONObject(i)
                    Sighting(e.optLong("ts"), e.optString("place", ""), e.optInt("rssi", -100))
                }
            }
            out
        }.getOrDefault(emptyMap())
    }

    /** Ajoute les traceurs de [devices] (lieu [place]) et purge > 7 jours. Pure. */
    fun record(
        existing: Map<String, List<Sighting>>,
        devices: List<BluetoothScanner.BtDevice>,
        place: String,
        nowMs: Long
    ): Map<String, List<Sighting>> {
        val out = HashMap<String, MutableList<Sighting>>()
        existing.forEach { (mac, list) ->
            val kept = list.filter { nowMs - it.ts <= RETENTION_MS }
            if (kept.isNotEmpty()) out[mac] = kept.toMutableList()
        }
        devices.filter { it.trackerType.isNotBlank() && it.type != "apparié" }.forEach { d ->
            out.getOrPut(d.mac) { mutableListOf() }.add(Sighting(nowMs, place, d.rssi))
        }
        return out
    }
}

/** Persistance des observations de traceurs (filesDir/tracker_sightings.json). */
class TrackerSightingStore(context: Context) {
    private val file = File(context.filesDir, "tracker_sightings.json")
    private val prefs = context.getSharedPreferences("tracker_prefs", Context.MODE_PRIVATE)

    fun load(): Map<String, List<BleTrackers.Sighting>> =
        BleTrackers.fromJson(runCatching { file.takeIf { it.exists() }?.readText() }.getOrNull())

    fun save(map: Map<String, List<BleTrackers.Sighting>>) {
        runCatching { file.writeText(BleTrackers.toJson(map)) }
    }

    fun assess(mac: String): BleTrackers.Assessment = BleTrackers.assess(load()[mac].orEmpty())

    /** Enregistre le scan et retourne les traceurs qui « suivent » (à notifier au plus 1×/jour). */
    fun recordScan(devices: List<BluetoothScanner.BtDevice>, place: String, nowMs: Long = System.currentTimeMillis()): List<BluetoothScanner.BtDevice> {
        val map = BleTrackers.record(load(), devices, place, nowMs)
        save(map)
        return devices.filter { d ->
            d.trackerType.isNotBlank() && BleTrackers.assess(map[d.mac].orEmpty()).following &&
                nowMs - prefs.getLong("notified_${d.mac}", 0L) > 24L * 3600_000
        }.also { list ->
            if (list.isNotEmpty()) {
                val e = prefs.edit()
                list.forEach { e.putLong("notified_${it.mac}", nowMs) }
                e.apply()
            }
        }
    }
}

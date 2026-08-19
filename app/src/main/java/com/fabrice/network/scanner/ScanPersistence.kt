package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Persistance du dernier scan : sauvegarde la liste des appareils en JSON
 * (SharedPreferences) et l'horodatage. Permet d'afficher le dernier scan sans
 * rescanner — comme Fing (« scan il y a 20 heures »).
 */
object ScanPersistence {

    private const val PREFS = "last_scan"
    private const val KEY_DEVICES = "devices_json"
    private const val KEY_TS = "timestamp_ms"

    fun save(context: Context, devices: List<Device>) {
        val arr = JSONArray()
        devices.forEach { d ->
            val o = JSONObject()
            o.put("ip", d.ip)
            o.put("mac", d.mac)
            o.put("vendor", d.vendor)
            o.put("hostname", d.hostname)
            o.put("alive", d.alive)
            o.put("isSelf", d.isSelf)
            o.put("isGateway", d.isGateway)
            o.put("ports", JSONArray(d.ports))
            o.put("os", d.os)
            o.put("ttl", d.ttl ?: JSONObject.NULL)
            o.put("type", d.type)
            o.put("banner", d.banner)
            o.put("latencyMs", d.latencyMs ?: JSONObject.NULL)
            o.put("snmpDescr", d.snmpDescr ?: JSONObject.NULL)
            o.put("snmpName", d.snmpName ?: JSONObject.NULL)
            o.put("snmpLocation", d.snmpLocation ?: JSONObject.NULL)
            o.put("snmpUptime", d.snmpUptime ?: JSONObject.NULL)
            arr.put(o)
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_DEVICES, arr.toString())
            .putLong(KEY_TS, System.currentTimeMillis())
            .apply()
    }

    fun load(context: Context): List<Device>? {
        val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_DEVICES, null) ?: return null
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                val ports = mutableListOf<Int>()
                val p = o.optJSONArray("ports")
                if (p != null) for (j in 0 until p.length()) ports.add(p.getInt(j))
                Device(
                    ip = o.optString("ip", ""),
                    mac = o.optString("mac", ""),
                    vendor = o.optString("vendor", ""),
                    hostname = o.optString("hostname", ""),
                    alive = o.optBoolean("alive", true),
                    isSelf = o.optBoolean("isSelf", false),
                    isGateway = o.optBoolean("isGateway", false),
                    ports = ports,
                    os = o.optString("os", ""),
                    ttl = if (o.isNull("ttl")) null else o.optInt("ttl"),
                    type = o.optString("type", "Inconnu"),
                    banner = o.optString("banner", ""),
                    latencyMs = if (o.isNull("latencyMs")) null else o.optInt("latencyMs"),
                    snmpDescr = if (o.isNull("snmpDescr")) null else o.optString("snmpDescr"),
                    snmpName = if (o.isNull("snmpName")) null else o.optString("snmpName"),
                    snmpLocation = if (o.isNull("snmpLocation")) null else o.optString("snmpLocation"),
                    snmpUptime = if (o.isNull("snmpUptime")) null else o.optLong("snmpUptime")
                )
            }
        } catch (e: Exception) {
            null
        }
    }

    /** Millisecondes depuis le dernier scan (null si jamais scanné). */
    fun ageMs(context: Context): Long? {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!p.contains(KEY_TS)) return null
        return System.currentTimeMillis() - p.getLong(KEY_TS, 0)
    }

    /** Libellé « il y a X min/heure » pour l'âge du scan. */
    fun ageLabel(ageMs: Long): String {
        val min = ageMs / 60_000
        return when {
            min < 1 -> "à l'instant"
            min < 60 -> "il y a $min min"
            else -> {
                val h = min / 60
                if (h < 24) "il y a $h h"
                else "il y a ${h / 24} j"
            }
        }
    }
}

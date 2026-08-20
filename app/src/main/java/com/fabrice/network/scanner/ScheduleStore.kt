package com.fabrice.network.scanner

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Calendar

/**
 * Blocage programmé (v1.9.3) : planifications par MAC — heure de début/fin
 * (minutes depuis minuit), jours (bitmask 0-127) et état actif. Exécutées à la
 * fin d'un scan et dans le worker de surveillance via l'API box.
 *
 * ⚠️ API box requise : Freebox OK (blockDevice/unblockDevice), SFR non supporté.
 * On ne bloque jamais le téléphone courant ni la passerelle (l'UI n'offre la
 * planification que sur les appareils, et l'exécution ne cible que les MAC vues
 * par la box).
 */
object ScheduleStore {

    data class Schedule(
        val mac: String,
        val startMinutes: Int,   // 0..1439
        val endMinutes: Int,     // 0..1439
        val days: Int = 127,     // bitmask 0..127 (bit 0 = dimanche)
        val active: Boolean = true
    )

    const val MAX_ENTRIES = 100

    /** Jour (Calendar.DAY_OF_WEEK : 1=dimanche…7=samedi) → bit correspondant. */
    fun dayBit(calendarDayOfWeek: Int): Int = 1 shl (calendarDayOfWeek - 1)

    /** Le jour courant est-il programmé ? (et la planification est active) */
    fun onDay(s: Schedule, dayBit: Int): Boolean = s.active && (s.days and dayBit != 0)

    /** L'heure courante est-elle dans la fenêtre [start, end) ? (gère minuit). */
    fun inWindow(s: Schedule, nowMinutes: Int): Boolean =
        if (s.startMinutes <= s.endMinutes)
            nowMinutes in s.startMinutes until s.endMinutes
        else
            nowMinutes >= s.startMinutes || nowMinutes < s.endMinutes

    /** Blocage requis MAINTENANT ? (jour programmé ET dans la fenêtre). Pure. */
    fun dueNow(s: Schedule, nowMinutes: Int, dayBit: Int): Boolean =
        onDay(s, dayBit) && inWindow(s, nowMinutes)

    // --- Opérations pures sur une liste de planifications ---

    /** Ajoute (ou remplace) une planification pour une MAC. */
    fun add(list: List<Schedule>, s: Schedule): List<Schedule> {
        val out = list.filterNot { it.mac.replace("-", ":").lowercase() == s.mac.replace("-", ":").lowercase() }.toMutableList()
        out.add(s)
        return out
    }

    /** Retire la planification d'une MAC. */
    fun remove(list: List<Schedule>, mac: String): List<Schedule> =
        list.filterNot { it.mac.replace("-", ":").lowercase() == mac.replace("-", ":").lowercase() }

    /** Bascule l'état actif d'une planification. */
    fun toggle(list: List<Schedule>, mac: String): List<Schedule> =
        list.map {
            if (it.mac.replace("-", ":").lowercase() == mac.replace("-", ":").lowercase())
                it.copy(active = !it.active)
            else it
        }

    // --- JSON ---

    fun toJson(list: List<Schedule>): String {
        val arr = JSONArray()
        list.forEach { s ->
            arr.put(
                JSONObject().apply {
                    put("mac", s.mac)
                    put("start", s.startMinutes)
                    put("end", s.endMinutes)
                    put("days", s.days)
                    put("active", s.active)
                }
            )
        }
        return arr.toString()
    }

    fun parse(raw: String): List<Schedule> = try {
        val arr = JSONArray(raw)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            Schedule(
                mac = o.getString("mac"),
                startMinutes = o.getInt("start"),
                endMinutes = o.getInt("end"),
                days = o.optInt("days", 127),
                active = o.optBoolean("active", true)
            )
        }
    } catch (e: Exception) {
        emptyList()
    }

    // --- Persistance fichier (Android) ---

    private fun file(context: Context) = File(context.filesDir, "schedules.json")

    fun load(context: Context): List<Schedule> =
        parse(file(context).takeIf { it.exists() }?.readText().orEmpty())

    fun save(context: Context, list: List<Schedule>) {
        runCatching { file(context).writeText(toJson(list)) }
    }

    /**
     * Exécute les planifications dues maintenant via l'API box. Pour chaque
     * planification active dont le jour est programmé ET dont la MAC est vue par
     * la box : bloque si on est dans la fenêtre, débloque sinon. Retourne le
     * nombre d'actions effectuées (0 si box indisponible).
     */
    suspend fun applyDue(context: Context): Int = withContext(Dispatchers.IO) {
        val schedules = load(context)
        if (schedules.isEmpty()) return@withContext 0
        val now = Calendar.getInstance()
        val nowMinutes = now.get(Calendar.HOUR_OF_DAY) * 60 + now.get(Calendar.MINUTE)
        val bit = dayBit(now.get(Calendar.DAY_OF_WEEK))
        val client = BoxManager.detect(context) ?: return@withContext 0
        val visible = client.fetchDevices()
            ?.associateBy { it.mac.replace("-", ":").lowercase() }
            ?: return@withContext 0
        var actions = 0
        schedules.filter { onDay(it, bit) }.forEach { s ->
            val norm = s.mac.replace("-", ":").lowercase()
            if (norm !in visible) return@forEach
            val block = inWindow(s, nowMinutes)
            val ok = runCatching {
                if (block) client.blockDevice(s.mac) else client.unblockDevice(s.mac)
            }.getOrDefault(false)
            if (ok) actions++
        }
        actions
    }
}

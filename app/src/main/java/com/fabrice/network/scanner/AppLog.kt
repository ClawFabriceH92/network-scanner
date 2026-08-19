package com.fabrice.network.scanner

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Logger mémoire en anneau (v1.9.0) : dernières 500 lignes, avec niveau et
 * horodatage. Utilisé aux points clés (scan, box, SNMP, update, WoL, creds…)
 * et exportable via `dump()` (boutons « Copier / Partager » dans À propos).
 *
 * Pur (aucune dépendance Android) → testable en JVM.
 */
object AppLog {

    enum class Level(val label: String) {
        DEBUG("D"),
        INFO("I"),
        WARN("W"),
        ERROR("E")
    }

    private data class Entry(val level: Level, val tag: String, val msg: String, val ts: Long)

    const val MAX_ENTRIES = 500

    private val entries = ArrayDeque<Entry>()
    private val timeFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    @Synchronized
    fun log(level: Level, tag: String, msg: String) {
        entries.addLast(Entry(level, tag, msg, System.currentTimeMillis()))
        while (entries.size > MAX_ENTRIES) entries.removeFirst()
    }

    fun d(tag: String, msg: String) = log(Level.DEBUG, tag, msg)
    fun i(tag: String, msg: String) = log(Level.INFO, tag, msg)
    fun w(tag: String, msg: String) = log(Level.WARN, tag, msg)
    fun e(tag: String, msg: String) = log(Level.ERROR, tag, msg)

    /** Nombre de lignes actuellement en mémoire. */
    @Synchronized
    fun size(): Int = entries.size

    @Synchronized
    fun clear() {
        entries.clear()
    }

    /** Export texte complet (format stable, lisible, trié chronologiquement). */
    @Synchronized
    fun dump(): String = buildString {
        appendLine("=== NetworkScanner logs (${entries.size} lignes, max $MAX_ENTRIES) ===")
        entries.forEach { e ->
            append("${timeFormat.format(Date(e.ts))} [${e.level.label}] ${e.tag}: ${e.msg}")
            appendLine()
        }
    }
}

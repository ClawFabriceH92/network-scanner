package com.fabrice.network.scanner

import android.content.Context
import java.io.File

/**
 * Persistance du journal d'audit (v1.9.3) : fichier `filesDir/audit_log.json`
 * (JSONArray d'événements {ts, message}). La rotation est gérée par
 * [AuditLog.recordEvent] (500 entrées max).
 *
 * Le fichier est écrit à la fois par le scan de premier plan et par le
 * [SurveillanceWorker] en arrière-plan : les accès sont sérialisés par un verrou
 * partagé au niveau processus ([LOCK]) et l'écriture est atomique (fichier
 * temporaire + renommage) pour ne jamais laisser un JSON tronqué.
 */
class AuditLogStore(context: Context) {

    private val file: File = File(context.filesDir, "audit_log.json")

    fun load(): List<AuditLog.Event> = synchronized(LOCK) {
        AuditLog.parse(file.takeIf { it.exists() }?.readText().orEmpty())
    }

    /** Ajoute un événement (borné à 500, FIFO). */
    fun append(message: String, ts: Long = System.currentTimeMillis()) = synchronized(LOCK) {
        val list = AuditLog.recordEvent(load(), message, ts)
        writeAtomic(AuditLog.toJson(list))
    }

    fun clear() = synchronized(LOCK) {
        writeAtomic(AuditLog.toJson(emptyList()))
    }

    private fun writeAtomic(text: String) {
        runCatching {
            val tmp = File(file.parentFile, "${file.name}.tmp")
            tmp.writeText(text)
            if (!tmp.renameTo(file)) {
                file.writeText(text)
                tmp.delete()
            }
        }
    }

    private companion object {
        /** Verrou partagé par TOUTES les instances (premier plan + worker). */
        val LOCK = Any()
    }
}

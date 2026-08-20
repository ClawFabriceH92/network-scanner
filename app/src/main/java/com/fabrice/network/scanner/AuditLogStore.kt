package com.fabrice.network.scanner

import android.content.Context
import java.io.File

/**
 * Persistance du journal d'audit (v1.9.3) : fichier `filesDir/audit_log.json`
 * (JSONArray d'événements {ts, message}). La rotation est gérée par
 * [AuditLog.recordEvent] (500 entrées max).
 */
class AuditLogStore(context: Context) {

    private val file: File = File(context.filesDir, "audit_log.json")

    fun load(): List<AuditLog.Event> =
        AuditLog.parse(file.takeIf { it.exists() }?.readText().orEmpty())

    /** Ajoute un événement (borné à 500, FIFO). */
    fun append(message: String, ts: Long = System.currentTimeMillis()) {
        val list = AuditLog.recordEvent(load(), message, ts)
        runCatching { file.writeText(AuditLog.toJson(list)) }
    }

    fun clear() {
        runCatching { file.writeText(AuditLog.toJson(emptyList())) }
    }
}

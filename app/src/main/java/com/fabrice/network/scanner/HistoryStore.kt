package com.fabrice.network.scanner

import android.content.Context
import java.io.File

/**
 * Historique persistant des appareils vus au fil des scans (format texte
 * stable, voir [ScanHistory]). Utilisé pour détecter les nouveaux appareils
 * d'un scan à l'autre.
 */
class HistoryStore(context: Context) {

    private val file: File = File(context.filesDir, "scan_history.txt")

    fun load(): List<Device> {
        return runCatching { ScanHistory.deserialize(file.readText()) }.getOrDefault(emptyList())
    }

    fun save(devices: List<Device>) {
        runCatching { file.writeText(ScanHistory.serialize(devices)) }
    }
}

package com.fabrice.network.scanner

import android.content.Context
import java.io.File

/**
 * Historique persistant des appareils vus au fil des scans (format texte
 * stable, voir [ScanHistory]). Utilisé pour détecter les nouveaux appareils
 * d'un scan à l'autre.
 *
 * Écrit par le scan de premier plan ET par le [SurveillanceWorker] : accès
 * sérialisés par un verrou partagé au niveau processus, écriture atomique
 * (fichier temporaire + renommage) pour éviter un fichier tronqué qui ferait
 * tout repasser en « nouveaux appareils » au scan suivant.
 */
class HistoryStore(context: Context) {

    private val file: File = File(context.filesDir, "scan_history.txt")

    fun load(): List<Device> = synchronized(LOCK) {
        runCatching { ScanHistory.deserialize(file.readText()) }.getOrDefault(emptyList())
    }

    fun save(devices: List<Device>) = synchronized(LOCK) {
        runCatching {
            val tmp = File(file.parentFile, "${file.name}.tmp")
            tmp.writeText(ScanHistory.serialize(devices))
            if (!tmp.renameTo(file)) {
                file.writeText(ScanHistory.serialize(devices))
                tmp.delete()
            }
        }
        Unit
    }

    private companion object {
        /** Verrou partagé par TOUTES les instances (premier plan + worker). */
        val LOCK = Any()
    }
}

package com.fabrice.network.scanner

import android.content.Context

/**
 * Base CVE embarquée — chargée une seule fois en mémoire.
 *
 * Ordre de priorité :
 * 1. Copie locale mise à jour (filesDir/cve_db.json, téléchargée par
 *    CveUpdateManager) — plus récente que l'asset.
 * 2. Asset embarqué (assets/cve_db.json).
 *
 * Générée par tools/build_cve_db.py depuis CISA KEV + NVD.
 */
object CveDatabaseStore {

    private var db: CveDatabase? = null

    fun load(context: Context): CveDatabase {
        db?.let { return it }
        val loaded = try {
            // Copie locale si elle existe (mise à jour en un tap)
            CveUpdateManager.readLocal(context)
                ?: context.assets.open("cve_db.json")
                    .bufferedReader(Charsets.UTF_8).use { CveDatabase.load(it.readText()) }
        } catch (e: Exception) {
            // Base vide = scan vulnérabilités désactivé, jamais de crash
            CveDatabase("", emptyMap(), emptyMap())
        }
        db = loaded
        return loaded
    }

    /** Version de la base (date de génération) ou null. */
    fun version(context: Context): String? = load(context).generated.ifBlank { null }

    /** True si la base en mémoire est obsolète (> 30 jours). */
    fun isStale(context: Context): Boolean = CveUpdateManager.isStale(version(context) ?: "")

    /** Vide le cache mémoire : force le rechargement (après mise à jour). */
    fun invalidate() {
        db = null
    }
}

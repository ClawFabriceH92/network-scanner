package com.fabrice.network.scanner

import android.content.Context

/**
 * Base CVE embarquée (assets/cve_db.json) — chargée une seule fois en mémoire.
 * Générée par tools/build_cve_db.py depuis CISA KEV + NVD.
 */
object CveDatabaseStore {

    private var db: CveDatabase? = null
    private var loadError: String? = null

    fun load(context: Context): CveDatabase {
        db?.let { return it }
        return try {
            val text = context.assets.open("cve_db.json")
                .bufferedReader(Charsets.UTF_8).use { it.readText() }
            val loaded = CveDatabase.load(text)
            db = loaded
            loaded
        } catch (e: Exception) {
            loadError = e.message
            // Base vide = scan vulnérabilités désactivé, jamais de crash
            CveDatabase("", emptyMap(), emptyMap())
        }
    }

    fun lastError(): String? = loadError

    /** Version de la base (date de génération) ou null. */
    fun version(context: Context): String? = load(context).generated.ifBlank { null }
}

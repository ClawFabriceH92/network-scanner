package com.fabrice.network.scanner

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

/**
 * Mise à jour de la base CVE embarquée (assets/cve_db.json).
 *
 * La base est régénérée côté repo (tools/build_cve_db.py, cron nocturne) puis
 * publiée sur GitHub. L'app peut la télécharger pour rester à jour sans
 * attendre une nouvelle release :
 *   https://raw.githubusercontent.com/ClawFabriceH92/network-scanner/main/app/src/main/assets/cve_db.json
 *
 * La copie locale (filesDir/cve_db.json) prend le pas sur l'asset au chargement.
 */
object CveUpdateManager {

    const val RAW_URL = "https://raw.githubusercontent.com/ClawFabriceH92/network-scanner/main/app/src/main/assets/cve_db.json"
    /** Une base de plus de 30 jours est considérée obsolète. */
    const val STALE_DAYS = 30L

    /** Fichier local où est stockée la base téléchargée. */
    fun localFile(context: Context): File = File(context.filesDir, "cve_db.json")

    fun localExists(context: Context): Boolean = localFile(context).exists()

    /** Lit la base locale si présente (sinon null). */
    fun readLocal(context: Context): CveDatabase? {
        val f = localFile(context)
        if (!f.exists()) return null
        return try {
            CveDatabase.load(f.readText(Charsets.UTF_8))
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Télécharge la base à jour et la sauvegarde localement.
     * @return la base chargée, ou null en cas d'échec (réseau, parse…).
     */
    fun update(context: Context): CveDatabase? {
        return try {
            val conn = URL(RAW_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = 10_000
            conn.readTimeout = 20_000
            conn.setRequestProperty("User-Agent", "NetworkScanner/1.0")
            if (conn.responseCode != 200) {
                conn.disconnect()
                return null
            }
            val text = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            conn.disconnect()
            // Validation : le parse doit réussir et la base ne doit pas être vide
            val db = CveDatabase.load(text)
            if (db.allCount == 0) return null
            localFile(context).writeText(text, Charsets.UTF_8)
            db
        } catch (e: Exception) {
            null
        }
    }

    /** Âge en jours de la base (date `generated` au format yyyy-MM-dd). */
    fun ageDays(generated: String): Long? {
        if (generated.isBlank()) return null
        return try {
            val d = LocalDate.parse(generated.trim(), DateTimeFormatter.ISO_LOCAL_DATE)
            ChronoUnit.DAYS.between(d, LocalDate.now())
        } catch (e: Exception) {
            null
        }
    }

    fun isStale(generated: String): Boolean {
        val age = ageDays(generated) ?: return true // inconnue = à mettre à jour
        return age > STALE_DAYS
    }
}

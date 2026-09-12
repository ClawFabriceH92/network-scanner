package com.fabrice.network.scanner.capture

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Liste de domaines trackers / publicité (v1.9.34) — classification des
 * connexions capturées (« Publicité · Google », « Analytique · comScore »…).
 *
 * Générée par tools/build_trackers.py (liste Disconnect) et régénérée chaque
 * nuit par le cron GitHub, comme la base CVE. L'app télécharge la version à
 * jour sans recompiler : la copie locale (filesDir/trackers.json) prend le pas
 * sur l'asset embarqué.
 */
object TrackerDatabase {

    const val RAW_URL = "https://raw.githubusercontent.com/ClawFabriceH92/network-scanner/main/app/src/main/assets/trackers.json"
    private const val FILE = "trackers.json"

    data class Info(val category: String, val company: String) {
        val label: String get() = if (company.isBlank()) category else "$category · $company"
    }

    class Db(val generated: String, private val domains: Map<String, String>) {
        val count: Int get() = domains.size

        /** Classification de [host] par suffixe (le plus spécifique gagne), ou null. */
        fun lookup(host: String): Info? {
            if (host.isBlank() || domains.isEmpty()) return null
            var h = host.lowercase().trimEnd('.')
            while (h.isNotEmpty()) {
                domains[h]?.let { v ->
                    val cat = v.substringBefore('|'); val org = v.substringAfter('|', "")
                    return Info(cat, org)
                }
                val dot = h.indexOf('.')
                if (dot < 0) break
                h = h.substring(dot + 1)
            }
            return null
        }
    }

    /** Parse le JSON {generated, domains:{domaine: "Catégorie|Société"}}. */
    fun parse(json: String): Db {
        val o = JSONObject(json)
        val d = o.optJSONObject("domains") ?: JSONObject()
        val map = HashMap<String, String>(d.length() * 2)
        d.keys().forEach { k -> map[k.lowercase()] = d.optString(k, "") }
        return Db(o.optString("generated", ""), map)
    }

    private val EMPTY = Db("", emptyMap())
    @Volatile private var cache: Db? = null

    fun localFile(context: Context): File = File(context.filesDir, FILE)

    /** Base en mémoire (copie locale > asset ; vide si aucune). */
    fun load(context: Context): Db {
        cache?.let { return it }
        val db = runCatching {
            val f = localFile(context)
            val text = if (f.exists()) f.readText(Charsets.UTF_8)
            else context.assets.open(FILE).bufferedReader(Charsets.UTF_8).use { it.readText() }
            parse(text)
        }.getOrDefault(EMPTY)
        cache = db
        return db
    }

    fun invalidate() { cache = null }

    /** Télécharge la liste à jour ; retourne la base chargée ou null si échec. */
    fun update(context: Context): Db? {
        var conn: HttpURLConnection? = null
        return try {
            conn = URL(RAW_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = 10_000
            conn.readTimeout = 20_000
            conn.setRequestProperty("User-Agent", "NetworkScanner/1.0")
            if (conn.responseCode != 200) return null
            val text = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            val db = parse(text)
            if (db.count < 500) return null
            localFile(context).writeText(text, Charsets.UTF_8)
            cache = db
            db
        } catch (e: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }
}

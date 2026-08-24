package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Historisation des statistiques d'imprimante (modèle, état, compteur de pages,
 * niveaux de consommables) par appareil.
 *
 * Stockage : un fichier JSON par appareil (clé d'identité = MAC/IP) dans
 * `filesDir/printer_stats/`. Chaque scan qui trouve une imprimante ajoute un
 * instantané horodaté (borné à [MAX_SNAPSHOTS]) — permet de suivre l'évolution
 * du compteur de pages et des niveaux dans le temps.
 */
class PrinterStatsStore(context: Context) {

    private val dir = java.io.File(context.filesDir, "printer_stats").apply { mkdirs() }

    /** Un instantané horodaté des stats d'une imprimante. */
    data class Snapshot(
        val timestamp: Long,
        val makeAndModel: String,
        val state: String,
        val pageCount: Long?,
        val supplies: List<PrinterProbe.Supply>
    )

    private fun fileFor(key: String): java.io.File {
        // Nom de fichier sûr (la clé peut contenir « : »).
        val safe = key.replace(Regex("[^A-Za-z0-9_.-]"), "_")
        return java.io.File(dir, "$safe.json")
    }

    /**
     * Enregistre un instantané pour cet appareil s'il expose des stats
     * imprimante. Déduplique : n'ajoute rien si le compteur de pages et les
     * niveaux sont identiques au dernier instantané (évite d'empiler des
     * doublons à chaque scan).
     */
    fun record(device: Device, now: Long) {
        val p = device.printer ?: return
        if (!p.hasData) return
        val key = ScanHistory.identityKey(device)
        val existing = load(key).toMutableList()
        val last = existing.lastOrNull()
        val unchanged = last != null &&
            last.pageCount == p.pageCount &&
            last.supplies.map { it.levelPercent } == p.supplies.map { it.levelPercent } &&
            last.state == p.state
        if (unchanged) return
        existing.add(
            Snapshot(
                timestamp = now,
                makeAndModel = p.makeAndModel,
                state = p.state,
                pageCount = p.pageCount,
                supplies = p.supplies
            )
        )
        while (existing.size > MAX_SNAPSHOTS) existing.removeAt(0)
        save(key, existing)
    }

    /** Instantanés d'un appareil, du plus ancien au plus récent (vide si aucun). */
    fun load(key: String): List<Snapshot> {
        val f = fileFor(key)
        if (!f.exists()) return emptyList()
        return try {
            val arr = JSONArray(f.readText())
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Snapshot(
                    timestamp = o.optLong("ts"),
                    makeAndModel = o.optString("model", ""),
                    state = o.optString("state", ""),
                    pageCount = if (o.isNull("pages")) null else o.optLong("pages"),
                    supplies = parseSupplies(o.optJSONArray("supplies"))
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Dernier instantané connu, ou null. */
    fun latest(key: String): Snapshot? = load(key).lastOrNull()

    private fun save(key: String, snapshots: List<Snapshot>) {
        val arr = JSONArray()
        snapshots.forEach { s ->
            val o = JSONObject()
            o.put("ts", s.timestamp)
            o.put("model", s.makeAndModel)
            o.put("state", s.state)
            o.put("pages", s.pageCount ?: JSONObject.NULL)
            val sup = JSONArray()
            s.supplies.forEach { m ->
                sup.put(
                    JSONObject()
                        .put("name", m.name)
                        .put("color", m.color)
                        .put("type", m.type)
                        .put("level", m.levelPercent ?: JSONObject.NULL)
                )
            }
            o.put("supplies", sup)
            arr.put(o)
        }
        runCatching { fileFor(key).writeText(arr.toString()) }
    }

    private fun parseSupplies(arr: JSONArray?): List<PrinterProbe.Supply> {
        if (arr == null) return emptyList()
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            PrinterProbe.Supply(
                name = o.optString("name", ""),
                color = o.optString("color", ""),
                type = o.optString("type", ""),
                levelPercent = if (o.isNull("level")) null else o.optInt("level")
            )
        }
    }

    companion object {
        const val MAX_SNAPSHOTS = 100
    }
}

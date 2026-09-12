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
        val scanCount: Long? = null,
        val copyCount: Long? = null,
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
            last.scanCount == p.scanCount &&
            last.copyCount == p.copyCount &&
            last.supplies.map { it.levelPercent } == p.supplies.map { it.levelPercent } &&
            last.state == p.state
        if (unchanged) return
        existing.add(
            Snapshot(
                timestamp = now,
                makeAndModel = p.makeAndModel,
                state = p.state,
                pageCount = p.pageCount,
                scanCount = p.scanCount,
                copyCount = p.copyCount,
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
                    scanCount = if (o.isNull("scans")) null else o.optLong("scans"),
                    copyCount = if (o.isNull("copies")) null else o.optLong("copies"),
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
            o.put("scans", s.scanCount ?: JSONObject.NULL)
            o.put("copies", s.copyCount ?: JSONObject.NULL)
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
        /** Seuil (%) sous lequel un consommable déclenche une alerte « niveau bas ». */
        const val TONER_THRESHOLD = 15

        /**
         * Consommables qui viennent de FRANCHIR le seuil vers le bas entre le
         * dernier instantané [prev] et l'état courant [current]. Un consommable
         * déjà sous le seuil au relevé précédent n'est PAS re-signalé (évite le
         * spam) ; un consommable rechargé repasse au-dessus et pourra ré-alerter.
         * Fonction pure → testable.
         */
        fun tonerCrossings(
            prev: Snapshot?,
            current: PrinterProbe.PrinterInfo,
            threshold: Int = TONER_THRESHOLD
        ): List<PrinterProbe.Supply> {
            return current.supplies.filter { s ->
                val lvl = s.levelPercent ?: return@filter false
                if (lvl > threshold) return@filter false
                val prevLvl = prev?.supplies
                    ?.firstOrNull { supplyKey(it) == supplyKey(s) }
                    ?.levelPercent
                prevLvl == null || prevLvl > threshold
            }
        }

        fun supplyKey(s: PrinterProbe.Supply): String =
            s.name.ifBlank { s.color.ifBlank { s.type } }.lowercase()

        /** Prévision d'épuisement d'un consommable (v1.9.36). */
        data class Forecast(
            /** Consommation en points de % par jour (> 0). */
            val percentPerDay: Double,
            /** Jours restants estimés avant 0 %. */
            val daysLeft: Double,
            /** Date estimée d'épuisement (ms epoch). */
            val emptyAtMs: Long
        )

        /**
         * Estime, par régression linéaire sur les relevés où le niveau BAISSE
         * (un remplacement de cartouche remet la série à zéro), la vitesse de
         * consommation d'un consommable et le nombre de jours restants.
         * null si moins de 2 relevés exploitables, moins de 12 h d'écart, ou
         * pas de baisse mesurable. Pure → testable.
         */
        fun tonerForecast(
            history: List<Snapshot>,
            supplyKey: String,
            nowMs: Long = System.currentTimeMillis()
        ): Forecast? {
            val points = history.mapNotNull { snap ->
                snap.supplies.firstOrNull { supplyKey(it) == supplyKey }?.levelPercent
                    ?.let { snap.timestamp to it }
            }
            if (points.size < 2) return null
            // Dernier segment monotone décroissant (depuis le dernier remplacement).
            var startIdx = points.size - 1
            while (startIdx > 0 && points[startIdx - 1].second >= points[startIdx].second) startIdx--
            val seg = points.subList(startIdx, points.size)
            if (seg.size < 2) return null
            val spanMs = seg.last().first - seg.first().first
            if (spanMs < 12L * 3600_000) return null
            // Régression linéaire niveau = a + b·t (t en jours).
            val t0 = seg.first().first
            val xs = seg.map { (it.first - t0) / 86_400_000.0 }
            val ys = seg.map { it.second.toDouble() }
            val n = xs.size
            val mx = xs.average(); val my = ys.average()
            val sxx = xs.sumOf { (it - mx) * (it - mx) }
            if (sxx == 0.0) return null
            val b = xs.indices.sumOf { (xs[it] - mx) * (ys[it] - my) } / sxx
            if (b >= -0.001) return null
            val rate = -b
            val current = ys.last()
            val daysLeft = current / rate
            val lastTs = seg.last().first
            val emptyAt = lastTs + (daysLeft * 86_400_000.0).toLong()
            // Jours restants relatifs à maintenant (peut être < 0 si déjà dépassé).
            val daysFromNow = (emptyAt - nowMs) / 86_400_000.0
            return Forecast(rate, daysFromNow, emptyAt)
        }

        /** Export CSV de l'historique d'une imprimante (séparateur ; + BOM). */
        fun buildCsv(history: List<Snapshot>): String = buildString {
            append('\uFEFF')
            val keys = history.flatMap { it.supplies.map { s -> supplyKey(s) } }.distinct()
            val labels = keys.map { k ->
                history.flatMap { it.supplies }.firstOrNull { supplyKey(it) == k }
                    ?.let { it.name.ifBlank { it.color.ifBlank { it.type } } } ?: k
            }
            appendLine((listOf("Date", "Modèle", "État", "Pages", "Numérisations", "Copies") + labels.map { "$it (%)" }).joinToString(";"))
            val fmt = java.text.SimpleDateFormat("dd/MM/yyyy HH:mm", java.util.Locale.FRENCH)
            history.forEach { s ->
                val cols = mutableListOf(
                    fmt.format(java.util.Date(s.timestamp)),
                    s.makeAndModel.replace(';', ','),
                    s.state.replace(';', ','),
                    s.pageCount?.toString() ?: "",
                    s.scanCount?.toString() ?: "",
                    s.copyCount?.toString() ?: ""
                )
                keys.forEach { k ->
                    cols.add(s.supplies.firstOrNull { supplyKey(it) == k }?.levelPercent?.toString() ?: "")
                }
                appendLine(cols.joinToString(";"))
            }
        }
    }
}

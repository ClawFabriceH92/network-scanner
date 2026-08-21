package com.fabrice.network.scanner

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.pdf.PdfDocument
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Rapport d'audit PDF professionnel : appareils du réseau, OS, services
 * exposés, vulnérabilités détectées, score de sécurité global.
 *
 * La partie agrégation (AuditData) est pure et testable ; le rendu PDF utilise
 * PdfDocument (API Android 19+, aucun poids ajouté).
 */
object PdfAuditReport {

    /** Données agrégées du rapport — logique pure. */
    data class AuditData(
        val generatedAt: String,
        val selfIp: String,
        val networkCidr: String,
        val deviceCount: Int,
        val onlineCount: Int,
        val criticalVulns: Int,
        val highVulns: Int,
        val kevVulns: Int,
        val devices: List<Device>,
        val vulnsByIp: Map<String, VulnScanner.DeviceVulns>,
        val ssid: String = ""
    ) {
        /** Score global 0-100 : pénalise les vulnérabilités critiques/hautes. */
        val globalScore: Int
            get() {
                if (deviceCount == 0) return 100
                var score = 100
                score -= criticalVulns * 15
                score -= highVulns * 8
                score -= kevVulns * 5
                return score.coerceIn(0, 100)
            }

        val riskLabel: String
            get() = VulnScanner.labelForScore(100 - globalScore)

        /** Nombre d'appareils avec une credential par défaut trouvée. */
        val defaultCredCount: Int
            get() = devices.count { it.defaultCred != null }
    }

    /** Agrège les données de scan — pure, testable. */
    fun buildData(
        devices: List<Device>,
        vulnsByIp: Map<String, VulnScanner.DeviceVulns>,
        selfIp: String,
        networkCidr: String,
        ssid: String = ""
    ): AuditData {
        var critical = 0
        var high = 0
        var kev = 0
        vulnsByIp.values.forEach { v ->
            critical += v.criticalCount
            high += v.highCount
            kev += v.kevCount
        }
        return AuditData(
            generatedAt = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.FRENCH).format(Date()),
            selfIp = selfIp,
            networkCidr = networkCidr,
            deviceCount = devices.size,
            onlineCount = devices.count { it.alive },
            criticalVulns = critical,
            highVulns = high,
            kevVulns = kev,
            devices = devices,
            vulnsByIp = vulnsByIp,
            ssid = ssid
        )
    }

    /** Synthèse exécutive (une ligne) — pure, testable. */
    fun buildSummary(data: AuditData): String =
        "Score global ${data.globalScore}/100 (${data.riskLabel}) — " +
            "${data.deviceCount} appareil(s), ${data.criticalVulns} vulnérabilité(s) critique(s), " +
            "${data.highVulns} élevée(s), ${data.defaultCredCount} credential(s) par défaut."

    /**
     * Recommandations hiérarchisées (top 5, générées depuis les données) — pure.
     * Priorité décroissante : credentials par défaut > vulnérabilités critiques >
     * vulnérabilités élevées > firmware de la box > WPA3.
     */
    fun buildRecommendations(data: AuditData): List<String> {
        data class Rec(val priority: Int, val text: String)
        val recs = mutableListOf<Rec>()

        data.devices.filter { it.defaultCred != null }.forEach { d ->
            recs.add(Rec(100, "Changer le mot de passe par défaut de ${d.ip} (${d.hostname.ifBlank { d.ip }}) : ${d.defaultCred}"))
        }
        data.devices.forEach { d ->
            val v = data.vulnsByIp[d.ip] ?: return@forEach
            val name = d.hostname.ifBlank { d.ip }
            if (v.criticalCount > 0) {
                recs.add(Rec(90, "Mettre à jour $name : ${v.criticalCount} vulnérabilité(s) critique(s)"))
            }
            if (v.highCount > 0) {
                recs.add(Rec(70, "Mettre à jour $name : ${v.highCount} vulnérabilité(s) élevée(s)"))
            }
        }
        if (data.devices.any { it.isGateway && data.vulnsByIp[it.ip]?.let { v -> v.criticalCount + v.highCount + v.kevCount > 0 } == true }) {
            recs.add(Rec(60, "Mettre à jour le firmware de la box"))
        }
        if (data.criticalVulns + data.highVulns > 0) {
            recs.add(Rec(50, "Passer le réseau Wi-Fi en WPA3"))
        }

        return recs.sortedByDescending { it.priority }.take(5).map { it.text }
    }

    /**
     * Génère le PDF (multi-pages) et retourne son URI partageable via
     * FileProvider, ou null si le rendu/l'écriture a échoué (disque plein…) :
     * on ne partage jamais un PDF vide/corrompu silencieusement.
     */
    fun generateAndShareUri(context: Context, data: AuditData): Uri? {
        val doc = PdfDocument()
        try {
            drawReport(doc, data)
        } catch (e: Exception) {
            runCatching { doc.close() }
            return null
        }

        val dir = File(context.filesDir, "exports").apply { mkdirs() }
        val file = File(dir, "audit_reseau_v${BuildConfig.VERSION_NAME}_${System.currentTimeMillis()}.pdf")
        val written = runCatching {
            file.outputStream().use { doc.writeTo(it) }
        }.isSuccess
        doc.close()
        if (!written || !file.exists() || file.length() == 0L) return null

        return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    }

    /**
     * Dessine le rapport complet, en paginant automatiquement (A4 595×842) :
     * dès que le contenu atteint le bas de page, une nouvelle page est ouverte —
     * la section Vulnérabilités et le pied de page ne sont plus perdus sur les
     * grands réseaux.
     */
    private fun drawReport(doc: PdfDocument, data: AuditData) {
        val margin = 40f
        val contentW = 595f - 2 * margin
        val contentBottom = 795f

        var pageNum = 1
        var page = doc.startPage(PdfDocument.PageInfo.Builder(595, 842, pageNum).create())
        var canvas = page.canvas
        var y = 50f

        val footerPaint = Paint().apply { textSize = 8f; color = Color.rgb(160, 160, 160) }
        fun drawFooter() {
            canvas.drawText(
                "NetworkScanner v${BuildConfig.VERSION_NAME} — scan passif, données locales · page $pageNum",
                margin, 822f, footerPaint
            )
        }
        fun newPage() {
            drawFooter()
            doc.finishPage(page)
            pageNum++
            page = doc.startPage(PdfDocument.PageInfo.Builder(595, 842, pageNum).create())
            canvas = page.canvas
            y = 50f
        }
        // Ouvre une nouvelle page si `needed` px ne tiennent pas avant le bas.
        fun ensureSpace(needed: Float) {
            if (y + needed > contentBottom) newPage()
        }

        // --- En-tête ---
        val title = Paint().apply {
            color = Color.rgb(11, 58, 110) // bleu nuit
            textSize = 24f
            isFakeBoldText = true
        }
        canvas.drawText("Rapport d'audit réseau", margin, y, title)
        y += 28f

        val sub = Paint().apply { textSize = 11f; color = Color.rgb(120, 120, 120) }
        canvas.drawText("Généré le ${data.generatedAt}", margin, y, sub)
        val ssidPart = if (data.ssid.isNotBlank()) " · SSID : ${data.ssid}" else ""
        canvas.drawText(
            "Réseau : ${data.selfIp}${if (data.networkCidr.isNotBlank()) " (${data.networkCidr})" else ""}$ssidPart",
            margin, y + 14f, sub
        )
        canvas.drawText("NetworkScanner v${BuildConfig.VERSION_NAME}", margin, y + 28f, sub)
        y += 52f

        // --- Score global ---
        val scorePaint = Paint().apply { textSize = 40f; isFakeBoldText = true }
        scorePaint.color = scoreColor(data.globalScore)
        canvas.drawText("${data.globalScore}/100", margin, y + 34f, scorePaint)
        val scoreLabel = Paint().apply { textSize = 14f; isFakeBoldText = true; color = scoreColor(data.globalScore) }
        canvas.drawText("Score de sécurité — ${data.riskLabel}", margin + 130f, y + 30f, scoreLabel)
        val scoreSub = Paint().apply { textSize = 10f; color = Color.rgb(120, 120, 120) }
        canvas.drawText("${data.deviceCount} appareils · ${data.onlineCount} en ligne · " +
            "${data.criticalVulns} critiques · ${data.highVulns} élevées · ${data.kevVulns} activement exploitées",
            margin, y + 52f, scoreSub)
        y += 80f

        // --- Synthèse exécutive ---
        y = drawSectionHeader(canvas, "Synthèse exécutive", margin, contentW, y)
        val summaryPaint = Paint().apply { textSize = 10f; color = Color.rgb(40, 40, 40) }
        drawWrapped(canvas, buildSummary(data), margin, y + 14f, summaryPaint, contentW, 14f)
        y += 40f

        // --- Recommandations hiérarchisées (top 5) ---
        val recos = buildRecommendations(data)
        if (recos.isNotEmpty()) {
            y = drawSectionHeader(canvas, "Recommandations hiérarchisées", margin, contentW, y)
            val recoPaint = Paint().apply { textSize = 10f; color = Color.rgb(40, 40, 40) }
            recos.forEachIndexed { i, r ->
                ensureSpace(18f)
                drawWrapped(canvas, "${i + 1}. $r", margin, y + 12f, recoPaint, contentW, 15f)
                y += 18f
            }
            y += 6f
        }

        // --- Appareils ---
        ensureSpace(46f)
        y = drawSectionHeader(canvas, "Appareils détectés", margin, contentW, y)
        val headerPaint = Paint().apply { textSize = 9f; isFakeBoldText = true; color = Color.WHITE }
        val rowPaint = Paint().apply { textSize = 9f; color = Color.rgb(40, 40, 40) }
        val altPaint = Paint().apply { textSize = 9f; color = Color.rgb(60, 60, 60) }
        // Somme des 6 largeurs fixes (456) < contentW (515) → colonne Services
        // positive (≈59) et dans la page (findings PDF largeur).
        val colWidths = floatArrayOf(78f, 96f, 82f, 82f, 66f, 52f, contentW - 456f)
        val colNames = arrayOf("IP", "MAC", "Fabricant", "Modèle", "Système", "Statut", "Services")
        val rowH = 16f

        fun drawTableHeader() {
            drawRow(canvas, margin, y, colWidths, colNames.toList(), headerPaint, Color.rgb(27, 58, 107), rowH, contentW)
            y += rowH
        }
        drawTableHeader()

        data.devices.forEachIndexed { i, d ->
            if (y + rowH > contentBottom) {
                newPage()
                drawTableHeader() // répète l'en-tête de tableau sur la nouvelle page
            }
            val statut = if (d.alive) "En ligne" else "ARP"
            val services = d.ports.take(6).joinToString(", ") { PortScanner.serviceName(it) }
            val modele = d.product.ifBlank { d.model }
            val bg = if (i % 2 == 0) Color.WHITE else Color.rgb(245, 243, 238)
            drawRow(
                canvas, margin, y, colWidths,
                listOf(d.ip, d.mac.ifBlank { "—" }, d.vendor.ifBlank { "—" },
                    modele.ifBlank { "—" }, d.os.ifBlank { "—" }, statut, services),
                if (i % 2 == 0) rowPaint else altPaint, bg, rowH, contentW
            )
            y += rowH
        }
        y += 16f

        // --- Vulnérabilités ---
        if (data.devices.any { data.vulnsByIp[it.ip]?.let { v -> !v.isEmpty } == true }) {
            ensureSpace(40f)
            y = drawSectionHeader(canvas, "Vulnérabilités détectées", margin, contentW, y)
            data.devices.forEach { d ->
                val v = data.vulnsByIp[d.ip]
                if (v != null && !v.isEmpty) {
                    ensureSpace(14f)
                    val p = Paint().apply { textSize = 9f; color = Color.rgb(40, 40, 40) }
                    canvas.drawText(
                        "• ${d.hostname.ifBlank { d.ip }} — ${v.label} (${v.score}/100)" +
                            if (v.kevCount > 0) " · ${v.kevCount} activement exploitée(s)" else "",
                        margin, y, p
                    )
                    y += 14f
                    v.cves.take(3).forEach { cve ->
                        ensureSpace(12f)
                        val c = Paint().apply { textSize = 8f; color = sevColor(cve.severity) }
                        canvas.drawText("    ${cve.id} [${cve.severity}] — ${cve.description.take(70)}", margin, y, c)
                        y += 12f
                    }
                    if (v.cves.size > 3) {
                        ensureSpace(12f)
                        val more = Paint().apply { textSize = 8f; color = Color.rgb(120, 120, 120) }
                        canvas.drawText("    +${v.cves.size - 3} autres…", margin, y, more)
                        y += 12f
                    }
                }
            }
        }

        // --- Pied de page de la dernière page + finalisation ---
        drawFooter()
        doc.finishPage(page)
    }

    private fun drawSectionHeader(canvas: Canvas, title: String, margin: Float, contentW: Float, y: Float): Float {
        val p = Paint().apply { textSize = 13f; isFakeBoldText = true; color = Color.rgb(27, 58, 107) }
        canvas.drawText(title, margin, y + 12f, p)
        val line = Paint().apply { strokeWidth = 1.5f; color = Color.rgb(201, 151, 43) }
        canvas.drawLine(margin, y + 18f, margin + contentW, y + 18f, line)
        return y + 30f
    }

    /** Dessine un texte avec retour à la ligne automatique (mot par mot). */
    private fun drawWrapped(
        canvas: Canvas, text: String, x: Float, y: Float, paint: Paint,
        maxWidth: Float, lineHeight: Float
    ) {
        var cy = y
        var line = ""
        text.split(' ').forEach { word ->
            val candidate = if (line.isEmpty()) word else "$line $word"
            if (paint.measureText(candidate) > maxWidth && line.isNotEmpty()) {
                canvas.drawText(line, x, cy, paint)
                cy += lineHeight
                line = word
            } else {
                line = candidate
            }
        }
        if (line.isNotEmpty()) canvas.drawText(line, x, cy, paint)
    }

    private fun drawRow(
        canvas: Canvas, margin: Float, y: Float, widths: FloatArray,
        values: List<String>, textPaint: Paint, bg: Int, rowH: Float, contentW: Float
    ) {
        val rect = RectF(margin, y, margin + contentW, y + rowH)
        val bgPaint = Paint().apply { color = bg }
        canvas.drawRect(rect, bgPaint)
        var x = margin + 4f
        values.forEachIndexed { i, value ->
            // Truncate pour tenir dans la colonne
            val maxChars = (widths[i] / 5.2f).toInt().coerceAtLeast(4)
            val text = if (value.length > maxChars) value.take(maxChars - 1) + "…" else value
            canvas.drawText(text, x, y + 12f, textPaint)
            x += widths[i]
        }
    }

    private fun scoreColor(score: Int): Int = when {
        score >= 80 -> Color.rgb(46, 125, 50)   // vert
        score >= 50 -> Color.rgb(201, 151, 43)  // or
        else -> Color.rgb(179, 38, 30)          // rouge
    }

    private fun sevColor(sev: String): Int = when (sev) {
        "CRITICAL" -> Color.rgb(179, 38, 30)
        "HIGH" -> Color.rgb(216, 67, 21)
        "MEDIUM" -> Color.rgb(201, 151, 43)
        "LOW" -> Color.rgb(46, 125, 50)
        else -> Color.rgb(100, 100, 100)
    }
}

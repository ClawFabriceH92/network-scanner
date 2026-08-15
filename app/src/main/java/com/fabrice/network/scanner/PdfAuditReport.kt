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
        val vulnsByIp: Map<String, VulnScanner.DeviceVulns>
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
    }

    /** Agrège les données de scan — pure, testable. */
    fun buildData(
        devices: List<Device>,
        vulnsByIp: Map<String, VulnScanner.DeviceVulns>,
        selfIp: String,
        networkCidr: String
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
            vulnsByIp = vulnsByIp
        )
    }

    /**
     * Génère le PDF et retourne son URI (partageable via FileProvider).
     */
    fun generateAndShareUri(context: Context, data: AuditData): Uri {
        val doc = PdfDocument()
        val page = doc.startPage(PdfDocument.PageInfo.Builder(595, 842, 1).create()) // A4
        val canvas = page.canvas
        drawReport(canvas, data)
        doc.finishPage(page)

        val dir = File(context.filesDir, "exports").apply { mkdirs() }
        val file = File(dir, "audit_reseau_v${BuildConfig.VERSION_NAME}_${System.currentTimeMillis()}.pdf")
        runCatching {
            file.outputStream().use { doc.writeTo(it) }
        }
        doc.close()

        return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    }

    /** Dessine le rapport complet sur la page A4. */
    private fun drawReport(canvas: Canvas, data: AuditData) {
        val w = 595f
        val margin = 40f
        val contentW = w - 2 * margin
        var y = 50f

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
        canvas.drawText("Réseau : ${data.selfIp}${if (data.networkCidr.isNotBlank()) " ($data.networkCidr)" else ""}", margin, y + 14f, sub)
        y += 40f

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

        // --- Appareils ---
        y = drawSectionHeader(canvas, "Appareils détectés", margin, contentW, y)
        val headerPaint = Paint().apply { textSize = 9f; isFakeBoldText = true; color = Color.WHITE }
        val rowPaint = Paint().apply { textSize = 9f; color = Color.rgb(40, 40, 40) }
        val altPaint = Paint().apply { textSize = 9f; color = Color.rgb(60, 60, 60) }
        val colWidths = floatArrayOf(90f, 110f, 100f, 90f, 90f, contentW - 480f)
        val colNames = arrayOf("IP", "MAC", "Fabricant", "Système", "Statut", "Services")
        val rowH = 16f

        // Ligne d'en-tête
        drawRow(canvas, margin, y, colWidths, colNames.map { it }, headerPaint, Color.rgb(27, 58, 107), rowH, contentW)
        y += rowH

        data.devices.forEachIndexed { i, d ->
            val statut = if (d.alive) "En ligne" else "ARP"
            val services = d.ports.take(6).joinToString(", ") { PortScanner.serviceName(it) }
            val bg = if (i % 2 == 0) Color.WHITE else Color.rgb(245, 243, 238)
            drawRow(
                canvas, margin, y, colWidths,
                listOf(d.ip, d.mac.ifBlank { "—" }, d.vendor.ifBlank { "—" },
                    d.os.ifBlank { "—" }, statut, services),
                if (i % 2 == 0) rowPaint else altPaint, bg, rowH, contentW
            )
            y += rowH
            if (y > 760) return // page pleine, on coupe proprement
        }
        y += 16f

        // --- Vulnérabilités ---
        if (data.devices.any { data.vulnsByIp[it.ip]?.let { v -> !v.isEmpty } == true }) {
            y = drawSectionHeader(canvas, "Vulnérabilités détectées", margin, contentW, y)
            data.devices.forEach { d ->
                val v = data.vulnsByIp[d.ip]
                if (v != null && !v.isEmpty) {
                    val p = Paint().apply { textSize = 9f; color = Color.rgb(40, 40, 40) }
                    canvas.drawText(
                        "• ${d.hostname.ifBlank { d.ip }} — ${v.label} (${v.score}/100)" +
                            if (v.kevCount > 0) " · ${v.kevCount} activement exploitée(s)" else "",
                        margin, y, p
                    )
                    y += 14f
                    v.cves.take(3).forEach { cve ->
                        val c = Paint().apply { textSize = 8f; color = sevColor(cve.severity) }
                        canvas.drawText("    ${cve.id} [${cve.severity}] — ${cve.description.take(70)}", margin, y, c)
                        y += 12f
                    }
                    if (v.cves.size > 3) {
                        val more = Paint().apply { textSize = 8f; color = Color.rgb(120, 120, 120) }
                        canvas.drawText("    +${v.cves.size - 3} autres…", margin, y, more)
                        y += 12f
                    }
                    if (y > 760) return
                }
            }
        }

        // --- Pied de page ---
        val footer = Paint().apply { textSize = 8f; color = Color.rgb(160, 160, 160) }
        canvas.drawText("NetworkScanner v${BuildConfig.VERSION_NAME} — scan passif, données locales uniquement", margin, 810f, footer)
    }

    private fun drawSectionHeader(canvas: Canvas, title: String, margin: Float, contentW: Float, y: Float): Float {
        val p = Paint().apply { textSize = 13f; isFakeBoldText = true; color = Color.rgb(27, 58, 107) }
        canvas.drawText(title, margin, y + 12f, p)
        val line = Paint().apply { strokeWidth = 1.5f; color = Color.rgb(201, 151, 43) }
        canvas.drawLine(margin, y + 18f, margin + contentW, y + 18f, line)
        return y + 30f
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

package com.fabrice.network.scanner.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.SpeedHistoryStore
import com.fabrice.network.scanner.SpeedTest
import com.fabrice.network.scanner.WifiQuality
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Panneau « Réseau » : qualité Wi-Fi en temps réel (barre RSSI qui réagit
 * aux déplacements) + test de vitesse (download / upload / latence).
 */
@Composable
fun NetworkPanel(rssi: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var testing by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<SpeedTest.Result?>(null) }
    var testError by remember { mutableStateOf(false) }
    var historyTick by remember { mutableStateOf(0) }

    // Le RSSI est fourni par NetworkScreen (une seule boucle de sondage pour
    // toute la vue) — évite deux sondages RSSI concurrents toutes les 2 s.

    fun runTest() {
        scope.launch(Dispatchers.IO) {
            testing = true
            testError = false
            val r = try {
                SpeedTest.runFullTest()
            } catch (e: Exception) {
                null
            }
            result = r
            testError = r == null || (r.downloadMbps <= 0 && r.uploadMbps <= 0 && r.latencyMs <= 0)
            if (r != null && !testError) {
                // Historique des débits (v1.9.0) : enregistré après chaque test complet.
                runCatching {
                    SpeedHistoryStore.append(context, SpeedHistoryStore.Entry(
                        ts = System.currentTimeMillis(),
                        downMbps = r.downloadMbps,
                        upMbps = r.uploadMbps,
                        latencyMs = r.latencyMs
                    ))
                }
                historyTick++
            }
            testing = false
        }
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            // --- Qualité Wi-Fi ---
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Qualité Wi-Fi",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.weight(1f))
                Text(
                    WifiQuality.formatRssi(rssi),
                    style = LocalMonoTextStyle.current,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                WifiBars(level = WifiQuality.level(rssi))
                Spacer(Modifier.width(10.dp))
                Text(
                    WifiQuality.label(rssi),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Medium
                )
            }

            Spacer(Modifier.height(12.dp))

            // --- Test de vitesse ---
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Test réseau",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.weight(1f))
                if (testing) {
                    CircularProgressIndicator(Modifier.width(20.dp), strokeWidth = 2.dp)
                } else {
                    Button(onClick = { runTest() }) {
                        Text(if (result == null) "Tester maintenant" else "Relancer")
                    }
                }
            }
            if (testError && !testing) {
                Text(
                    "Test impossible (pas d'accès Internet ?).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
            result?.let { r ->
                Spacer(Modifier.height(8.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    MetricBox("Télécharger", "${SpeedTest.formatMbps(r.downloadMbps)} Mbps")
                    MetricBox("Charger", "${SpeedTest.formatMbps(r.uploadMbps)} Mbps")
                    MetricBox("Latence", "${r.latencyMs} ms")
                }
            }

            // --- Historique des débits (v1.9.0) — chargé hors thread UI ---
            var history by remember { mutableStateOf<List<SpeedHistoryStore.Entry>>(emptyList()) }
            LaunchedEffect(historyTick) {
                history = withContext(Dispatchers.IO) { SpeedHistoryStore.load(context) }
            }
            if (history.isNotEmpty()) {
                Spacer(Modifier.height(16.dp))
                SpeedHistorySection(history)
            }
        }
    }
}

/** Barre de signal 0-4 segments (style indicateur Wi-Fi). */
@Composable
private fun WifiBars(level: Int) {
    Row(
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(3.dp)
    ) {
        val heights = listOf(6.dp, 10.dp, 14.dp, 18.dp)
        heights.forEachIndexed { index, h ->
            val on = index < level
            Box(
                modifier = Modifier
                    .width(8.dp)
                    .height(h)
                    .background(
                        if (on) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.surfaceVariant,
                        RoundedCornerShape(2.dp)
                    )
            )
        }
    }
}

@Composable
private fun RowScope.MetricBox(label: String, value: String) {
    Column(
        modifier = Modifier
            .weight(1f)
            .background(MaterialTheme.colorScheme.primaryContainer, RoundedCornerShape(8.dp))
            .padding(vertical = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onPrimaryContainer
        )
        Spacer(Modifier.height(2.dp))
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
            fontWeight = FontWeight.Bold
        )
    }
}

/** Section « Historique des débits » : dernier test + mini-graphique + 5 derniers. */
@Composable
private fun SpeedHistorySection(history: List<SpeedHistoryStore.Entry>) {
    val last = history.last()
    Column {
        Text(
            "📈 Historique des débits",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "Dernier test : ↓ ${SpeedTest.formatMbps(last.downMbps)} Mbps · ↑ " +
                "${SpeedTest.formatMbps(last.upMbps)} Mbps · ${last.latencyMs} ms",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(8.dp))
        SpeedHistoryGraph(history.takeLast(20))
        Spacer(Modifier.height(8.dp))
        Text(
            "5 derniers tests",
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold
        )
        history.takeLast(5).asReversed().forEach { e ->
            Row(Modifier.padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    formatHistoryDate(e.ts),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.width(84.dp)
                )
                Text(
                    "↓ ${SpeedTest.formatMbps(e.downMbps)}",
                    style = LocalMonoTextStyle.current,
                    modifier = Modifier.width(72.dp)
                )
                Text(
                    "↑ ${SpeedTest.formatMbps(e.upMbps)}",
                    style = LocalMonoTextStyle.current,
                    modifier = Modifier.width(72.dp)
                )
                Text("${e.latencyMs} ms", style = LocalMonoTextStyle.current)
            }
        }
    }
}

/** Mini-graphique Canvas des débits down (primaire) / up (tertiaire). */
@Composable
private fun SpeedHistoryGraph(
    entries: List<SpeedHistoryStore.Entry>,
    modifier: Modifier = Modifier
) {
    val downColor = MaterialTheme.colorScheme.primary
    val upColor = MaterialTheme.colorScheme.tertiary
    Canvas(
        modifier = modifier
            .fillMaxWidth()
            .height(120.dp)
    ) {
        if (entries.size < 2) return@Canvas
        val w = size.width
        val h = size.height
        val maxVal = maxOf(entries.maxOf { it.downMbps }, entries.maxOf { it.upMbps }, 1.0)

        fun yOf(v: Double): Float = h - ((v / maxVal) * h).toFloat().coerceIn(0f, h)
        fun xOf(i: Int): Float = (i.toFloat() / (entries.size - 1)) * w

        fun drawSeries(color: androidx.compose.ui.graphics.Color, sel: (SpeedHistoryStore.Entry) -> Double) {
            val path = Path()
            entries.forEachIndexed { i, e ->
                val x = xOf(i)
                val y = yOf(sel(e))
                if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
            }
            drawPath(path, color, style = Stroke(width = 2.5f, cap = StrokeCap.Round))
        }
        drawSeries(downColor) { it.downMbps }
        drawSeries(upColor) { it.upMbps }
    }
}

private fun formatHistoryDate(ts: Long): String =
    java.text.SimpleDateFormat("dd/MM HH:mm", java.util.Locale.FRENCH).format(java.util.Date(ts))

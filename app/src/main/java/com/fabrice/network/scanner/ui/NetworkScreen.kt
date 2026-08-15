package com.fabrice.network.scanner.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.NetworkInfoProvider
import com.fabrice.network.scanner.WifiQuality
import kotlinx.coroutines.delay

/**
 * Écran « Réseau » : infos du réseau Wi-Fi (SSID, BSSID, passerelle, DNS,
 * masque, bande, débit) + graphe RSSI en temps réel (courbe du signal sur
 * les 2 dernières minutes — bouge quand on se déplace).
 */
@Composable
fun NetworkScreen() {
    val context = LocalContext.current
    var info by remember { mutableStateOf(NetworkInfoProvider.read(context)) }
    var rssi by remember { mutableStateOf(WifiQuality.currentRssi(context)) }
    var publicIp by remember { mutableStateOf<String?>(null) }
    // Historique RSSI : (secondes, dBm) — 120 échantillons = 2 min
    val history = remember { mutableListOf<Pair<Long, Int>>() }
    val startTime = remember { System.currentTimeMillis() }

    // Récupère l'IP publique (WAN) au chargement, hors thread UI
    LaunchedEffect(Unit) {
        publicIp = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            NetworkInfoProvider.fetchPublicIp()
        }
    }

    // Rafraîchit infos + RSSI toutes les 2 s
    LaunchedEffect(Unit) {
        while (true) {
            info = NetworkInfoProvider.read(context)
            rssi = WifiQuality.currentRssi(context)
            if (rssi != Int.MIN_VALUE) {
                history.add(((System.currentTimeMillis() - startTime) / 1000) to rssi)
                if (history.size > 120) history.removeAt(0)
            }
            delay(2_000)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 12.dp)
    ) {
        Spacer(Modifier.height(4.dp))

        // --- Qualité Wi-Fi + test réseau (déplacé depuis l'onglet Périphériques) ---
        NetworkPanel()

        Spacer(Modifier.height(8.dp))

        // --- Infos réseau ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
            Column(Modifier.padding(12.dp)) {
                Text(
                    "🌐 Réseau Wi-Fi",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(8.dp))
                InfoRow("SSID", info.ssid.ifBlank { "inconnu" })
                InfoRow("BSSID", info.bssid.ifBlank { "non disponible" })
                InfoRow("Réseau", info.networkAddress.ifBlank { "—" } + if (info.mask.isNotBlank()) " / ${info.mask}" else "")
                InfoRow("Passerelle", info.gateway.ifBlank { "inconnue" })
                InfoRow("IP publique", publicIp ?: "…")
                InfoRow("DNS", info.dns.joinToString(", ").ifBlank { "inconnu" })
                InfoRow("Bande", info.band.ifBlank { "—" })
                InfoRow("Débit liaison", if (info.linkSpeedMbps > 0) "${info.linkSpeedMbps} Mbps" else "—")
                InfoRow("Signal", "${WifiQuality.formatRssi(rssi)} · ${WifiQuality.label(rssi)}")
            }
        }

        Spacer(Modifier.height(8.dp))

        // --- Graphe RSSI ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
            Column(Modifier.padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "📈 Signal dans le temps",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.weight(1f))
                    Text(
                        WifiQuality.formatRssi(rssi),
                        style = MaterialTheme.typography.labelMedium,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    "Promène-toi : la courbe monte quand le signal s'améliore.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(8.dp))
                RssiGraph(history = history.toList(), modifier = Modifier
                    .fillMaxWidth()
                    .height(140.dp))
                Spacer(Modifier.height(4.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("0 s", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text("1 min", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text("2 min", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

/** Courbe du RSSI (dBm) sur la fenêtre glissante. */
@Composable
private fun RssiGraph(history: List<Pair<Long, Int>>, modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height

        // Fond quadrillé (palier -50 / -70 / -90)
        val gridColor = Color(0xFFE0E0E0)
        listOf(-50, -70, -90).forEach { level ->
            val y = ((level - -100f) / (-40f)) * h
            drawLine(gridColor, Offset(0f, y), Offset(w, y), strokeWidth = 1f)
        }

        if (history.size < 2) {
            drawLine(
                Color(0xFFBDBDBD),
                Offset(w * 0.1f, h / 2),
                Offset(w * 0.9f, h / 2),
                strokeWidth = 2f,
                cap = StrokeCap.Round
            )
            return@Canvas
        }

        // Normalisation : RSSI -100..-40 → hauteur 0..h
        fun yOf(rssi: Int): Float {
            val t = (rssi - -100f) / (-40f - -100f)
            return h - (t * h).coerceIn(0f, h)
        }

        val maxT = history.maxOf { it.first }.toFloat().coerceAtLeast(1f)
        val path = Path()
        history.forEachIndexed { i, (t, rssi) ->
            val x = (t / maxT) * w
            val y = yOf(rssi)
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }

        // Zone sous la courbe
        val fillPath = Path().apply {
            addPath(path)
            lineTo(w, h)
            lineTo(0f, h)
            close()
        }
        drawPath(fillPath, Color(0x1F2E7D32))

        // Courbe
        drawPath(path, Color(0xFF2E7D32), style = Stroke(width = 2.5f, cap = StrokeCap.Round))

        // Dernier point (position actuelle)
        val last = history.last()
        drawCircle(
            Color(0xFFC9972B),
            radius = 5f,
            center = Offset((last.first / maxT) * w, yOf(last.second))
        )
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.padding(vertical = 3.dp)) {
        Text(
            "$label :",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(end = 8.dp)
        )
        Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
    }
}

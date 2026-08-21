package com.fabrice.network.scanner.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.NetworkInfoProvider
import com.fabrice.network.scanner.ProximityIndicator
import com.fabrice.network.scanner.WifiQuality
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Écran « Réseau » : infos du réseau Wi-Fi (SSID, BSSID, passerelle, DNS,
 * masque, bande, débit) + graphe RSSI en temps réel (courbe du signal sur
 * les 2 dernières minutes — bouge quand on se déplace).
 */
@Composable
fun NetworkScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var info by remember { mutableStateOf(NetworkInfoProvider.read(context)) }
    var rssi by remember { mutableStateOf(WifiQuality.currentRssi(context)) }
    var publicIp by remember { mutableStateOf<String?>(null) }
    var geoInfo by remember { mutableStateOf<NetworkInfoProvider.GeoIpInfo?>(null) }
    // Historique RSSI : (secondes, dBm) — 120 échantillons = 2 min
    val history = remember { mutableListOf<Pair<Long, Int>>() }
    // Fenêtre glissante de 4 échantillons RSSI pour la tendance de proximité
    val rssiWindow = remember { mutableListOf<Int>() }
    val startTime = remember { System.currentTimeMillis() }

    // Récupère l'IP publique (WAN) + GeoIP au chargement, hors thread UI
    LaunchedEffect(Unit) {
        val ip = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            NetworkInfoProvider.fetchPublicIp()
        }
        publicIp = ip
        if (ip != null) {
            geoInfo = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                NetworkInfoProvider.fetchGeoIp(ip)
            }
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
                rssiWindow.add(rssi)
                if (rssiWindow.size > 4) rssiWindow.removeAt(0)
            }
            delay(2_000)
        }
    }

    Box(Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 12.dp)
        ) {
        Spacer(Modifier.height(4.dp))

        // --- Qualité Wi-Fi + test réseau (déplacé depuis l'onglet Périphériques) ---
        // RSSI partagé (une seule boucle de sondage dans NetworkScreen).
        NetworkPanel(rssi = rssi)

        Spacer(Modifier.height(8.dp))

        // --- Proximité de la box (tendance RSSI) ---
        ProximityCard(samples = rssiWindow.toList())

        Spacer(Modifier.height(8.dp))

        // --- Infos réseau ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
        ) {
            Column(Modifier.padding(16.dp)) {
                Text(
                    "Réseau Wi-Fi",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(8.dp))
                InfoRow("SSID", info.ssid.ifBlank { "inconnu" })
                InfoRow("BSSID", info.bssid.ifBlank { "non disponible" }, mono = true)
                InfoRow("Réseau", info.networkAddress.ifBlank { "—" } + if (info.mask.isNotBlank()) " / ${info.mask}" else "", mono = true)
                InfoRow("Passerelle", info.gateway.ifBlank { "inconnue" }, mono = true)
                Row(
                    Modifier.padding(vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "IP publique :",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(end = 8.dp)
                    )
                    Text(
                        publicIp ?: "…",
                        style = LocalMonoTextStyle.current,
                        fontWeight = FontWeight.Medium
                    )
                    publicIp?.let {
                        TextButton(onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("ip", it))
                            scope.launch { snackbar.showSnackbar("IP publique copiée") }
                        }) { Text("📋 Copier") }
                    }
                }
                geoInfo?.let { g ->
                    InfoRow("Localisation", listOfNotNull(g.city, g.region, g.country).joinToString(", ").ifBlank { "—" })
                    if (g.org.isNotBlank()) InfoRow("FAI", g.org)
                }
                InfoRow("DNS", info.dns.joinToString(", ").ifBlank { "inconnu" }, mono = true)
                InfoRow("Bande", info.band.ifBlank { "—" })
                InfoRow("Débit liaison", if (info.linkSpeedMbps > 0) "${info.linkSpeedMbps} Mbps" else "—")
                InfoRow("Signal", "${WifiQuality.formatRssi(rssi)} · ${WifiQuality.label(rssi)}")
            }
        }

        Spacer(Modifier.height(8.dp))

        // --- Graphe RSSI ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
        ) {
            Column(Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "Signal dans le temps",
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
                Spacer(Modifier.height(4.dp))
                Text(
                    "Promène-toi : la courbe monte quand le signal s'améliore (échelle −40 à −100 dBm).",
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
    SnackbarHost(hostState = snackbar, modifier = Modifier.align(Alignment.BottomCenter))
    }
}

/** Carte proximité de la box : tendance RSSI + flèche animée. */
@Composable
private fun ProximityCard(samples: List<Int>) {
    val trend = ProximityIndicator.tendency(samples)
    val emoji = ProximityIndicator.emoji(trend)
    val arrow = ProximityIndicator.arrow(trend)
    val label = ProximityIndicator.trendLabel(trend)
    val strength = ProximityIndicator.strength(samples)
    // Animation : la flèche pulse légèrement quand on se déplace
    val scale by animateFloatAsState(
        targetValue = if (trend != ProximityIndicator.Trend.NEUTRAL) 1.25f else 1f,
        label = "proximityScale"
    )
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "$emoji $arrow",
                style = MaterialTheme.typography.headlineMedium,
                modifier = Modifier.graphicsLayer { scaleX = scale; scaleY = scale }
            )
            Spacer(Modifier.padding(horizontal = 8.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    "Proximité de la box",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    label,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    "Signal ${WifiQuality.formatRssi(samples.lastOrNull() ?: Int.MIN_VALUE)} · $strength/4",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

/** Courbe du RSSI (dBm) sur la fenêtre glissante. */
@Composable
private fun RssiGraph(history: List<Pair<Long, Int>>, modifier: Modifier = Modifier) {
    val gridColor = MaterialTheme.colorScheme.outlineVariant
    val idleColor = MaterialTheme.colorScheme.onSurfaceVariant
    val curveColor = MaterialTheme.colorScheme.primary
    val fillColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)
    val dotColor = MaterialTheme.colorScheme.tertiary
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height

        // Fond quadrillé (palier -50 / -70 / -90) — même normalisation que yOf
        // (échelle -100..-40 dBm inversée), sinon les lignes tombent hors du canvas.
        listOf(-50, -70, -90).forEach { level ->
            val y = h - ((level + 100f) / 60f) * h
            drawLine(gridColor, Offset(0f, y), Offset(w, y), strokeWidth = 1f)
        }

        if (history.size < 2) {
            drawLine(
                idleColor,
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
        drawPath(fillPath, fillColor)

        // Courbe
        drawPath(path, curveColor, style = Stroke(width = 2.5f, cap = StrokeCap.Round))

        // Dernier point (position actuelle)
        val last = history.last()
        drawCircle(
            dotColor,
            radius = 5f,
            center = Offset((last.first / maxT) * w, yOf(last.second))
        )
    }
}

@Composable
private fun InfoRow(label: String, value: String, mono: Boolean = false) {
    Row(Modifier.padding(vertical = 3.dp)) {
        Text(
            "$label :",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(end = 8.dp)
        )
        Text(
            value,
            style = if (mono) LocalMonoTextStyle.current else MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium
        )
    }
}

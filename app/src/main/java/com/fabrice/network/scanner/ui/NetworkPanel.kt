package com.fabrice.network.scanner.ui

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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.SpeedTest
import com.fabrice.network.scanner.WifiQuality
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Panneau « Réseau » : qualité Wi-Fi en temps réel (barre RSSI qui réagit
 * aux déplacements) + test de vitesse (download / upload / latence).
 */
@Composable
fun NetworkPanel() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var rssi by remember { mutableStateOf(Int.MIN_VALUE) }
    var testing by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<SpeedTest.Result?>(null) }
    var testError by remember { mutableStateOf(false) }

    // Rafraîchit le RSSI toutes les 2 s — la barre bouge quand on se déplace
    LaunchedEffect(Unit) {
        while (true) {
            rssi = WifiQuality.currentRssi(context)
            delay(2_000)
        }
    }

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
            testing = false
        }
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(Modifier.padding(12.dp)) {
            // --- Qualité Wi-Fi ---
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "📶 Qualité Wi-Fi",
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
                    "🚀 Test réseau",
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
                    MetricBox("⬇️ Télécharger", "${SpeedTest.formatMbps(r.downloadMbps)} Mbps", Color(0xFF2E7D32))
                    MetricBox("⬆️ Charger", "${SpeedTest.formatMbps(r.uploadMbps)} Mbps", Color(0xFF1B3A6B))
                    MetricBox("⏱️ Latence", "${r.latencyMs} ms", Color(0xFFC62828))
                }
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
                        if (on) Color(0xFF2E7D32) else Color(0xFFE0E0E0),
                        RoundedCornerShape(2.dp)
                    )
            )
        }
    }
}

@Composable
private fun RowScope.MetricBox(label: String, value: String, color: Color) {
    Column(
        modifier = Modifier
            .weight(1f)
            .background(color, RoundedCornerShape(8.dp))
            .padding(vertical = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = Color.White.copy(alpha = 0.85f)
        )
        Spacer(Modifier.height(2.dp))
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = Color.White,
            fontWeight = FontWeight.Bold
        )
    }
}

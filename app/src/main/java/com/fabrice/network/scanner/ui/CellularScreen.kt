package com.fabrice.network.scanner.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.CellularInfo
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import com.fabrice.network.scanner.ui.theme.LocalScannerColors
import com.fabrice.network.scanner.ui.theme.onColorFor
import kotlinx.coroutines.delay

/**
 * Onglet « Cellulaire » (v1.8.0) : réseau mobile 2G/3G/4G/5G — opérateur,
 * type de réseau, signal (dBm/barres), roaming, vulnérabilité.
 *
 * ⚠️ Android 10+ : `getCellInfo()` (cellId/PCI) est restreint → on n'affiche
 * que l'opérateur/réseau/signal/roaming (voir CellularInfo.read).
 */
@Composable
fun CellularScreen() {
    val context = LocalContext.current
    var status by remember { mutableStateOf(CellularInfo.read(context)) }
    val vuln = CellularInfo.analyze(status.roaming, status.networkType)

    // Rafraîchit toutes les 5 s
    LaunchedEffect(Unit) {
        while (true) {
            status = CellularInfo.read(context)
            delay(5_000)
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 12.dp)
    ) {
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Réseau cellulaire", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Text(
                    "Opérateur · signal · vulnérabilité",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Button(onClick = { status = CellularInfo.read(context) }) { Text("🔄 Actualiser") }
        }
        Spacer(Modifier.height(8.dp))

        // --- Carte opérateur + réseau ---
        Card(
            Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("Opérateur", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(8.dp))
                CellRow("Réseau", status.operator.ifBlank { "—" })
                if (status.operatorCode.isNotBlank()) CellRow("Code (MCC/MNC)", status.operatorCode, mono = true)
                if (status.simOperator.isNotBlank()) CellRow("Opérateur SIM", status.simOperator)
                CellRow("Type de réseau", status.networkType)
                CellRow("Roaming", if (status.roaming) "🟡 Oui" else "Non")
            }
        }

        Spacer(Modifier.height(8.dp))

        // --- Jauge de signal ---
        Card(
            Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("Signal", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(8.dp))
                val dbm = status.signalDbm
                if (dbm != null) {
                    Text("$dbm dBm", style = LocalMonoTextStyle.current, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(6.dp))
                    SignalGauge(status.signalBars)
                } else {
                    Text("Non disponible", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        // --- Vulnérabilité ---
        Card(
            Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("Vulnérabilité", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(8.dp))
                val semantic = LocalScannerColors.current
                val scoreColor = when {
                    vuln.score < 25 -> semantic.riskNone
                    vuln.score < 50 -> semantic.riskModerate
                    vuln.score < 75 -> semantic.riskHigh
                    else -> semantic.riskCritical
                }
                Box(
                    Modifier
                        .background(scoreColor, MaterialTheme.shapes.small)
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Text(
                        "${vuln.score} / 100 · ${vuln.label}",
                        color = onColorFor(scoreColor),
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
                Spacer(Modifier.height(8.dp))
                vuln.risks.forEach { r ->
                    Text("• $r", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 2.dp))
                }
                Spacer(Modifier.height(6.dp))
                Text("Recommandations", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                vuln.recommendations.forEach { r ->
                    Text("→ $r", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 2.dp))
                }
            }
        }
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun CellRow(label: String, value: String, mono: Boolean = false) {
    Row(Modifier.padding(vertical = 3.dp)) {
        Text(
            "$label :",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(130.dp)
        )
        Text(
            value,
            style = if (mono) LocalMonoTextStyle.current else MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium
        )
    }
}

/** Jauge de signal : 4 barres dont la couleur varie selon la force. */
@Composable
private fun SignalGauge(bars: Int) {
    val semantic = LocalScannerColors.current
    val color: Color = when (bars) {
        4 -> semantic.riskNone
        3 -> semantic.riskLow
        2 -> semantic.riskModerate
        1 -> semantic.riskHigh
        else -> semantic.offline
    }
    Row(verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(3.dp)) {
        (1..4).forEach { i ->
            val active = i <= bars
            Box(
                Modifier
                    .width(8.dp)
                    .height((8 + i * 4).dp)
                    .background(
                        if (active) color else MaterialTheme.colorScheme.surfaceVariant,
                        MaterialTheme.shapes.small
                    )
            )
        }
    }
}

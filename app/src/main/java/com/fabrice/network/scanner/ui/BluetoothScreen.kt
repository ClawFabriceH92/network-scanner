package com.fabrice.network.scanner.ui

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.BluetoothScanner
import com.fabrice.network.scanner.BluetoothServiceProbe
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Onglet « Bluetooth » : scan BT/BLE des périphériques à proximité,
 * avec nom, MAC, RSSI (signal), type et fabricant. Tri par signal
 * (plus fort en premier), barre de RSSI, état permissions guidé.
 */
@Composable
fun BluetoothScreen(
    devices: List<BluetoothScanner.BtDevice>,
    scanning: Boolean,
    error: String?,
    onScan: () -> Unit
) {
    val context = LocalContext.current
    Column(Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "Périphériques à proximité",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    "Bluetooth + BLE — ${devices.size} trouvé(s)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Button(onClick = onScan, enabled = !scanning) {
                if (scanning) {
                    CircularProgressIndicator(
                        Modifier.width(16.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Scan…")
                } else {
                    Text("Scanner")
                }
            }
        }

        error?.let {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 4.dp),
                shape = MaterialTheme.shapes.large,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        it,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = {
                        context.startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
                    }) { Text("Réglages") }
                }
            }
        }

        if (devices.isEmpty() && !scanning) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Icon(
                    Icons.Filled.Info,
                    contentDescription = null,
                    modifier = Modifier.size(48.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(16.dp))
                Text(
                    "Aucun appareil Bluetooth détecté",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Vérifie que le Bluetooth et la localisation sont actifs, puis lance un scan pour détecter les appareils autour de toi.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )
                Spacer(Modifier.height(20.dp))
                FilledTonalButton(
                    onClick = onScan,
                    shape = MaterialTheme.shapes.extraLarge
                ) {
                    Text("Scanner Bluetooth")
                }
                TextButton(onClick = {
                    context.startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
                }) { Text("Ouvrir les réglages Bluetooth") }
            }
        } else if (devices.isNotEmpty()) {
            val sorted = devices.sortedByDescending { it.rssi }
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(sorted, key = { it.mac }) { device ->
                    BtDeviceCard(device)
                }
            }
        }
    }
}

/** Icône Material monochrome selon le type Bluetooth (BLE / classique / apparié). */
private fun btTypeIcon(type: String): ImageVector = when (type) {
    "BLE" -> Icons.Filled.Build
    "BR" -> Icons.Filled.Phone
    "apparié" -> Icons.Filled.Check
    else -> Icons.Filled.Info
}

@Composable
private fun BtDeviceCard(device: BluetoothScanner.BtDevice) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var probing by remember { mutableStateOf(false) }
    var probe by remember { mutableStateOf<BluetoothServiceProbe.Result?>(null) }
    var showDialog by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.fillMaxWidth().padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(44.dp)
                        .background(MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.shapes.medium),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        btTypeIcon(device.type),
                        contentDescription = device.type,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(24.dp)
                    )
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        text = device.name.ifBlank { "Inconnu" },
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 1
                    )
                    Text(
                        text = device.mac,
                        style = LocalMonoTextStyle.current,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = if (device.vendor.isNotBlank()) device.vendor else "Fabricant inconnu",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (device.services.isNotBlank()) {
                        Text(
                            text = device.services,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1
                        )
                    }
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(
                        text = "${device.rssi} dBm",
                        style = LocalMonoTextStyle.current,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = device.type,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(4.dp))
                    RssiBar(device.rssi)
                }
            }
            Spacer(Modifier.height(4.dp))
            TextButton(onClick = {
                probe = null
                probing = true
                showDialog = true
                scope.launch {
                    val r = withContext(Dispatchers.IO) {
                        runCatching { BluetoothServiceProbe.probe(context, device.mac) }.getOrNull()
                    }
                    probe = r
                    probing = false
                }
            }, enabled = !probing) {
                Text(if (probing) "🔎 Analyse…" else "🔎 Services & risques")
            }
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            title = { Text("🔵 ${device.name.ifBlank { device.mac }}") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    if (probing) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(8.dp))
                            Text("Connexion et découverte des services…", style = MaterialTheme.typography.bodySmall)
                        }
                    } else {
                        val r = probe
                        if (r != null && r.services.isNotEmpty()) {
                            Text("Services joignables (${r.services.size})",
                                fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodyMedium)
                            Spacer(Modifier.height(4.dp))
                            r.services.forEach { s ->
                                Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                                    Text(s.name, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                                    Text(s.kind, style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        } else {
                            Text(
                                r?.note?.ifBlank { null } ?: "Échec de la sonde (permission Bluetooth ou appareil injoignable).",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                        val risks = probe?.risks ?: emptyList()
                        if (risks.isNotEmpty()) {
                            Spacer(Modifier.height(10.dp))
                            Text("Analyse de risque", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodyMedium)
                            Spacer(Modifier.height(4.dp))
                            risks.forEach { risk ->
                                Text(risk, style = MaterialTheme.typography.bodySmall)
                                Spacer(Modifier.height(3.dp))
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showDialog = false }) { Text("Fermer") }
            }
        )
    }
}

/** Barre de signal RSSI (−100 → −40 dBm), visuelle et parlante. */
@Composable
private fun RssiBar(rssi: Int) {
    val fraction = ((rssi + 100).coerceIn(0, 60)) / 60f
    Box(
        modifier = Modifier
            .width(72.dp)
            .height(6.dp)
            .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(3.dp))
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth(fraction)
                .height(6.dp)
                .background(MaterialTheme.colorScheme.primary, RoundedCornerShape(3.dp))
        )
    }
}

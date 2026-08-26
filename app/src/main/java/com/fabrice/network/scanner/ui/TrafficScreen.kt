package com.fabrice.network.scanner.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.fabrice.network.scanner.capture.AppTrafficMonitor
import com.fabrice.network.scanner.capture.CaptureState
import com.fabrice.network.scanner.capture.CaptureVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Écran « Capture réseau » (icône Pac-Man) — équivalent des fonctions clés de
 * PCAPdroid :
 *  1. Consommation par application (via NetworkStatsManager, sans VPN) ;
 *  2. Capture de paquets en direct via un VpnService qui **réémet** le trafic
 *     (l'accès Internet reste actif) et enregistre un fichier .pcap exportable.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrafficScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    val running by CaptureState.running.collectAsState()
    val connections by CaptureState.connections.collectAsState()
    val totalIn by CaptureState.totalIn.collectAsState()
    val totalOut by CaptureState.totalOut.collectAsState()
    val packetCount by CaptureState.packetCount.collectAsState()
    val pcapPath by CaptureState.pcapPath.collectAsState()
    val captureError by CaptureState.error.collectAsState()

    // Consentement VPN (dialogue système). Sur RESULT_OK → on démarre le service.
    val vpnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) startCaptureService(context)
        else scope.launch { snackbar.showSnackbar("Autorisation VPN refusée") }
    }

    fun toggleCapture() {
        if (running) {
            CaptureVpnService.stop(context)
        } else {
            val prep = VpnService.prepare(context)
            if (prep != null) vpnLauncher.launch(prep) else startCaptureService(context)
        }
    }

    LaunchedEffect(captureError) {
        captureError?.let { snackbar.showSnackbar(it) }
    }

    // ---- Section « usage par app » -----------------------------------------
    var hasUsage by remember { mutableStateOf(AppTrafficMonitor.hasUsageAccess(context)) }
    var usage by remember { mutableStateOf<List<AppTrafficMonitor.AppUsage>>(emptyList()) }
    var usageLoading by remember { mutableStateOf(false) }
    // Période : 0 = 24 h, 1 = 7 j, 2 = 30 j
    var period by remember { mutableStateOf(0) }

    fun refreshUsage() {
        hasUsage = AppTrafficMonitor.hasUsageAccess(context)
        if (!hasUsage) { usage = emptyList(); return }
        scope.launch {
            usageLoading = true
            val now = System.currentTimeMillis()
            val since = now - when (period) {
                0 -> 24L * 3600_000
                1 -> 7L * 24 * 3600_000
                else -> 30L * 24 * 3600_000
            }
            usage = withContext(Dispatchers.IO) {
                runCatching { AppTrafficMonitor.query(context, since, now) }.getOrDefault(emptyList())
            }
            usageLoading = false
        }
    }

    LaunchedEffect(period) { refreshUsage() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Capture réseau") },
                navigationIcon = {
                    TextButton(onClick = onBack) { Text("← Retour") }
                }
            )
        },
        snackbarHost = { SnackbarHost(snackbar) }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.padding(padding).fillMaxSize().padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // ---- Carte capture VPN ----------------------------------------
            item {
                Card(colors = CardDefaults.cardColors()) {
                    Column(Modifier.padding(14.dp)) {
                        Text("🟡 Capture de paquets (VPN local)", fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "Démarre un VPN sur l'appareil qui capture le trafic IPv4 et le " +
                            "réémet vers Internet (la connexion reste active). Génère un " +
                            "fichier .pcap lisible dans Wireshark.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(10.dp))
                        Button(
                            onClick = { toggleCapture() },
                            modifier = Modifier.fillMaxWidth(),
                            colors = if (running)
                                ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                            else ButtonDefaults.buttonColors()
                        ) {
                            Text(if (running) "⏹ Arrêter la capture" else "▶ Démarrer la capture")
                        }
                        if (running || packetCount > 0) {
                            Spacer(Modifier.height(10.dp))
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                StatCell("Paquets", packetCount.toString())
                                StatCell("↑ Émis", AppTrafficMonitor.formatBytes(totalOut))
                                StatCell("↓ Reçus", AppTrafficMonitor.formatBytes(totalIn))
                                StatCell("Flux", connections.size.toString())
                            }
                        }
                        if (!running && pcapPath != null && packetCount > 0) {
                            Spacer(Modifier.height(10.dp))
                            OutlinedButton(
                                onClick = { sharePcap(context, pcapPath!!) },
                                modifier = Modifier.fillMaxWidth()
                            ) { Text("📤 Exporter le fichier .pcap") }
                        }
                    }
                }
            }

            // ---- Connexions en direct -------------------------------------
            if (connections.isNotEmpty()) {
                item {
                    Text("Connexions (${connections.size})", fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.titleSmall)
                }
                items(connections) { c -> ConnRow(c) }
            }

            item { HorizontalDivider(Modifier.padding(vertical = 4.dp)) }

            // ---- Usage par application ------------------------------------
            item {
                Card {
                    Column(Modifier.padding(14.dp)) {
                        Text("📊 Consommation par application", fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "Données Wi-Fi + mobile par app, sans VPN.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (!hasUsage) {
                            Spacer(Modifier.height(10.dp))
                            Text(
                                "Autorisation « Accès aux données d'utilisation » requise.",
                                style = MaterialTheme.typography.bodySmall
                            )
                            Spacer(Modifier.height(6.dp))
                            Button(onClick = {
                                runCatching {
                                    context.startActivity(AppTrafficMonitor.usageAccessSettingsIntent())
                                }
                            }, modifier = Modifier.fillMaxWidth()) {
                                Text("Ouvrir les réglages d'accès")
                            }
                            Spacer(Modifier.height(6.dp))
                            OutlinedButton(onClick = { refreshUsage() }, modifier = Modifier.fillMaxWidth()) {
                                Text("J'ai autorisé — recharger")
                            }
                        } else {
                            Spacer(Modifier.height(10.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                FilterChip(selected = period == 0, onClick = { period = 0 }, label = { Text("24 h") })
                                FilterChip(selected = period == 1, onClick = { period = 1 }, label = { Text("7 j") })
                                FilterChip(selected = period == 2, onClick = { period = 2 }, label = { Text("30 j") })
                            }
                        }
                    }
                }
            }

            if (hasUsage) {
                if (usageLoading) {
                    item { Text("Chargement…", style = MaterialTheme.typography.bodySmall) }
                } else if (usage.isEmpty()) {
                    item { Text("Aucune donnée sur la période.", style = MaterialTheme.typography.bodySmall) }
                } else {
                    items(usage) { u -> UsageRow(u) }
                }
            }

            item { Spacer(Modifier.height(24.dp)) }
        }
    }
}

@Composable
private fun StatCell(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodyMedium)
        Text(label, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ConnRow(c: CaptureState.Conn) {
    Card {
        Column(Modifier.fillMaxWidth().padding(10.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    "${c.protocol}  ${c.remoteIp}:${c.remotePort}",
                    fontWeight = FontWeight.SemiBold,
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    if (c.status == "actif") "● actif" else "○ fermé",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (c.status == "actif") Color(0xFF2E7D32) else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(
                "${c.appLabel.ifBlank { "app inconnue" }}  ·  port local ${c.localPort}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "↑ ${AppTrafficMonitor.formatBytes(c.bytesOut)}  ↓ ${AppTrafficMonitor.formatBytes(c.bytesIn)}",
                style = MaterialTheme.typography.labelSmall
            )
        }
    }
}

@Composable
private fun UsageRow(u: AppTrafficMonitor.AppUsage) {
    Card {
        Row(
            Modifier.fillMaxWidth().padding(10.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(u.label, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium)
                Text(
                    "↑ ${AppTrafficMonitor.formatBytes(u.txBytes)}   ↓ ${AppTrafficMonitor.formatBytes(u.rxBytes)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(AppTrafficMonitor.formatBytes(u.total), fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.bodyMedium)
        }
    }
}

private fun startCaptureService(context: Context) {
    val i = Intent(context, CaptureVpnService::class.java).setAction(CaptureVpnService.ACTION_START)
    ContextCompat.startForegroundService(context, i)
}

private fun sharePcap(context: Context, path: String) {
    runCatching {
        val file = File(path)
        if (!file.exists()) return
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "Exporter la capture .pcap"))
    }
}

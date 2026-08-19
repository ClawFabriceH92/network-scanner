package com.fabrice.network.scanner.ui

import android.content.Context
import androidx.compose.foundation.Canvas
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.BoxBandwidth
import com.fabrice.network.scanner.BoxClient
import com.fabrice.network.scanner.BoxConnection
import com.fabrice.network.scanner.BoxLease
import com.fabrice.network.scanner.BoxManager
import com.fabrice.network.scanner.BoxSystem
import com.fabrice.network.scanner.BoxWifi
import com.fabrice.network.scanner.FreeboxBoxClient
import com.fabrice.network.scanner.LiveboxBoxClient
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Onglet « Box » (v1.8.0) : infos de la box locale (Freebox/Bbox/Livebox) —
 * connexion WAN, débit temps réel, WiFi de la box, système, baux DHCP.
 * Chaque section est conditionnelle : si l'endpoint renvoie null, la carte
 * n'apparaît pas. Si TOUT est null → message « scan direct uniquement ».
 */
@Composable
fun BoxScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var client by remember { mutableStateOf<BoxClient?>(null) }
    var loading by remember { mutableStateOf(true) }
    var connection by remember { mutableStateOf<BoxConnection?>(null) }
    var bandwidth by remember { mutableStateOf<BoxBandwidth?>(null) }
    var wifi by remember { mutableStateOf<BoxWifi?>(null) }
    var system by remember { mutableStateOf<BoxSystem?>(null) }
    var leases by remember { mutableStateOf<List<BoxLease>?>(null) }
    // Échantillons de débit temps réel (Mo/s) pour le graphique ↑↓
    val bwHistory = remember { mutableListOf<BoxBandwidth>() }
    var passwordDraft by remember { mutableStateOf("") }

    fun fetchAll() {
        val box = BoxManager.detect(context)
        client = box
        scope.launch {
            loading = true
            withContext(Dispatchers.IO) {
                if (box == null) {
                    connection = null; bandwidth = null; wifi = null; system = null; leases = null
                } else {
                    connection = runCatching { box.fetchConnection() }.getOrNull()
                    bandwidth = runCatching { box.fetchBandwidth() }.getOrNull()
                    wifi = runCatching { box.fetchWifi() }.getOrNull()
                    system = runCatching { box.fetchSystem() }.getOrNull()
                    leases = runCatching { box.fetchLeases() }.getOrNull()
                }
            }
            loading = false
            BoxManager.reset() // force le re-détect si la box a changé
        }
    }

    LaunchedEffect(Unit) { fetchAll() }

    // Échantillonnage du débit toutes les 2 s (15 points ≈ 30 s)
    LaunchedEffect(client) {
        val box = client ?: return@LaunchedEffect
        bwHistory.clear()
        repeat(15) {
            val bw = withContext(Dispatchers.IO) {
                runCatching { box.fetchBandwidth() }.getOrNull()
            }
            if (bw != null) {
                bwHistory.add(bw)
                bandwidth = bw
            }
            delay(2_000)
        }
    }

    Box(Modifier.fillMaxSize()) {
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 12.dp)
        ) {
            Spacer(Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Box", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Text(
                        client?.name ?: "non détectée",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Medium
                    )
                }
                if (loading) {
                    CircularProgressIndicator(Modifier.height(20.dp))
                } else {
                    TextButton(onClick = { fetchAll() }) { Text("🔄 Actualiser") }
                }
            }

            val everythingNull = connection == null && bandwidth == null &&
                wifi == null && system == null && (leases == null || leases!!.isEmpty())

            if (everythingNull && !loading) {
                Spacer(Modifier.height(8.dp))
                Card(
                    Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
                ) {
                    Text(
                        "📡 Box non accessible via API (SFR ?) — scan direct uniquement.\n" +
                            "Les Bbox/Livebox nécessitent un mot de passe device ou une autorisation.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }

            connection?.let { ConnectionCard(it) }
            if (bwHistory.size >= 2) {
                BandwidthCard(bandwidth = bandwidth, history = bwHistory.toList())
            }
            wifi?.let { BoxWifiCard(it) }
            system?.let { SystemCard(it) }
            leases?.let { LeasesCard(it) }

            Spacer(Modifier.height(8.dp))
            SettingsCard(
                client = client,
                context = context,
                passwordDraft = passwordDraft,
                onPasswordDraftChange = { passwordDraft = it },
                onSaved = {
                    scope.launch {
                        BoxManager.reset()
                        fetchAll()
                        snackbar.showSnackbar("Réglages box enregistrés")
                    }
                }
            )
            Spacer(Modifier.height(16.dp))
        }
        SnackbarHost(hostState = snackbar, modifier = Modifier.align(Alignment.BottomCenter))
    }
}

@Composable
private fun ConnectionCard(c: BoxConnection) {
    Card(
        Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Connexion", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            BoxInfoRow("IP publique", c.publicIp.ifBlank { "—" }, mono = true)
            BoxInfoRow("Type d'accès", connectionTypeLabel(c.connectionType))
            BoxInfoRow("Débit contractuel", formatRates(c.downloadRate, c.uploadRate))
        }
    }
}

@Composable
private fun BandwidthCard(bandwidth: BoxBandwidth?, history: List<BoxBandwidth>) {
    Card(
        Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Bande passante temps réel", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            if (bandwidth != null) {
                Text(
                    "⬇️ ${formatMoS(bandwidth.downloadBps)} · ⬆️ ${formatMoS(bandwidth.uploadBps)}",
                    style = LocalMonoTextStyle.current,
                    fontWeight = FontWeight.Medium
                )
            }
            Spacer(Modifier.height(8.dp))
            BandwidthGraph(history, Modifier.fillMaxWidth().height(120.dp))
            Text(
                "Échantillon toutes les 2 s (30 s) — ↓ descendant (bleu), ↑ montant (or).",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/** Graphique débit ↑↓ : deux courbes normalisées sur le max observé. */
@Composable
private fun BandwidthGraph(history: List<BoxBandwidth>, modifier: Modifier = Modifier) {
    val downColor = MaterialTheme.colorScheme.primary
    val upColor = MaterialTheme.colorScheme.tertiary
    val gridColor = MaterialTheme.colorScheme.outlineVariant
    Canvas(modifier) {
        val w = size.width
        val h = size.height
        drawLine(gridColor, Offset(0f, h / 2), Offset(w, h / 2), strokeWidth = 1f)
        if (history.size < 2) return@Canvas
        val maxV = history.maxOf { maxOf(it.downloadBps, it.uploadBps, 1L) }.toFloat()
        fun yOf(v: Long): Float {
            val t = (v.toFloat() / maxV).coerceIn(0f, 1f)
            return h - (t * (h * 0.9f))
        }
        val downPath = Path()
        val upPath = Path()
        history.forEachIndexed { i, b ->
            val x = (i.toFloat() / (history.size - 1)) * w
            if (i == 0) {
                downPath.moveTo(x, yOf(b.downloadBps))
                upPath.moveTo(x, yOf(b.uploadBps))
            } else {
                downPath.lineTo(x, yOf(b.downloadBps))
                upPath.lineTo(x, yOf(b.uploadBps))
            }
        }
        drawPath(downPath, downColor, style = Stroke(width = 2.5f, cap = StrokeCap.Round))
        drawPath(upPath, upColor, style = Stroke(width = 2.5f, cap = StrokeCap.Round))
    }
}

@Composable
private fun BoxWifiCard(w: BoxWifi) {
    Card(
        Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("WiFi box", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            BoxInfoRow("SSID", w.ssid.ifBlank { "—" })
            BoxInfoRow("Sécurité", w.security.ifBlank { "—" })
            BoxInfoRow("Canal", w.channel.ifBlank { "—" })
            if (w.band.isNotBlank()) BoxInfoRow("Bande", w.band)
            if (w.clients.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                Text(
                    "${w.clients.size} client(s) WiFi",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                w.clients.forEach { cl ->
                    Row(Modifier.padding(vertical = 2.dp)) {
                        Text(
                            cl.hostname.ifBlank { cl.mac.ifBlank { cl.ip } },
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.weight(1f)
                        )
                        cl.rssi?.let { Text("$it dBm", style = LocalMonoTextStyle.current, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    }
                }
            }
        }
    }
}

@Composable
private fun SystemCard(s: BoxSystem) {
    Card(
        Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Système", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            BoxInfoRow("Firmware", s.firmware.ifBlank { "—" })
            s.uptimeSeconds?.let { BoxInfoRow("Uptime", formatUptime(it)) }
            s.temperatureC?.let { BoxInfoRow("Température", "$it °C") }
        }
    }
}

@Composable
private fun LeasesCard(leases: List<BoxLease>) {
    Card(
        Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Baux DHCP (${leases.size})", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            LazyColumn(
                Modifier.height(180.dp),
                contentPadding = PaddingValues(0.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                items(leases, key = { "${it.ip}-${it.mac}" }) { l ->
                    Row(Modifier.fillMaxWidth()) {
                        Text(
                            l.ip,
                            style = LocalMonoTextStyle.current,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            l.hostname.ifBlank { l.mac },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.weight(2f)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsCard(
    client: BoxClient?,
    context: Context,
    passwordDraft: String,
    onPasswordDraftChange: (String) -> Unit,
    onSaved: () -> Unit
) {
    Card(
        Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("Réglages box", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            when (client) {
                is LiveboxBoxClient -> {
                    Text(
                        "Mot de passe device (TR-064) :",
                        style = MaterialTheme.typography.labelMedium
                    )
                    OutlinedTextField(
                        value = passwordDraft,
                        onValueChange = onPasswordDraftChange,
                        singleLine = true,
                        label = { Text("Mot de passe device") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(8.dp))
                    Button(onClick = {
                        client.setPassword(passwordDraft.trim())
                        onSaved()
                    }, enabled = passwordDraft.isNotBlank()) { Text("Enregistrer") }
                }
                is FreeboxBoxClient -> {
                    Text(
                        "Autorisation app Freebox :",
                        style = MaterialTheme.typography.labelMedium
                    )
                    Button(onClick = {
                        client.requestAuthorization()
                        onSaved()
                    }) { Text("🔑 Ré-autoriser la box") }
                }
                else -> {
                    Text(
                        "Aucun réglage requis pour cette box (ou box non reconnue).",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun BoxInfoRow(label: String, value: String, mono: Boolean = false) {
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

private fun connectionTypeLabel(t: String): String = when (t.lowercase()) {
    "ftth", "fiber", "fibre" -> "FTTH (fibre)"
    "xdsl", "adsl", "vdsl" -> "xDSL (ADSL/VDSL)"
    "cable", "docsis" -> "Câble (DOCSIS)"
    "" -> "—"
    else -> t
}

private fun formatRates(down: Long?, up: Long?): String {
    val d = down?.let { formatMbps(it) } ?: "—"
    val u = up?.let { formatMbps(it) } ?: "—"
    return "↓ $d · ↑ $u"
}

/** Formate un débit en bits/s → Mb/s (une décimale, virgule FR). */
private fun formatMbps(bps: Long): String {
    val v = bps / 1_000_000.0
    return String.format(java.util.Locale.FRENCH, "%.1f Mb/s", v)
}

/** Formate un débit en octets/s → Mo/s. */
private fun formatMoS(bps: Long): String {
    val v = bps / 1_000_000.0
    return String.format(java.util.Locale.FRENCH, "%.2f Mo/s", v)
}

private fun formatUptime(seconds: Long): String {
    val d = seconds / 86400
    val h = (seconds % 86400) / 3600
    val m = (seconds % 3600) / 60
    return when {
        d > 0 -> "${d}j ${h}h ${m}m"
        h > 0 -> "${h}h ${m}m"
        else -> "${m}m"
    }
}

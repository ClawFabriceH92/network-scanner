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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
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
import com.fabrice.network.scanner.NetworkInfoProvider
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
    // DNS réellement utilisés par le téléphone + passerelle + diagnostic box.
    var dnsServers by remember { mutableStateOf<List<String>>(emptyList()) }
    var gateway by remember { mutableStateOf("") }
    var diag by remember { mutableStateOf<BoxDiag?>(null) }

    fun fetchAll() {
        scope.launch {
            loading = true
            // Infos réseau (DNS, passerelle) — indépendantes de l'API box.
            val net = withContext(Dispatchers.IO) { NetworkInfoProvider.read(context) }
            dnsServers = net.dns
            gateway = net.gateway
            // detect() lit /proc/net/arp + la base OUI → hors thread UI.
            val box = withContext(Dispatchers.IO) { BoxManager.detect(context) }
            client = box
            val endpoints = mutableListOf<Pair<String, String>>()
            withContext(Dispatchers.IO) {
                if (box == null) {
                    connection = null; bandwidth = null; wifi = null; system = null; leases = null
                } else {
                    val cRes = runCatching { box.fetchConnection() }; connection = cRes.getOrNull()
                    endpoints.add("Connexion / WAN" to endpointStatus(cRes))
                    val bRes = runCatching { box.fetchBandwidth() }; bandwidth = bRes.getOrNull()
                    endpoints.add("Débit" to endpointStatus(bRes))
                    val wRes = runCatching { box.fetchWifi() }; wifi = wRes.getOrNull()
                    endpoints.add("WiFi" to endpointStatus(wRes))
                    val sRes = runCatching { box.fetchSystem() }; system = sRes.getOrNull()
                    endpoints.add("Système" to endpointStatus(sRes))
                    val lRes = runCatching { box.fetchLeases() }; leases = lRes.getOrNull()
                    endpoints.add("Baux DHCP" to when {
                        lRes.isFailure -> "erreur"
                        lRes.getOrNull().isNullOrEmpty() -> "vide"
                        else -> "OK (${lRes.getOrNull()!!.size})"
                    })
                }
            }
            diag = BoxDiag(gateway = net.gateway, boxName = box?.name, endpoints = endpoints)
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

            // DNS utilisés par le téléphone (toujours affiché, indépendant de la box).
            Spacer(Modifier.height(8.dp))
            DnsCard(dnsServers, gateway)

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

            // Redémarrage de la box (action destructive → confirmation).
            if (client != null) {
                Spacer(Modifier.height(8.dp))
                var confirmReboot by remember { mutableStateOf(false) }
                Button(
                    onClick = { confirmReboot = true },
                    modifier = Modifier.fillMaxWidth()
                ) { Text("♻️ Redémarrer la box") }
                if (confirmReboot) {
                    androidx.compose.material3.AlertDialog(
                        onDismissRequest = { confirmReboot = false },
                        title = { Text("Redémarrer la box ?") },
                        text = { Text("La connexion Internet sera coupée ~2 minutes.") },
                        confirmButton = {
                            TextButton(onClick = {
                                confirmReboot = false
                                val box = client
                                scope.launch {
                                    val ok = withContext(Dispatchers.IO) {
                                        runCatching { box?.reboot() ?: false }.getOrDefault(false)
                                    }
                                    snackbar.showSnackbar(
                                        if (ok) "Redémarrage demandé."
                                        else "Redémarrage non supporté (ou authentification requise)."
                                    )
                                }
                            }) { Text("Redémarrer") }
                        },
                        dismissButton = {
                            TextButton(onClick = { confirmReboot = false }) { Text("Annuler") }
                        }
                    )
                }
            }

            Spacer(Modifier.height(8.dp))
            DiagnosticCard(diag)

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
            ScheduleSection()
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
            if (c.lineStatus.isNotBlank()) BoxInfoRow("État ligne", c.lineStatus)
            BoxInfoRow("Débit contractuel", formatRates(c.downloadRate, c.uploadRate))
            c.uptimeSeconds?.let { BoxInfoRow("Uptime connexion", formatUptime(it)) }
            // Diagnostic xDSL (ADSL/VDSL uniquement).
            if (c.snrDown != null || c.attenuationDown != null) {
                c.snrDown?.let { BoxInfoRow("Marge de bruit ↓", "$it dB") }
                c.snrUp?.let { BoxInfoRow("Marge de bruit ↑", "$it dB") }
                c.attenuationDown?.let { BoxInfoRow("Atténuation ↓", "$it dB") }
                c.attenuationUp?.let { BoxInfoRow("Atténuation ↑", "$it dB") }
            }
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
            if (s.model.isNotBlank()) BoxInfoRow("Modèle", s.model)
            BoxInfoRow("Firmware", s.firmware.ifBlank { "—" })
            if (s.serial.isNotBlank()) BoxInfoRow("N° de série", s.serial)
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
    val scope = rememberCoroutineScope()
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
                        // Masquage du credential + clavier mot de passe.
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
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
                        // requestAuthorization() fait un POST réseau → hors thread UI
                        // (sinon NetworkOnMainThreadException).
                        scope.launch(Dispatchers.IO) {
                            client.requestAuthorization()
                            withContext(Dispatchers.Main) { onSaved() }
                        }
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

// ---- DNS + Diagnostic (v1.9.31) -------------------------------------------

/** Résumé du diagnostic box : passerelle, box détectée, statut par endpoint. */
private data class BoxDiag(
    val gateway: String,
    val boxName: String?,
    val endpoints: List<Pair<String, String>>   // (libellé, statut)
)

/** Statut d'un endpoint box : OK / vide / erreur. */
private fun <T> endpointStatus(res: Result<T>): String = when {
    res.isFailure -> "erreur"
    res.getOrNull() == null -> "vide"
    else -> "OK"
}

@Composable
private fun DnsCard(dns: List<String>, gateway: String) {
    Card(
        Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("🌐 DNS utilisés", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            if (dns.isEmpty()) {
                Text(
                    "Non disponible (pas de réseau actif ?).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                dns.forEach { ip ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
                        Text(
                            ip,
                            style = LocalMonoTextStyle.current,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            dnsLabel(ip, gateway),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DiagnosticCard(diag: BoxDiag?) {
    if (diag == null) return
    Card(
        Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("🩺 Diagnostic box", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            BoxInfoRow("Passerelle", diag.gateway.ifBlank { "—" }, mono = true)
            BoxInfoRow("Box détectée", diag.boxName ?: "aucune (API)")
            if (diag.endpoints.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                diag.endpoints.forEach { (label, status) ->
                    Row(
                        Modifier.fillMaxWidth().padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("●", color = statusColor(status), modifier = Modifier.padding(end = 6.dp))
                        Text(label, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                        Text(status, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            } else if (diag.boxName == null) {
                Text(
                    "Aucune box pilotable par API détectée. Les box SFR récentes n'exposent pas d'API locale : le scan direct du réseau reste disponible.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

private fun statusColor(status: String): Color = when {
    status.startsWith("OK") -> Color(0xFF2E7D32)
    status == "vide" -> Color(0xFFF57C00)
    status == "erreur" -> Color(0xFFC62828)
    else -> Color(0xFF9E9E9E)
}

/** Étiquette d'un serveur DNS : box / réseau local / résolveur public / externe. */
private fun dnsLabel(ip: String, gateway: String): String {
    if (ip.isNotBlank() && ip == gateway) return "box (passerelle)"
    knownResolver(ip)?.let { return it }
    if (isPrivateIp(ip)) return "réseau local"
    return "externe / FAI"
}

private fun knownResolver(ip: String): String? = when (ip) {
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844" -> "Google"
    "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001" -> "Cloudflare"
    "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9" -> "Quad9"
    "208.67.222.222", "208.67.220.220" -> "OpenDNS"
    "80.67.169.12", "80.67.169.40" -> "FDN"
    "94.140.14.14", "94.140.15.15" -> "AdGuard"
    else -> null
}

private fun isPrivateIp(ip: String): Boolean {
    if (ip.contains(":")) {
        val low = ip.lowercase()
        return low == "::1" || low.startsWith("fe80") || low.startsWith("fc") || low.startsWith("fd")
    }
    val p = ip.split(".").mapNotNull { it.toIntOrNull() }
    if (p.size != 4) return false
    return when {
        p[0] == 10 -> true
        p[0] == 192 && p[1] == 168 -> true
        p[0] == 172 && p[1] in 16..31 -> true
        p[0] == 169 && p[1] == 254 -> true
        p[0] == 127 -> true
        else -> false
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

package com.fabrice.network.scanner.ui

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.provider.Settings
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.fabrice.network.scanner.PermissionHelper
import com.fabrice.network.scanner.PublicWifiAnalyzer
import com.fabrice.network.scanner.WifiChannels
import com.fabrice.network.scanner.WifiScanner
import com.fabrice.network.scanner.WifiVulnAnalyzer
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import com.fabrice.network.scanner.ui.theme.LocalScannerColors
import com.fabrice.network.scanner.ui.theme.onColorFor
import com.fabrice.network.scanner.ui.theme.riskColor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Onglet « WiFi » (v1.7.0) : scan des réseaux environnants + analyse de
 * vulnérabilité (sécurité annoncée) + détection de réseau public / portail
 * captif quand on est connecté.
 *
 * ⚠️ Le scan fonctionne CONNECTÉ (pas de déconnexion possible sans root).
 * Android 10+ : BSSID randomisés → on n'affiche pas la MAC comme identifiant.
 */
@Composable
fun WifiScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var networks by remember { mutableStateOf<List<WifiScanner.WifiNetwork>>(emptyList()) }
    var scanning by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var selected by remember { mutableStateOf<WifiScanner.WifiNetwork?>(null) }
    // Analyse « réseau public » (portail captif) du réseau CONNECTÉ
    var publicVuln by remember { mutableStateOf<PublicWifiAnalyzer.PublicWifiVuln?>(null) }
    var publicChecked by remember { mutableStateOf(false) }
    // BSSID du réseau connecté (pour le conseil de canal) — v1.9.36.
    val currentBssid = remember {
        runCatching {
            (context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager)
                .connectionInfo?.bssid
        }.getOrNull()
    }
    var showChannels by remember { mutableStateOf(false) }

    // lateinit : la lambda est assignée après (évite la forward reference)
    lateinit var runWifiScan: () -> Unit

    fun locationEnabled(): Boolean {
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        return lm.isProviderEnabled(LocationManager.GPS_PROVIDER) ||
            lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
    }

    fun analyzeCurrentNetwork(results: List<WifiScanner.WifiNetwork>) {
        scope.launch {
            val vuln = withContext(Dispatchers.IO) {
                runCatching {
                    val wifi = context.applicationContext
                        .getSystemService(Context.WIFI_SERVICE) as WifiManager
                    val ssid = wifi.connectionInfo?.ssid?.trim('"').orEmpty()
                    if (ssid.isBlank()) return@runCatching null
                    val captive = PublicWifiAnalyzer.detectCaptivePortal()
                    val net = results.firstOrNull { it.ssid == ssid }
                    val sec = net?.security ?: WifiScanner.WifiSecurity.UNKNOWN
                    PublicWifiAnalyzer.analyzePublicNetwork(ssid, sec, captive)
                }.getOrNull()
            }
            publicVuln = vuln
            publicChecked = true
        }
    }

    runWifiScan = {
        val perm = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
        when {
            perm != PackageManager.PERMISSION_GRANTED -> {
                val act = context as? Activity
                if (act != null) {
                    PermissionHelper.requestLocation(act) { granted ->
                        if (granted) runWifiScan() else
                            error = "📍 Localisation refusée — indispensable pour scanner le WiFi."
                    }
                } else {
                    error = "📍 Localisation refusée — indispensable pour scanner le WiFi."
                }
            }
            !locationEnabled() -> error = "📡 Active la localisation pour scanner le WiFi"
            else -> {
                scanning = true
                error = null
                WifiScanner.startScan(context, onResults = { results ->
                    networks = results.sortedByDescending { it.score }
                    scanning = false
                    if (results.isEmpty()) {
                        error = "Aucun réseau trouvé — le système limite les scans (~4 / 2 min), réessaie dans ~30 s."
                    }
                    analyzeCurrentNetwork(results)
                })
            }
        }
    }

    // Analyse du réseau connecté au lancement de l'onglet
    LaunchedEffect(Unit) {
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val ssid = runCatching { wifi.connectionInfo?.ssid?.trim('"') }.getOrNull()
        if (!ssid.isNullOrBlank()) analyzeCurrentNetwork(networks)
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "Réseaux Wi-Fi autour",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    "Les plus vulnérables en premier — ${networks.size} trouvé(s)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Button(onClick = { runWifiScan() }, enabled = !scanning) {
                if (scanning) {
                    CircularProgressIndicator(
                        Modifier.size(16.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Scan…")
                } else {
                    Text("🔍 Scanner")
                }
            }
        }

        // Bannière « réseau public » si connecté à un réseau suspect
        if (publicVuln != null && publicVuln!!.score >= 50) {
            PublicNetworkBanner(publicVuln!!)
        } else if (publicChecked && publicVuln == null) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 2.dp),
                shape = MaterialTheme.shapes.large,
                colors = CardDefaults.cardColors(containerColor = LocalScannerColors.current.riskNone)
            ) {
                Text(
                    "✅ Réseau vérifié — pas de portail",
                    color = onColorFor(LocalScannerColors.current.riskNone),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                )
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
                        context.startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
                    }) { Text("Réglages") }
                }
            }
        }

        if (networks.isEmpty() && !scanning) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text("📶", style = MaterialTheme.typography.headlineMedium)
                Spacer(Modifier.height(16.dp))
                Text(
                    "Scanner les réseaux Wi-Fi",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Analyse la sécurité des réseaux autour de toi (chiffrement, SSID par défaut, portail captif).",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(20.dp))
                FilledTonalButton(
                    onClick = { runWifiScan() },
                    shape = MaterialTheme.shapes.extraLarge
                ) { Text("Scanner les réseaux") }
            }
        } else if (networks.isNotEmpty()) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                item(key = "channels") {
                    ChannelOccupancyCard(
                        networks = networks,
                        currentBssid = currentBssid,
                        expanded = showChannels,
                        onToggle = { showChannels = !showChannels }
                    )
                }
                // Clé unique par position : deux réseaux cachés (BSSID+SSID vides)
                // ne doivent pas produire la même clé → sinon crash LazyColumn.
                itemsIndexed(
                    networks,
                    key = { i, net -> "$i-${net.bssid}-${net.ssid}" }
                ) { _, net ->
                    WifiNetworkCard(net, onClick = { selected = net })
                }
            }
        }
    }

    selected?.let { net ->
        WifiNetworkDetail(net, networks, onDismiss = { selected = null })
    }
}

/** Bannière d'alerte « réseau public / portail captif » (score ≥ 50). */
@Composable
private fun PublicNetworkBanner(vuln: PublicWifiAnalyzer.PublicWifiVuln) {
    val semantic = LocalScannerColors.current
    val bg = if (vuln.score >= 75) semantic.riskCritical else semantic.riskHigh
    val fg = onColorFor(bg)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 2.dp),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = bg)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "⚠️ Réseau public — portail captif, score ${vuln.score}/100",
                color = fg,
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

/** Carte réseau : SSID, badge score coloré, bande, RSSI, chiffrement, risques. */
@Composable
private fun WifiNetworkCard(net: WifiScanner.WifiNetwork, onClick: () -> Unit) {
    val vuln = WifiVulnAnalyzer.analyze(net.security, net.ssid)
    val semantic = LocalScannerColors.current
    // Fond du badge dérivé du MÊME libellé que le texte (rampe cohérente).
    val scoreColor = semantic.riskColor(vuln.label)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    net.ssid.ifBlank { "(caché)" },
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1
                )
                Text(
                    "${net.security.label} · ${net.channel?.let { "Canal $it" } ?: net.band.ifBlank { "bande ?" }}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (vuln.risks.isNotEmpty()) {
                    Spacer(Modifier.height(2.dp))
                    vuln.risks.take(2).forEach { r ->
                        Text(
                            "• $r",
                            style = MaterialTheme.typography.labelSmall,
                            color = semantic.riskCritical,
                            maxLines = 1
                        )
                    }
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                Box(
                    modifier = Modifier
                        .background(scoreColor, MaterialTheme.shapes.small)
                        .padding(horizontal = 8.dp, vertical = 2.dp)
                ) {
                    Text(
                        "${vuln.score} · ${vuln.label}",
                        color = onColorFor(scoreColor),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    "${net.rssi} dBm",
                    style = LocalMonoTextStyle.current,
                    color = MaterialTheme.colorScheme.primary
                )
                RssiSignalBar(net.rssi)
            }
        }
    }
}

/** Barre de signal RSSI (−100 → −40 dBm). */
@Composable
private fun RssiSignalBar(rssi: Int) {
    val fraction = ((rssi + 100).coerceIn(0, 60)) / 60f
    Box(
        modifier = Modifier
            .width(72.dp)
            .height(6.dp)
            .background(MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.shapes.small)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth(fraction)
                .height(6.dp)
                .background(MaterialTheme.colorScheme.primary, MaterialTheme.shapes.small)
        )
    }
}

/**
 * Fiche détail d'un réseau (dialog), consultable AVANT connexion : champs +
 * risques PRÉCIS (chiffrement, WPS, evil-twin, réseau ouvert/captif) +
 * recommandations adaptées (protection avant de se connecter à un public/captif).
 */
@Composable
private fun WifiNetworkDetail(
    net: WifiScanner.WifiNetwork,
    all: List<WifiScanner.WifiNetwork>,
    onDismiss: () -> Unit
) {
    val vuln = WifiVulnAnalyzer.analyzeDetailed(net, all)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(net.ssid.ifBlank { "(caché)" }, fontWeight = FontWeight.Bold) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                InfoRow("SSID", net.ssid.ifBlank { "(caché)" })
                InfoRow("BSSID", net.bssid.ifBlank { "non disponible (randomisé)" }, mono = true)
                InfoRow("Bande", net.band.ifBlank { "—" })
                InfoRow("Canal", net.channel?.toString() ?: "—", mono = true)
                InfoRow("Signal", "${net.rssi} dBm", mono = true)
                InfoRow("Chiffrement", net.security.label)
                if (vuln.wps) InfoRow("WPS", "actif ⚠️")
                if (vuln.evilTwin) InfoRow("Evil twin", "plusieurs bornes ⚠️")
                InfoRow("Score", "${vuln.score}/100 — ${vuln.label}")
                Spacer(Modifier.height(8.dp))
                Text("Risques précis", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                vuln.risks.forEach { r ->
                    Text("• $r", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 2.dp))
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    if (vuln.publicOrOpen) "Avant de te connecter" else "Recommandation",
                    style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold
                )
                vuln.recommendations.forEach { r ->
                    Text("→ $r", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 2.dp))
                }
                if (vuln.publicOrOpen) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Note : le portail captif ne se sonde qu'une fois connecté — connecte-toi VPN activé, puis reviens ici pour l'analyse du portail.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Fermer") } }
    )
}

@Composable
private fun InfoRow(label: String, value: String, mono: Boolean = false) {
    Row(Modifier.padding(vertical = 2.dp)) {
        Text(
            "$label :",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(110.dp)
        )
        Text(
            value,
            style = if (mono) LocalMonoTextStyle.current else MaterialTheme.typography.bodyMedium
        )
    }
}


/**
 * Occupation des canaux Wi-Fi (v1.9.36) : histogramme 2,4 GHz (1..13) et
 * 5 GHz, meilleur canal par bande et conseil pour le réseau connecté.
 */
@Composable
private fun ChannelOccupancyCard(
    networks: List<WifiScanner.WifiNetwork>,
    currentBssid: String?,
    expanded: Boolean,
    onToggle: () -> Unit
) {
    val occ24 = remember(networks) { WifiChannels.occupancy24(networks) }
    val occ5 = remember(networks) { WifiChannels.occupancy5(networks) }
    val best24 = remember(networks) { WifiChannels.best24(networks) }
    val best5 = remember(networks) { WifiChannels.best5(networks) }
    val advice = remember(networks, currentBssid) { WifiChannels.advice(networks, currentBssid) }
    val myChannel = networks.firstOrNull { it.bssid.equals(currentBssid ?: "", true) }?.channel
    val n24 = networks.count { WifiChannels.is24(it) }
    val n5 = networks.count { WifiChannels.is5(it) }
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onToggle),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("📊 Occupation des canaux", style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                Text(if (expanded) "▲" else "▼", style = MaterialTheme.typography.labelMedium)
            }
            Text(
                buildString {
                    if (best24 != null && n24 > 0) append("2,4 GHz : meilleur canal ${best24.channel} ($n24 réseaux)")
                    if (best5 != null && n5 > 0) { if (isNotEmpty()) append("  ·  "); append("5 GHz : canal ${best5.channel} ($n5 réseaux)") }
                    if (isEmpty()) append("Aucun réseau mesuré.")
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            advice?.let {
                Spacer(Modifier.height(4.dp))
                Text("💡 $it", style = MaterialTheme.typography.bodySmall)
            }
            if (expanded) {
                if (n24 > 0) {
                    Spacer(Modifier.height(8.dp))
                    Text("2,4 GHz (charge pondérée, chevauchement ±2 canaux)", style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    ChannelBars(occ24.map { Triple(it.channel, it.load, it.networks) }, myChannel, best24?.channel)
                }
                if (n5 > 0) {
                    Spacer(Modifier.height(8.dp))
                    Text("5 GHz (réseaux par canal)", style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    ChannelBars(occ5.map { Triple(it.channel, it.load, it.networks) }, myChannel, best5?.channel)
                }
            }
        }
    }
}

@Composable
private fun ChannelBars(items: List<Triple<Int, Double, Int>>, mine: Int?, best: Int?) {
    val maxLoad = (items.maxOfOrNull { it.second } ?: 1.0).coerceAtLeast(1.0)
    val barColor = MaterialTheme.colorScheme.primary
    val mineColor = MaterialTheme.colorScheme.error
    val bestColor = androidx.compose.ui.graphics.Color(0xFF2E7D32)
    val grid = MaterialTheme.colorScheme.outlineVariant
    Canvas(Modifier.fillMaxWidth().height(90.dp)) {
        val n = items.size
        if (n == 0) return@Canvas
        val slot = size.width / n
        val barW = slot * 0.6f
        val h = size.height - 16f
        drawLine(grid, Offset(0f, h), Offset(size.width, h), 1f)
        items.forEachIndexed { i, (ch, load, _) ->
            val bh = (load / maxLoad * (h - 4f)).toFloat()
            val x = i * slot + (slot - barW) / 2
            val color = when (ch) { mine -> mineColor; best -> bestColor; else -> barColor }
            drawRect(color, Offset(x, h - bh), Size(barW, bh))
        }
    }
    Row(Modifier.fillMaxWidth()) {
        items.forEach { (ch, _, _) ->
            Text(
                ch.toString(),
                style = MaterialTheme.typography.labelSmall,
                color = when (ch) { mine -> mineColor; best -> bestColor; else -> MaterialTheme.colorScheme.onSurfaceVariant },
                modifier = Modifier.weight(1f),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
        }
    }
    Text(
        "rouge = ta box · vert = meilleur canal",
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

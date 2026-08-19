package com.fabrice.network.scanner.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.fabrice.network.scanner.PublicWifiAnalyzer
import com.fabrice.network.scanner.WifiScanner
import com.fabrice.network.scanner.WifiVulnAnalyzer
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import com.fabrice.network.scanner.ui.theme.LocalScannerColors
import com.fabrice.network.scanner.ui.theme.onColorFor
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

    // lateinit : la lambda est assignée après le launcher (évite la forward
    // reference — une fonction locale ne peut pas être appelée avant sa déclaration)
    lateinit var runWifiScan: () -> Unit
    val locationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) runWifiScan() else error = "📍 Localisation refusée — indispensable pour scanner le WiFi."
    }

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
            perm != PackageManager.PERMISSION_GRANTED ->
                locationLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
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
                items(networks, key = { it.bssid.ifBlank { it.ssid } }) { net ->
                    WifiNetworkCard(net, onClick = { selected = net })
                }
            }
        }
    }

    selected?.let { net ->
        WifiNetworkDetail(net, onDismiss = { selected = null })
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
    val scoreColor = scoreColor(vuln.score)
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
                    "${net.security.label} · ${net.band.ifBlank { "bande ?" }}",
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

/** Couleur du score : vert <25, jaune <50, orange <75, rouge ≥75. */
@Composable
private fun scoreColor(score: Int): Color {
    val semantic = LocalScannerColors.current
    return when {
        score < 25 -> semantic.riskNone
        score < 50 -> semantic.riskModerate
        score < 75 -> semantic.riskHigh
        else -> semantic.riskCritical
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

/** Fiche détail d'un réseau (dialog) : champs + risques + recommandation. */
@Composable
private fun WifiNetworkDetail(net: WifiScanner.WifiNetwork, onDismiss: () -> Unit) {
    val vuln = WifiVulnAnalyzer.analyze(net.security, net.ssid)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(net.ssid.ifBlank { "(caché)" }, fontWeight = FontWeight.Bold) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                InfoRow("SSID", net.ssid.ifBlank { "(caché)" })
                InfoRow("BSSID", net.bssid.ifBlank { "non disponible (randomisé)" }, mono = true)
                InfoRow("Bande", net.band.ifBlank { "—" })
                InfoRow("Signal", "${net.rssi} dBm", mono = true)
                InfoRow("Chiffrement", net.security.label)
                InfoRow("Score", "${vuln.score}/100 — ${vuln.label}")
                Spacer(Modifier.height(8.dp))
                Text("Risques", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                vuln.risks.forEach { r ->
                    Text("• $r", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 2.dp))
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "Recommandation : passe ce réseau en WPA3/WPA2-CCMP et renomme-le (SSID par défaut = cible facile).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
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

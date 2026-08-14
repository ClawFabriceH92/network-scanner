package com.fabrice.network.scanner.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.wifi.WifiManager
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.fabrice.network.scanner.BluetoothScanner
import com.fabrice.network.scanner.BuildConfig
import com.fabrice.network.scanner.CsvExporter
import com.fabrice.network.scanner.CveDatabaseStore
import com.fabrice.network.scanner.CveEntry
import com.fabrice.network.scanner.CveUpdateManager
import com.fabrice.network.scanner.Device
import com.fabrice.network.scanner.DeviceStore
import com.fabrice.network.scanner.DeviceType
import com.fabrice.network.scanner.HistoryStore
import com.fabrice.network.scanner.NetworkScanner
import com.fabrice.network.scanner.OuiDatabase
import com.fabrice.network.scanner.PortScanner
import com.fabrice.network.scanner.ScanHistory
import com.fabrice.network.scanner.SmbShareScanner
import com.fabrice.network.scanner.VulnScanner
import com.fabrice.network.scanner.WakeOnLan
import kotlinx.coroutines.launch
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScannerScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    val deviceStore = remember { DeviceStore(context) }
    val historyStore = remember { HistoryStore(context) }

    var devices by remember { mutableStateOf<List<Device>>(emptyList()) }
    var scanning by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0) }
    var error by remember { mutableStateOf<String?>(null) }
    var selected by remember { mutableStateOf<Device?>(null) }
    var newDevices by remember { mutableStateOf<List<Device>>(emptyList()) }
    // IP locale de l'appareil qui lance le scan (affichée après le premier scan)
    var selfIp by remember { mutableStateOf<String?>(null) }
    // Clés des appareils absents de l'historique avant le dernier scan → badges 🆕
    var newKeys by remember { mutableStateOf(setOf<String>()) }
    // Force la recomposition des cartes après renommage/favori
    var refreshTick by remember { mutableStateOf(0) }
    var scanCount by remember { mutableStateOf(0) }
    // Onglet actif : 0 = Périphériques, 1 = Réseau, 2 = Bluetooth
    var selectedTab by remember { mutableStateOf(0) }
    // Scan Bluetooth
    var btDevices by remember { mutableStateOf<List<BluetoothScanner.BtDevice>>(emptyList()) }
    var btScanning by remember { mutableStateOf(false) }
    var btError by remember { mutableStateOf<String?>(null) }
    // Vulnérabilités par IP (calculées après chaque scan, base CVE embarquée)
    var vulnsByIp by remember { mutableStateOf<Map<String, VulnScanner.DeviceVulns>>(emptyMap()) }
    var cveDbVersion by remember { mutableStateOf<String?>(null) }
    // Écran : 0 = scan, 1 = aide, 2 = à propos
    var screen by remember { mutableStateOf(0) }
    // État de la mise à jour de la base CVE
    var cveUpdating by remember { mutableStateOf(false) }
    var cveUpdateResult by remember { mutableStateOf<String?>(null) }
    var cveStale by remember { mutableStateOf(false) }

    fun runScan() {
        scope.launch {
            scanning = true
            error = null
            progress = 0
            newDevices = emptyList()
            newKeys = emptySet()
            val subnet = NetworkScanner.detectSubnet()
            if (subnet == null) {
                // Feature 3 : erreur réseau claire avant de lancer un scan inutile
                error = "Aucun réseau Wi-Fi détecté. Connecte-toi à un réseau, puis réessaie."
                scanning = false
                return@launch
            }
            selfIp = subnet.first
            val oui = OuiDatabase.load(context)
            // Base CVE embarquée pour le scan de vulnérabilités (CISA KEV + NVD)
            val cveDb = CveDatabaseStore.load(context)
            cveDbVersion = cveDb.generated.ifBlank { null }
            cveStale = CveUpdateManager.isStale(cveDbVersion ?: "")
            // Cache persistant des fabricants résolus en ligne (par préfixe OUI).
            val vendorPrefs = context.getSharedPreferences("vendor_cache", Context.MODE_PRIVATE)
            val result = try {
                // Le multicast lock est requis pour le SSDP (239.255.255.250)
                withMulticastLock(context) {
                    NetworkScanner.scan(oui, scanPorts = true, prefs = vendorPrefs) { done, total -> progress = done }
                }
            } catch (e: Exception) {
                error = e.message ?: "Erreur inconnue"
                emptyList()
            }
            // Détection des nouveaux appareils par rapport à l'historique connu
            if (result.isNotEmpty()) {
                val previous = historyStore.load()
                val fresh = ScanHistory.detectNewDevices(previous, result)
                if (fresh.isNotEmpty()) {
                    newDevices = fresh
                    newKeys = fresh.map { ScanHistory.identityKey(it) }.toSet()
                }
                historyStore.save(result)
            }
            // Scan de vulnérabilités : banner → produit/version → matching CVE
            vulnsByIp = result.associate { device ->
                val services = VulnScanner.parseBanner(device.banner)
                device.ip to VulnScanner.match(services, cveDb)
            }
            devices = result
            scanning = false
            scanCount++
            refreshTick++
        }
    }

    fun updateCveBase(
        context: Context,
        onResult: (String) -> Unit
    ) {
        scope.launch {
            cveUpdating = true
            cveUpdateResult = null
            val result = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                CveUpdateManager.update(context)
            }
            if (result != null) {
                // La base a changé : on force le rechargement au prochain scan
                CveDatabaseStore.invalidate()
                cveDbVersion = result.generated
                cveStale = CveUpdateManager.isStale(result.generated)
                onResult("✅ Base mise à jour : ${result.generated} (${result.allCount} CVE)")
            } else {
                onResult("❌ Échec de la mise à jour (réseau ou base indisponible)")
            }
            cveUpdating = false
        }
    }

    // Permissions Bluetooth (Android 12+ : BLUETOOTH_SCAN + BLUETOOTH_CONNECT,
    // et ACCESS_FINE_LOCATION pour le BLE sur certains appareils)
    val btPermissions = remember {
        arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
    }
    // lateinit : la lambda est assignée après le launcher (évite la forward
    // reference — une fonction locale ne peut pas être appelée avant sa déclaration)
    lateinit var runBtScan: (Context) -> Unit
    val btPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { granted ->
        if (granted.values.any { it }) {
            runBtScan(context)
        } else {
            btError = "Permissions Bluetooth refusées — active-les dans les réglages."
        }
    }
    runBtScan = { ctx ->
        val missing = btPermissions.filter {
            ContextCompat.checkSelfPermission(ctx, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            btPermissionLauncher.launch(btPermissions)
        } else if (!BluetoothScanner.isSupported(ctx)) {
            btError = "Bluetooth désactivé — active-le dans les réglages."
        } else {
            scope.launch {
                btScanning = true
                btError = null
                val oui = OuiDatabase.load(ctx)
                btDevices = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                    BluetoothScanner.scan(ctx, durationMs = 8_000, oui = oui)
                }
                btScanning = false
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        when (screen) {
                            1 -> "Aide"
                            2 -> "À propos"
                            else -> "Scan Réseau"
                        }
                    )
                },
                actions = {
                    if (screen != 0) {
                        TextButton(onClick = { screen = 0 }) { Text("← Retour") }
                    } else {
                        if (devices.isNotEmpty() && !scanning) {
                            TextButton(onClick = { exportCsv(context, devices, vulnsByIp) }) {
                                Text("📤 Export")
                            }
                        }
                        TextButton(onClick = { runScan() }, enabled = !scanning) {
                            Text(if (scanning) "Scan…" else "🔄 Scanner")
                        }
                        TextButton(onClick = { screen = 1 }) { Text("?") }
                        TextButton(onClick = { screen = 2 }) { Text("ℹ️") }
                    }
                }
            )
        },
        snackbarHost = { SnackbarHost(snackbar) }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
        ) {
            if (screen == 1) {
                HelpScreen()
            } else if (screen == 2) {
                AboutScreen()
            } else {
            // Onglets : Périphériques / Réseau / Bluetooth
            TabRow(selectedTabIndex = selectedTab) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("📱 Périphériques") }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("🌐 Réseau") }
                )
                Tab(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    text = { Text("📡 Bluetooth") }
                )
            }
            if (selectedTab == 1) {
                NetworkScreen()
            } else if (selectedTab == 2) {
                BluetoothScreen(
                    devices = btDevices,
                    scanning = btScanning,
                    error = btError,
                    onScan = { runBtScan(context) }
                )
            } else {
            if (scanning) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    CircularProgressIndicator(Modifier.width(24.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(12.dp))
                    Text("Recherche d'appareils… ($progress)")
                }
            }
            if (newDevices.isNotEmpty()) {
                NewDevicesBanner(newDevices)
            }
            NetworkPanel()
            // Bandeau base CVE : obsolète ou mise à jour proposée
            if (!cveUpdating && (cveStale || cveUpdateResult != null)) {
                CveBanner(
                    version = cveDbVersion,
                    stale = cveStale,
                    result = cveUpdateResult,
                    onUpdate = { updateCveBase(context) { msg -> cveUpdateResult = msg } },
                    onDismiss = { cveUpdateResult = null }
                )
            }
            error?.let {
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(16.dp)
                )
            }
            if (devices.isEmpty() && !scanning) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        "Appuie sur Scanner pour détecter les appareils du réseau local.\nPing, ARP, fabricants, services (ports) et réveil à distance.",
                        style = MaterialTheme.typography.bodyLarge
                    )
                    Spacer(Modifier.height(16.dp))
                    Button(onClick = { runScan() }) { Text("📡 Scanner le réseau") }
                }
            } else if (devices.isNotEmpty()) {
                // Bandeau : appareil qui lance le scan + compteur
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 4.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFFF4EDE0)
                    )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("📱 Scan depuis ", style = MaterialTheme.typography.labelMedium)
                        Text(
                            selfIp ?: "—",
                            style = MaterialTheme.typography.labelMedium,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.weight(1f))
                        Text(
                            "${devices.size} appareils",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(devices, key = { it.ip }) { device ->
                        val key = ScanHistory.identityKey(device)
                        // Lecture du tick pour recomposer après renommage/favori
                        @Suppress("UNUSED_EXPRESSION") refreshTick
                        val vulns = vulnsByIp[device.ip]
                        DeviceCard(
                            device = device,
                            displayName = deviceStore.displayName(device),
                            isFavorite = deviceStore.isFavorite(key),
                            isNew = key in newKeys,
                            vulns = vulns,
                            onClick = { selected = device }
                        )
                    }
                }
            }
            } // fin onglet Périphériques (else)
            } // fin écran scan (screen == 0)
        }
    }

    selected?.let { device ->
        val key = ScanHistory.identityKey(device)
        DeviceDialog(
            device = device,
            store = deviceStore,
            isNew = key in newKeys,
            vulns = vulnsByIp[device.ip],
            onDismiss = { selected = null },
            onSaved = { refreshTick++ },
            onWol = {
                scope.launch {
                    val mac = device.mac
                    val subnet = NetworkScanner.detectSubnet()
                    val broadcast = if (subnet != null) NetworkScanner.broadcastAddress(subnet.first, subnet.second)
                    else "255.255.255.255"
                    val ok = withMulticastLock(context) {
                        WakeOnLan.send(mac, broadcast)
                    }
                    val msg = if (ok) "Magic packet envoyé → $mac" else "Échec de l'envoi WoL"
                    snackbar.showSnackbar(msg)
                }
            }
        )
    }
}

@Composable
private fun NewDevicesBanner(newDevices: List<Device>) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1B3A6B)
        )
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(
                "🆕 ${newDevices.size} nouvel${if (newDevices.size > 1) "s appareil" else " appareil"}${if (newDevices.size > 1) "s" else ""} détecté${if (newDevices.size > 1) "s" else ""}",
                color = Color(0xFFC9972B),
                fontWeight = FontWeight.Bold
            )
            newDevices.take(5).forEach { d ->
                Text(
                    "• ${d.hostname.ifBlank { d.ip }} (${d.ip})",
                    color = Color.White,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

/** Bandeau base CVE : obsolète ou résultat de mise à jour. */
@Composable
private fun CveBanner(
    version: String?,
    stale: Boolean,
    result: String?,
    onUpdate: () -> Unit,
    onDismiss: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (stale) Color(0xFFB3261E) else Color(0xFFF4EDE0)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    if (stale) "⚠️ Base CVE obsolète (${version ?: "?"})"
                    else "🛡️ ${result ?: "Base CVE"}",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = if (stale) Color.White else MaterialTheme.colorScheme.onSurface
                )
                if (stale) {
                    Text(
                        "Plus de 30 jours : les nouvelles failles ne sont pas couvertes.",
                        style = MaterialTheme.typography.labelSmall,
                        color = Color.White
                    )
                }
                result?.let {
                    Text(
                        it,
                        style = MaterialTheme.typography.labelSmall,
                        color = if (stale) Color.White else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            if (stale) {
                TextButton(onClick = onUpdate) {
                    Text("Mettre à jour", color = Color.White, fontWeight = FontWeight.Bold)
                }
            } else {
                TextButton(onClick = onDismiss) {
                    Text("OK", color = MaterialTheme.colorScheme.primary)
                }
            }
        }
    }
}

@Composable
private fun DeviceCard(
    device: Device,
    displayName: String,
    isFavorite: Boolean,
    isNew: Boolean,
    vulns: VulnScanner.DeviceVulns?,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = Color.White
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Icône du type d'appareil (comme Fing)
            Box(
                modifier = Modifier
                    .background(
                        Brush.linearGradient(listOf(Color(0xFF1B3A6B), Color(0xFF2E5A9E))),
                        RoundedCornerShape(10.dp)
                    )
                    .padding(8.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(DeviceType.icon(device.type), style = MaterialTheme.typography.titleMedium)
            }
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (isFavorite) Text("⭐ ", style = MaterialTheme.typography.titleSmall)
                    if (isNew) NewBadge()
                    Text(
                        text = displayName,
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Text(
                    text = if (device.vendor.isNotBlank()) device.vendor
                    else if (device.os.isNotBlank()) "💻 ${device.os}"
                    else "Fabricant inconnu",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (device.mac.isNotBlank()) {
                    Text(
                        text = device.mac,
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (device.ports.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        device.ports.take(4).forEach { port ->
                            PortBadge(port)
                        }
                        if (device.ports.size > 4) {
                            Text(
                                "+${device.ports.size - 4}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = device.ip,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = if (device.alive) "● en ligne" else "○ récent",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (device.alive) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (device.isSelf) {
                    Spacer(Modifier.height(2.dp))
                    SelfBadge()
                }
                vulns?.let { v ->
                    if (!v.isEmpty) {
                        Spacer(Modifier.height(2.dp))
                        VulnBadge(v)
                    }
                }
            }
        }
    }
}

/** Badge vulnérabilité : score + label, rouge si critique/élevé. */
@Composable
private fun VulnBadge(v: VulnScanner.DeviceVulns) {
    val critical = v.score >= 50
    val bg = if (critical) Color(0xFFB3261E) else Color(0xFFC9972B)
    Box(
        modifier = Modifier
            .background(bg, RoundedCornerShape(4.dp))
            .padding(horizontal = 4.dp, vertical = 1.dp)
    ) {
        Text(
            "⚠ ${v.label} (${v.total})",
            style = MaterialTheme.typography.labelSmall,
            color = Color.White,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun SelfBadge() {
    Box(
        modifier = Modifier
            .background(Color(0xFFC9972B), RoundedCornerShape(4.dp))
            .padding(horizontal = 4.dp, vertical = 1.dp)
    ) {
        Text(
            "ce périphérique",
            style = MaterialTheme.typography.labelSmall,
            color = Color(0xFF1B3A6B),
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun NewBadge() {
    Box(
        modifier = Modifier
            .background(Color(0xFF2E7D32), RoundedCornerShape(4.dp))
            .padding(horizontal = 4.dp, vertical = 1.dp)
    ) {
        Text(
            "nouveau",
            style = MaterialTheme.typography.labelSmall,
            color = Color.White,
            fontWeight = FontWeight.Bold
        )
    }
    Spacer(Modifier.width(4.dp))
}

@Composable
private fun PortBadge(port: Int) {
    Box(
        modifier = Modifier
            .background(
                Brush.linearGradient(listOf(Color(0xFF1B3A6B), Color(0xFF2E5A9E))),
                RoundedCornerShape(6.dp)
            )
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            PortScanner.serviceName(port),
            style = MaterialTheme.typography.labelSmall,
            color = Color.White
        )
    }
}

@Composable
private fun DeviceDialog(
    device: Device,
    store: DeviceStore,
    isNew: Boolean,
    vulns: VulnScanner.DeviceVulns?,
    onDismiss: () -> Unit,
    onSaved: () -> Unit,
    onWol: () -> Unit
) {
    val key = ScanHistory.identityKey(device)
    var customName by remember { mutableStateOf(store.customName(key)) }
    var isFav by remember { mutableStateOf(store.isFavorite(key)) }
    val wolAvailable = device.mac.isNotBlank()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(store.displayName(device)) },
        text = {
            Column {
                InfoRow("IP", device.ip)
                InfoRow("MAC", device.mac.ifBlank { "non disponible" })
                InfoRow("Fabricant", device.vendor.ifBlank { "inconnu" })
                InfoRow("Type", "${DeviceType.icon(device.type)} ${device.type}")
                if (device.os.isNotBlank()) InfoRow("Système", device.os)
                if (device.hostname.isNotBlank()) InfoRow("Nom réseau", device.hostname)
                device.latencyMs?.let { InfoRow("Latence", "$it ms") }
                device.ttl?.let { InfoRow("TTL", "$it") }
                InfoRow("Statut", if (device.alive) "En ligne" else "Vu récemment (ARP)")
                InfoRow("Historique", if (isNew) "🆕 Nouveau sur le réseau" else "✅ Déjà vu auparavant")
                device.upnp?.let { u ->
                    if (u.friendlyName.isNotBlank()) InfoRow("Nom UPnP", u.friendlyName)
                    if (u.manufacturer.isNotBlank() && device.vendor.isBlank()) InfoRow("Fab. UPnP", u.manufacturer)
                    if (u.modelName.isNotBlank()) InfoRow("Modèle", u.modelName)
                    if (u.modelDescription.isNotBlank()) InfoRow("Description", u.modelDescription)
                    if (u.server.isNotBlank()) InfoRow("Serveur", u.server)
                }
                if (device.banner.isNotBlank()) InfoRow("Bannière", device.banner)
                if (device.ports.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text("Services ouverts :", style = MaterialTheme.typography.labelMedium)
                    Spacer(Modifier.height(4.dp))
                    device.ports.forEach { port ->
                        Row(Modifier.padding(vertical = 2.dp)) {
                            Text(
                                PortScanner.serviceName(port),
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                                modifier = Modifier.width(120.dp)
                            )
                            Text(
                                "port $port",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                vulns?.let { v ->
                    if (!v.isEmpty) {
                        Spacer(Modifier.height(12.dp))
                        VulnSection(v)
                    } else if (v.services.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "🛡️ Aucune CVE connue pour ce service",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                if (device.smbShares.isNotEmpty()) {
                    Spacer(Modifier.height(12.dp))
                    SmbSection(device.smbShares)
                }
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = customName,
                    onValueChange = { customName = it },
                    label = { Text("Nom personnalisé") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TextButton(onClick = {
                        isFav = !isFav
                        store.setFavorite(key, isFav)
                        onSaved()
                    }) {
                        Text(if (isFav) "★ Favori" else "☆ Favori")
                    }
                    if (wolAvailable) {
                        TextButton(onClick = onWol) {
                            Text("⏰ Réveiller (WoL)")
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                store.setCustomName(key, customName)
                onSaved()
                onDismiss()
            }) { Text("OK") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Fermer") }
        }
    )
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.padding(vertical = 4.dp)) {
        Text(
            "$label :",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(110.dp)
        )
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

/** Section partages SMB (dossiers partagés, y compris cachés). */
@Composable
private fun SmbSection(shares: List<SmbShareScanner.SmbShare>) {
    val accessible = shares.count { it.accessible }
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("📁 Partages SMB", style = MaterialTheme.typography.labelMedium)
            Spacer(Modifier.weight(1f))
            Text(
                "$accessible/${shares.size} accessibles",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = FontWeight.Bold
            )
        }
        Spacer(Modifier.height(4.dp))
        shares.forEach { share ->
            Row(Modifier.padding(vertical = 2.dp)) {
                Text(
                    if (share.accessible) "🟢" else "🔒",
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    share.name,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.width(110.dp)
                )
                Text(
                    share.note,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        Text(
            "Partages testés en accès invité. 🔒 = existe mais protégé.",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

/** Section vulnérabilités dans la fiche appareil (scan CERT/KEV). */
@Composable
private fun VulnSection(v: VulnScanner.DeviceVulns) {
    val scoreColor = when {
        v.score >= 75 -> Color(0xFFB3261E)
        v.score >= 50 -> Color(0xFFD84315)
        v.score >= 25 -> Color(0xFFC9972B)
        else -> Color(0xFF2E7D32)
    }
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("🛡️ Vulnérabilités", style = MaterialTheme.typography.labelMedium)
            Spacer(Modifier.weight(1f))
            Text(
                "score ${v.score}/100",
                style = MaterialTheme.typography.labelMedium,
                color = scoreColor,
                fontWeight = FontWeight.Bold
            )
        }
        Text(
            "Risque : ${v.label}" +
                if (v.kevCount > 0) " · ${v.kevCount} activement exploitée(s)" else "",
            style = MaterialTheme.typography.bodySmall,
            color = scoreColor
        )
        Spacer(Modifier.height(6.dp))
        v.cves.take(6).forEach { cve ->
            Row(Modifier.padding(vertical = 3.dp)) {
                Text(
                    cve.id,
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.width(140.dp)
                )
                Text(
                    sevLabel(cve) + (if (cve.kev) " ⚡" else ""),
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = sevColor(cve.severity)
                )
            }
            if (cve.description.isNotBlank()) {
                Text(
                    cve.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
        if (v.cves.size > 6) {
            Text(
                "+${v.cves.size - 6} autres…",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun sevLabel(cve: CveEntry): String =
    "${cve.severity}" + (cve.cvss?.let { " (${it})" } ?: "")

private fun sevColor(sev: String): Color = when (sev) {
    "CRITICAL" -> Color(0xFFB3261E)
    "HIGH" -> Color(0xFFD84315)
    "MEDIUM" -> Color(0xFFC9972B)
    "LOW" -> Color(0xFF2E7D32)
    else -> Color(0xFF616161)
}

/** Exporte le scan en CSV (BOM UTF-8, séparateur ;) et ouvre le partage. */
private fun exportCsv(
    context: Context,
    devices: List<Device>,
    vulnsByIp: Map<String, VulnScanner.DeviceVulns> = emptyMap()
) {
    val dir = File(context.filesDir, "exports").apply { mkdirs() }
    val file = File(
        dir,
        "scan_reseau_v${BuildConfig.VERSION_NAME}_${System.currentTimeMillis()}.csv"
    )
    file.writeText(CsvExporter.buildCsv(devices, vulnsByIp), Charsets.UTF_8)

    val uri: Uri = FileProvider.getUriForFile(
        context,
        "${context.packageName}.fileprovider",
        file
    )
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/csv"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, "Exporter le scan"))
}

/** Acquiert le multicast lock le temps de l'exécution (requis pour broadcast/SSDP). */
private suspend fun <T> withMulticastLock(context: Context, block: suspend () -> T): T {
    val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    val lock = wifi.createMulticastLock("network-scanner-wol")
    lock.setReferenceCounted(false)
    lock.acquire()
    return try {
        block()
    } finally {
        runCatching { lock.release() }
    }
}

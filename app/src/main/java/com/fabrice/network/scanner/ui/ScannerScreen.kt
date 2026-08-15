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
import androidx.compose.foundation.layout.ColumnScope
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
import com.fabrice.network.scanner.PdfAuditReport
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
    // Écran : 0 = scan, 1 = aide, 2 = à propos, 3 = nouveaux appareils
    var screen by remember { mutableStateOf(0) }
    // Mode de scan de ports : 0 = standard (16), 1 = élargi (52) — persisté
    var portMode by remember {
        mutableStateOf(
            context.getSharedPreferences("scan_prefs", Context.MODE_PRIVATE)
                .getInt("port_mode", 0)
        )
    }
    // État de la mise à jour de la base CVE
    var cveUpdating by remember { mutableStateOf(false) }
    var cveUpdateResult by remember { mutableStateOf<String?>(null) }
    var cveStale by remember { mutableStateOf(false) }
    // Menu d'actions secondaires (⋮) : rapport, export, aide, à propos
    var menuExpanded by remember { mutableStateOf(false) }

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
                val portsToScan = if (portMode == 1) PortScanner.ALL_PORTS.map { it.first }
                else PortScanner.COMMON_PORTS.map { it.first }
                withMulticastLock(context) {
                    NetworkScanner.scan(
                        oui,
                        scanPorts = true,
                        prefs = vendorPrefs,
                        portsToScan = portsToScan
                    ) { done, total -> progress = done }
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
                    BluetoothScanner.scan(ctx, durationMs = 12_000, oui = oui)
                }
                btScanning = false
            }
        }
    }

    // Fiche appareil : écran plein au lieu d'un AlertDialog (plus lisible)
    val detail = selected
    if (detail != null) {
        DeviceDetailScreen(
            device = detail,
            store = deviceStore,
            isNew = ScanHistory.identityKey(detail) in newKeys,
            vulns = vulnsByIp[detail.ip],
            onDismiss = { selected = null },
            onSaved = { refreshTick++ }
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        when (screen) {
                            1 -> "Aide"
                            2 -> "À propos"
                            3 -> "Nouveaux appareils"
                            else -> "Scan Réseau"
                        }
                    )
                },
                navigationIcon = {
                    if (screen != 0) {
                        TextButton(onClick = { screen = 0 }) { Text("← Retour") }
                    }
                },
                actions = {
                    if (screen == 0) {
                        Box {
                            TextButton(onClick = { menuExpanded = true }) {
                                Text("⋮", fontSize = 22.sp, fontWeight = FontWeight.Bold)
                            }
                            DropdownMenu(
                                expanded = menuExpanded,
                                onDismissRequest = { menuExpanded = false }
                            ) {
                                DropdownMenuItem(
                                    text = { Text("📄 Rapport PDF") },
                                    onClick = {
                                        menuExpanded = false
                                        exportPdf(context, devices, vulnsByIp, selfIp)
                                    },
                                    enabled = devices.isNotEmpty() && !scanning
                                )
                                DropdownMenuItem(
                                    text = { Text("📤 Export CSV") },
                                    onClick = {
                                        menuExpanded = false
                                        exportCsv(context, devices, vulnsByIp)
                                    },
                                    enabled = devices.isNotEmpty() && !scanning
                                )
                                HorizontalDivider()
                                DropdownMenuItem(
                                    text = { Text("❓ Aide") },
                                    onClick = {
                                        menuExpanded = false
                                        screen = 1
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("ℹ️ À propos") },
                                    onClick = {
                                        menuExpanded = false
                                        screen = 2
                                    }
                                )
                            }
                        }
                    }
                }
            )
        },
        bottomBar = {
            if (screen == 0) {
                NavigationBar {
                    NavigationBarItem(
                        selected = selectedTab == 0,
                        onClick = { selectedTab = 0 },
                        icon = { Text("📱", fontSize = 20.sp) },
                        label = { Text("Périphériques") }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 1,
                        onClick = { selectedTab = 1 },
                        icon = { Text("🌐", fontSize = 20.sp) },
                        label = { Text("Réseau") }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 2,
                        onClick = { selectedTab = 2 },
                        icon = { Text("📡", fontSize = 20.sp) },
                        label = { Text("Bluetooth") }
                    )
                }
            }
        },
        floatingActionButton = {
            // FAB visible seulement avec des appareils — l'état vide a son
            // propre bouton central (un seul bouton Scanner à l'écran)
            if (screen == 0 && selectedTab == 0 && devices.isNotEmpty()) {
                ExtendedFloatingActionButton(
                    onClick = { if (!scanning) runScan() },
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ) {
                    if (scanning) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                        Spacer(Modifier.width(8.dp))
                        Text("Scan en cours…")
                    } else {
                        Text("🔍 Scanner")
                    }
                }
            }
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
            } else if (screen == 3) {
                NewDevicesScreen(
                    devices = newDevices,
                    onDeviceClick = { selected = it }
                )
            } else {
                when (selectedTab) {
                    1 -> NetworkScreen()
                    2 -> BluetoothScreen(
                        devices = btDevices,
                        scanning = btScanning,
                        error = btError,
                        onScan = { runBtScan(context) }
                    )
                    else -> {
                        // Onglet Périphériques
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
                            NewDevicesBanner(
                                newDevices = newDevices,
                                onClick = { screen = 3 }
                            )
                        }
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
                            EmptyDevicesState(onScan = { runScan() })
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
                            // Mode de scan de ports (masqué pendant un scan)
                            if (!scanning) {
                                PortModeSelector(
                                    mode = portMode,
                                    onChange = { newMode ->
                                        portMode = newMode
                                        context.getSharedPreferences("scan_prefs", Context.MODE_PRIVATE)
                                            .edit().putInt("port_mode", newMode).apply()
                                    }
                                )
                            }
                            LazyColumn(
                                modifier = Modifier.fillMaxSize(),
                                contentPadding = PaddingValues(
                                    start = 12.dp,
                                    end = 12.dp,
                                    top = 4.dp,
                                    bottom = 88.dp
                                ),
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
                    }
                }
            }
        }
    }
}

/** État vide soigné : grand emoji décoratif + message + bouton arrondi. */
@Composable
private fun EmptyDevicesState(onScan: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("📡", fontSize = 64.sp)
        Spacer(Modifier.height(16.dp))
        Text(
            "Aucun appareil détecté",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "Appuie sur Scanner pour détecter les appareils du réseau local : ping, ARP, fabricants, services (ports) et réveil à distance.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
        Spacer(Modifier.height(20.dp))
        Button(
            onClick = onScan,
            shape = RoundedCornerShape(24.dp)
        ) {
            Text("📡 Scanner le réseau")
        }
    }
}

@Composable
private fun NewDevicesBanner(newDevices: List<Device>, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp)
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1B3A6B)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                if (newDevices.size == 1) "🆕 1 nouvel appareil détecté"
                else "🆕 ${newDevices.size} nouveaux appareils détectés",
                color = Color(0xFFC9972B),
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(Modifier.weight(1f))
            Text(
                "Voir →",
                color = Color.White,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

/** Écran plein : liste des appareils nouvellement détectés. */
@Composable
private fun NewDevicesScreen(
    devices: List<Device>,
    onDeviceClick: (Device) -> Unit
) {
    Column(Modifier.fillMaxSize()) {
        Text(
            "🆕 ${devices.size} nouveaux appareils détectés lors du dernier scan",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(16.dp)
        )
        if (devices.isEmpty()) {
            Text(
                "Aucun nouvel appareil.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp)
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(devices, key = { it.ip }) { device ->
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onDeviceClick(device) },
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .background(
                                        Brush.linearGradient(
                                            listOf(Color(0xFF1B3A6B), Color(0xFF2E5A9E))
                                        ),
                                        RoundedCornerShape(10.dp)
                                    )
                                    .padding(8.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    DeviceType.icon(device.type),
                                    style = MaterialTheme.typography.titleMedium
                                )
                            }
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(
                                    device.hostname.ifBlank { device.ip },
                                    style = MaterialTheme.typography.titleSmall,
                                    maxLines = 1
                                )
                                TypeBadge(device.type)
                                Text(
                                    device.vendor.ifBlank { "Fabricant inconnu" },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Text(
                                device.ip,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }
            }
        }
    }
}

/** Sélecteur de mode de scan de ports (standard / élargi). */
@Composable
private fun PortModeSelector(mode: Int, onChange: (Int) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            "Ports :",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        TextButton(
            onClick = { onChange(0) },
            enabled = mode != 0
        ) {
            Text(
                "Standard (16)",
                color = if (mode == 0) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = if (mode == 0) FontWeight.Bold else FontWeight.Normal
            )
        }
        TextButton(
            onClick = { onChange(1) },
            enabled = mode != 1
        ) {
            Text(
                "Élargi (${PortScanner.ALL_PORTS.size})",
                color = if (mode == 1) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = if (mode == 1) FontWeight.Bold else FontWeight.Normal
            )
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
                // Type d'appareil explicite (imprimante, PC, NAS…)
                TypeBadge(device.type)
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

/** Badge du type d'appareil (imprimante, PC, NAS…) — explicite, coloré. */
@Composable
private fun TypeBadge(type: String) {
    val color = when (type) {
        "Imprimante" -> Color(0xFF1565C0)
        "Ordinateur" -> Color(0xFF2E7D32)
        "Smartphone" -> Color(0xFF6A1B9A)
        "NAS" -> Color(0xFFE65100)
        "Routeur / Box" -> Color(0xFF00838F)
        "Caméra" -> Color(0xFFC62828)
        "TV / Media" -> Color(0xFF283593)
        "IoT" -> Color(0xFF5D4037)
        else -> Color(0xFF757575)
    }
    Box(
        modifier = Modifier
            .background(color, RoundedCornerShape(4.dp))
            .padding(horizontal = 5.dp, vertical = 1.dp)
    ) {
        Text(
            "${DeviceType.icon(type)} $type",
            style = MaterialTheme.typography.labelSmall,
            color = Color.White,
            fontWeight = FontWeight.Bold
        )
    }
    Spacer(Modifier.height(2.dp))
}

/**
 * Fiche appareil plein écran : sections titrées, scroll, couleurs de sévérité
 * cohérentes. Remplace l'ancien AlertDialog (trop chargé).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DeviceDetailScreen(
    device: Device,
    store: DeviceStore,
    isNew: Boolean,
    vulns: VulnScanner.DeviceVulns?,
    onDismiss: () -> Unit,
    onSaved: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val key = ScanHistory.identityKey(device)
    var customName by remember { mutableStateOf(store.customName(key)) }
    var isFav by remember { mutableStateOf(store.isFavorite(key)) }
    val wolAvailable = device.mac.isNotBlank()
    val name = store.displayName(device)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                navigationIcon = {
                    TextButton(onClick = {
                        store.setCustomName(key, customName)
                        onSaved()
                        onDismiss()
                    }) { Text("← Retour") }
                }
            )
        },
        snackbarHost = { SnackbarHost(snackbar) }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // --- Identité ---
            SectionCard("📱 Identité") {
                if (isNew) {
                    Text(
                        "🆕 Nouveau sur le réseau",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(0xFF2E7D32),
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(4.dp))
                }
                InfoRow("IP", device.ip)
                InfoRow("MAC", device.mac.ifBlank { "non disponible" })
                InfoRow("Fabricant", device.vendor.ifBlank { "inconnu" })
                InfoRow("Type", "${DeviceType.icon(device.type)} ${device.type}")
                if (device.os.isNotBlank()) InfoRow("Système", device.os)
                if (device.hostname.isNotBlank()) InfoRow("Nom réseau", device.hostname)
                device.latencyMs?.let { InfoRow("Latence", "$it ms") }
                device.ttl?.let { InfoRow("TTL", "$it") }
                InfoRow("Statut", if (device.alive) "En ligne" else "Vu récemment (ARP)")
                if (device.isSelf) {
                    Spacer(Modifier.height(4.dp))
                    SelfBadge()
                }
            }

            // --- UPnP ---
            device.upnp?.let { u ->
                if (u.friendlyName.isNotBlank() || u.manufacturer.isNotBlank() ||
                    u.modelName.isNotBlank() || u.modelDescription.isNotBlank() ||
                    u.server.isNotBlank()
                ) {
                    SectionCard("🔌 UPnP") {
                        if (u.friendlyName.isNotBlank()) InfoRow("Nom", u.friendlyName)
                        if (u.manufacturer.isNotBlank() && device.vendor.isBlank())
                            InfoRow("Fabricant", u.manufacturer)
                        if (u.modelName.isNotBlank()) InfoRow("Modèle", u.modelName)
                        if (u.modelDescription.isNotBlank()) InfoRow("Description", u.modelDescription)
                        if (u.server.isNotBlank()) InfoRow("Serveur", u.server)
                    }
                }
            }

            // --- Bannière ---
            if (device.banner.isNotBlank()) {
                SectionCard("🧾 Bannière") {
                    Text(
                        device.banner,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            // --- Services ouverts ---
            if (device.ports.isNotEmpty()) {
                SectionCard("🔓 Services ouverts") {
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
            }

            // --- Vulnérabilités ---
            vulns?.let { v ->
                if (!v.isEmpty) {
                    SectionCard("🛡️ Vulnérabilités") { VulnSection(v) }
                } else if (v.services.isNotEmpty()) {
                    SectionCard("🛡️ Vulnérabilités") {
                        Text(
                            "Aucune CVE connue pour ce service",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // --- Partages SMB ---
            if (device.smbShares.isNotEmpty()) {
                SectionCard("📁 Partages SMB") { SmbSection(device.smbShares) }
            }

            // --- Personnalisation & actions ---
            SectionCard("✏️ Personnalisation") {
                OutlinedTextField(
                    value = customName,
                    onValueChange = { customName = it },
                    label = { Text("Nom personnalisé") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = {
                            isFav = !isFav
                            store.setFavorite(key, isFav)
                            onSaved()
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(if (isFav) "★ Favori" else "☆ Favori")
                    }
                    if (wolAvailable) {
                        Button(
                            onClick = {
                                scope.launch {
                                    val mac = device.mac
                                    val subnet = NetworkScanner.detectSubnet()
                                    val broadcast = if (subnet != null)
                                        NetworkScanner.broadcastAddress(subnet.first, subnet.second)
                                    else "255.255.255.255"
                                    val ok = withMulticastLock(context) {
                                        WakeOnLan.send(mac, broadcast)
                                    }
                                    val msg = if (ok) "Magic packet envoyé → $mac"
                                    else "Échec de l'envoi WoL"
                                    snackbar.showSnackbar(msg)
                                }
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("⏰ Réveiller (WoL)")
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = {
                        store.setCustomName(key, customName)
                        onSaved()
                        onDismiss()
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Enregistrer")
                }
            }
        }
    }
}

/** Carte de section titrée pour la fiche appareil. */
@Composable
private fun SectionCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
            Spacer(Modifier.height(8.dp))
            content()
        }
    }
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

/** Génère le rapport d'audit PDF et ouvre le partage. */
private fun exportPdf(
    context: Context,
    devices: List<Device>,
    vulnsByIp: Map<String, VulnScanner.DeviceVulns>,
    selfIp: String?
) {
    val subnet = NetworkScanner.detectSubnet()
    val cidr = if (subnet != null) "${subnet.first}/${subnet.second}" else ""
    val data = PdfAuditReport.buildData(
        devices = devices,
        vulnsByIp = vulnsByIp,
        selfIp = selfIp ?: "—",
        networkCidr = cidr
    )
    val uri = PdfAuditReport.generateAndShareUri(context, data)
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "application/pdf"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, "Partager le rapport d'audit"))
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

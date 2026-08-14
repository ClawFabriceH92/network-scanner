package com.fabrice.network.scanner.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.wifi.WifiManager
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
import androidx.core.content.FileProvider
import com.fabrice.network.scanner.CsvExporter
import com.fabrice.network.scanner.Device
import com.fabrice.network.scanner.DeviceStore
import com.fabrice.network.scanner.HistoryStore
import com.fabrice.network.scanner.NetworkScanner
import com.fabrice.network.scanner.OuiDatabase
import com.fabrice.network.scanner.PortScanner
import com.fabrice.network.scanner.ScanHistory
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
    // Clés des appareils absents de l'historique avant le dernier scan → badges 🆕
    var newKeys by remember { mutableStateOf(setOf<String>()) }
    // Force la recomposition des cartes après renommage/favori
    var refreshTick by remember { mutableStateOf(0) }
    var scanCount by remember { mutableStateOf(0) }

    fun runScan() {
        scope.launch {
            scanning = true
            error = null
            progress = 0
            newDevices = emptyList()
            newKeys = emptySet()
            val oui = OuiDatabase.load(context)
            val result = try {
                NetworkScanner.scan(oui, scanPorts = true) { done, total -> progress = done }
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
            devices = result
            scanning = false
            scanCount++
            refreshTick++
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan Réseau") },
                actions = {
                    if (devices.isNotEmpty() && !scanning) {
                        TextButton(onClick = { exportCsv(context, devices) }) {
                            Text("📤 Export")
                        }
                    }
                    TextButton(onClick = { runScan() }, enabled = !scanning) {
                        Text(if (scanning) "Scan…" else "🔄 Scanner")
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
                Text(
                    "${devices.size} appareils trouvés",
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                )
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(devices, key = { it.ip }) { device ->
                        val key = ScanHistory.identityKey(device)
                        // Lecture du tick pour recomposer après renommage/favori
                        @Suppress("UNUSED_EXPRESSION") refreshTick
                        DeviceCard(
                            device = device,
                            displayName = deviceStore.displayName(device),
                            isFavorite = deviceStore.isFavorite(key),
                            isNew = key in newKeys,
                            onClick = { selected = device }
                        )
                    }
                }
            }
        }
    }

    selected?.let { device ->
        val key = ScanHistory.identityKey(device)
        DeviceDialog(
            device = device,
            store = deviceStore,
            isNew = key in newKeys,
            onDismiss = { selected = null },
            onSaved = { refreshTick++ },
            onWol = {
                val mac = device.mac
                val subnet = NetworkScanner.detectSubnet()
                val broadcast = if (subnet != null) NetworkScanner.broadcastAddress(subnet.first, subnet.second)
                else "255.255.255.255"
                val ok = withMulticastLock(context) {
                    WakeOnLan.send(mac, broadcast)
                }
                val msg = if (ok) "Magic packet envoyé → $mac" else "Échec de l'envoi WoL"
                scope.launch { snackbar.showSnackbar(msg) }
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

@Composable
private fun DeviceCard(
    device: Device,
    displayName: String,
    isFavorite: Boolean,
    isNew: Boolean,
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
                    text = device.vendor.ifBlank { "Fabricant inconnu" },
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
            }
        }
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
                if (device.hostname.isNotBlank()) InfoRow("Nom réseau", device.hostname)
                InfoRow("Statut", if (device.alive) "En ligne" else "Vu récemment (ARP)")
                InfoRow("Historique", if (isNew) "🆕 Nouveau sur le réseau" else "✅ Déjà vu auparavant")
                if (device.ports.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text("Services ouverts :", style = MaterialTheme.typography.labelMedium)
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        device.ports.forEach { port ->
                            PortBadge(port)
                        }
                    }
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

/** Exporte le scan en CSV (BOM UTF-8, séparateur ;) et ouvre le partage. */
private fun exportCsv(context: Context, devices: List<Device>) {
    val dir = File(context.filesDir, "exports").apply { mkdirs() }
    val file = File(dir, "scan_reseau_${System.currentTimeMillis()}.csv")
    file.writeText(CsvExporter.buildCsv(devices), Charsets.UTF_8)

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

/** Acquiert le multicast lock le temps de l'envoi du magic packet. */
private fun <T> withMulticastLock(context: Context, block: () -> T): T {
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

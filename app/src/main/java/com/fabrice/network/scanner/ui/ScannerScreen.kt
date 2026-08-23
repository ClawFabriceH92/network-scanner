package com.fabrice.network.scanner.ui

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.fabrice.network.scanner.AppLog
import com.fabrice.network.scanner.AuditLogStore
import com.fabrice.network.scanner.PermissionHelper
import com.fabrice.network.scanner.R
import com.fabrice.network.scanner.BluetoothScanner
import com.fabrice.network.scanner.BoxClient
import com.fabrice.network.scanner.BoxManager
import com.fabrice.network.scanner.BoxStore
import com.fabrice.network.scanner.BuildConfig
import com.fabrice.network.scanner.CsvExporter
import com.fabrice.network.scanner.CveDatabaseStore
import com.fabrice.network.scanner.CveEntry
import com.fabrice.network.scanner.CveUpdateManager
import com.fabrice.network.scanner.DepartureAlert
import com.fabrice.network.scanner.Device
import com.fabrice.network.scanner.DeviceStore
import com.fabrice.network.scanner.DeviceType
import com.fabrice.network.scanner.DownloadUpdate
import com.fabrice.network.scanner.FreeboxBoxClient
import com.fabrice.network.scanner.GatewayWatcher
import com.fabrice.network.scanner.HistoryStore
import com.fabrice.network.scanner.NetworkScanner
import com.fabrice.network.scanner.NetworkInfoProvider
import com.fabrice.network.scanner.OuiDatabase
import com.fabrice.network.scanner.PdfAuditReport
import com.fabrice.network.scanner.PortScanner
import com.fabrice.network.scanner.ScanHistory
import com.fabrice.network.scanner.ScanPersistence
import com.fabrice.network.scanner.ScheduleStore
import com.fabrice.network.scanner.ServiceFingerprint
import com.fabrice.network.scanner.SmbShareScanner
import com.fabrice.network.scanner.SnmpScanner
import com.fabrice.network.scanner.TechOptions
import com.fabrice.network.scanner.TrustStore
import com.fabrice.network.scanner.UpdateChecker
import com.fabrice.network.scanner.VulnScanner
import com.fabrice.network.scanner.WakeOnLan
import com.fabrice.network.scanner.DefaultCredsChecker
import com.fabrice.network.scanner.NewDeviceNotifier
import com.fabrice.network.scanner.NmapSignatures
import com.fabrice.network.scanner.PresenceHistory
import com.fabrice.network.scanner.PresenceHistoryStore
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import com.fabrice.network.scanner.ui.theme.LocalScannerColors
import com.fabrice.network.scanner.ui.theme.onColorFor
import com.fabrice.network.scanner.ui.theme.riskColor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.TimeUnit

/** Mode de tri de la liste d'appareils. */
private enum class SortMode(val label: String) {
    ONLINE("En ligne d'abord"),
    IP("Par IP"),
    TYPE("Par type"),
    NAME("Par nom")
}

/** Élément de liste : en-tête de groupe (regroupement) ou appareil. */
private sealed interface DeviceListItem {
    data class Header(val title: String) : DeviceListItem
    data class Row(val device: Device) : DeviceListItem
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScannerScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    val deviceStore = remember { DeviceStore(context) }
    val historyStore = remember { HistoryStore(context) }
    val presenceStore = remember { PresenceHistoryStore(context) }
    val trustStore = remember { TrustStore(context) }
    val auditStore = remember { AuditLogStore(context) }

    var devices by remember { mutableStateOf<List<Device>>(emptyList()) }
    var scanning by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0) }
    var progressTotal by remember { mutableStateOf(0) }
    var error by remember { mutableStateOf<String?>(null) }
    var selected by remember { mutableStateOf<Device?>(null) }
    var newDevices by remember { mutableStateOf<List<Device>>(emptyList()) }
    // IP locale de l'appareil qui lance le scan (affichée après le premier scan)
    var selfIp by remember { mutableStateOf<String?>(null) }
    // Dernier scan persisté : chargé au démarrage pour éviter de rescanner
    var lastScanAge by remember { mutableStateOf<Long?>(null) }
    var scanSource by remember { mutableStateOf("") } // "" = scan frais, sinon "sauvegarde"

    // Charge le dernier scan sauvegardé au démarrage (pas de rescan obligatoire)
    LaunchedEffect(Unit) {
        val saved = ScanPersistence.load(context)
        if (saved != null && saved.isNotEmpty() && devices.isEmpty()) {
            devices = saved
            scanSource = "sauvegarde"
            lastScanAge = ScanPersistence.ageMs(context)
            selfIp = saved.firstOrNull { it.isSelf }?.ip
        }
    }
    // Clés des appareils absents de l'historique avant le dernier scan → badges 🆕
    var newKeys by remember { mutableStateOf(setOf<String>()) }
    // Clés des appareils marqués « de confiance » (pas d'alerte ni badge nouveau)
    var trustedKeys by remember { mutableStateOf(trustStore.trustedKeys()) }
    // Force la recomposition des cartes après renommage/favori
    var refreshTick by remember { mutableStateOf(0) }
    // Onglet actif : 0 = Scanner, 1 = Réseau, 2 = Bluetooth
    var selectedTab by remember { mutableStateOf(0) }
    // Scan Bluetooth
    var btDevices by remember { mutableStateOf<List<BluetoothScanner.BtDevice>>(emptyList()) }
    var btScanning by remember { mutableStateOf(false) }
    var btError by remember { mutableStateOf<String?>(null) }
    // Vulnérabilités par IP (calculées après chaque scan, base CVE embarquée)
    var vulnsByIp by remember { mutableStateOf<Map<String, VulnScanner.DeviceVulns>>(emptyMap()) }
    var cveDbVersion by remember { mutableStateOf<String?>(null) }
    // Équipements vus par la box (baux DHCP) — complète le scan direct
    var boxDevices by remember { mutableStateOf<List<BoxClient.BoxDevice>>(emptyList()) }
    var boxStatus by remember { mutableStateOf<String?>(null) } // null = pas de box, "" = ok
    // MAC bloquées via la box — persistées (le blocage box survit au redémarrage
    // de l'app, l'état affiché doit refléter cette réalité).
    var blockedMacs by remember {
        mutableStateOf(
            context.getSharedPreferences("scan_prefs", Context.MODE_PRIVATE)
                .getStringSet("blocked_macs", emptySet())?.toSet() ?: emptySet()
        )
    }
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
    // --- Auto-update GitHub Releases (section « Mise à jour » de À propos) ---
    var updateInfo by remember { mutableStateOf<UpdateChecker.UpdateInfo?>(null) }
    var updateStatus by remember { mutableStateOf<String?>(null) }
    var updateChecking by remember { mutableStateOf(false) }
    var updateDownloading by remember { mutableStateOf(false) }
    // Pop-up « mise à jour disponible » (affichée une fois par lancement quand
    // le check silencieux détecte une nouvelle version).
    var showUpdateDialog by remember { mutableStateOf(false) }
    var updateDialogShown by remember { mutableStateOf(false) }

    // --- Ergonomie : recherche / tri / filtres / regroupement ---
    var searchQuery by remember { mutableStateOf("") }
    var sortMode by remember { mutableStateOf(SortMode.ONLINE) }
    var filterType by remember { mutableStateOf<String?>(null) }
    var onlineOnly by remember { mutableStateOf(false) }
    var groupByType by remember { mutableStateOf(false) }
    var riskBannerDismissed by remember { mutableStateOf(false) }
    // Bannière « nouveau réseau détecté » après un changement de passerelle
    var newNetworkBanner by remember { mutableStateOf(false) }

    // Détecte un changement de passerelle : invalide la config box, efface les
    // tokens et affiche la bannière « nouveau réseau ». Retourne true si un
    // changement a eu lieu (le scan doit alors être relancé).
    fun onGatewayChangeDetected(): Boolean {
        val gw = NetworkInfoProvider.readGateway()
        if (!GatewayWatcher.remember(context, gw)) return false
        BoxManager.reset()
        FreeboxBoxClient.clearTokens(context)
        newNetworkBanner = true
        return true
    }

    // Permission de notification (Android 13+) demandée au 1er scan si les
    // alertes « nouveaux appareils » sont actives (via PermissionHelper, codes fixes).

    fun runScan() {
        scope.launch {
            scanning = true
            error = null
            progress = 0
            progressTotal = 0
            newDevices = emptyList()
            newKeys = emptySet()
            // Demande la permission de notification (Android 13+) si les alertes
            // « nouveaux appareils » sont actives — demandé au 1er scan.
            if (Build.VERSION.SDK_INT >= 33 &&
                NewDeviceNotifier.isEnabled(context) &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                val act = context as? Activity
                if (act != null) PermissionHelper.requestNotifications(act) { }
            }
            val subnet = NetworkScanner.detectSubnet()
            if (subnet == null) {
                // Feature 3 : erreur réseau claire avant de lancer un scan inutile
                error = "Aucun réseau Wi-Fi détecté. Connecte-toi à un réseau, puis réessaie."
                scanning = false
                return@launch
            }
            selfIp = subnet.first
            // Chargements disque/assets (base OUI ~40k lignes, base CVE, signatures
            // Nmap, creds) hors du thread UI — évite le jank/ANR au 1er scan.
            val (oui, cveDb) = withContext(Dispatchers.IO) {
                val loadedOui = OuiDatabase.load(context)
                val loadedCve = CveDatabaseStore.load(context)
                runCatching {
                    context.assets.open("nmap_signatures.json").bufferedReader()
                        .use { NmapSignatures.load(it.readText()) }
                }
                runCatching {
                    context.assets.open("default_creds.json").bufferedReader()
                        .use { DefaultCredsChecker.load(it.readText()) }
                }
                loadedOui to loadedCve
            }
            cveDbVersion = cveDb.generated.ifBlank { null }
            cveStale = CveUpdateManager.isStale(cveDbVersion ?: "")
            // Cache persistant des fabricants résolus en ligne (par préfixe OUI).
            val vendorPrefs = context.getSharedPreferences("vendor_cache", Context.MODE_PRIVATE)
            AppLog.i("Scan", "Démarrage du scan réseau (fast=${TechOptions.scanFast(context)}, economy=${TechOptions.scanEconomy(context)})")
            val result = try {
                // Le multicast lock est requis pour le SSDP (239.255.255.250)
                val portsToScan = if (portMode == 1) PortScanner.ALL_PORTS.map { it.first }
                else PortScanner.COMMON_PORTS.map { it.first }
                withMulticastLock(context) {
                    NetworkScanner.scan(
                        oui,
                        scanPorts = true,
                        prefs = vendorPrefs,
                        portsToScan = portsToScan,
                        scanFast = TechOptions.scanFast(context),
                        scanEconomy = TechOptions.scanEconomy(context)
                    ) { done, total ->
                        progress = done
                        progressTotal = total
                    }
                }
            } catch (e: Exception) {
                error = e.message ?: "Erreur inconnue"
                AppLog.e("Scan", "Échec du scan : ${e.message}")
                emptyList()
            }
            AppLog.i("Scan", "Scan terminé : ${result.size} appareil(s)")
            // Détection des nouveaux appareils (hors confiance) par rapport à
            // l'historique connu, puis des départs (étaient là, ne répondent plus).
            if (result.isNotEmpty()) {
                // Lecture de l'historique hors thread UI.
                val previous = withContext(Dispatchers.IO) { historyStore.load() }
                val trusted = trustStore.trustedKeys()
                val fresh = ScanHistory.detectNewDevices(previous, result, trusted)
                if (fresh.isNotEmpty()) {
                    newDevices = fresh
                    newKeys = fresh.map { ScanHistory.identityKey(it) }.toSet()
                    // ⚠️ Pas de notification au tout premier scan (historique vide
                    // → tout serait « nouveau »). On ne notifie que si un
                    // historique connu existe déjà.
                    if (previous.isNotEmpty()) {
                        NewDeviceNotifier.notify(context, fresh)
                    }
                }
                // Appareils absents du scan courant (étaient là, ne répondent plus).
                val departed = DepartureAlert.detectDepartures(previous, result, trusted)
                if (departed.isNotEmpty()) {
                    DepartureAlert.notify(context, departed)
                }
                // Toutes les écritures disque (journal d'audit, historique, présence)
                // groupées hors du thread UI — évite le jank en fin de scan.
                withContext(Dispatchers.IO) {
                    fresh.forEach { d ->
                        val name = deviceDisplayName(d, deviceStore.customName(ScanHistory.identityKey(d)))
                        auditStore.append("$name (${d.ip}) apparu")
                    }
                    departed.forEach { d ->
                        val name = deviceDisplayName(d, deviceStore.customName(ScanHistory.identityKey(d)))
                        auditStore.append("$name (${d.ip}) absent")
                    }
                    auditStore.append(
                        "Scan terminé : ${result.size} appareil(s) (${result.count { it.alive }} en ligne)"
                    )
                    historyStore.save(result)
                    runCatching {
                        val registry = presenceStore.load()
                        presenceStore.save(PresenceHistory.record(registry, result))
                    }
                }
            }
            // Scan de vulnérabilités : banner → produit/version → matching CVE
            // (le champ defaultCred alimente le score : +50 si credential par défaut)
            vulnsByIp = withContext(Dispatchers.IO) {
                result.associate { device ->
                    val services = VulnScanner.parseBanner(device.banner)
                    device.ip to VulnScanner.match(services, cveDb, device.defaultCred)
                }
            }
            // Équipements vus par la box (baux DHCP) — complète le scan.
            // Détection (lecture /proc/net/arp + base OUI) hors thread UI.
            val box = withContext(Dispatchers.IO) { BoxManager.detect(context) }
            if (box != null) {
                boxStatus = ""
                // runCatching : une réponse box malformée ne doit jamais faire
                // remonter d'exception jusqu'à l'UI.
                val fetched = withContext(Dispatchers.IO) {
                    runCatching { box.fetchDevices() }.getOrNull()
                }
                if (fetched != null) {
                    boxDevices = fetched
                    boxStatus = "" // ok
                } else {
                    boxDevices = emptyList()
                    boxStatus = "Box ${box.name} non autorisée — ouvre l'app, puis valide l'autorisation sur la box."
                }
            } else {
                boxDevices = emptyList()
                boxStatus = null
            }
            devices = result
            // Alerte push si une credential par défaut a été trouvée (même canal)
            result.filter { it.defaultCred != null }.take(3).forEach { d ->
                NewDeviceNotifier.notifyDefaultCred(context, d)
            }
            withContext(Dispatchers.IO) { ScanPersistence.save(context, result) }
            // Blocages programmés : applique les fenêtres dues via l'API box
            // (no-op rapide si aucune planification). Non-bloquant pour l'UI.
            val scheduledActions = withContext(Dispatchers.IO) {
                runCatching { ScheduleStore.applyDue(context) }.getOrDefault(0)
            }
            if (scheduledActions > 0) {
                AppLog.i("Scan", "$scheduledActions action(s) de blocage programmé")
            }
            scanSource = ""
            lastScanAge = null
            scanning = false
            refreshTick++
            // Changement de passerelle détecté après ce scan → rescan auto.
            if (onGatewayChangeDetected()) runScan()
        }
    }

    // Au démarrage : détecte un éventuel changement de passerelle depuis la
    // dernière session → reset box + rescan automatique sur le nouveau réseau.
    LaunchedEffect(Unit) {
        if (onGatewayChangeDetected()) runScan()
    }

    fun updateCveBase(
        context: Context,
        onResult: (String) -> Unit
    ) {
        scope.launch {
            cveUpdating = true
            cveUpdateResult = null
            val result = withContext(Dispatchers.IO) {
                CveUpdateManager.update(context)
            }
            if (result != null) {
                // La base a changé : on force le rechargement au prochain scan
                CveDatabaseStore.invalidate()
                cveDbVersion = result.generated
                cveStale = CveUpdateManager.isStale(result.generated)
                onResult("Base mise à jour : ${result.generated} (${result.allCount} CVE)")
            } else {
                onResult("Échec de la mise à jour (réseau ou base indisponible)")
            }
            cveUpdating = false
        }
    }

    // --- Auto-update : vérifie GitHub Releases (manuel depuis À propos, ou
    //     silencieux au lancement — jamais sur le thread UI). ---
    fun checkAppUpdate(silent: Boolean) {
        if (updateChecking) return
        scope.launch {
            updateChecking = true
            if (!silent) updateStatus = null
            val info = withContext(Dispatchers.IO) { UpdateChecker.check() }
            updateChecking = false
            val err = UpdateChecker.lastError
            when {
                info != null -> {
                    updateInfo = info
                    if (!silent) updateStatus = "⬇️ Nouvelle version disponible : v${info.version}"
                    // Au lancement (check silencieux) : proposer la MAJ via pop-up,
                    // une seule fois par session.
                    if (silent && !updateDialogShown) {
                        showUpdateDialog = true
                        updateDialogShown = true
                    }
                }
                err != null -> {
                    updateInfo = null
                    if (!silent) updateStatus = "⚠️ Erreur API : $err"
                }
                else -> {
                    updateInfo = null
                    if (!silent) updateStatus = "✅ À jour (v${BuildConfig.VERSION_NAME})"
                }
            }
        }
    }

    fun downloadAppUpdate() {
        val info = updateInfo ?: return
        scope.launch {
            updateDownloading = true
            updateStatus = "⬇️ Téléchargement en cours… (suis la notification)"
            withContext(Dispatchers.IO) { DownloadUpdate.start(context, info.url) }
            updateDownloading = false
        }
    }

    // Téléchargement DIRECT de la dernière version (lien stable), indépendant de
    // la vérification : marche toujours, même si l'app se croit à jour.
    fun downloadLatestDirect() {
        scope.launch {
            updateDownloading = true
            updateStatus = "⬇️ Téléchargement de la dernière version… (suis la notification)"
            withContext(Dispatchers.IO) { DownloadUpdate.start(context, UpdateChecker.LATEST_APK_URL) }
            updateDownloading = false
        }
    }

    // Check auto silencieux au lancement (ne pollue pas l'UI).
    LaunchedEffect(Unit) { checkAppUpdate(silent = true) }

    // Permissions Bluetooth (Android 12+ : BLUETOOTH_SCAN + BLUETOOTH_CONNECT,
    // et ACCESS_FINE_LOCATION pour le BLE sur certains appareils)
    val btPermissions = remember {
        arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
    }
    // lateinit : la lambda est assignée après (évite la forward reference)
    lateinit var runBtScan: (Context) -> Unit

    // Demande la localisation au démarrage si absente (nécessaire pour lire le
    // SSID/nom du Wi-Fi sur Android 8.1+ ET pour le scan BLE) — via PermissionHelper.
    LaunchedEffect(Unit) {
        val act = context as? Activity
        if (act != null && !PermissionHelper.has(act, Manifest.permission.ACCESS_FINE_LOCATION)) {
            PermissionHelper.requestLocation(act) { }
        }
    }

    runBtScan = { ctx ->
        val missing = btPermissions.filter {
            ContextCompat.checkSelfPermission(ctx, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            val act = ctx as? Activity
            if (act != null) {
                PermissionHelper.requestBluetooth(act, btPermissions) { granted ->
                    if (granted.values.any { it }) runBtScan(act) else {
                        btError = "Permissions refusées — active la localisation et le Bluetooth."
                    }
                }
            } else {
                btError = "Permissions Bluetooth non accordées."
            }
        } else if (!BluetoothScanner.isSupported(ctx)) {
            btError = "Bluetooth désactivé — active-le dans les réglages."
        } else {
            scope.launch {
                btScanning = true
                btError = null
                btDevices = withContext(Dispatchers.IO) {
                    val oui = OuiDatabase.load(ctx)
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
            isTrusted = ScanHistory.identityKey(detail) in trustedKeys,
            vulns = vulnsByIp[detail.ip],
            onDismiss = { selected = null },
            onSaved = { refreshTick++ },
            onToggleTrust = {
                val key = ScanHistory.identityKey(detail)
                val nowTrusted = trustStore.toggle(key)
                trustedKeys = if (nowTrusted) trustedKeys + key else trustedKeys - key
                refreshTick++
            }
        )
        return
    }

    // Bouton/geste retour système : revient aux périphériques depuis un
    // sous-écran (Réglages, À propos, Timeline, Carte, Nouveaux appareils) au
    // lieu de quitter l'application.
    BackHandler(enabled = screen != 0) { screen = 0 }

    // Pop-up « mise à jour disponible » (détectée au lancement).
    val pendingUpdate = updateInfo
    if (showUpdateDialog && pendingUpdate != null) {
        val dialogClipboard = LocalClipboardManager.current
        AlertDialog(
            onDismissRequest = { showUpdateDialog = false },
            title = { Text("Mise à jour disponible") },
            text = {
                Text(
                    "Une nouvelle version est disponible : v${pendingUpdate.version}\n" +
                        "(version actuelle : v${BuildConfig.VERSION_NAME})."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showUpdateDialog = false
                    downloadAppUpdate()
                }) { Text("Télécharger") }
            },
            dismissButton = {
                Row {
                    TextButton(onClick = {
                        dialogClipboard.setText(AnnotatedString(UpdateChecker.LATEST_APK_URL))
                    }) { Text("Copier le lien") }
                    TextButton(onClick = { showUpdateDialog = false }) { Text("Plus tard") }
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        when (screen) {
                            1 -> "Réglages"
                            2 -> "À propos"
                            3 -> "Nouveaux appareils"
                            4 -> "Timeline d'audit"
                            5 -> "Carte réseau"
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
                            IconButton(onClick = { menuExpanded = true }) {
                                Icon(Icons.Filled.MoreVert, contentDescription = "Menu")
                            }
                            DropdownMenu(
                                expanded = menuExpanded,
                                onDismissRequest = { menuExpanded = false }
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Rapport PDF") },
                                    onClick = {
                                        menuExpanded = false
                                        exportPdf(context, devices, vulnsByIp, selfIp)
                                    },
                                    enabled = devices.isNotEmpty() && !scanning
                                )
                                DropdownMenuItem(
                                    text = { Text("Export CSV") },
                                    onClick = {
                                        menuExpanded = false
                                        exportCsv(context, devices, vulnsByIp)
                                    },
                                    enabled = devices.isNotEmpty() && !scanning
                                )
                                HorizontalDivider()
                                DropdownMenuItem(
                                    text = { Text("Aide") },
                                    onClick = {
                                        menuExpanded = false
                                        screen = 1
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("À propos") },
                                    onClick = {
                                        menuExpanded = false
                                        screen = 2
                                    }
                                )
                                HorizontalDivider()
                                DropdownMenuItem(
                                    text = { Text("Timeline d'audit") },
                                    onClick = {
                                        menuExpanded = false
                                        screen = 4
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("🗺️ Carte réseau") },
                                    onClick = {
                                        menuExpanded = false
                                        screen = 5
                                    },
                                    enabled = devices.isNotEmpty() && !scanning
                                )
                            }
                        }
                    }
                }
            )
        },
        bottomBar = {
            if (screen == 0 || screen == 1) {
                // 6 onglets : le libellé n'est affiché que sur l'onglet ACTIF
                // (alwaysShowLabel = false) et forcé sur une seule ligne — évite
                // que « Bluetooth » / « Réglages » passent à la ligne. Les icônes
                // portent un contentDescription pour l'accessibilité (les onglets
                // inactifs n'affichent pas de texte).
                NavigationBar {
                    NavigationBarItem(
                        selected = screen == 0 && selectedTab == 0,
                        onClick = { screen = 0; selectedTab = 0 },
                        icon = { Icon(Icons.AutoMirrored.Filled.List, contentDescription = "Appareils") },
                        label = { NavLabel("Appareils") },
                        alwaysShowLabel = false
                    )
                    NavigationBarItem(
                        selected = screen == 0 && selectedTab == 1,
                        onClick = { screen = 0; selectedTab = 1 },
                        icon = { Icon(painterResource(R.drawable.ic_network), contentDescription = "Réseau") },
                        label = { NavLabel("Réseau") },
                        alwaysShowLabel = false
                    )
                    NavigationBarItem(
                        selected = screen == 0 && selectedTab == 2,
                        onClick = { screen = 0; selectedTab = 2 },
                        icon = { Icon(painterResource(R.drawable.ic_bluetooth), contentDescription = "Bluetooth") },
                        label = { NavLabel("Bluetooth") },
                        alwaysShowLabel = false
                    )
                    NavigationBarItem(
                        selected = screen == 0 && selectedTab == 3,
                        onClick = { screen = 0; selectedTab = 3 },
                        icon = { Icon(painterResource(R.drawable.ic_wifi), contentDescription = "WiFi") },
                        label = { NavLabel("WiFi") },
                        alwaysShowLabel = false
                    )
                    NavigationBarItem(
                        selected = screen == 0 && selectedTab == 4,
                        onClick = { screen = 0; selectedTab = 4 },
                        icon = { Icon(painterResource(R.drawable.ic_nfc), contentDescription = "NFC") },
                        label = { NavLabel("NFC") },
                        alwaysShowLabel = false
                    )
                    NavigationBarItem(
                        selected = screen == 1,
                        onClick = { screen = 1 },
                        icon = { Icon(Icons.Filled.Settings, contentDescription = "Réglages") },
                        label = { NavLabel("Réglages") },
                        alwaysShowLabel = false
                    )
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
                // Onglet « Réglages » : l'écran À propos regroupe PIN, surveillance,
                // alertes, options, mise à jour et support. L'aide reste dans le menu ⋮.
                AboutScreen(
                    updateInfo = updateInfo,
                    updateStatus = updateStatus,
                    updateChecking = updateChecking,
                    updateDownloading = updateDownloading,
                    onCheckUpdate = { checkAppUpdate(silent = false) },
                    onDownloadUpdate = { downloadAppUpdate() },
                    onDownloadLatest = { downloadLatestDirect() },
                    onOpenTimeline = { screen = 4 }
                )
            } else if (screen == 2) {
                AboutScreen(
                    updateInfo = updateInfo,
                    updateStatus = updateStatus,
                    updateChecking = updateChecking,
                    updateDownloading = updateDownloading,
                    onCheckUpdate = { checkAppUpdate(silent = false) },
                    onDownloadUpdate = { downloadAppUpdate() },
                    onDownloadLatest = { downloadLatestDirect() },
                    onOpenTimeline = { screen = 4 }
                )
            } else if (screen == 3) {
                NewDevicesScreen(
                    devices = newDevices,
                    onDeviceClick = { selected = it }
                )
            } else if (screen == 4) {
                AuditLogScreen()
            } else if (screen == 5) {
                NetworkMapScreen(
                    devices = devices,
                    deviceStore = deviceStore,
                    vulnsByIp = vulnsByIp,
                    onBack = { screen = 0 },
                    onDeviceClick = { selected = it }
                )
            } else {
                // Léger fondu à la bascule d'onglet.
                Crossfade(
                    targetState = selectedTab,
                    label = "tab",
                    modifier = Modifier.fillMaxSize()
                ) { tabState ->
                when (tabState) {
                    1 -> NetworkScreen()
                    2 -> BluetoothScreen(
                        devices = btDevices,
                        scanning = btScanning,
                        error = btError,
                        onScan = { runBtScan(context) }
                    )
                    3 -> WifiScreen()
                    4 -> NfcScreen()
                    else -> {
                        // Onglet Scanner (Périphériques). Column car Crossfade
                        // place son contenu dans une Box (sinon les enfants se
                        // superposeraient).
                        Column(Modifier.fillMaxSize()) {
                        if (scanning) {
                            LinearProgressIndicator(
                                progress = {
                                    if (progressTotal > 0) progress.toFloat() / progressTotal else 0f
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 8.dp)
                            )
                            Text(
                                "📡 Scan en cours… ${
                                    if (progressTotal > 0) (progress * 100 / progressTotal) else 0
                                } %",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(horizontal = 16.dp)
                            )
                        }
                        error?.let { msg ->
                            ErrorBanner(message = msg, onRetry = { runScan() })
                        }
                        // Bouton « Scanner » compact en haut de l'écran
                        // (remplace l'ancien FAB en bas — une seule action
                        // primaire par état : l'état vide a son bouton central).
                        if (devices.isNotEmpty()) {
                            ScanButton(
                                scanning = scanning,
                                progress = progress,
                                progressTotal = progressTotal,
                                onScan = { runScan() }
                            )
                        }
                        if (devices.isEmpty() && !scanning) {
                            EmptyDevicesState(onScan = { runScan() })
                        } else if (devices.isNotEmpty()) {
                            PullToRefreshBox(
                                isRefreshing = scanning,
                                onRefresh = { if (!scanning) runScan() },
                                modifier = Modifier.fillMaxSize()
                            ) {
                                DeviceList(
                                    devices = devices,
                                    deviceStore = deviceStore,
                                    refreshTick = refreshTick,
                                    searchQuery = searchQuery,
                                    onSearchQueryChange = { searchQuery = it },
                                    sortMode = sortMode,
                                    onSortModeChange = { sortMode = it },
                                    filterType = filterType,
                                    onFilterTypeChange = { filterType = it },
                                    onlineOnly = onlineOnly,
                                    onOnlineOnlyChange = { onlineOnly = it },
                                    groupByType = groupByType,
                                    onGroupByTypeChange = { groupByType = it },
                                    selfIp = selfIp,
                                    lastScanAge = lastScanAge,
                                    scanSource = scanSource,
                                    newKeys = newKeys,
                                    vulnsByIp = vulnsByIp,
                                    newDevices = newDevices,
                                    onNewDevicesClick = { screen = 3 },
                                    cveDbVersion = cveDbVersion,
                                    cveStale = cveStale,
                                    cveUpdateResult = cveUpdateResult,
                                    cveUpdating = cveUpdating,
                                    onCveUpdate = { updateCveBase(context) { msg -> cveUpdateResult = msg } },
                                    onCveDismiss = { cveUpdateResult = null },
                                    riskBannerDismissed = riskBannerDismissed,
                                    onRiskBannerDismiss = { riskBannerDismissed = true },
                                    newNetworkBanner = newNetworkBanner,
                                    onNewNetworkDismiss = { newNetworkBanner = false },
                                    portMode = portMode,
                                    onPortModeChange = { newMode ->
                                        portMode = newMode
                                        context.getSharedPreferences("scan_prefs", Context.MODE_PRIVATE)
                                            .edit().putInt("port_mode", newMode).apply()
                                    },
                                    boxStatus = boxStatus,
                                    boxDevices = boxDevices,
                                    onAuthorizeBox = {
                                        // detect() (lecture ARP/OUI) + requestAuthorization()
                                        // (requête réseau) hors thread UI, sinon
                                        // NetworkOnMainThreadException.
                                        scope.launch(Dispatchers.IO) {
                                            val box = BoxManager.detect(context)
                                            if (box is FreeboxBoxClient) {
                                                box.requestAuthorization()
                                                withContext(Dispatchers.Main) {
                                                    snackbar.showSnackbar(
                                                        "Autorisation envoyée — valide-la sur la box, puis rescanne."
                                                    )
                                                }
                                            }
                                        }
                                    },
                                    onToggleBlock = { device ->
                                        scope.launch(Dispatchers.IO) {
                                            val client = BoxManager.detect(context) ?: return@launch
                                            val blocked = device.mac in blockedMacs
                                            val ok = if (blocked) client.unblockDevice(device.mac)
                                            else client.blockDevice(device.mac)
                                            withContext(Dispatchers.Main) {
                                                if (ok) {
                                                    blockedMacs = if (blocked) blockedMacs - device.mac
                                                    else blockedMacs + device.mac
                                                    context.getSharedPreferences("scan_prefs", Context.MODE_PRIVATE)
                                                        .edit().putStringSet("blocked_macs", blockedMacs).apply()
                                                    snackbar.showSnackbar(
                                                        if (blocked) "✅ ${device.name.ifBlank { device.ip }} débloqué"
                                                        else "⛔ ${device.name.ifBlank { device.ip }} bloqué — accès coupé"
                                                    )
                                                } else {
                                                    snackbar.showSnackbar("Échec — box non accessible ou action refusée ?")
                                                }
                                            }
                                        }
                                    },
                                    blockedMacs = blockedMacs,
                                    onDeviceClick = { selected = it },
                                    onToggleFavorite = { device ->
                                        val key = ScanHistory.identityKey(device)
                                        val fav = !deviceStore.isFavorite(key)
                                        deviceStore.setFavorite(key, fav)
                                        refreshTick++
                                    },
                                    trustedKeys = trustedKeys,
                                    onToggleTrust = { device ->
                                        val key = ScanHistory.identityKey(device)
                                        val nowTrusted = trustStore.toggle(key)
                                        trustedKeys = if (nowTrusted) trustedKeys + key else trustedKeys - key
                                        refreshTick++
                                    }
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
}

/** Libellé d'onglet : une seule ligne, petit (tient dans un onglet de 1/6). */
@Composable
private fun NavLabel(text: String) {
    Text(
        text,
        maxLines = 1,
        softWrap = false,
        style = MaterialTheme.typography.labelSmall
    )
}

/** Liste des appareils : résumé + alertes + recherche/tri/filtres + cartes. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DeviceList(
    devices: List<Device>,
    deviceStore: DeviceStore,
    refreshTick: Int,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    sortMode: SortMode,
    onSortModeChange: (SortMode) -> Unit,
    filterType: String?,
    onFilterTypeChange: (String?) -> Unit,
    onlineOnly: Boolean,
    onOnlineOnlyChange: (Boolean) -> Unit,
    groupByType: Boolean,
    onGroupByTypeChange: (Boolean) -> Unit,
    selfIp: String?,
    lastScanAge: Long?,
    scanSource: String,
    newKeys: Set<String>,
    vulnsByIp: Map<String, VulnScanner.DeviceVulns>,
    newDevices: List<Device>,
    onNewDevicesClick: () -> Unit,
    cveDbVersion: String?,
    cveStale: Boolean,
    cveUpdateResult: String?,
    cveUpdating: Boolean,
    onCveUpdate: () -> Unit,
    onCveDismiss: () -> Unit,
    riskBannerDismissed: Boolean,
    onRiskBannerDismiss: () -> Unit,
    newNetworkBanner: Boolean,
    onNewNetworkDismiss: () -> Unit,
    portMode: Int,
    onPortModeChange: (Int) -> Unit,
    boxStatus: String?,
    boxDevices: List<BoxClient.BoxDevice>,
    onAuthorizeBox: () -> Unit,
    onToggleBlock: (BoxClient.BoxDevice) -> Unit = {},
    blockedMacs: Set<String> = emptySet(),
    onDeviceClick: (Device) -> Unit,
    onToggleFavorite: (Device) -> Unit,
    trustedKeys: Set<String> = emptySet(),
    onToggleTrust: (Device) -> Unit = {}
) {
    @Suppress("UNUSED_EXPRESSION") refreshTick
    val displayList = buildDisplayList(
        devices = devices,
        deviceStore = deviceStore,
        query = searchQuery,
        sortMode = sortMode,
        filterType = filterType,
        onlineOnly = onlineOnly,
        groupByType = groupByType
    )
    val maxRisk = remember(devices, vulnsByIp) { highestRiskLabel(vulnsByIp) }
    val riskCount = remember(devices, vulnsByIp) { vulnsByIp.values.count { !it.isEmpty } }

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
        item(key = "summary") {
            ScanSummaryHeader(
                devices = devices,
                selfIp = selfIp,
                lastScanAge = lastScanAge,
                scanSource = scanSource
            )
        }
        if (newDevices.isNotEmpty()) {
            item(key = "new") { NewDevicesBanner(newDevices = newDevices, onClick = onNewDevicesClick) }
        }
        if (newNetworkBanner) {
            item(key = "newnetwork") { NewNetworkBanner(onDismiss = onNewNetworkDismiss) }
        }
        if (maxRisk != null && riskCount > 0 && !riskBannerDismissed) {
            item(key = "risk") {
                RiskSummaryBanner(
                    maxRiskLabel = maxRisk,
                    count = riskCount,
                    onDismiss = onRiskBannerDismiss
                )
            }
        }
        if (!cveUpdating && (cveStale || cveUpdateResult != null)) {
            item(key = "cve") {
                CveBanner(
                    version = cveDbVersion,
                    stale = cveStale,
                    result = cveUpdateResult,
                    onUpdate = onCveUpdate,
                    onDismiss = onCveDismiss
                )
            }
        }
        item(key = "search") {
            SearchFilterBar(
                query = searchQuery,
                onQueryChange = onSearchQueryChange,
                sortMode = sortMode,
                onSortChange = onSortModeChange,
                filterType = filterType,
                onFilterType = onFilterTypeChange,
                onlineOnly = onlineOnly,
                onOnlineOnly = onOnlineOnlyChange,
                groupByType = groupByType,
                onGroupByType = onGroupByTypeChange,
                availableTypes = remember(devices) { devices.map { it.type }.distinct().sorted() }
            )
        }
        if (boxStatus != null) {
            item(key = "box") {
                BoxDevicesSection(
                    status = boxStatus ?: "",
                    devices = boxDevices,
                    onAuthorize = onAuthorizeBox,
                    onToggleBlock = onToggleBlock,
                    blockedMacs = blockedMacs
                )
            }
        }
        items(displayList, key = { item ->
            when (item) {
                is DeviceListItem.Header -> "h:${item.title}"
                is DeviceListItem.Row -> "d:${item.device.ip}"
            }
        }) { item ->
            when (item) {
                is DeviceListItem.Header -> {
                    Text(
                        item.title,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(start = 4.dp, top = 8.dp)
                    )
                }
                is DeviceListItem.Row -> {
                    val device = item.device
                    val key = ScanHistory.identityKey(device)
                    DeviceCard(
                        device = device,
                        displayName = deviceDisplayName(device, deviceStore.customName(key)),
                        isFavorite = deviceStore.isFavorite(key),
                        isNew = key in newKeys,
                        isTrusted = key in trustedKeys,
                        vulns = vulnsByIp[device.ip],
                        onClick = { onDeviceClick(device) },
                        onToggleFavorite = { onToggleFavorite(device) },
                        onToggleTrust = { onToggleTrust(device) }
                    )
                }
            }
        }
        item(key = "version") {
            Text(
                "v${BuildConfig.VERSION_NAME}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp)
            )
        }
    }
}

/** Résumé en tête de liste : « X en ligne / Y total » + dernier scan. */
@Composable
private fun ScanSummaryHeader(
    devices: List<Device>,
    selfIp: String?,
    lastScanAge: Long?,
    scanSource: String
) {
    val online = devices.count { it.alive }
    Card(
        modifier = Modifier.fillMaxWidth(),
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
                Row(verticalAlignment = Alignment.Bottom) {
                    Text(
                        "$online",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        " en ligne",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
                Text(
                    "${devices.size} appareil(s) au total",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    when {
                        scanSource == "sauvegarde" ->
                            "Dernier scan : ${lastScanAge?.let { ScanPersistence.ageLabel(it) } ?: "—"}"
                        else -> "Scan depuis : ${selfIp ?: "—"}"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

/** Bandeau de risque : couleur = niveau le plus élevé présent, dismissible. */
@Composable
private fun RiskSummaryBanner(
    maxRiskLabel: String,
    count: Int,
    onDismiss: () -> Unit
) {
    val semantic = LocalScannerColors.current
    val bg = semantic.riskColor(maxRiskLabel)
    val fg = onColorFor(bg)
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = bg)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "$count appareil(s) avec vulnérabilité(s)",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = fg
                )
                Text(
                    "Risque le plus élevé : $maxRiskLabel",
                    style = MaterialTheme.typography.labelSmall,
                    color = fg
                )
            }
            TextButton(onClick = onDismiss) {
                Text("Fermer", color = fg, fontWeight = FontWeight.Bold)
            }
        }
    }
}

/** Barre recherche + tri + filtres (type, en ligne, regroupement). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SearchFilterBar(
    query: String,
    onQueryChange: (String) -> Unit,
    sortMode: SortMode,
    onSortChange: (SortMode) -> Unit,
    filterType: String?,
    onFilterType: (String?) -> Unit,
    onlineOnly: Boolean,
    onOnlineOnly: (Boolean) -> Unit,
    groupByType: Boolean,
    onGroupByType: (Boolean) -> Unit,
    availableTypes: List<String>
) {
    var sortExpanded by remember { mutableStateOf(false) }
    Column {
        OutlinedTextField(
            value = query,
            onValueChange = onQueryChange,
            modifier = Modifier.fillMaxWidth(),
            placeholder = {
                Text("Rechercher…", style = MaterialTheme.typography.bodySmall)
            },
            leadingIcon = {
                Icon(
                    Icons.Filled.Search,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
            },
            singleLine = true,
            textStyle = MaterialTheme.typography.bodySmall,
            shape = MaterialTheme.shapes.medium
        )
        Spacer(Modifier.height(4.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Box {
                FilterChip(
                    selected = true,
                    onClick = { sortExpanded = true },
                    label = { Text("Tri : ${sortMode.label}") }
                )
                DropdownMenu(expanded = sortExpanded, onDismissRequest = { sortExpanded = false }) {
                    SortMode.entries.forEach { mode ->
                        DropdownMenuItem(
                            text = { Text(mode.label) },
                            onClick = {
                                onSortChange(mode)
                                sortExpanded = false
                            }
                        )
                    }
                }
            }
            FilterChip(
                selected = onlineOnly,
                onClick = { onOnlineOnly(!onlineOnly) },
                label = { Text("En ligne") }
            )
            FilterChip(
                selected = groupByType,
                onClick = { onGroupByType(!groupByType) },
                label = { Text("Regrouper") }
            )
            availableTypes.forEach { type ->
                FilterChip(
                    selected = filterType == type,
                    onClick = { onFilterType(if (filterType == type) null else type) },
                    label = { Text(type) }
                )
            }
        }
    }
}

/** Bandeau d'erreur réseau avec action « Réessayer ». */
@Composable
private fun ErrorBanner(message: String, onRetry: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                message,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.weight(1f)
            )
            TextButton(onClick = onRetry) {
                Text("Réessayer", fontWeight = FontWeight.Bold)
            }
        }
    }
}

/** Bouton « Scanner » compact en haut de l'écran (remplace l'ancien FAB). */
@Composable
private fun ScanButton(
    scanning: Boolean,
    progress: Int,
    progressTotal: Int,
    onScan: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.End
    ) {
        Button(
            onClick = { if (!scanning) onScan() },
            shape = MaterialTheme.shapes.medium
        ) {
            if (scanning) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    if (progressTotal > 0) "Scan ${progress * 100 / progressTotal} %"
                    else "Scan en cours…"
                )
            } else {
                Text("⚡ Scanner")
            }
        }
    }
}

/** État vide soigné : icône + message + bouton arrondi. */
@Composable
private fun EmptyDevicesState(onScan: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            Icons.Filled.Search,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
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
        FilledTonalButton(
            onClick = onScan,
            shape = MaterialTheme.shapes.extraLarge
        ) {
            Text("Scanner le réseau")
        }
    }
}

@Composable
private fun NewDevicesBanner(newDevices: List<Device>, onClick: () -> Unit) {
    val semantic = LocalScannerColors.current
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = semantic.newDevice)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                if (newDevices.size == 1) "1 nouvel appareil détecté"
                else "${newDevices.size} nouveaux appareils détectés",
                color = onColorFor(semantic.newDevice),
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(Modifier.weight(1f))
            Text(
                "Voir →",
                color = onColorFor(semantic.newDevice),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

/** Bandeau « nouveau réseau détecté » (changement de passerelle). */
@Composable
private fun NewNetworkBanner(onDismiss: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "📡 Nouveau réseau détecté — rescan automatique",
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f)
            )
            TextButton(onClick = onDismiss) {
                Text(
                    "Fermer",
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

/** Section « Vu par la box » : équipements des baux DHCP, en accordéon. */
@Composable
private fun BoxDevicesSection(
    status: String,
    devices: List<BoxClient.BoxDevice>,
    onAuthorize: () -> Unit,
    onToggleBlock: (BoxClient.BoxDevice) -> Unit = {},
    blockedMacs: Set<String> = emptySet()
) {
    val context = LocalContext.current
    val gateway = remember { NetworkInfoProvider.readGateway() }
    val prefs = remember { context.getSharedPreferences(BoxStore.PREFS, Context.MODE_PRIVATE) }
    var boxName by remember { mutableStateOf(BoxStore.getBoxName(prefs, gateway)) }
    var renaming by remember { mutableStateOf(false) }
    var expanded by remember { mutableStateOf(false) }
    var confirmBlock by remember { mutableStateOf<BoxClient.BoxDevice?>(null) }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded },
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        "Vu par la box (${devices.size})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    boxName?.let {
                        Text(
                            it,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
                if (boxName != null) {
                    IconButton(
                        onClick = { renaming = true },
                        modifier = Modifier.semantics { contentDescription = "Renommer la box" }
                    ) {
                        Icon(
                            Icons.Filled.Edit,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Text(if (expanded) "▲" else "▼", style = MaterialTheme.typography.labelMedium)
            }
            if (status.isNotBlank()) {
                Text(
                    status,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(top = 4.dp)
                )
                if (status.contains("autorisée")) {
                    TextButton(onClick = onAuthorize) {
                        Text("Autoriser l'app sur la box")
                    }
                }
            } else if (expanded) {
                Spacer(Modifier.height(8.dp))
                if (devices.isEmpty()) {
                    Text(
                        "Aucun équipement retourné.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    devices.sortedBy { it.name.lowercase() }.forEach { d ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(vertical = 3.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            StatusDot(if (d.reachable) true else false)
                            Spacer(Modifier.width(6.dp))
                            Column(Modifier.weight(1f)) {
                                Text(
                                    d.name.ifBlank { "inconnu" },
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.Medium,
                                    maxLines = 1
                                )
                                if (d.hostType.isNotBlank() && d.hostType != "unknown") {
                                    Text(
                                        boxTypeLabel(d.hostType),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                            if (d.ip.isNotBlank()) {
                                Text(
                                    d.ip,
                                    style = LocalMonoTextStyle.current,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                            IconButton(
                                onClick = { confirmBlock = d },
                                modifier = Modifier.semantics {
                                    contentDescription =
                                        if (d.mac in blockedMacs) "Débloquer l'appareil" else "Bloquer l'appareil"
                                }
                            ) {
                                Icon(
                                    if (d.mac in blockedMacs) Icons.Filled.Lock else Icons.Outlined.Lock,
                                    contentDescription = null,
                                    tint = if (d.mac in blockedMacs) MaterialTheme.colorScheme.error
                                    else MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    confirmBlock?.let { target ->
        val blocked = target.mac in blockedMacs
        AlertDialog(
            onDismissRequest = { confirmBlock = null },
            title = { Text(if (blocked) "Débloquer ${target.name.ifBlank { target.ip }} ?" else "Bloquer ${target.name.ifBlank { target.ip }} ?") },
            text = {
                Text(
                    if (blocked) "Le périphérique retrouvera l'accès réseau/Internet."
                    else "Le périphérique perdra l'accès réseau/Internet. (Le blocage peut ne pas survivre au redémarrage de la box.)"
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    onToggleBlock(target)
                    confirmBlock = null
                }) { Text(if (blocked) "✅ Débloquer" else "⛔ Bloquer") }
            },
            dismissButton = {
                TextButton(onClick = { confirmBlock = null }) { Text("Annuler") }
            }
        )
    }

    if (renaming) {
        var draft by remember { mutableStateOf(boxName ?: "") }
        AlertDialog(
            onDismissRequest = { renaming = false },
            title = { Text("Renommer la box") },
            text = {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    singleLine = true,
                    label = { Text("Nom de la box") },
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val name = draft.trim()
                    if (name.isNotEmpty()) {
                        BoxStore.setBoxName(prefs, gateway, name)
                        boxName = name
                    }
                    renaming = false
                }) { Text("OK") }
            },
            dismissButton = {
                TextButton(onClick = { renaming = false }) { Text("Annuler") }
            }
        )
    }
}

/** Traduit le type Freebox (computer, printer…) en libellé lisible. */
private fun boxTypeLabel(t: String): String = when (t.lowercase()) {
    "computer" -> "Ordinateur"
    "printer" -> "Imprimante"
    "camera" -> "Caméra"
    "phone" -> "Téléphone"
    "nas" -> "NAS"
    "router" -> "Routeur"
    "tablet" -> "Tablette"
    "tv" -> "TV"
    else -> t
}

/** Écran plein : liste des appareils nouvellement détectés. */
@Composable
private fun NewDevicesScreen(
    devices: List<Device>,
    onDeviceClick: (Device) -> Unit
) {
    Column(Modifier.fillMaxSize()) {
        Text(
            "${devices.size} nouveaux appareils détectés lors du dernier scan",
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
                        shape = MaterialTheme.shapes.large,
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainer
                        )
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            DeviceTypeAvatar(device.type, device.alive)
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(
                                    deviceDisplayName(device, ""),
                                    style = MaterialTheme.typography.titleSmall,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    "${device.type} · ${deviceVendorLabel(device)}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Text(
                                device.ip,
                                style = LocalMonoTextStyle.current,
                                color = MaterialTheme.colorScheme.primary
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
    val bg = if (stale) MaterialTheme.colorScheme.errorContainer
    else MaterialTheme.colorScheme.surfaceContainer
    val fg = if (stale) MaterialTheme.colorScheme.onErrorContainer
    else MaterialTheme.colorScheme.onSurfaceVariant
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = bg)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    if (stale) "Base CVE obsolète (${version ?: "?"})"
                    else result ?: "Base CVE",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = fg
                )
                if (stale) {
                    Text(
                        "Plus de 30 jours : les nouvelles failles ne sont pas couvertes.",
                        style = MaterialTheme.typography.labelSmall,
                        color = fg
                    )
                }
            }
            if (stale) {
                TextButton(onClick = onUpdate) {
                    Text("Mettre à jour", color = fg, fontWeight = FontWeight.Bold)
                }
            } else {
                TextButton(onClick = onDismiss) {
                    Text("OK", color = MaterialTheme.colorScheme.primary)
                }
            }
        }
    }
}

/** Carte appareil : icône type + point de statut, nom, IP mono, fabricant, favori. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DeviceCard(
    device: Device,
    displayName: String,
    isFavorite: Boolean,
    isNew: Boolean,
    isTrusted: Boolean,
    vulns: VulnScanner.DeviceVulns?,
    onClick: () -> Unit,
    onToggleFavorite: () -> Unit,
    onToggleTrust: () -> Unit
) {
    val semantic = LocalScannerColors.current
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(
            containerColor = if (device.isGateway) MaterialTheme.colorScheme.surfaceContainerHigh
            else MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            DeviceTypeAvatar(device.type, device.alive)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = displayName,
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis
                    )
                    if (device.isGateway) {
                        Spacer(Modifier.width(6.dp))
                        GatewayBadge()
                    }
                    if (device.isSelf) {
                        Spacer(Modifier.width(6.dp))
                        SelfBadge()
                    }
                }
                if (displayName != device.ip && device.ip.isNotBlank()) {
                    Text(
                        text = device.ip,
                        style = LocalMonoTextStyle.current,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                if (isNew) {
                    Spacer(Modifier.height(2.dp))
                    NewBadge()
                }
                Text(
                    text = deviceVendorLabel(device),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                if (device.mac.isNotBlank() && device.isRandomizedMac) {
                    Spacer(Modifier.height(2.dp))
                    Pill(
                        text = "MAC privée",
                        bg = semantic.privateMac,
                        fg = MaterialTheme.colorScheme.surface
                    )
                }
                if (device.ports.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    // FlowRow : les pastilles de ports passent à la ligne au lieu
                    // de déborder hors écran en mode « ports élargi » (jusqu'à 52).
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        device.ports.sorted().forEach { p ->
                            Pill(
                                text = ":$p",
                                bg = semantic.portOpen,
                                fg = onColorFor(semantic.portOpen)
                            )
                        }
                    }
                }
                if (device.defaultCred != null) {
                    Spacer(Modifier.height(2.dp))
                    Pill(
                        text = "🔑 Credential par défaut : ${device.defaultCred}",
                        bg = semantic.riskCritical,
                        fg = onColorFor(semantic.riskCritical)
                    )
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                IconButton(onClick = onToggleFavorite) {
                    Icon(
                        if (isFavorite) Icons.Filled.Star else Icons.Outlined.Star,
                        contentDescription = if (isFavorite) "Retirer des favoris" else "Ajouter aux favoris",
                        tint = if (isFavorite) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                IconButton(
                    onClick = onToggleTrust,
                    modifier = Modifier.semantics {
                        contentDescription =
                            if (isTrusted) "Retirer de la confiance" else "Marquer comme de confiance"
                    }
                ) {
                    Icon(
                        if (isTrusted) Icons.Filled.CheckCircle else Icons.Filled.Add,
                        contentDescription = null,
                        tint = if (isTrusted) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (!device.alive) {
                    Text(
                        "hors-ligne",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
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

/** Avatar de type : icône Material monochrome (ou emoji de repli) + point de statut. */
@Composable
private fun DeviceTypeAvatar(type: String, alive: Boolean) {
    val semantic = LocalScannerColors.current
    Box(Modifier.size(44.dp)) {
        Box(
            Modifier
                .matchParentSize()
                .background(MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.shapes.medium),
            contentAlignment = Alignment.Center
        ) {
            val icon = deviceTypeIcon(type)
            if (icon != null) {
                Icon(
                    icon,
                    contentDescription = type,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(24.dp)
                )
            } else {
                Text(DeviceType.icon(type), style = MaterialTheme.typography.titleMedium)
            }
        }
        Box(
            Modifier
                .align(Alignment.BottomEnd)
                .size(12.dp)
                .background(
                    if (alive) semantic.online else semantic.offline,
                    CircleShape
                )
                .border(2.dp, MaterialTheme.colorScheme.surface, CircleShape)
        )
    }
}

/** Petit point de statut (en ligne / hors-ligne). */
@Composable
private fun StatusDot(alive: Boolean) {
    val semantic = LocalScannerColors.current
    Box(
        Modifier
            .size(8.dp)
            .background(if (alive) semantic.online else semantic.offline, CircleShape)
    )
}

/** Pastille générique (badge/chip), texte contrasté sur fond coloré. */
@Composable
private fun Pill(text: String, bg: Color, fg: Color) {
    Box(
        modifier = Modifier
            .background(bg, MaterialTheme.shapes.small)
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(
            text,
            style = MaterialTheme.typography.labelSmall,
            color = fg,
            fontWeight = FontWeight.Bold
        )
    }
}

/** Badge vulnérabilité : nombre de CVE + niveau, couleur sémantique de risque. */
@Composable
private fun VulnBadge(v: VulnScanner.DeviceVulns) {
    val semantic = LocalScannerColors.current
    val bg = semantic.riskColor(v.label)
    val fg = onColorFor(bg)
    Pill("${v.total} CVE · ${v.label}", bg, fg)
}

@Composable
private fun GatewayBadge() {
    val semantic = LocalScannerColors.current
    Pill("Passerelle", semantic.gateway, MaterialTheme.colorScheme.onPrimary)
}

@Composable
private fun SelfBadge() {
    val semantic = LocalScannerColors.current
    Pill("Moi", semantic.self, MaterialTheme.colorScheme.onTertiary)
}

@Composable
private fun NewBadge() {
    val semantic = LocalScannerColors.current
    Pill("Nouveau", semantic.newDevice, onColorFor(semantic.newDevice))
}

/**
 * Fiche appareil plein écran : sections titrées, scroll, actions rapides.
 * Remplace l'ancien AlertDialog (trop chargé).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DeviceDetailScreen(
    device: Device,
    store: DeviceStore,
    isNew: Boolean,
    isTrusted: Boolean,
    vulns: VulnScanner.DeviceVulns?,
    onDismiss: () -> Unit,
    onSaved: () -> Unit,
    onToggleTrust: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val clipboard = LocalClipboardManager.current
    val key = ScanHistory.identityKey(device)
    // Historique de présence chargé hors thread UI (le fichier peut être gros) :
    // la section « Présence » apparaît quand la valeur arrive.
    var presenceTimestamps by remember(key) { mutableStateOf<List<Long>>(emptyList()) }
    LaunchedEffect(key) {
        presenceTimestamps = withContext(Dispatchers.IO) {
            runCatching { PresenceHistoryStore(context).load()[key] ?: emptyList() }
                .getOrDefault(emptyList())
        }
    }
    var customName by remember { mutableStateOf(store.customName(key)) }
    var isFav by remember { mutableStateOf(store.isFavorite(key)) }
    val wolAvailable = device.mac.isNotBlank()
    val name = deviceDisplayName(device, store.customName(key))
    val hasWeb = device.ports.any { it == 80 || it == 443 || it == 8080 }

    // Scan complet des ports (1-65535) à la demande : découvre les services des
    // conteneurs Docker en mode bridge (ports publiés sur l'IP de l'hôte, hors
    // des listes prédéfinies). Résultats fusionnés avec les ports déjà connus.
    var deepPorts by remember(device.ip) { mutableStateOf<List<Int>?>(null) }
    var deepScanning by remember(device.ip) { mutableStateOf(false) }
    var deepProgress by remember(device.ip) { mutableStateOf(0) }
    val openPorts = remember(device.ports, deepPorts) {
        (device.ports + (deepPorts ?: emptyList())).distinct().sorted()
    }

    // Bouton/geste retour système : sauvegarde le nom personnalisé saisi et
    // revient à la liste (comme le bouton « ← Retour »), au lieu de quitter l'app.
    BackHandler {
        store.setCustomName(key, customName)
        onSaved()
        onDismiss()
    }

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
                },
                actions = {
                    IconButton(onClick = {
                        isFav = !isFav
                        store.setFavorite(key, isFav)
                        onSaved()
                    }) {
                        Icon(
                            if (isFav) Icons.Filled.Star else Icons.Outlined.Star,
                            contentDescription = "Favori",
                            tint = if (isFav) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(
                        onClick = onToggleTrust,
                        modifier = Modifier.semantics {
                            contentDescription =
                                if (isTrusted) "Retirer de la confiance" else "Marquer comme de confiance"
                        }
                    ) {
                        Icon(
                            if (isTrusted) Icons.Filled.CheckCircle else Icons.Filled.Add,
                            contentDescription = null,
                            tint = if (isTrusted) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurfaceVariant
                        )
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
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // --- Actions rapides ---
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilledTonalButton(onClick = {
                    scope.launch {
                        val (ok, ms) = ping(device.ip)
                        snackbar.showSnackbar(
                            if (ok) "Réponse de ${device.ip}" + (ms?.let { " en ${it} ms" } ?: "")
                            else "Pas de réponse de ${device.ip}"
                        )
                    }
                }) { Text("Ping") }
                if (wolAvailable) {
                    FilledTonalButton(onClick = {
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
                    }) { Text("Réveiller") }
                }
                if (hasWeb) {
                    FilledTonalButton(onClick = {
                        context.startActivity(
                            Intent(Intent.ACTION_VIEW, Uri.parse(deviceWebUrl(device)))
                        )
                    }) { Text("Ouvrir web") }
                }
                FilledTonalButton(onClick = {
                    clipboard.setText(AnnotatedString(device.ip))
                    scope.launch { snackbar.showSnackbar("IP copiée : ${device.ip}") }
                }) { Text("Copier IP") }
                if (device.mac.isNotBlank()) {
                    FilledTonalButton(onClick = {
                        clipboard.setText(AnnotatedString(device.mac))
                        scope.launch { snackbar.showSnackbar("MAC copiée : ${device.mac}") }
                    }) { Text("Copier MAC") }
                }
                // Scan complet des 65535 ports (Docker bridge / services sur
                // ports non standard). Désactivé pendant l'exécution (progression).
                FilledTonalButton(
                    onClick = {
                        deepScanning = true
                        deepProgress = 0
                        scope.launch {
                            val found = withContext(Dispatchers.IO) {
                                PortScanner.scanAllPorts(device.ip) { d, t ->
                                    deepProgress = if (t == 0) 0 else d * 100 / t
                                }
                            }
                            deepPorts = found
                            deepScanning = false
                            val extra = found.filterNot { it in device.ports }
                            snackbar.showSnackbar(
                                when {
                                    found.isEmpty() -> "Scan complet : aucun port ouvert"
                                    extra.isEmpty() -> "Scan complet : ${found.size} port(s), rien de nouveau"
                                    else -> "Scan complet : ${extra.size} nouveau(x) port(s) trouvé(s)"
                                }
                            )
                        }
                    },
                    enabled = !deepScanning
                ) {
                    Text(if (deepScanning) "Scan… $deepProgress%" else "Scan complet des ports")
                }
            }

            // --- Identité ---
            SectionCard("Identité") {
                if (isNew) {
                    Text(
                        "Nouveau sur le réseau",
                        style = MaterialTheme.typography.bodySmall,
                        color = LocalScannerColors.current.newDevice,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(4.dp))
                }
                InfoRow("IP", device.ip, mono = true)
                InfoRow("MAC", device.mac.ifBlank { "non disponible" }, mono = true)
                InfoRow("Fabricant", deviceVendorLabel(device))
                InfoRow("Type", "${DeviceType.icon(device.type)} ${device.type}")
                if (device.model.isNotBlank()) InfoRow("Modèle", device.model)
                if (device.product.isNotBlank() && device.product != device.model)
                    InfoRow("Produit", device.product)
                if (device.os.isNotBlank()) InfoRow("Système", device.os)
                if (device.hostname.isNotBlank()) InfoRow("Nom réseau", device.hostname)
                device.latencyMs?.let { InfoRow("Latence", "$it ms", mono = true) }
                device.ttl?.let { InfoRow("TTL", "$it", mono = true) }
                InfoRow("Statut", if (device.alive) "En ligne" else "Vu récemment (ARP)")
                if (device.isSelf) {
                    Spacer(Modifier.height(4.dp))
                    SelfBadge()
                }
            }

            // --- Présence (historique) ---
            if (presenceTimestamps.isNotEmpty()) {
                SectionCard("Présence") {
                    InfoRow("Vu", PresenceHistory.lastSeen(presenceTimestamps))
                    InfoRow("Apparitions", "${presenceTimestamps.size}")
                }
            }

            // --- UPnP ---
            device.upnp?.let { u ->
                if (u.friendlyName.isNotBlank() || u.manufacturer.isNotBlank() ||
                    u.modelName.isNotBlank() || u.modelDescription.isNotBlank() ||
                    u.server.isNotBlank()
                ) {
                    SectionCard("UPnP") {
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
                SectionCard("Bannière") {
                    Text(
                        device.banner,
                        style = LocalMonoTextStyle.current
                    )
                }
            }

            // --- Services ouverts (ports du scan + éventuel scan complet) ---
            if (openPorts.isNotEmpty()) {
                SectionCard("Services ouverts") {
                    val webCount = openPorts.count { PortScanner.isWebPort(it) }
                    if (webCount > 0) {
                        Text(
                            "🌐 $webCount site(s) web détecté(s) — appuie pour ouvrir",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(Modifier.height(4.dp))
                    }
                    openPorts.forEach { port ->
                        val fromDeep = port !in device.ports
                        val url = PortScanner.webUrl(device.ip, port)
                        val rowMod = Modifier
                            .fillMaxWidth()
                            .then(
                                if (url != null) Modifier.clickable {
                                    runCatching {
                                        context.startActivity(
                                            Intent(Intent.ACTION_VIEW, Uri.parse(url))
                                        )
                                    }
                                } else Modifier
                            )
                            .padding(vertical = 3.dp)
                        Row(rowMod, verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                PortScanner.serviceName(port),
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                                modifier = Modifier.width(120.dp)
                            )
                            Text(
                                "port $port",
                                style = LocalMonoTextStyle.current,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            if (url != null) {
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    "🌐 site web",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.primary,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                            if (fromDeep) {
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    "• scan complet",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }

            // --- SNMP ---
            if (!device.snmpName.isNullOrBlank() || !device.snmpDescr.isNullOrBlank()) {
                SectionCard("SNMP") {
                    device.snmpName?.takeIf { it.isNotBlank() }?.let { InfoRow("System Name", it) }
                    device.snmpDescr?.takeIf { it.isNotBlank() }?.let { InfoRow("Description", it) }
                    device.snmpLocation?.takeIf { it.isNotBlank() }?.let { InfoRow("Location", it) }
                    device.snmpUptime?.let { InfoRow("Uptime", SnmpScanner.formatUptime(it)) }
                }
            }

            // --- Credentials par défaut ---
            device.defaultCred?.let { cred ->
                SectionCard("🔑 Credentials par défaut") {
                    Text(
                        "Combo trouvé : $cred",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = LocalScannerColors.current.riskCritical
                    )
                    Spacer(Modifier.height(8.dp))
                    FilledTonalButton(onClick = {
                        context.startActivity(
                            Intent(Intent.ACTION_VIEW, Uri.parse(deviceWebUrl(device)))
                        )
                    }) { Text("🔗 Ouvrir") }
                    Text(
                        "⚠️ Change immédiatement ce mot de passe.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }

            // --- Vulnérabilités ---
            vulns?.let { v ->
                if (!v.isEmpty) {
                    SectionCard("Vulnérabilités") { VulnSection(v) }
                } else if (v.services.isNotEmpty()) {
                    SectionCard("Vulnérabilités") {
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
                SectionCard("Partages SMB") { SmbSection(device.smbShares) }
            }

            // --- Personnalisation ---
            SectionCard("Nom personnalisé") {
                OutlinedTextField(
                    value = customName,
                    onValueChange = { customName = it },
                    label = { Text("Nom personnalisé") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "S'applique immédiatement. Ce nom reste stocké localement.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
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
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
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
private fun InfoRow(label: String, value: String, mono: Boolean = false) {
    Row(Modifier.padding(vertical = 4.dp)) {
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

/** Section partages SMB (dossiers partagés, y compris cachés). */
@Composable
private fun SmbSection(shares: List<SmbShareScanner.SmbShare>) {
    val accessible = shares.count { it.accessible }
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Partages SMB", style = MaterialTheme.typography.labelMedium)
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
                    if (share.accessible) "●" else "🔒",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (share.accessible) LocalScannerColors.current.online
                    else MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    share.name,
                    style = LocalMonoTextStyle.current,
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
    val semantic = LocalScannerColors.current
    val scoreColor = semantic.riskColor(v.label)
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Vulnérabilités", style = MaterialTheme.typography.labelMedium)
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
                    style = LocalMonoTextStyle.current,
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

@Composable
private fun sevColor(sev: String): Color {
    val semantic = LocalScannerColors.current
    return when (sev) {
        "CRITICAL" -> semantic.riskCritical
        "HIGH" -> semantic.riskHigh
        "MEDIUM" -> semantic.riskModerate
        "LOW" -> semantic.riskLow
        else -> semantic.offline
    }
}

// --- Construction de la liste (recherche / tri / filtres / regroupement) ---

private fun buildDisplayList(
    devices: List<Device>,
    deviceStore: DeviceStore,
    query: String,
    sortMode: SortMode,
    filterType: String?,
    onlineOnly: Boolean,
    groupByType: Boolean
): List<DeviceListItem> {
    val q = query.trim().lowercase()
    val filtered = devices.filter { d ->
        (filterType == null || d.type == filterType) &&
            (!onlineOnly || d.alive) &&
            (q.isEmpty() || deviceMatches(d, deviceStore, q))
    }
    val sorted = sortDevices(filtered, deviceStore, sortMode)
    return if (groupByType) groupByType(sorted) else sorted.map { DeviceListItem.Row(it) }
}

private fun deviceMatches(d: Device, store: DeviceStore, q: String): Boolean {
    val name = deviceDisplayName(d, store.customName(ScanHistory.identityKey(d)))
    return d.ip.contains(q, true) ||
        name.contains(q, true) ||
        d.vendor.contains(q, true) ||
        d.model.contains(q, true) ||
        d.product.contains(q, true) ||
        d.mac.contains(q, true)
}

private fun sortDevices(list: List<Device>, store: DeviceStore, mode: SortMode): List<Device> {
    val nameOf: (Device) -> String = {
        deviceDisplayName(it, store.customName(ScanHistory.identityKey(it)))
    }
    val ipOf: (Device) -> Long = {
        runCatching { NetworkScanner.ipToInt(it.ip) }.getOrDefault(0L)
    }
    val comparator = when (mode) {
        SortMode.ONLINE -> compareByDescending<Device> { it.alive }.thenBy { ipOf(it) }
        SortMode.IP -> compareBy { ipOf(it) }
        SortMode.TYPE -> compareBy<Device> { it.type }.thenBy { nameOf(it).lowercase() }
        SortMode.NAME -> compareBy<Device> { nameOf(it).lowercase() }.thenBy { ipOf(it) }
    }
    return list.sortedWith(
        compareByDescending<Device> { store.isFavorite(ScanHistory.identityKey(it)) }
            .then(comparator)
    )
}

private fun groupByType(sorted: List<Device>): List<DeviceListItem> {
    val result = mutableListOf<DeviceListItem>()
    var lastType: String? = null
    sorted.forEach { d ->
        if (d.type != lastType) {
            result.add(DeviceListItem.Header(d.type))
            lastType = d.type
        }
        result.add(DeviceListItem.Row(d))
    }
    return result
}

/** Libellé du niveau de risque le plus élevé présent (null si aucun). */
private fun highestRiskLabel(vulnsByIp: Map<String, VulnScanner.DeviceVulns>): String? {
    val order = listOf("Critique", "Élevé", "Modéré", "Faible", "Aucune")
    val present = vulnsByIp.values.filter { !it.isEmpty }.map { it.label }.toSet()
    return order.firstOrNull { it in present }
}

/**
 * URL web d'un appareil, en tenant compte du port réellement ouvert :
 * 443/8443 → https, sinon http ; le port non standard (8080/8443) est inclus
 * dans l'URL. Évite d'ouvrir http://ip (port 80) pour un appareil dont seul
 * 8080 est exposé.
 */
private fun deviceWebUrl(device: Device): String {
    val port = when {
        443 in device.ports -> 443
        80 in device.ports -> 80
        8443 in device.ports -> 8443
        8080 in device.ports -> 8080
        else -> 80
    }
    val scheme = if (port == 443 || port == 8443) "https" else "http"
    val host = if (port == 80 || port == 443) device.ip else "${device.ip}:$port"
    return "$scheme://$host"
}

/** Ping ICMP (binaire système, comme le moteur) — hors thread UI. */
private suspend fun ping(ip: String): Pair<Boolean, Int?> =
    withContext(Dispatchers.IO) {
        try {
            val p = ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "1", ip)
                .redirectErrorStream(true)
                .start()
            val out = p.inputStream.bufferedReader().use { it.readText() }
            val ok = p.waitFor(3, TimeUnit.SECONDS) && p.exitValue() == 0
            val ms = Regex("time=([0-9.]+) ms").find(out)?.groupValues?.get(1)?.toDoubleOrNull()?.toInt()
            ok to ms
        } catch (e: Exception) {
            false to null
        }
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
    val ssid = runCatching { NetworkInfoProvider.read(context).ssid }.getOrDefault("")
    val data = PdfAuditReport.buildData(
        devices = devices,
        vulnsByIp = vulnsByIp,
        selfIp = selfIp ?: "—",
        networkCidr = cidr,
        ssid = ssid
    )
    val uri = PdfAuditReport.generateAndShareUri(context, data)
    if (uri == null) {
        Toast.makeText(context, "Échec de génération du rapport PDF.", Toast.LENGTH_LONG).show()
        return
    }
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

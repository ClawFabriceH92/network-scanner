package com.fabrice.network.scanner.ui

import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.DeviceType
import com.fabrice.network.scanner.PortScanner
import com.fabrice.network.scanner.ProfileStore
import com.fabrice.network.scanner.ScanPersistence
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Écran « Profils / Lieux de connexion » : liste les réseaux mémorisés (par
 * SSID/passerelle) et permet de consulter l'instantané des appareils de chacun,
 * même hors de ce réseau.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfilesScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val store = remember { ProfileStore(context) }
    var profiles by remember { mutableStateOf<List<ProfileStore.Profile>>(emptyList()) }
    var selected by remember { mutableStateOf<ProfileStore.Profile?>(null) }
    var reloadTick by remember { mutableStateOf(0) }

    LaunchedEffect(reloadTick) {
        profiles = withContext(Dispatchers.IO) {
            runCatching { store.list() }.getOrDefault(emptyList())
        }
    }

    val current = selected
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(current?.name ?: "Profils / Lieux") },
                navigationIcon = {
                    TextButton(onClick = { if (current != null) selected = null else onBack() }) {
                        Text("← Retour")
                    }
                }
            )
        }
    ) { padding ->
        if (current == null) {
            if (profiles.isEmpty()) {
                Column(
                    Modifier.padding(padding).fillMaxSize().padding(24.dp),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        "Aucun profil enregistré pour l'instant.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Chaque scan mémorise automatiquement le réseau courant " +
                            "(Wi-Fi/passerelle) et les appareils qui y sont vus.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.padding(padding).fillMaxSize().padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(profiles, key = { it.id }) { p ->
                        ProfileCard(
                            profile = p,
                            onOpen = { selected = p },
                            onDelete = {
                                store.delete(p.id)
                                reloadTick++
                            }
                        )
                    }
                }
            }
        } else {
            ProfileDetail(store, current, Modifier.padding(padding))
        }
    }
}

@Composable
private fun ProfileCard(
    profile: ProfileStore.Profile,
    onOpen: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable { onOpen() },
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Row(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "📍 ${profile.name}",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(2.dp))
                val subtitle = buildString {
                    append("${profile.deviceCount} appareil(s)")
                    if (profile.gateway.isNotBlank()) append(" · passerelle ${profile.gateway}")
                }
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                val age = System.currentTimeMillis() - profile.lastSeen
                Text(
                    "Vu ${ScanPersistence.ageLabel(age)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(onClick = onDelete) {
                Icon(
                    Icons.Filled.Delete,
                    contentDescription = "Supprimer le profil",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun ProfileDetail(
    store: ProfileStore,
    profile: ProfileStore.Profile,
    modifier: Modifier
) {
    val devices = remember(profile.id) {
        runCatching { store.loadDevices(profile.id) }.getOrDefault(emptyList())
    }
    Column(
        modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        if (profile.ssid.isNotBlank()) Text("Wi-Fi : ${profile.ssid}", style = MaterialTheme.typography.bodyMedium)
        if (profile.gateway.isNotBlank()) Text("Passerelle : ${profile.gateway}", style = MaterialTheme.typography.bodySmall)
        if (profile.networkAddress.isNotBlank()) Text("Réseau : ${profile.networkAddress}", style = MaterialTheme.typography.bodySmall)
        Text(
            "${devices.size} appareil(s) mémorisé(s)",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(4.dp))
        devices.forEach { d ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.medium,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
            ) {
                Column(Modifier.padding(12.dp)) {
                    Text(
                        "${DeviceType.icon(d.type)} ${d.name.ifBlank { d.ip }}",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium
                    )
                    Text(
                        "${d.ip}${if (d.mac.isNotBlank()) " · ${d.mac}" else ""}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (d.vendor.isNotBlank()) {
                        Text(
                            d.vendor,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (d.ports.isNotEmpty()) {
                        Text(
                            "Ports : " + d.ports.joinToString(", ") {
                                ":$it" + (if (PortScanner.isWebPort(it)) " 🌐" else "")
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }
    }
}

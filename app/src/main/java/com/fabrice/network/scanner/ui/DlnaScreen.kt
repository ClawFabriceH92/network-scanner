package com.fabrice.network.scanner.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.layout.Spacer
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.DlnaBrowser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Écran « Médias DLNA » : découvre les serveurs multimédia du réseau et permet
 * de parcourir leurs dossiers/fichiers. Un fichier s'ouvre dans le lecteur
 * externe (VLC…) via son URL.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DlnaScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var servers by remember { mutableStateOf<List<DlnaBrowser.Server>>(emptyList()) }
    var server by remember { mutableStateOf<DlnaBrowser.Server?>(null) }
    // Pile de navigation : (objectId, titre).
    val stack = remember { mutableStateListOf<Pair<String, String>>() }
    var entries by remember { mutableStateOf<List<DlnaBrowser.Entry>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }

    // Découverte au chargement.
    LaunchedEffect(Unit) {
        loading = true
        servers = withContext(Dispatchers.IO) {
            runCatching { DlnaBrowser.discover() }.getOrDefault(emptyList())
        }
        loading = false
    }

    fun openContainer(srv: DlnaBrowser.Server, objectId: String, title: String) {
        scope.launch {
            loading = true
            entries = withContext(Dispatchers.IO) {
                runCatching { DlnaBrowser.browse(srv.controlUrl, objectId) }.getOrDefault(emptyList())
            }
            loading = false
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(server?.let { stack.lastOrNull()?.second ?: it.name } ?: "Médias DLNA") },
                navigationIcon = {
                    TextButton(onClick = {
                        when {
                            server != null && stack.size > 1 -> {
                                stack.removeAt(stack.size - 1)
                                openContainer(server!!, stack.last().first, stack.last().second)
                            }
                            server != null -> { server = null; stack.clear(); entries = emptyList() }
                            else -> onBack()
                        }
                    }) { Text("← Retour") }
                }
            )
        }
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize().padding(12.dp)) {
            if (loading) {
                Column(
                    Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(8.dp))
                    Text("Recherche…", style = MaterialTheme.typography.bodySmall)
                }
                return@Column
            }
            if (server == null) {
                if (servers.isEmpty()) {
                    Text(
                        "Aucun serveur DLNA trouvé sur le réseau.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                } else {
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(servers) { s ->
                            RowCard("🖥️ ${s.name}") {
                                server = s
                                stack.clear()
                                stack.add("0" to s.name)
                                openContainer(s, "0", s.name)
                            }
                        }
                    }
                }
            } else {
                if (entries.isEmpty()) {
                    Text("(vide)", style = MaterialTheme.typography.bodySmall)
                } else {
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        items(entries) { e ->
                            if (e.isContainer) {
                                RowCard("📁 ${e.title}") {
                                    stack.add(e.id to e.title)
                                    openContainer(server!!, e.id, e.title)
                                }
                            } else {
                                RowCard("🎵 ${e.title}") {
                                    if (e.url.isNotBlank()) {
                                        runCatching {
                                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(e.url)))
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
}

@Composable
private fun RowCard(label: String, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable { onClick() },
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(14.dp)
        )
    }
}

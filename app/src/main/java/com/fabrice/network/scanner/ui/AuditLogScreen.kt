package com.fabrice.network.scanner.ui

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.fabrice.network.scanner.AuditLog
import com.fabrice.network.scanner.AuditLogStore
import com.fabrice.network.scanner.BuildConfig
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Timeline d'audit (v1.9.3) : journal horodaté des événements du scan
 * (« X apparu », « X absent », « Scan terminé : … »). Liste chronologique
 * (plus récent en premier) + copier / partager (export texte).
 */
@Composable
fun AuditLogScreen() {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val store = remember { AuditLogStore(context) }
    // Chargé hors thread UI (jusqu'à 500 entrées JSON à parser) → pas de jank
    // à l'ouverture de l'écran.
    var events by remember { mutableStateOf<List<AuditLog.Event>>(emptyList()) }
    LaunchedEffect(Unit) {
        events = withContext(Dispatchers.IO) { store.load() }
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.End
        ) {
            TextButton(onClick = { clipboard.setText(AnnotatedString(exportText(events))) }) {
                Text("📋 Copier")
            }
            TextButton(onClick = { shareAudit(context, events) }) {
                Text("📤 Partager")
            }
            TextButton(
                onClick = {
                    store.clear()
                    events = emptyList()
                },
                enabled = events.isNotEmpty()
            ) {
                Text("🗑 Effacer")
            }
        }

        if (events.isEmpty()) {
            Text(
                "Aucun événement enregistré.\nLance un scan pour alimenter la timeline.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp)
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(
                    start = 12.dp, end = 12.dp, top = 4.dp, bottom = 16.dp
                ),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(events.asReversed(), key = { "${it.ts}-${it.message}" }) { e ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.medium,
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainer
                        )
                    ) {
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                AuditLog.formatTime(e.ts),
                                style = LocalMonoTextStyle.current,
                                color = MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.width(52.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                e.message,
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                }
            }
        }
    }
}

/** Export texte complet (horodatage complet + message). */
private fun exportText(events: List<AuditLog.Event>): String = buildString {
    appendLine("=== Timeline d'audit (${events.size} événements) ===")
    events.forEach { e ->
        appendLine("[${AuditLog.formatFull(e.ts)}] ${e.message}")
    }
}

/** Écrit l'export dans un fichier texte et ouvre le partage (FileProvider). */
private fun shareAudit(context: Context, events: List<AuditLog.Event>) {
    val dir = File(context.filesDir, "exports").apply { mkdirs() }
    val file = File(dir, "audit_reseau_v${BuildConfig.VERSION_NAME}.txt")
    file.writeText(exportText(events))
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, "Partager la timeline"))
}

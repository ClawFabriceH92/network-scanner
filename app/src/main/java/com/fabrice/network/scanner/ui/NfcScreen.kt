package com.fabrice.network.scanner.ui

import android.nfc.NfcAdapter
import android.nfc.Tag
import androidx.compose.foundation.background
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
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.NfcHistoryStore
import com.fabrice.network.scanner.NfcReader
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Écran NFC (v1.9.0) : lecteur au premier plan (pas de foreground service).
 * Affiche l'UID, les technologies et le contenu NDEF de chaque tag lu, plus un
 * historique local (dédup par UID). L'app doit être ouverte sur cet écran.
 */
@Composable
fun NfcScreen() {
    val context = LocalContext.current
    val activity = remember { context.findActivity() }
    val scope = rememberCoroutineScope()

    val adapter = remember { NfcAdapter.getDefaultAdapter(context) }
    val nfcSupported = adapter != null
    var nfcEnabled by remember { mutableStateOf(adapter?.isEnabled == true) }
    var entries by remember { mutableStateOf(NfcHistoryStore.all(context)) }
    var current by remember { mutableStateOf<NfcReader.NfcLogEntry?>(null) }

    // Active le mode lecteur au premier plan tant que l'écran est affiché.
    DisposableEffect(activity) {
        val act = activity
        if (act != null && adapter != null) {
            adapter.enableReaderMode(
                act,
                { tag: Tag ->
                    scope.launch {
                        val entry = withContext(Dispatchers.IO) {
                            val e = NfcReader.buildEntry(tag)
                            NfcHistoryStore.record(context, e)
                            e
                        }
                        entries = NfcHistoryStore.all(context)
                        current = entry
                        nfcEnabled = adapter.isEnabled
                    }
                },
                NfcAdapter.FLAG_READER_NFC_A or
                    NfcAdapter.FLAG_READER_NFC_B or
                    NfcAdapter.FLAG_READER_NFC_F or
                    NfcAdapter.FLAG_READER_NFC_V or
                    NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                null
            )
        }
        onDispose {
            if (act != null && adapter != null) runCatching { adapter.disableReaderMode(act) }
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item(key = "reader") {
                val statusText = when {
                    !nfcSupported -> "📴 NFC non supporté sur cet appareil"
                    !nfcEnabled -> "📴 NFC désactivé — active-le dans les réglages"
                    else -> "Lecteur actif 🟢"
                }
                val statusColor = when {
                    !nfcSupported || !nfcEnabled -> MaterialTheme.colorScheme.error
                    else -> MaterialTheme.colorScheme.primary
                }
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
                ) {
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text("📱", style = MaterialTheme.typography.displayMedium)
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Touche un tag NFC",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            statusText,
                            style = MaterialTheme.typography.bodyMedium,
                            color = statusColor,
                            fontWeight = FontWeight.Medium
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "L'app doit rester ouverte sur cet écran. Android ne donne pas d'historique " +
                                "système des tags, et les paiements NFC sont invisibles aux apps : seuls les " +
                                "tags lus ici sont enregistrés.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }

            current?.let { tag ->
                item(key = "current") {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.large,
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            Text(
                                "Tag lu à l'instant",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                            Spacer(Modifier.height(4.dp))
                            NfcTagContent(tag.uid, tag.techs, tag.payload)
                        }
                    }
                }
            }

            item(key = "header") {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Historique (${entries.size})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.weight(1f)
                    )
                    if (entries.isNotEmpty()) {
                        TextButton(onClick = {
                            NfcHistoryStore.clear(context)
                            entries = emptyList()
                        }) { Text("🗑 Effacer l'historique") }
                    }
                }
            }

            if (entries.isEmpty()) {
                item(key = "empty") {
                    Text(
                        "Aucun tag lu pour l'instant.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 8.dp)
                    )
                }
            } else {
                items(entries, key = { it.uid + it.lastTs }) { entry ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.medium,
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
                    ) {
                        Column(Modifier.padding(12.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    entry.uid,
                                    style = LocalMonoTextStyle.current,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.weight(1f)
                                )
                                Text(
                                    "${formatTs(entry.lastTs)} · ${entry.views}×",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            NfcTagContent(entry.uid, entry.techs, entry.payload)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun NfcTagContent(uid: String, techs: List<String>, payload: String?) {
    Column {
        if (techs.isNotEmpty()) {
            Text(
                techs.joinToString(", "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        payload?.let {
            Spacer(Modifier.height(2.dp))
            Text(
                "NDEF : $it",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }
}

private fun formatTs(ts: Long): String =
    SimpleDateFormat("dd/MM HH:mm", Locale.FRENCH).format(Date(ts))

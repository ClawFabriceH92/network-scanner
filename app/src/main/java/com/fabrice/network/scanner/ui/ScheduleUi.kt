package com.fabrice.network.scanner.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.ScheduleStore
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle

/** Jours proposés (bit = 1 shl (Calendar.DAY_OF_WEEK - 1), dimanche = bit 0). */
private val DAY_OPTIONS = listOf(
    "Lun" to (1 shl 1),
    "Mar" to (1 shl 2),
    "Mer" to (1 shl 3),
    "Jeu" to (1 shl 4),
    "Ven" to (1 shl 5),
    "Sam" to (1 shl 6),
    "Dim" to (1 shl 0)
)

/** Libellé lisible des jours programmés (ou « Tous les jours »). */
internal fun daysLabel(days: Int): String {
    if (days and 127 == 127) return "Tous les jours"
    val labels = DAY_OPTIONS.filter { days and it.second != 0 }.map { it.first }
    return if (labels.isEmpty()) "Aucun jour" else labels.joinToString(", ")
}

/** Formate des minutes depuis minuit en « HH:MM ». */
internal fun formatHm(minutes: Int): String = "%02d:%02d".format(minutes / 60, minutes % 60)

/**
 * Carte « Blocage programmé » (v1.9.3) : liste des planifications par MAC +
 * bouton ajouter (dialog heures + jours). Exécutée à la fin de chaque scan et
 * dans le worker de surveillance. ⚠️ API box requise (Freebox OK, SFR non supporté).
 */
@Composable
fun ScheduleSection() {
    val context = LocalContext.current
    var schedules by remember { mutableStateOf(ScheduleStore.load(context)) }
    var adding by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf<String?>(null) }

    Card(
        Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "⏱️ Blocage programmé",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f)
                )
                TextButton(onClick = { adding = true }) { Text("➕ Ajouter") }
            }
            Text(
                "Blocage/déblocage automatique d'un appareil à des horaires définis, via l'API de la box " +
                    "(Freebox OK, SFR non supporté).",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(8.dp))

            if (schedules.isEmpty()) {
                Text(
                    "Aucune planification.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                schedules.forEach { s ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(s.mac, style = LocalMonoTextStyle.current, fontWeight = FontWeight.Bold)
                            Text(
                                "${formatHm(s.startMinutes)} → ${formatHm(s.endMinutes)} · ${daysLabel(s.days)}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = s.active,
                            onCheckedChange = {
                                schedules = ScheduleStore.toggle(schedules, s.mac)
                                ScheduleStore.save(context, schedules)
                            }
                        )
                        TextButton(onClick = { confirmDelete = s.mac }) { Text("🗑") }
                    }
                }
            }
        }
    }

    if (adding) {
        ScheduleDialog(
            onDismiss = { adding = false },
            onConfirm = { s ->
                schedules = ScheduleStore.add(schedules, s)
                ScheduleStore.save(context, schedules)
                adding = false
            }
        )
    }

    confirmDelete?.let { mac ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text("Supprimer la planification ?") },
            text = { Text("Le blocage programmé de $mac sera retiré.") },
            confirmButton = {
                TextButton(onClick = {
                    schedules = ScheduleStore.remove(schedules, mac)
                    ScheduleStore.save(context, schedules)
                    confirmDelete = null
                }) { Text("Supprimer") }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = null }) { Text("Annuler") }
            }
        )
    }
}

/** Dialog « Planifier le blocage » : MAC + heures (numériques) + jours (chips). */
@Composable
private fun ScheduleDialog(
    onDismiss: () -> Unit,
    onConfirm: (ScheduleStore.Schedule) -> Unit
) {
    var mac by remember { mutableStateOf("") }
    var startH by remember { mutableStateOf("22") }
    var startM by remember { mutableStateOf("00") }
    var endH by remember { mutableStateOf("07") }
    var endM by remember { mutableStateOf("00") }
    var days by remember { mutableStateOf(127) }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Planifier le blocage") },
        text = {
            Column(
                Modifier
                    .verticalScroll(rememberScrollState())
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = mac,
                    onValueChange = { mac = it },
                    label = { Text("Adresse MAC") },
                    placeholder = { Text("aa:bb:cc:dd:ee:ff") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                HourFields("Début", startH, { startH = it }, startM, { startM = it })
                HourFields("Fin", endH, { endH = it }, endM, { endM = it })
                Text(
                    "Jours",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    DAY_OPTIONS.forEach { (label, bit) ->
                        FilterChip(
                            selected = days and bit != 0,
                            onClick = { days = days xor bit },
                            label = { Text(label) }
                        )
                    }
                }
                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val sh = startH.toIntOrNull()
                val sm = startM.toIntOrNull()
                val eh = endH.toIntOrNull()
                val em = endM.toIntOrNull()
                when {
                    mac.isBlank() -> error = "Indique une adresse MAC."
                    sh == null || sm == null || eh == null || em == null ->
                        error = "Heures invalides."
                    sh !in 0..23 || sm !in 0..59 || eh !in 0..23 || em !in 0..59 ->
                        error = "Heures hors bornes (0-23 h, 0-59 min)."
                    else -> onConfirm(
                        ScheduleStore.Schedule(
                            mac = mac.trim(),
                            startMinutes = sh * 60 + sm,
                            endMinutes = eh * 60 + em,
                            days = days,
                            active = true
                        )
                    )
                }
            }) { Text("OK") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Annuler") }
        }
    )
}

/** Deux champs numériques (heures : minutes). */
@Composable
private fun HourFields(
    label: String,
    hour: String,
    onHour: (String) -> Unit,
    minute: String,
    onMinute: (String) -> Unit
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(56.dp)
        )
        OutlinedTextField(
            value = hour,
            onValueChange = { onHour(it.filter(Char::isDigit).take(2)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.width(64.dp)
        )
        Text(":", modifier = Modifier.padding(horizontal = 4.dp))
        OutlinedTextField(
            value = minute,
            onValueChange = { onMinute(it.filter(Char::isDigit).take(2)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.width(64.dp)
        )
    }
}

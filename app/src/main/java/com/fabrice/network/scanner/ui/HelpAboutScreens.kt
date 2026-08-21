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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.fabrice.network.scanner.AppLock
import com.fabrice.network.scanner.AppLog
import com.fabrice.network.scanner.BuildConfig
import com.fabrice.network.scanner.CveDatabaseStore
import com.fabrice.network.scanner.CveUpdateManager
import com.fabrice.network.scanner.NewDeviceNotifier
import com.fabrice.network.scanner.SurveillanceScheduler
import com.fabrice.network.scanner.TechOptions
import com.fabrice.network.scanner.UpdateChecker
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle
import java.io.File

/** Écran d'aide : explication du scan, du score, des limites. */
@Composable
fun HelpScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Comprendre le scan", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        HelpCard("Comment ça marche ?") {
            "L'app scanne le réseau Wi-Fi local : ping parallèle pour détecter les " +
                "appareils en ligne, lecture de la table ARP pour les appareils silencieux, " +
                "puis identification (fabricant via la MAC, système via TTL/bannières, " +
                "services via les ports ouverts)."
        }
        HelpCard("Qu'est-ce que le score de risque ?") {
            "Une note de 0 à 100 calculée à partir des vulnérabilités détectées sur les " +
                "services exposés : une CVE critique pèse lourd, une CVE activement exploitée " +
                "ajoute un bonus. 0 = rien trouvé, 100 = plusieurs failles critiques."
        }
        HelpCard("CVE, KEV, CVSS — le jargon") {
            "• CVE : identifiant public d'une vulnérabilité (CVE-2024-1234).\n" +
                "• CVSS : note de gravité de 0 à 10 (9+ = critique).\n" +
                "• KEV : catalogue CISA des vulnérabilités activement exploitées (⚡) — " +
                "c'est le signal le plus important : un attaquant l'utilise en ce moment."
        }
        HelpCard("Les limites (important)") {
            "Le scan est passif : il identifie les versions des services visibles et les " +
                "compare à la base CVE. Il ne teste pas d'exploit, ne nécessite pas " +
                "d'identifiants et ne couvre que les services détectables par bannière " +
                "(HTTP, SSH, FTP, SMTP, mail). Un pare-feu, une version masquée ou une " +
                "application derrière un port non standard peuvent échapper au détecteur."
        }
        HelpCard("Base de vulnérabilités") {
            "Les CVE viennent de NVD (NIST) et du catalogue KEV (CISA) — les mêmes sources " +
                "que CERT-FR. La base est embarquée dans l'app et peut être mise à jour en " +
                "un tap. Si elle date de plus de 30 jours, un avertissement " +
                "s'affiche : une base obsolète rate les nouvelles failles."
        }
        HelpCard("Que faire si un score est élevé ?") {
            "1. Mettre à jour le firmware/logiciel de l'appareil concerné.\n" +
                "2. Désactiver les services inutiles (Telnet, FTP…).\n" +
                "3. Changer les mots de passe par défaut (routeur, NAS, caméras).\n" +
                "4. Vérifier les appareils inconnus sur le réseau — un intrus probable."
        }
        HelpCard("Vie privée") {
            "Tout se passe sur votre téléphone : aucune donnée du réseau n'est envoyée " +
                "à un serveur. Seuls les fabricants MAC inconnus et la mise à jour de la " +
                "base CVE font des requêtes ponctuelles (macvendors.com, GitHub)."
        }
    }
}

/** Écran À propos : version, sources, RGPD, changelog + mise à jour. */
@Composable
fun AboutScreen(
    updateInfo: UpdateChecker.UpdateInfo?,
    updateStatus: String?,
    updateChecking: Boolean,
    updateDownloading: Boolean,
    onCheckUpdate: () -> Unit,
    onDownloadUpdate: () -> Unit,
    onDownloadLatest: () -> Unit = {},
    onOpenTimeline: () -> Unit = {}
) {
    val context = LocalContext.current
    val dbVersion = CveDatabaseStore.version(context) ?: "inconnue"
    val dbAge = CveUpdateManager.ageDays(dbVersion)
    val ageLabel = when {
        dbAge == null -> "—"
        dbAge < 0 -> "à venir ?"
        dbAge == 0L -> "aujourd'hui"
        dbAge == 1L -> "il y a 1 jour"
        else -> "il y a $dbAge jours"
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("À propos", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        InfoCard("Version", BuildConfig.VERSION_NAME)
        InfoCard("Base CVE", "$dbVersion ($ageLabel)")
        Spacer(Modifier.height(4.dp))
        Text("Réglages", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        var alertsEnabled by remember { mutableStateOf(NewDeviceNotifier.isEnabled(context)) }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text("Alertes nouveaux appareils", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "Notification quand un appareil inconnu apparaît sur le réseau.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(
                checked = alertsEnabled,
                onCheckedChange = {
                    alertsEnabled = it
                    NewDeviceNotifier.setEnabled(context, it)
                }
            )
        }
        Spacer(Modifier.height(4.dp))
        Button(onClick = onOpenTimeline, modifier = Modifier.fillMaxWidth()) {
            Text("🕐 Timeline d'audit")
        }
        Spacer(Modifier.height(4.dp))
        LockSection()
        Spacer(Modifier.height(4.dp))
        SurveillanceSection()
        Spacer(Modifier.height(4.dp))
        TechOptionsSection()
        Spacer(Modifier.height(4.dp))
        Text("Mise à jour", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        UpdateSection(
            onDownloadLatest = onDownloadLatest,
            updateInfo = updateInfo,
            updateStatus = updateStatus,
            updateChecking = updateChecking,
            updateDownloading = updateDownloading,
            onCheckUpdate = onCheckUpdate,
            onDownloadUpdate = onDownloadUpdate
        )
        Spacer(Modifier.height(4.dp))
        SupportSection()
        Text("Sources des données", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        HelpCard("NVD (NIST)") {
            "National Vulnerability Database — descriptif et gravité (CVSS) de toutes les CVE."
        }
        HelpCard("CISA KEV") {
            "Known Exploited Vulnerabilities — vulnérabilités activement exploitées, suivies par CERT-FR."
        }
        HelpCard("OUI IEEE") {
            "Base des fabricants par préfixe MAC (39 900+ entrées embarquées)."
        }
        Spacer(Modifier.height(4.dp))
        Text("Données & vie privée", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        HelpCard("RGPD") {
            "Aucune donnée personnelle collectée, aucun compte, aucune télémétrie. " +
                "Les scans, noms personnalisés et favoris restent sur l'appareil. " +
                "L'export CSV est généré localement et partagé uniquement si vous le demandez."
        }
        Spacer(Modifier.height(4.dp))
        Text("Changelog", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        HelpCard("v1.0.0") {
            "Scan de vulnérabilités CERT (CVE + KEV), score de risque, mise à jour de la base en un tap, " +
                "pages Aide et À propos, gestion des erreurs réseau."
        }
        HelpCard("v0.2.x") {
            "Fing complet : ports, WoL, historique, OS, UPnP, test de débit, qualité Wi-Fi, RSSI, " +
                "export CSV, recherche de fabricants."
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "Développé par Fabrice Heuvrard — expert-comptable & développeur Android.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

/** Section « Mise à jour » de l'écran À propos (auto-update GitHub Releases). */
@Composable
private fun UpdateSection(
    updateInfo: UpdateChecker.UpdateInfo?,
    updateStatus: String?,
    updateChecking: Boolean,
    updateDownloading: Boolean,
    onCheckUpdate: () -> Unit,
    onDownloadUpdate: () -> Unit,
    onDownloadLatest: () -> Unit = {}
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onCheckUpdate, enabled = !updateChecking) {
                if (updateChecking) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp,
                        // Contraste sur le fond primary du bouton (sinon invisible).
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Vérification…")
                } else {
                    Text("Vérifier les mises à jour")
                }
            }
            if (updateStatus != null) {
                Text(
                    updateStatus,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (updateInfo != null) {
                Button(onClick = onDownloadUpdate, enabled = !updateDownloading) {
                    if (updateDownloading) Text("Téléchargement…")
                    else Text("Installer v${updateInfo.version}")
                }
            }
            HorizontalDivider()
            // Téléchargement DIRECT de la dernière version (lien stable) — marche
            // même si la vérification n'a rien détecté.
            OutlinedButton(onClick = onDownloadLatest, enabled = !updateDownloading) {
                Text("⬇️ Télécharger la dernière version (APK)")
            }
            Text(
                "Télécharge directement l'APK de la dernière version depuis GitHub, " +
                    "puis lance l'installation.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun HelpCard(title: String, body: () -> String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            Text(body(), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun InfoCard(label: String, value: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh)
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(
                "$label :",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.width(110.dp)
            )
            Text(
                value,
                style = LocalMonoTextStyle.current,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

/** Réglage « Verrouillage de l'app » (PIN 4 chiffres ou empreinte). */
@Composable
private fun LockSection() {
    val context = LocalContext.current
    var lockEnabled by remember { mutableStateOf(AppLock.isEnabled(context)) }
    var showSetup by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text("Verrouillage de l'app", style = MaterialTheme.typography.bodyMedium)
            Text(
                "PIN à 4 chiffres ou empreinte digitale demandé au lancement.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(
            checked = lockEnabled,
            onCheckedChange = { enable ->
                if (enable) showSetup = true
                else {
                    AppLock.disable(context)
                    lockEnabled = false
                }
            }
        )
    }
    if (lockEnabled) {
        TextButton(onClick = { showSetup = true }) { Text("Changer le PIN") }
    }
    if (showSetup) {
        PinSetupDialog(
            onDismiss = { showSetup = false },
            onConfirm = { pin ->
                AppLock.setPin(context, pin)
                lockEnabled = true
                showSetup = false
            }
        )
    }
}

/** Dialogue de configuration du PIN (4 chiffres, jamais stocké en clair). */
@Composable
private fun PinSetupDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Configurer le PIN") },
        text = {
            Column {
                OutlinedTextField(
                    value = pin,
                    onValueChange = { pin = it.filter(Char::isDigit).take(4) },
                    label = { Text("PIN (4 chiffres)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                error?.let {
                    Text(
                        it,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (pin.length != 4) error = "Le PIN doit contenir 4 chiffres."
                else onConfirm(pin)
            }) { Text("OK") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Annuler") }
        }
    )
}

/** Réglage « Surveillance continue » (scan planifié, OFF par défaut). */
@Composable
private fun SurveillanceSection() {
    val context = LocalContext.current
    var enabled by remember { mutableStateOf(SurveillanceScheduler.isEnabled(context)) }
    var interval by remember { mutableStateOf(SurveillanceScheduler.intervalHours(context)) }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text("Surveillance continue", style = MaterialTheme.typography.bodyMedium)
            Text(
                "Scan périodique du réseau en arrière-plan.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(
            checked = enabled,
            onCheckedChange = { e ->
                SurveillanceScheduler.setEnabled(context, e)
                enabled = e
            }
        )
    }
    if (enabled) {
        Text(
            "⚠️ Cette option consomme de la batterie — scans en arrière-plan.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error
        )
        Spacer(Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SurveillanceScheduler.INTERVALS_HOURS.forEach { h ->
                FilterChip(
                    selected = interval == h,
                    onClick = {
                        SurveillanceScheduler.setInterval(context, h)
                        interval = h
                    },
                    label = { Text("${h} h") }
                )
            }
        }
    }
}

/** Réglage « Options techniques » (scan rapide, économie, accessibilité). */
@Composable
private fun TechOptionsSection() {
    val context = LocalContext.current
    var scanFast by remember { mutableStateOf(TechOptions.scanFast(context)) }
    var economy by remember { mutableStateOf(TechOptions.scanEconomy(context)) }
    var large by remember { mutableStateOf(TechOptions.largeText(context)) }

    Text(
        "⚙️ Options techniques",
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold
    )
    ToggleRow(
        title = "Scan rapide (ARP-first)",
        desc = "Ordre optimisé : ARP + découvertes d'abord, ping en parallèle.",
        checked = scanFast,
        onChange = { TechOptions.setScanFast(context, it); scanFast = it }
    )
    ToggleRow(
        title = "Consommation réduite",
        desc = "Réserve SNMP, credentials et partages SMB à l'analyse complète.",
        checked = economy,
        onChange = { TechOptions.setScanEconomy(context, it); economy = it }
    )
    ToggleRow(
        title = "Accessibilité (grands textes)",
        desc = "Augmente la taille des textes et les contrastes.",
        checked = large,
        onChange = { TechOptions.setLargeText(context, it); large = it }
    )
}

/** Ligne de toggle avec titre + description courte. */
@Composable
private fun ToggleRow(title: String, desc: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyMedium)
            Text(
                desc,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

/** Section « Support » : copier / partager les logs de diagnostic. */
@Composable
private fun SupportSection() {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    Text(
        "🔧 Support",
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold
    )
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { clipboard.setText(AnnotatedString(AppLog.dump())) }) {
            Text("📋 Copier les logs")
        }
        Button(onClick = { shareLogs(context) }) {
            Text("📤 Partager les logs")
        }
    }
    Text(
        "Les logs sont conservés en mémoire (500 dernières lignes) et servent au diagnostic.",
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

/** Écrit le dump des logs dans un fichier texte et ouvre le partage (FileProvider). */
private fun shareLogs(context: Context) {
    val dir = File(context.filesDir, "exports").apply { mkdirs() }
    val file = File(dir, "logs_network_scanner_v${BuildConfig.VERSION_NAME}.txt")
    file.writeText(AppLog.dump())
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, "Partager les logs"))
}

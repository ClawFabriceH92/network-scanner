package com.fabrice.network.scanner.ui

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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.BuildConfig
import com.fabrice.network.scanner.CveDatabaseStore
import com.fabrice.network.scanner.CveUpdateManager
import com.fabrice.network.scanner.UpdateChecker
import com.fabrice.network.scanner.ui.theme.LocalMonoTextStyle

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
    onDownloadUpdate: () -> Unit
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
        Text("Mise à jour", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        UpdateSection(
            updateInfo = updateInfo,
            updateStatus = updateStatus,
            updateChecking = updateChecking,
            updateDownloading = updateDownloading,
            onCheckUpdate = onCheckUpdate,
            onDownloadUpdate = onDownloadUpdate
        )
        Spacer(Modifier.height(4.dp))
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
    onDownloadUpdate: () -> Unit
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
                        strokeWidth = 2.dp
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

package com.fabrice.network.scanner.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.graphics.vector.ImageVector
import com.fabrice.network.scanner.Device

/**
 * Helpers d'affichage partagés par les écrans (ergonomie + style).
 * Aucune couleur codée en dur ici : les composants lisent le thème.
 */

/**
 * Nom d'affichage par priorité claire (déterminant pour la findabilité) :
 * nom personnalisé > nom mDNS > hostname > produit/modèle > fabricant > IP.
 * Un appareil n'est jamais réduit à une IP si mieux existe.
 */
fun deviceDisplayName(device: Device, customName: String): String {
    val candidates = listOf(
        customName,
        device.mdnsName,
        device.hostname,
        device.product,
        device.model,
        device.vendor,
        device.ip
    )
    return candidates.firstOrNull { it.isNotBlank() } ?: device.ip
}

/**
 * Icône Material monochrome associée à un type d'appareil. Retourne `null`
 * quand aucune icône de base pertinente n'existe (le composant retombe alors
 * sur `DeviceType.icon`, l'emoji historique, comme repli).
 *
 * La couleur est réservée au statut/risque : ces icônes sont rendues en
 * `onSurfaceVariant` (monochrome), jamais colorées par catégorie.
 */
fun deviceTypeIcon(type: String): ImageVector? = when (type) {
    "Smartphone" -> Icons.Filled.Phone
    "Routeur / Box" -> Icons.Filled.Settings
    "TV / Media" -> Icons.Filled.PlayArrow
    "IoT" -> Icons.Filled.Build
    "Inconnu" -> Icons.Filled.Info
    else -> null
}

/**
 * Libellé du fabricant avec explication des cas « inconnu » — jamais un
 * « Fabricant inconnu » sec et anxiogène :
 * - MAC aléatoire (localement administrée) → « Adresse privée (MAC aléatoire) » ;
 * - MAC absente → « MAC masquée par Android » (limite de la plateforme).
 */
fun deviceVendorLabel(device: Device): String = when {
    device.isRandomizedMac || device.vendor == "Adresse privée" ->
        "Adresse privée (MAC aléatoire)"
    device.mac.isBlank() && device.vendor.isBlank() ->
        "Fabricant inconnu · MAC masquée par Android"
    device.vendor.isNotBlank() -> device.vendor
    else -> "Fabricant inconnu"
}

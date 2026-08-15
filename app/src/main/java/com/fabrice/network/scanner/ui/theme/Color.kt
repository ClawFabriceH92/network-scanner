package com.fabrice.network.scanner.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance

/**
 * Rôles Material 3 de repli (Android 8–11), générés depuis la seed `#2563EB`
 * (bleu technique). Les tons sont fournis explicitement (pas de noir pur en
 * sombre : surfaces gris très foncé, profondeur par élévation tonale).
 *
 * Sur Android 12+, ces schémas sont ignorés au profit du dynamic color
 * (couleurs du fond d'écran système) — voir Theme.kt.
 */

// --- Schéma clair (seed #2563EB) ---
val LightColors = lightColorScheme(
    primary = Color(0xFF2563EB),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFDBE1FF),
    onPrimaryContainer = Color(0xFF00174B),
    inversePrimary = Color(0xFFB3C5FF),
    secondary = Color(0xFF575E71),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFDBE2F9),
    onSecondaryContainer = Color(0xFF141B2C),
    tertiary = Color(0xFF715573),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFFBD7FA),
    onTertiaryContainer = Color(0xFF29132D),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    background = Color(0xFFF8F9FF),
    onBackground = Color(0xFF191C20),
    surface = Color(0xFFF8F9FF),
    onSurface = Color(0xFF191C20),
    surfaceVariant = Color(0xFFE0E2EC),
    onSurfaceVariant = Color(0xFF44474F),
    outline = Color(0xFF74777F),
    outlineVariant = Color(0xFFC4C6D0),
    scrim = Color(0xFF000000),
    inverseSurface = Color(0xFF2E3036),
    inverseOnSurface = Color(0xFFF0F0F4),
    surfaceBright = Color(0xFFF8F9FF),
    surfaceDim = Color(0xFFD8DAE0),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF2F3F9),
    surfaceContainer = Color(0xFFECEEF4),
    surfaceContainerHigh = Color(0xFFE6E8EE),
    surfaceContainerHighest = Color(0xFFE0E2E9)
)

// --- Schéma sombre (seed #2563EB) ---
val DarkColors = darkColorScheme(
    primary = Color(0xFFB3C5FF),
    onPrimary = Color(0xFF003283),
    primaryContainer = Color(0xFF1F4789),
    onPrimaryContainer = Color(0xFFDBE1FF),
    inversePrimary = Color(0xFF2563EB),
    secondary = Color(0xFFBFC6DC),
    onSecondary = Color(0xFF293041),
    secondaryContainer = Color(0xFF404659),
    onSecondaryContainer = Color(0xFFDBE2F9),
    tertiary = Color(0xFFDEBCDC),
    onTertiary = Color(0xFF402843),
    tertiaryContainer = Color(0xFF583E5A),
    onTertiaryContainer = Color(0xFFFBD7FA),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF111318),
    onBackground = Color(0xFFE2E2E7),
    surface = Color(0xFF111318),
    onSurface = Color(0xFFE2E2E7),
    surfaceVariant = Color(0xFF44474F),
    onSurfaceVariant = Color(0xFFC4C6D0),
    outline = Color(0xFF8E9099),
    outlineVariant = Color(0xFF44474F),
    scrim = Color(0xFF000000),
    inverseSurface = Color(0xFFE2E2E7),
    inverseOnSurface = Color(0xFF2E3036),
    surfaceBright = Color(0xFF38393F),
    surfaceDim = Color(0xFF111318),
    surfaceContainerLowest = Color(0xFF0C0E12),
    surfaceContainerLow = Color(0xFF191C20),
    surfaceContainer = Color(0xFF1D2025),
    surfaceContainerHigh = Color(0xFF282B30),
    surfaceContainerHighest = Color(0xFF33363C)
)

/**
 * Couleurs sémantiques (hors rôles M3) : statuts et niveaux de risque.
 * Exposées via `LocalScannerColors` — jamais codées en dur dans les écrans.
 */
data class ScannerSemanticColors(
    // Niveaux de risque (alignés sur VulnScanner.labelForScore)
    val riskNone: Color,
    val riskLow: Color,
    val riskModerate: Color,
    val riskHigh: Color,
    val riskCritical: Color,
    // Statuts
    val online: Color,
    val offline: Color,
    val gateway: Color,
    val self: Color,
    val newDevice: Color,
    val privateMac: Color
)

// Rampe de risque (clair) : vert → rouge
private val RiskNoneLight = Color(0xFF2E7D32)
private val RiskLowLight = Color(0xFF689F38)
private val RiskModerateLight = Color(0xFFF9A825)
private val RiskHighLight = Color(0xFFEF6C00)
private val RiskCriticalLight = Color(0xFFC62828)
private val NewDeviceLight = Color(0xFFF9A825)

// Rampe de risque (sombre) : vert → rouge
private val RiskNoneDark = Color(0xFF66BB6A)
private val RiskLowDark = Color(0xFF9CCC65)
private val RiskModerateDark = Color(0xFFFFCA28)
private val RiskHighDark = Color(0xFFFFA726)
private val RiskCriticalDark = Color(0xFFEF5350)
private val NewDeviceDark = Color(0xFFFFCA28)

/** Instance claire des couleurs sémantiques (statuts liés au schéma courant). */
fun lightSemanticColors(scheme: ColorScheme) = ScannerSemanticColors(
    riskNone = RiskNoneLight,
    riskLow = RiskLowLight,
    riskModerate = RiskModerateLight,
    riskHigh = RiskHighLight,
    riskCritical = RiskCriticalLight,
    online = RiskNoneLight,
    offline = scheme.onSurfaceVariant,
    gateway = scheme.primary,
    self = scheme.tertiary,
    newDevice = NewDeviceLight,
    privateMac = scheme.onSurfaceVariant
)

/** Instance sombre des couleurs sémantiques (statuts liés au schéma courant). */
fun darkSemanticColors(scheme: ColorScheme) = ScannerSemanticColors(
    riskNone = RiskNoneDark,
    riskLow = RiskLowDark,
    riskModerate = RiskModerateDark,
    riskHigh = RiskHighDark,
    riskCritical = RiskCriticalDark,
    online = RiskNoneDark,
    offline = scheme.onSurfaceVariant,
    gateway = scheme.primary,
    self = scheme.tertiary,
    newDevice = NewDeviceDark,
    privateMac = scheme.onSurfaceVariant
)

/** Couleur de risque associée à un libellé (« Aucune »…« Critique »). */
fun ScannerSemanticColors.riskColor(label: String): Color = when (label) {
    "Aucune" -> riskNone
    "Faible" -> riskLow
    "Modéré" -> riskModerate
    "Élevé" -> riskHigh
    "Critique" -> riskCritical
    else -> offline
}

/** Couleur de texte contrastée sur un fond sémantique (noir sur clair, blanc sur sombre). */
fun onColorFor(bg: Color): Color =
    if (bg.luminance() > 0.5f) Color(0xFF1A1A1A) else Color.White

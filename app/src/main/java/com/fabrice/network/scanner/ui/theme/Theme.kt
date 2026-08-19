package com.fabrice.network.scanner.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import com.fabrice.network.scanner.TechOptions

/**
 * Couleurs sémantiques (statut / risque) accessibles partout via
 * `LocalScannerColors.current`. Jamais de hex en dur dans les écrans.
 */
val LocalScannerColors = staticCompositionLocalOf {
    lightSemanticColors(LightColors)
}

/** Style monospace technique partagé (IP / MAC / ports). */
val LocalMonoTextStyle = staticCompositionLocalOf { TechnicalMono }

/**
 * Thème de l'application :
 * - Android 12+ : dynamic color (couleurs du fond d'écran système) ;
 * - Android 8–11 : repli sur les schémas générés depuis la seed `#2563EB` ;
 * - clair/sombre selon le système.
 */
@Composable
fun NetworkScannerTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }
    val semantic = if (darkTheme) darkSemanticColors(colorScheme) else lightSemanticColors(colorScheme)

    // Accessibilité (toggle `a11y_large`) : augmente l'échelle de police globale.
    val appContext = LocalContext.current
    val density = LocalDensity.current
    val scaledDensity = if (TechOptions.largeText(appContext)) {
        Density(density.density, fontScale = density.fontScale * 1.25f)
    } else density

    CompositionLocalProvider(
        LocalDensity provides scaledDensity,
        LocalScannerColors provides semantic,
        LocalMonoTextStyle provides TechnicalMono
    ) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = AppTypography,
            shapes = AppShapes,
            content = content
        )
    }
}

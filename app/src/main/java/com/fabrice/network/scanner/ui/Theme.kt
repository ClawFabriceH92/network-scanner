package com.fabrice.network.scanner.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** Palette du thème bleu nuit + or (clair et sombre). */
object ScannerColors {
    val Navy = Color(0xFF1B3A6B)
    val NavyLight = Color(0xFF2E5A9E)
    val Gold = Color(0xFFC9972B)
    val GoldDark = Color(0xFFE0B54E)
    val Cream = Color(0xFFFAF6EF)
    val SurfaceDark = Color(0xFF121A2B)
    val SurfaceDarkElevated = Color(0xFF1C2842)
}

@Composable
fun NetworkScannerTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) {
        darkColorScheme(
            primary = ScannerColors.GoldDark,
            onPrimary = Color(0xFF1B3A6B),
            secondary = ScannerColors.GoldDark,
            background = ScannerColors.SurfaceDark,
            onBackground = Color(0xFFE8ECF4),
            surface = ScannerColors.SurfaceDarkElevated,
            onSurface = Color(0xFFE8ECF4),
            surfaceVariant = Color(0xFF263252),
            onSurfaceVariant = Color(0xFFA9B4CC),
            error = Color(0xFFEF9A9A)
        )
    } else {
        lightColorScheme(
            primary = ScannerColors.Navy,
            onPrimary = Color.White,
            secondary = ScannerColors.Gold,
            background = ScannerColors.Cream,
            onBackground = Color(0xFF1A1A1A),
            surface = Color.White,
            onSurface = Color(0xFF1A1A1A),
            surfaceVariant = Color(0xFFEDE7DA),
            onSurfaceVariant = Color(0xFF6B6B6B),
            error = Color(0xFFB3261E)
        )
    }
    MaterialTheme(colorScheme = colorScheme, content = content)
}

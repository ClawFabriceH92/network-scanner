package com.fabrice.network.scanner.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * Type scale Material 3 standard (Roboto par défaut) pour toute l'UI.
 * Un `TextStyle` monospace dédié est fourni pour les jetons techniques
 * (IP, MAC, ports, TTL) : chasse fixe = colonnes alignées, comparaison rapide.
 */
val AppTypography = Typography()

/** Style monospace technique (jetons réseau), légère chasse réduite. */
val TechnicalMono = TextStyle(
    fontFamily = FontFamily.Monospace,
    fontSize = 14.sp,
    lineHeight = 20.sp,
    letterSpacing = (-0.2).sp
)

/** Variante pour les chiffres clés (mono, plus lisible). */
val TechnicalMonoBold = TechnicalMono.copy(fontWeight = FontWeight.Bold)

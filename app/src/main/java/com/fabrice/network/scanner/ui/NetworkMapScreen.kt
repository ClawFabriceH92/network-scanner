package com.fabrice.network.scanner.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.fabrice.network.scanner.Device
import com.fabrice.network.scanner.DeviceStore
import com.fabrice.network.scanner.DeviceType
import com.fabrice.network.scanner.ScanHistory
import com.fabrice.network.scanner.VulnScanner
import com.fabrice.network.scanner.ui.theme.LocalScannerColors
import com.fabrice.network.scanner.ui.theme.riskColor
import kotlin.math.cos
import kotlin.math.sin

/**
 * Carte réseau visuelle (v1.9.3) : Canvas Compose pur. La passerelle au centre,
 * les appareils vivants disposés en cercle (rayon proportionnel au nombre),
 * lignes de connexion, nom + icône (emoji) par appareil, couleur selon risque.
 * Défilement horizontal/vertical (la carte peut dépasser l'écran).
 */

/** Position (en px) d'un nœud sur la carte. */
data class MapPosition(val x: Float, val y: Float)

/**
 * Dispose [devices] en cercle autour de (centerX, centerY) à distance [radius].
 * Premier nœud en haut (angle -90°), puis sens horaire, espacement régulier.
 * Pure → testable en JVM.
 */
fun layoutPositions(
    devices: List<Device>,
    centerX: Float,
    centerY: Float,
    radius: Float
): List<MapPosition> {
    val n = devices.size
    if (n == 0) return emptyList()
    return (0 until n).map { i ->
        val angle = -Math.PI / 2.0 + (2.0 * Math.PI * i) / n
        MapPosition(
            (centerX + radius * cos(angle)).toFloat(),
            (centerY + radius * sin(angle)).toFloat()
        )
    }
}

@Composable
fun NetworkMapScreen(
    devices: List<Device>,
    deviceStore: DeviceStore,
    vulnsByIp: Map<String, VulnScanner.DeviceVulns>,
    onBack: () -> Unit,
    onDeviceClick: (Device) -> Unit
) {
    val semantic = LocalScannerColors.current
    val density = LocalDensity.current

    val alive = devices.filter { it.alive && !it.isGateway }
    val gateway = devices.firstOrNull { it.isGateway }
    val offline = devices.filter { !it.alive && !it.isGateway }

    // Rayon proportionnel au nombre d'appareils, borné pour rester lisible.
    val n = alive.size.coerceAtLeast(1)
    val radiusDp = (110 + n * 16).dp
    val canvasDp = (radiusDp.value * 2 + 160).dp
    val canvasPx = with(density) { canvasDp.toPx() }
    val centerPx = canvasPx / 2f
    val radiusPx = with(density) { radiusDp.toPx() }
    val nodeRadiusPx = with(density) { 15.dp.toPx() }
    val gatewayRadiusPx = with(density) { 30.dp.toPx() }
    val nameSizePx = with(density) { 11.dp.toPx() }
    val emojiSizePx = with(density) { 18.dp.toPx() }

    val positions = remember(alive) { layoutPositions(alive, centerPx, centerPx, radiusPx) }

    val lineColor = MaterialTheme.colorScheme.outlineVariant
    val gatewayColor = semantic.gateway
    val onlineColor = semantic.online
    val labelColorArgb = MaterialTheme.colorScheme.onSurface.toArgb()
    val gatewayLabelArgb = MaterialTheme.colorScheme.onSurface.toArgb()

    Column(Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Retour") }
            Text("Carte réseau", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }

        if (alive.isEmpty() && gateway == null) {
            Column(Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Aucun appareil en ligne à afficher.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(8.dp))
                Text("Lance un scan pour construire la carte.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            return
        }

        Box(
            Modifier
                .weight(1f)
                .fillMaxSize()
                .horizontalScroll(rememberScrollState())
                .verticalScroll(rememberScrollState())
        ) {
            Canvas(
                Modifier
                    .size(canvasDp)
                    // Un tap sur un nœud (ou la passerelle) ouvre la fiche appareil.
                    .pointerInput(alive, positions, gateway) {
                        detectTapGestures { tap ->
                            val hitR = nodeRadiusPx * 1.8f
                            val idx = positions.indexOfFirst { p ->
                                val dx = p.x - tap.x
                                val dy = p.y - tap.y
                                dx * dx + dy * dy <= hitR * hitR
                            }
                            if (idx >= 0) {
                                onDeviceClick(alive[idx])
                            } else if (gateway != null) {
                                val dx = centerPx - tap.x
                                val dy = centerPx - tap.y
                                if (dx * dx + dy * dy <= gatewayRadiusPx * gatewayRadiusPx) {
                                    onDeviceClick(gateway)
                                }
                            }
                        }
                    }
            ) {
                // Lignes passerelle → nœuds
                alive.forEachIndexed { i, _ ->
                    drawLine(
                        lineColor,
                        Offset(centerPx, centerPx),
                        Offset(positions[i].x, positions[i].y),
                        strokeWidth = 1.5f
                    )
                }
                // Nœuds appareils (couleur = risque, sinon en ligne)
                alive.forEachIndexed { i, d ->
                    val riskLabel = vulnsByIp[d.ip]?.label
                    val color = if (riskLabel != null) semantic.riskColor(riskLabel) else onlineColor
                    drawCircle(color, nodeRadiusPx, Offset(positions[i].x, positions[i].y))
                }
                // Passerelle au centre
                if (gateway != null) {
                    drawCircle(gatewayColor, gatewayRadiusPx, Offset(centerPx, centerPx))
                }

                // Étiquettes (emoji + nom) via le canvas natif (texte centré)
                drawIntoCanvas { canvas ->
                    val textPaint = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
                        textAlign = android.graphics.Paint.Align.CENTER
                    }
                    alive.forEachIndexed { i, d ->
                        val pos = positions[i]
                        val name = deviceDisplayName(d, deviceStore.customName(ScanHistory.identityKey(d)))
                        val shortName = if (name.length > 16) name.take(15) + "…" else name
                        textPaint.color = labelColorArgb
                        textPaint.textSize = emojiSizePx
                        canvas.nativeCanvas.drawText(
                            DeviceType.icon(d.type),
                            pos.x,
                            pos.y - nodeRadiusPx - 6f,
                            textPaint
                        )
                        textPaint.textSize = nameSizePx
                        canvas.nativeCanvas.drawText(
                            shortName,
                            pos.x,
                            pos.y + nodeRadiusPx + nameSizePx,
                            textPaint
                        )
                    }
                    if (gateway != null) {
                        textPaint.color = gatewayLabelArgb
                        textPaint.textSize = nameSizePx
                        val gwName = deviceDisplayName(gateway, deviceStore.customName(ScanHistory.identityKey(gateway)))
                        val shortGw = if (gwName.length > 16) gwName.take(15) + "…" else gwName
                        canvas.nativeCanvas.drawText(
                            shortGw,
                            centerPx,
                            centerPx + gatewayRadiusPx + nameSizePx,
                            textPaint
                        )
                    }
                }
            }
        }

        if (offline.isNotEmpty()) {
            Card(
                Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                shape = MaterialTheme.shapes.large,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
            ) {
                Column(Modifier.padding(12.dp)) {
                    Text(
                        "Hors-ligne (${offline.size})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    offline.take(8).forEach { d ->
                        Text(
                            "${DeviceType.icon(d.type)} ${deviceDisplayName(d, deviceStore.customName(ScanHistory.identityKey(d)))}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
    }
}

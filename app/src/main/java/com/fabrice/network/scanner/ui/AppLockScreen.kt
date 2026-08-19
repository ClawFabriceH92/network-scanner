package com.fabrice.network.scanner.ui

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.fabrice.network.scanner.AppLock
import kotlinx.coroutines.delay

/**
 * Écran de verrouillage plein écran (v1.9.0) : clavier numérique PIN + bouton
 * empreinte (si biométrie dispo). Après 5 échecs → compte à rebours 30 s.
 */
@Composable
fun AppLockScreen(onUnlocked: () -> Unit) {
    val context = LocalContext.current
    val activity = remember { context.findActivity() as? FragmentActivity }

    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var lockedUntil by remember { mutableStateOf(0L) }
    var remainingMs by remember { mutableStateOf(0L) }

    val biometricAvailable = remember {
        runCatching {
            BiometricManager.from(context).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            ) == BiometricManager.BIOMETRIC_SUCCESS
        }.getOrDefault(false)
    }

    // Compte à rebours pendant le blocage (30 s).
    LaunchedEffect(lockedUntil) {
        while (lockedUntil > 0L) {
            val rem = lockedUntil - System.currentTimeMillis()
            if (rem <= 0L) {
                lockedUntil = 0L
                remainingMs = 0L
                break
            }
            remainingMs = rem
            delay(200)
        }
    }

    fun submit() {
        if (pin.isEmpty()) return
        when (val r = AppLock.verify(context, pin)) {
            is AppLock.VerifyResult.Success -> {
                error = null
                pin = ""
                onUnlocked()
            }
            is AppLock.VerifyResult.WrongPin -> {
                error = "PIN incorrect"
                pin = ""
            }
            is AppLock.VerifyResult.Locked -> {
                error = "Trop d'échecs — réessaie dans un instant"
                lockedUntil = System.currentTimeMillis() + r.remainingMs
                remainingMs = r.remainingMs
                pin = ""
            }
        }
    }

    fun onDigit(d: Int) {
        if (lockedUntil > 0L) return
        if (pin.length < 4) {
            pin += d
            if (pin.length == 4) submit()
        }
    }

    Surface(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text("🔒", style = MaterialTheme.typography.displayMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "App verrouillée",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "Saisis ton code PIN pour continuer.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(20.dp))

            // Points du PIN
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                repeat(4) { i ->
                    Box(
                        Modifier
                            .size(16.dp)
                            .background(
                                if (i < pin.length) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.surfaceVariant,
                                CircleShape
                            )
                    )
                }
            }

            Spacer(Modifier.height(16.dp))

            val blocked = lockedUntil > 0L
            if (blocked) {
                Text(
                    "⏳ Verrouillé — ${(remainingMs / 1000).coerceAtLeast(1)} s",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.error,
                    fontWeight = FontWeight.Bold
                )
            } else {
                Text(
                    error ?: " ",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Spacer(Modifier.height(16.dp))

            // Clavier numérique
            val keys = listOf("1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "⌫")
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                keys.chunked(3).forEach { row ->
                    Row(horizontalArrangement = Arrangement.spacedBy(24.dp)) {
                        row.forEach { key ->
                            if (key.isEmpty()) {
                                Spacer(Modifier.width(72.dp))
                            } else if (key == "⌫") {
                                KeyPadButton("⌫") {
                                    if (!blocked && pin.isNotEmpty()) pin = pin.dropLast(1)
                                }
                            } else {
                                KeyPadButton(key) { onDigit(key.toInt()) }
                            }
                        }
                    }
                }
            }

            Spacer(Modifier.height(20.dp))

            // Bouton biométrie
            if (biometricAvailable && activity != null) {
                BiometricUnlockButton(
                    enabled = !blocked,
                    onClick = {
                        val prompt = BiometricPrompt(
                            activity,
                            ContextCompat.getMainExecutor(context),
                            object : BiometricPrompt.AuthenticationCallback() {
                                override fun onAuthenticationSucceeded(
                                    result: BiometricPrompt.AuthenticationResult
                                ) {
                                    super.onAuthenticationSucceeded(result)
                                    onUnlocked()
                                }
                            }
                        )
                        val info = BiometricPrompt.PromptInfo.Builder()
                            .setTitle("Déverrouiller NetworkScanner")
                            .setSubtitle("Utilise ton empreinte digitale")
                            .setNegativeButtonText("Annuler")
                            .setAllowedAuthenticators(
                                BiometricManager.Authenticators.BIOMETRIC_STRONG
                            )
                            .build()
                        prompt.authenticate(info)
                    }
                )
            }
        }
    }
}

@Composable
private fun KeyPadButton(label: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .size(72.dp)
            .background(MaterialTheme.colorScheme.surfaceContainerHigh, CircleShape)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            label,
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
private fun BiometricUnlockButton(enabled: Boolean, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxWidth(0.7f)
            .height(48.dp)
            .background(
                if (enabled) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.surfaceVariant,
                MaterialTheme.shapes.medium
            )
            .clickable(enabled = enabled, onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            "🔓 Empreinte",
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.Bold,
            color = if (enabled) MaterialTheme.colorScheme.onPrimary
            else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

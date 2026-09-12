package com.fabrice.network.scanner
import com.fabrice.network.scanner.update.UpdateManager

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.fragment.app.FragmentActivity
import android.content.Intent
import com.fabrice.network.scanner.ui.AppLockScreen
import com.fabrice.network.scanner.ui.OnboardingPrefs
import com.fabrice.network.scanner.ui.OnboardingScreen
import com.fabrice.network.scanner.ui.ScannerScreen
import com.fabrice.network.scanner.ui.theme.NetworkScannerTheme

/**
 * Point d'entrée. Si un verrou (PIN/empreinte) est configuré, affiche
 * l'écran de verrouillage plein écran avant le contenu — l'état « unlocked »
 * est en mémoire : il ne se réaffiche qu'au relancement de l'app.
 *
 * FragmentActivity (au lieu de ComponentActivity) : requis par
 * androidx.biometric.BiometricPrompt.
 */
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        UpdateManager.start(this)
        LaunchActions.consume(intent)   // tuile / widget / notification → scan
        enableEdgeToEdge()
        setContent {
            NetworkScannerTheme {
                val context = LocalContext.current
                var unlocked by remember { mutableStateOf(!AppLock.isEnabled(context)) }
                var onboarding by remember { mutableStateOf(!OnboardingPrefs.done(context)) }
                when {
                    !unlocked -> AppLockScreen(onUnlocked = { unlocked = true })
                    onboarding -> OnboardingScreen(onDone = { onboarding = false })
                    else -> ScannerScreen(onShowOnboarding = { onboarding = true })
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        LaunchActions.consume(intent)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        PermissionHelper.onResult(requestCode, grantResults)
    }
}

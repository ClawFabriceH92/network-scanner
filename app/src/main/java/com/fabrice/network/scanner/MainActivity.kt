package com.fabrice.network.scanner
import com.fabrice.network.scanner.update.UpdateManager

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.fabrice.network.scanner.ui.ScannerScreen
import com.fabrice.network.scanner.ui.theme.NetworkScannerTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        UpdateManager.start(this)
        enableEdgeToEdge()
        setContent {
            NetworkScannerTheme {
                ScannerScreen()
            }
        }
    }
}

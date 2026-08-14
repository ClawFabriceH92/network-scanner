package com.fabrice.network.scanner

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.fabrice.network.scanner.ui.NetworkScannerTheme
import com.fabrice.network.scanner.ui.ScannerScreen

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NetworkScannerTheme {
                ScannerScreen()
            }
        }
    }
}

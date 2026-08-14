package com.fabrice.network.scanner

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import com.fabrice.network.scanner.ui.ScannerScreen

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = lightColorScheme(
                    primary = Color(0xFF1B3A6B),
                    onPrimary = Color.White,
                    secondary = Color(0xFFC9972B),
                    background = Color(0xFFFAF6EF),
                    surface = Color.White
                )
            ) {
                ScannerScreen()
            }
        }
    }
}

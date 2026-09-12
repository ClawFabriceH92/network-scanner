package com.fabrice.network.scanner.ui

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.fabrice.network.scanner.PermissionHelper
import com.fabrice.network.scanner.R

/** Préférence « introduction vue » (v1.9.38). */
object OnboardingPrefs {
    private const val PREFS = "settings"
    private const val KEY = "onboarding_done"
    fun done(context: Context): Boolean = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY, false)
    fun setDone(context: Context, v: Boolean) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY, v).apply()
}

/**
 * Introduction au premier lancement : ce que fait l'app, et POURQUOI chaque
 * permission est demandée (avec le bouton pour l'accorder). Textes en
 * ressources (FR + EN). Réaffichable depuis « À propos ».
 */
@Composable
fun OnboardingScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    var step by remember { mutableStateOf(0) }
    var tick by remember { mutableStateOf(0) }

    fun granted(p: String) = ContextCompat.checkSelfPermission(context, p) == PackageManager.PERMISSION_GRANTED
    @Suppress("UNUSED_EXPRESSION") tick

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        when (step) {
            0 -> {
                Text("📡", style = MaterialTheme.typography.displayMedium)
                Spacer(Modifier.height(12.dp))
                Text(stringResource(R.string.onb_welcome_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(8.dp))
                Text(stringResource(R.string.onb_welcome_body), style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(16.dp))
                listOf(
                    R.string.onb_feature_scan, R.string.onb_feature_alerts, R.string.onb_feature_wifi,
                    R.string.onb_feature_capture, R.string.onb_feature_local
                ).forEach { Text(stringResource(it), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(vertical = 3.dp)) }
            }
            1 -> {
                Text(stringResource(R.string.onb_perm_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(8.dp))
                Text(stringResource(R.string.onb_perm_body), style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(12.dp))
                val act = context as? Activity
                PermissionCard(
                    title = stringResource(R.string.onb_perm_location),
                    why = stringResource(R.string.onb_perm_location_why),
                    granted = granted(Manifest.permission.ACCESS_FINE_LOCATION),
                    onRequest = { act?.let { a -> PermissionHelper.requestLocation(a) { tick++ } } }
                )
                if (Build.VERSION.SDK_INT >= 33) {
                    PermissionCard(
                        title = stringResource(R.string.onb_perm_notif),
                        why = stringResource(R.string.onb_perm_notif_why),
                        granted = granted(Manifest.permission.POST_NOTIFICATIONS),
                        onRequest = { act?.let { a -> PermissionHelper.requestNotifications(a) { tick++ } } }
                    )
                }
                if (Build.VERSION.SDK_INT >= 31) {
                    PermissionCard(
                        title = stringResource(R.string.onb_perm_bt),
                        why = stringResource(R.string.onb_perm_bt_why),
                        granted = granted(Manifest.permission.BLUETOOTH_SCAN) && granted(Manifest.permission.BLUETOOTH_CONNECT),
                        onRequest = {
                            act?.let { a ->
                                PermissionHelper.requestBluetooth(
                                    a, arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
                                ) { tick++ }
                            }
                        }
                    )
                }
                PermissionCard(
                    title = stringResource(R.string.onb_perm_optional),
                    why = stringResource(R.string.onb_perm_optional_why),
                    granted = null,
                    onRequest = {}
                )
            }
            else -> {
                Text("✅", style = MaterialTheme.typography.displayMedium)
                Spacer(Modifier.height(12.dp))
                Text(stringResource(R.string.onb_done_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(8.dp))
                Text(stringResource(R.string.onb_done_body), style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Spacer(Modifier.height(24.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            if (step > 0) TextButton(onClick = { step-- }) { Text(stringResource(R.string.onb_back)) }
            else TextButton(onClick = { OnboardingPrefs.setDone(context, true); onDone() }) { Text(stringResource(R.string.onb_skip)) }
            Button(onClick = {
                if (step < 2) step++ else { OnboardingPrefs.setDone(context, true); onDone() }
            }) { Text(stringResource(if (step < 2) R.string.onb_next else R.string.onb_start)) }
        }
        Spacer(Modifier.height(8.dp))
        Text("${step + 1} / 3", style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.align(Alignment.CenterHorizontally))
    }
}

@Composable
private fun PermissionCard(title: String, why: String, granted: Boolean?, onRequest: () -> Unit) {
    Card(
        Modifier.fillMaxWidth().padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium)
                Text(why, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Spacer(Modifier.width(8.dp))
            when (granted) {
                true -> Text("✅", style = MaterialTheme.typography.titleMedium)
                false -> OutlinedButton(onClick = onRequest) { Text(stringResource(R.string.onb_allow)) }
                null -> {}
            }
        }
    }
}

package com.fabrice.network.scanner

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

/**
 * Demande de permissions SANS ActivityResultRegistry (requestCodes fixes).
 *
 * Corrige le crash « Can only use lower 16 bits for requestCode » (androidx
 * activity-compose 1.9.x) : le registre interne déborde quand des composables
 * contenant des rememberLauncherForActivityResult sont montés/démontés
 * souvent. Ici les codes sont codés en dur (≤ 0xFFFF) et le résultat est
 * routé via onRequestPermissionsResult de l'Activity — aucune fuite possible.
 */
object PermissionHelper {

    const val RC_LOCATION = 1001
    const val RC_NOTIFICATIONS = 1002
    const val RC_BLUETOOTH = 1003

    private var locationCb: ((Boolean) -> Unit)? = null
    private var notificationsCb: ((Boolean) -> Unit)? = null
    private var bluetoothCb: ((IntArray?) -> Unit)? = null

    fun has(activity: Activity, permission: String): Boolean =
        ContextCompat.checkSelfPermission(activity, permission) == PackageManager.PERMISSION_GRANTED

    /** Demande la localisation (ACCESS_FINE_LOCATION). */
    fun requestLocation(activity: Activity, onResult: (Boolean) -> Unit) {
        locationCb = onResult
        ActivityCompat.requestPermissions(activity, arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), RC_LOCATION)
    }

    /** Demande POST_NOTIFICATIONS (Android 13+). */
    fun requestNotifications(activity: Activity, onResult: (Boolean) -> Unit) {
        notificationsCb = onResult
        ActivityCompat.requestPermissions(activity, arrayOf(Manifest.permission.POST_NOTIFICATIONS), RC_NOTIFICATIONS)
    }

    /** Demande les permissions Bluetooth (scan + connect) + localisation. */
    fun requestBluetooth(activity: Activity, permissions: Array<String>, onResult: (Map<String, Boolean>) -> Unit) {
        // Chaque permission est évaluée sur SON propre grantResult (et non sur
        // le seul premier) : SCAN accordé mais CONNECT refusé doit rester refusé.
        bluetoothCb = { res ->
            onResult(
                permissions.mapIndexed { i, p ->
                    p to (res?.getOrNull(i) == PackageManager.PERMISSION_GRANTED)
                }.toMap()
            )
        }
        ActivityCompat.requestPermissions(activity, permissions, RC_BLUETOOTH)
    }

    /** Appelé depuis MainActivity.onRequestPermissionsResult. */
    fun onResult(requestCode: Int, grantResults: IntArray?) {
        val granted = grantResults?.firstOrNull() == PackageManager.PERMISSION_GRANTED
        when (requestCode) {
            RC_LOCATION -> locationCb?.invoke(granted).also { locationCb = null }
            RC_NOTIFICATIONS -> notificationsCb?.invoke(granted).also { notificationsCb = null }
            RC_BLUETOOTH -> bluetoothCb?.invoke(grantResults).also { bluetoothCb = null }
        }
    }
}

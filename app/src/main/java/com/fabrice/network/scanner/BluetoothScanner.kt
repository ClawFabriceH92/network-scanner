package com.fabrice.network.scanner

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.Intent
import android.os.Build
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.resume

/**
 * Scan des périphériques Bluetooth/BLE à proximité (comme Fing).
 *
 * Combine :
 * - BLE (Bluetooth Low Energy) : scan passif, liste les balises/capteurs/appareils
 * - BT classique : appareils appariés + découverte
 *
 * Nécessite (Android 12+) : BLUETOOTH_SCAN + BLUETOOTH_CONNECT (+ ACCESS_FINE_LOCATION
 * selon la config). Retourne nom, MAC, RSSI, type.
 */
object BluetoothScanner {

    data class BtDevice(
        val name: String,
        val mac: String,
        val rssi: Int,
        val type: String,   // BLE / BR / apparié
        val vendor: String
    )

    /** Cherche le fabricant depuis la MAC (OUI local ou en ligne). */
    fun vendorFor(mac: String, oui: Map<String, String>): String {
        val prefix = NetworkScanner.macPrefix(mac) ?: return ""
        return oui[prefix] ?: ""
    }

    /** True si le scan BT est possible sur cet appareil. */
    fun isSupported(context: Context): Boolean {
        val adapter = BluetoothAdapter.getDefaultAdapter() ?: return false
        return adapter.isEnabled
    }

    /**
     * Scan BLE + BT classique pendant `durationMs`. Retourne les appareils
     * détectés (sans doublon par MAC), triés par RSSI décroissant.
     */
    @SuppressLint("MissingPermission")
    suspend fun scan(
        context: Context,
        durationMs: Int = 8_000,
        oui: Map<String, String> = emptyMap()
    ): List<BtDevice> = suspendCancellableCoroutine { cont ->
        val adapter = BluetoothAdapter.getDefaultAdapter()
        if (adapter == null || !adapter.isEnabled) {
            cont.resume(emptyList())
            return@suspendCancellableCoroutine
        }
        val found = ConcurrentHashMap<String, BtDevice>()

        fun addDevice(device: BluetoothDevice?, rssi: Int, type: String) {
            if (device == null) return
            val name = device.name ?: ""
            val mac = device.address
            if (mac.isBlank()) return
            val vendor = vendorFor(mac, oui)
            found[mac] = BtDevice(name, mac, rssi, type, vendor)
        }

        // BLE scan (si dispo)
        val bleScanner = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            runCatching { adapter.bluetoothLeScanner }.getOrNull()
        } else null
        val bleCallback = if (bleScanner != null) {
            object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult?) {
                    result ?: return
                    addDevice(result.device, result.rssi, "BLE")
                }
            }
        } else null

        // BT classique (découverte)
        val discoveryReceiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                if (intent?.action == BluetoothDevice.ACTION_FOUND) {
                    val device = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE)
                    val rssi = intent.getShortExtra(BluetoothDevice.EXTRA_RSSI, -100).toInt()
                    addDevice(device, rssi, "BT")
                }
            }
        }
        val filter = android.content.IntentFilter(BluetoothDevice.ACTION_FOUND)
        runCatching { context.registerReceiver(discoveryReceiver, filter) }

        val startedBle = runCatching {
            bleScanner?.startScan(
                null,
                ScanSettings.Builder()
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                    .build(),
                bleCallback
            )
        }.isSuccess && bleScanner != null

        val startedDiscovery = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                adapter.bluetoothLeScanner != null // S+ : la découverte classique passe par le scanner BLE
            } else {
                adapter.startDiscovery()
            }
        }.getOrDefault(false) || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)

        // Appareils appariés (toujours visibles)
        runCatching {
            adapter.bondedDevices.forEach { addDevice(it, -100, "apparié") }
        }

        // Timeout : arrête tout et retourne
        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        val timeoutRunnable = Runnable {
            runCatching { if (startedBle) bleScanner?.stopScan(bleCallback) }
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                runCatching { if (startedDiscovery) adapter.cancelDiscovery() }
            }
            runCatching { context.unregisterReceiver(discoveryReceiver) }
            val list = found.values.sortedByDescending { it.rssi }
            if (cont.isActive) cont.resume(list)
        }
        handler.postDelayed(timeoutRunnable, durationMs.toLong())

        cont.invokeOnCancellation {
            handler.removeCallbacks(timeoutRunnable)
            runCatching { if (startedBle) bleScanner?.stopScan(bleCallback) }
            runCatching { if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) adapter.cancelDiscovery() }
            runCatching { context.unregisterReceiver(discoveryReceiver) }
        }
    }
}

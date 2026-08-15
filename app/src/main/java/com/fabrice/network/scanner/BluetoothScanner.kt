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
 * Récupère le MAX d'infos des trames BLE :
 * - nom réel (deviceName du ScanRecord, plus fiable que device.name)
 * - UUID des services annoncés (ex: batterie, heart rate…)
 * - fabricant par Company ID (0x004C = Apple, 0x0075 = Samsung…)
 * - puissance TX (distance estimée)
 * - RSSI (signal)
 *
 * ⚠️ Le flag `neverForLocation` sur BLUETOOTH_SCAN fait filtrer les appareils
 * BLE par le système → NE PAS le mettre si on veut tout voir.
 */
object BluetoothScanner {

    data class BtDevice(
        val name: String,
        val mac: String,
        val rssi: Int,
        val type: String,      // BLE / BR / apparié
        val vendor: String,    // fabricant (OUI MAC ou Company ID BLE)
        val services: String,  // UUID services annoncés, lisibles
        val txPower: String    // dBm annoncé (ou "")
    )

    /** Fabricant par Company ID BLE (16-bit) — les plus courants. */
    private val COMPANY_IDS = mapOf(
        0x004C to "Apple",
        0x0075 to "Samsung",
        0x00E0 to "Xiaomi",
        0x00E4 to "Google",
        0x0107 to "Huawei",
        0x0006 to "Microsoft",
        0x000D to "Texas Instruments",
        0x0059 to "Nordic Semi",
        0x00C2 to "Espressif",
        0x00FA to "Fitbit",
        0x00A6 to "Nike",
        0x0003 to "IBM",
        0x00F8 to "Garmin",
        0x012C to "Sony",
        0x02A9 to "Amazon"
    )

    /** Cherche le fabricant depuis la MAC (OUI local). */
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
     * Les appareils appariés sont toujours inclus (RSSI -100).
     */
    @SuppressLint("MissingPermission")
    suspend fun scan(
        context: Context,
        durationMs: Int = 12_000,
        oui: Map<String, String> = emptyMap()
    ): List<BtDevice> = suspendCancellableCoroutine { cont ->
        val adapter = BluetoothAdapter.getDefaultAdapter()
        if (adapter == null || !adapter.isEnabled) {
            cont.resume(emptyList())
            return@suspendCancellableCoroutine
        }
        val found = ConcurrentHashMap<String, BtDevice>()

        fun addDevice(device: BluetoothDevice?, rssi: Int, type: String, services: String = "", tx: String = "") {
            if (device == null) return
            val mac = device.address
            if (mac.isBlank()) return
            val name = device.name ?: ""
            val vendor = vendorFor(mac, oui)
            // Fusionne : garde la meilleure info (nom non vide, services non vides)
            val existing = found[mac]
            val bestName = if (name.isNotBlank()) name else existing?.name ?: ""
            val bestServices = if (services.isNotBlank()) services else existing?.services ?: ""
            val bestTx = if (tx.isNotBlank()) tx else existing?.txPower ?: ""
            val bestRssi = if (existing != null && existing.rssi > rssi) existing.rssi else rssi
            found[mac] = BtDevice(
                name = bestName,
                mac = mac,
                rssi = bestRssi,
                type = type,
                vendor = vendor,
                services = bestServices,
                txPower = bestTx
            )
        }

        // BLE : scan avec parsing complet du ScanRecord
        val bleScanner = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            runCatching { adapter.bluetoothLeScanner }.getOrNull()
        } else null
        val bleCallback = if (bleScanner != null) {
            object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult?) {
                    result ?: return
                    val record = result.scanRecord
                    // Nom annoncé dans la trame (plus fiable que device.name)
                    var name = record?.deviceName ?: result.device.name ?: ""
                    var services = ""
                    var tx = ""
                    var companyVendor: String? = null
                    record?.let { r ->
                        // UUID des services annoncés (16-bit → nom lisible)
                        val uuids = r.serviceUuids
                        if (!uuids.isNullOrEmpty()) {
                            services = uuids.mapNotNull { uuid ->
                                shortServiceName(uuid.toString())
                            }.filter { it.isNotBlank() }.joinToString(", ")
                        }
                        // Puissance TX annoncée (indice de distance)
                        if (r.txPowerLevel != Int.MIN_VALUE) {
                            tx = "${r.txPowerLevel} dBm"
                        }
                        // Fabricant par Company ID (manufacturer specific data)
                        val mfg: android.util.SparseArray<ByteArray>? = r.manufacturerSpecificData
                        if (mfg != null && mfg.size() > 0) {
                            val companyId = mfg.keyAt(0)
                            companyVendor = COMPANY_IDS[companyId]
                        }
                    }
                    if (name.isBlank() && companyVendor != null) {
                        name = "$companyVendor device"
                    }
                    val mac = result.device.address
                    if (mac.isBlank()) return
                    val vendor = companyVendor ?: vendorFor(mac, oui)
                    val existing = found[mac]
                    found[mac] = BtDevice(
                        name = if (name.isNotBlank()) name else existing?.name ?: "",
                        mac = mac,
                        rssi = result.rssi,
                        type = "BLE",
                        vendor = vendor,
                        services = if (services.isNotBlank()) services else existing?.services ?: "",
                        txPower = if (tx.isNotBlank()) tx else existing?.txPower ?: ""
                    )
                }
            }
        } else null

        // BT classique : découverte (startDiscovery marche encore sur Android 12+,
        // malgré la doc — on tente, on ignore l'échec silencieux)
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

        val startedDiscovery = runCatching { adapter.startDiscovery() }.getOrDefault(false)

        // Appareils appariés (toujours visibles)
        runCatching {
            adapter.bondedDevices.forEach { addDevice(it, -100, "apparié") }
        }

        // Timeout : arrête tout et retourne
        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        val timeoutRunnable = Runnable {
            runCatching { if (startedBle) bleScanner?.stopScan(bleCallback) }
            runCatching { if (startedDiscovery) adapter.cancelDiscovery() }
            runCatching { context.unregisterReceiver(discoveryReceiver) }
            val list = found.values.sortedByDescending { it.rssi }
            if (cont.isActive) cont.resume(list)
        }
        handler.postDelayed(timeoutRunnable, durationMs.toLong())

        cont.invokeOnCancellation {
            handler.removeCallbacks(timeoutRunnable)
            runCatching { if (startedBle) bleScanner?.stopScan(bleCallback) }
            runCatching { adapter.cancelDiscovery() }
            runCatching { context.unregisterReceiver(discoveryReceiver) }
        }
    }

    /** UUID 16-bit courts → nom lisible du service. */
    internal fun shortServiceName(uuid: String): String {
        val short = uuid.replace("-", "").substring(4, 8).uppercase()
        return when (short) {
            "180F" -> "Batterie"
            "180A" -> "Infos device"
            "180D" -> "Heart Rate"
            "1801" -> "Generic"
            "1800" -> "Generic Access"
            "1809" -> "Health Thermometer"
            "1810" -> "Blood Pressure"
            "1812" -> "HID"
            "1814" -> "Step Counter"
            "1816" -> "Cycling"
            "181A" -> "Environmental"
            "181D" -> "Body Comp."
            "181C" -> "User Data"
            "1820" -> "Internet"
            "2A00" -> "Device Name"
            "2A19" -> "Niveau batterie"
            "FEE7" -> "iBeacon"
            "FE9F" -> "Google Eddystone"
            "FD6F" -> "Tile"
            else -> ""
        }
    }
}

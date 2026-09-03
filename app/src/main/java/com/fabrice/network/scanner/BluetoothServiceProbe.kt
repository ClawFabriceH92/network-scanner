package com.fabrice.network.scanner

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothProfile
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Parcelable
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Découverte des services JOIGNABLES d'un périphérique Bluetooth (au-delà des
 * UUID annoncés passivement) + évaluation de risques :
 *
 *  - **SDP** (Bluetooth classique) : profils exposés (SPP, A2DP, HFP, HID,
 *    OBEX…) via [BluetoothDevice.fetchUuidsWithSdp] + ACTION_UUID.
 *  - **GATT** (BLE) : connexion + [BluetoothGatt.discoverServices] pour lister
 *    les services réellement présents (plus complet que la pub BLE).
 *
 * ⚠️ Honnêteté : les CVE de PILE Bluetooth (BlueBorne, KNOB, BIAS…) ne se
 * détectent PAS à distance (elles dépendent de la version d'OS/firmware, non
 * exposée en Bluetooth). Les « risques » ci-dessous sont des repères basés sur
 * les PROFILS exposés, pas un matching CVE.
 */
object BluetoothServiceProbe {

    data class BtService(val uuid: String, val name: String, val kind: String) // "SDP" / "GATT"

    data class Result(
        val services: List<BtService>,
        val risks: List<String>,
        val note: String
    )

    /** Nom lisible d'un UUID Bluetooth assigné (16 bits), sinon "propriétaire". */
    fun uuidName(uuid: String): String {
        val hex = uuid.replace("-", "").lowercase()
        val assigned = hex.length == 32 && hex.substring(8) == "00001000800000805f9b34fb"
        if (!assigned) return "Service propriétaire"
        val short = hex.substring(4, 8).uppercase()
        return SHORT_NAMES[short] ?: "Service 0x$short"
    }

    private fun short(uuid: String): String {
        val hex = uuid.replace("-", "").lowercase()
        val assigned = hex.length == 32 && hex.substring(8) == "00001000800000805f9b34fb"
        return if (assigned) hex.substring(4, 8).uppercase() else ""
    }

    private fun canon(uuid: String) = uuid.replace("-", "").lowercase()

    private val SHORT_NAMES = mapOf(
        // --- Profils Bluetooth classique (SDP) ---
        "1000" to "Service Discovery",
        "1101" to "Port série (SPP)",
        "1103" to "Accès réseau commuté (DUN)",
        "1105" to "OBEX Push (fichiers)",
        "1106" to "OBEX File Transfer (fichiers)",
        "1108" to "Casque (HSP)",
        "110A" to "Source audio (A2DP)",
        "110B" to "Sortie audio (A2DP)",
        "110C" to "Télécommande AV (cible)",
        "110E" to "Télécommande AV (AVRCP)",
        "1112" to "Passerelle casque",
        "1115" to "PAN (utilisateur)",
        "1116" to "PAN (accès réseau)",
        "111E" to "Mains-libres (HFP)",
        "111F" to "Mains-libres (passerelle)",
        "1124" to "Périphérique HID (clavier/souris)",
        "112F" to "Répertoire (PBAP)",
        "1132" to "Messages (MAP)",
        "1200" to "Infos PnP",
        // --- Services BLE (GATT) ---
        "1800" to "Accès générique",
        "1801" to "Attribut générique",
        "1809" to "Thermomètre médical",
        "180A" to "Infos appareil",
        "180D" to "Fréquence cardiaque",
        "180F" to "Batterie",
        "1810" to "Tension artérielle",
        "1812" to "HID over GATT (clavier/souris)",
        "1814" to "Vitesse/cadence course",
        "1816" to "Vitesse/cadence vélo",
        "1819" to "Localisation",
        "181A" to "Environnement",
        "181C" to "Données utilisateur",
        "181D" to "Composition corporelle",
        "1820" to "Objet (IP support)",
        // --- Vendeurs 16-bit courants ---
        "FE9F" to "Google",
        "FEE7" to "Xiaomi",
        "FD6F" to "Contact tracing / Tile"
    )

    /** Repères de risque à partir des profils exposés (informational). */
    fun assessRisks(services: List<BtService>): List<String> {
        val shorts = services.map { short(it.uuid) }.toSet()
        val risks = mutableListOf<String>()
        if ("1124" in shorts || "1812" in shorts) {
            risks.add("⚠️ Profil HID exposé : risque d'injection de frappes (clavier/souris factice) si l'appairage n'est pas exigé.")
        }
        if ("1105" in shorts || "1106" in shorts) {
            risks.add("⚠️ Transfert de fichiers OBEX exposé : réception/envoi de fichiers possible.")
        }
        if ("1101" in shorts) {
            risks.add("⚠️ Port série RFCOMM (SPP) ouvert : canal de commande possible si non protégé.")
        }
        if ("1103" in shorts || "1115" in shorts || "1116" in shorts) {
            risks.add("⚠️ Partage réseau (DUN/PAN) exposé : accès réseau possible via l'appareil.")
        }
        if (services.any { it.kind == "GATT" }) {
            risks.add("ℹ️ Services BLE joignables : vérifier que les caractéristiques sensibles exigent un appairage chiffré.")
        }
        risks.add("ℹ️ Les failles de pile (BlueBorne, KNOB, BIAS) ne se détectent pas à distance — garder l'OS/firmware à jour.")
        return risks
    }

    /** Sonde complète (SDP + GATT). À appeler hors thread UI (suspend). */
    @SuppressLint("MissingPermission")
    suspend fun probe(context: Context, mac: String): Result {
        val adapter = BluetoothAdapter.getDefaultAdapter()
            ?: return Result(emptyList(), emptyList(), "Bluetooth indisponible.")
        val device = runCatching { adapter.getRemoteDevice(mac) }.getOrNull()
            ?: return Result(emptyList(), emptyList(), "Adresse Bluetooth invalide.")

        val services = LinkedHashMap<String, BtService>()
        runCatching { sdpUuids(context, device) }.getOrDefault(emptyList()).forEach { u ->
            services[canon(u)] = BtService(u, uuidName(u), "SDP")
        }
        runCatching { gattServices(context, device) }.getOrDefault(emptyList()).forEach { u ->
            // GATT prime sur SDP si doublon (service réellement joignable).
            services[canon(u)] = BtService(u, uuidName(u), "GATT")
        }

        val list = services.values.toList()
        val note = if (list.isEmpty())
            "Aucun service joignable détecté (appareil hors de portée, éteint, ou refusant la connexion)."
        else ""
        return Result(list, assessRisks(list), note)
    }

    /** UUID des profils classiques via SDP (+ cache d'appairage). */
    @SuppressLint("MissingPermission")
    private suspend fun sdpUuids(context: Context, device: BluetoothDevice): List<String> =
        suspendCancellableCoroutine { cont ->
            val handler = Handler(Looper.getMainLooper())
            val received = LinkedHashSet<String>()
            // Cache éventuel (appairage précédent).
            runCatching { device.uuids }.getOrNull()?.forEach { received.add(it.uuid.toString()) }

            val receiver = object : BroadcastReceiver() {
                override fun onReceive(c: Context?, intent: Intent?) {
                    if (intent?.action != BluetoothDevice.ACTION_UUID) return
                    val dev = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE)
                    if (dev?.address != device.address) return
                    intent.getParcelableArrayExtra(BluetoothDevice.EXTRA_UUID)?.forEach { p: Parcelable ->
                        received.add(p.toString())
                    }
                }
            }
            runCatching { context.registerReceiver(receiver, IntentFilter(BluetoothDevice.ACTION_UUID)) }

            val done = Runnable {
                runCatching { context.unregisterReceiver(receiver) }
                if (cont.isActive) cont.resume(received.toList())
            }
            handler.postDelayed(done, 6_000)
            runCatching { device.fetchUuidsWithSdp() }

            cont.invokeOnCancellation {
                handler.removeCallbacks(done)
                runCatching { context.unregisterReceiver(receiver) }
            }
        }

    /** Services GATT (BLE) via connexion + discoverServices. */
    @SuppressLint("MissingPermission")
    private suspend fun gattServices(context: Context, device: BluetoothDevice): List<String> =
        suspendCancellableCoroutine { cont ->
            val handler = Handler(Looper.getMainLooper())
            var gatt: BluetoothGatt? = null
            var resumed = false
            lateinit var timeout: Runnable

            fun finish(list: List<String>) {
                if (resumed) return
                resumed = true
                handler.removeCallbacks(timeout)
                runCatching { gatt?.close() }
                if (cont.isActive) cont.resume(list)
            }

            val cb = object : BluetoothGattCallback() {
                override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                    when (newState) {
                        BluetoothProfile.STATE_CONNECTED -> runCatching { g.discoverServices() }
                        BluetoothProfile.STATE_DISCONNECTED -> finish(emptyList())
                    }
                }

                override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                    val out = mutableListOf<String>()
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        runCatching { g.services }.getOrNull()?.forEach { out.add(it.uuid.toString()) }
                    }
                    finish(out)
                }
            }

            timeout = Runnable { finish(emptyList()) }
            handler.postDelayed(timeout, 9_000)

            gatt = runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                    device.connectGatt(context, false, cb, BluetoothDevice.TRANSPORT_LE)
                else
                    device.connectGatt(context, false, cb)
            }.getOrNull()
            if (gatt == null) finish(emptyList())

            cont.invokeOnCancellation {
                handler.removeCallbacks(timeout)
                runCatching { gatt?.disconnect() }
                runCatching { gatt?.close() }
            }
        }
}

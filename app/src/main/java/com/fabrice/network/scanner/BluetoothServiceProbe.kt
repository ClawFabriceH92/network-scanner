package com.fabrice.network.scanner

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
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
        val note: String,
        /** Caractéristiques lisibles SANS appairage (v1.9.40) : fabricant, modèle, firmware, batterie… */
        val details: List<Pair<String, String>> = emptyList()
    )

    /** Services + caractéristiques lues d'une session GATT. */
    data class GattInfo(val services: List<String>, val details: List<Pair<String, String>>)

    /** Caractéristiques standard lisibles sans appairage → libellé. */
    val READABLE_CHARS: Map<String, String> = linkedMapOf(
        "2A00" to "Nom (GAP)",
        "2A29" to "Fabricant",
        "2A24" to "Modèle",
        "2A25" to "N° de série",
        "2A26" to "Firmware",
        "2A27" to "Matériel",
        "2A28" to "Logiciel",
        "2A19" to "Batterie",
        "2A01" to "Apparence"
    )

    /** Formate la valeur brute d'une caractéristique connue (pure, testable). */
    fun formatCharacteristic(short: String, value: ByteArray): String? {
        if (value.isEmpty()) return null
        return when (short) {
            "2A19" -> "${value[0].toInt() and 0xFF} %"
            "2A01" -> appearanceName(((value.getOrElse(1) { 0 }.toInt() and 0xFF) shl 8) or (value[0].toInt() and 0xFF))
            else -> String(value, Charsets.UTF_8).trim().trimEnd('\u0000').ifBlank { null }
        }
    }

    /** Catégorie d'apparence GAP (bits 15..6). */
    fun appearanceName(v: Int): String = when (v shr 6) {
        1 -> "Téléphone"; 2 -> "Ordinateur"; 3 -> "Montre"; 4 -> "Horloge"; 5 -> "Écran"
        6 -> "Télécommande"; 7 -> "Lunettes"; 8 -> "Tag"; 9 -> "Porte-clés"; 10 -> "Lecteur média"
        11 -> "Lecteur code-barres"; 12 -> "Thermomètre"; 13 -> "Cardiofréquencemètre"; 14 -> "Tensiomètre"
        15 -> "HID (clavier/souris…)"; 16 -> "Glucomètre"; 17 -> "Capteur course"; 18 -> "Capteur vélo"
        49 -> "Oxymètre"; 50 -> "Balance"; 0x0F -> "HID"
        else -> "Catégorie $v"
    }

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
        val gatt = runCatching { gattServices(context, device) }.getOrDefault(GattInfo(emptyList(), emptyList()))
        gatt.services.forEach { u ->
            // GATT prime sur SDP si doublon (service réellement joignable).
            services[canon(u)] = BtService(u, uuidName(u), "GATT")
        }

        val list = services.values.toList()
        val note = if (list.isEmpty())
            "Aucun service joignable détecté (appareil hors de portée, éteint, ou refusant la connexion)."
        else ""
        return Result(list, assessRisks(list), note, gatt.details)
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

    /**
     * Services GATT (BLE) via connexion + discoverServices, puis lecture en
     * série des caractéristiques standard lisibles sans appairage (Device
     * Information, Battery, Generic Access) — v1.9.40.
     */
    @SuppressLint("MissingPermission")
    private suspend fun gattServices(context: Context, device: BluetoothDevice): GattInfo =
        suspendCancellableCoroutine { cont ->
            val handler = Handler(Looper.getMainLooper())
            var gatt: BluetoothGatt? = null
            var resumed = false
            lateinit var timeout: Runnable
            val found = mutableListOf<String>()
            val details = mutableListOf<Pair<String, String>>()
            val queue = ArrayDeque<BluetoothGattCharacteristic>()

            fun finish() {
                if (resumed) return
                resumed = true
                handler.removeCallbacks(timeout)
                runCatching { gatt?.close() }
                if (cont.isActive) cont.resume(GattInfo(found.toList(), details.toList()))
            }

            fun readNext(g: BluetoothGatt) {
                val c = queue.removeFirstOrNull() ?: run { finish(); return }
                val ok = runCatching { g.readCharacteristic(c) }.getOrDefault(false)
                if (!ok) readNext(g)
            }

            fun onRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray?, status: Int) {
                if (status == BluetoothGatt.GATT_SUCCESS && value != null) {
                    val sh = short(c.uuid.toString())
                    val label = READABLE_CHARS[sh]
                    val text = formatCharacteristic(sh, value)
                    if (label != null && text != null) details.add(label to text)
                }
                readNext(g)
            }

            val cb = object : BluetoothGattCallback() {
                override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                    when (newState) {
                        BluetoothProfile.STATE_CONNECTED -> runCatching { g.discoverServices() }
                        BluetoothProfile.STATE_DISCONNECTED -> finish()
                    }
                }

                override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        runCatching { g.services }.getOrNull()?.forEach { s ->
                            found.add(s.uuid.toString())
                            s.characteristics.forEach { c ->
                                val readable = c.properties and BluetoothGattCharacteristic.PROPERTY_READ != 0
                                if (readable && READABLE_CHARS.containsKey(short(c.uuid.toString()))) queue.add(c)
                            }
                        }
                    }
                    if (queue.isEmpty()) finish() else readNext(g)
                }

                @Deprecated("Deprecated in Java")
                override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) {
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                        @Suppress("DEPRECATION") onRead(g, c, c.value, status)
                    }
                }

                override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
                    onRead(g, c, value, status)
                }
            }

            timeout = Runnable { finish() }
            handler.postDelayed(timeout, 12_000)

            gatt = runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                    device.connectGatt(context, false, cb, BluetoothDevice.TRANSPORT_LE)
                else
                    device.connectGatt(context, false, cb)
            }.getOrNull()
            if (gatt == null) finish()

            cont.invokeOnCancellation {
                handler.removeCallbacks(timeout)
                runCatching { gatt?.disconnect() }
                runCatching { gatt?.close() }
            }
        }
}

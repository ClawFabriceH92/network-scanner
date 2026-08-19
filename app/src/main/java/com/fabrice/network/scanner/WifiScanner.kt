package com.fabrice.network.scanner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.WifiManager
import android.os.Handler
import android.os.Looper

/**
 * Scanner Wi-Fi (v1.7.0) : liste les réseaux autour (SSID, BSSID, RSSI, bande,
 * chiffrement) via `WifiManager.startScan()` + BroadcastReceiver.
 *
 * ⚠️ Contraintes Android (à connaître) :
 *  - Le scan fonctionne CONNECTÉ (pas besoin de se déconnecter — impossible sans
 *    root). Ne jamais promettre une déconnexion programmatique.
 *  - Android 10+ : BSSID randomisés → ne pas afficher la MAC comme identifiant fiable.
 *  - Le système limite les scans (~4 / 2 min sur Android 9+) → debounce dans l'UI.
 *  - Nécessite ACCESS_FINE_LOCATION + localisation système active.
 */
object WifiScanner {

    /** Niveau de sécurité du chiffrement ANNONCÉ (capabilities), pas un pentest. */
    enum class WifiSecurity(val label: String) {
        OPEN("Ouvert"),
        WEP("WEP"),
        WPA_TKIP("WPA-TKIP"),
        WPA2_CCMP("WPA2-CCMP"),
        WPA2_WPA3_MIXED("WPA2/WPA3"),
        WPA3_SAE("WPA3-SAE"),
        WPA2_ENTERPRISE("WPA2-Enterprise"),
        WPA3_ENTERPRISE("WPA3-Enterprise"),
        OWE("OWE (Enhanced Open)"),
        UNKNOWN("Inconnu")
    }

    /** Un réseau Wi-Fi détecté (données pures, sans objet Android). */
    data class WifiNetwork(
        val ssid: String,
        val bssid: String,
        val rssi: Int,
        val frequency: Int,
        val capabilities: String
    ) {
        val band: String get() = NetworkInfoProvider.bandForFrequency(frequency)
        val security: WifiSecurity get() = parseCapabilities(capabilities)
        val score: Int get() = WifiVulnAnalyzer.analyze(security, ssid).score
    }

    private var receiver: BroadcastReceiver? = null

    /**
     * Parse la chaîne `capabilities` d'un ScanResult → niveau de sécurité.
     * Exemples : "[WPA2-PSK-CCMP][ESS]", "[WEP][ESS]", "[WPA3-SAE][ESS]",
     * "[WPA-PSK-TKIP][ESS]", "[ESS]" (ouvert), "[OWE][ESS]".
     */
    fun parseCapabilities(capabilities: String): WifiSecurity {
        val c = capabilities.uppercase()
        val wpa3 = c.contains("WPA3")
        val wpa2 = c.contains("WPA2") || c.contains("RSN")
        val wpa = c.contains("WPA")
        val eap = c.contains("EAP") || c.contains("802.1X") || c.contains("IEEE8021X")
        val wep = c.contains("WEP")
        val owe = c.contains("OWE")
        return when {
            wpa3 && wpa2 -> WifiSecurity.WPA2_WPA3_MIXED
            wpa3 && eap -> WifiSecurity.WPA3_ENTERPRISE
            wpa3 -> WifiSecurity.WPA3_SAE
            eap -> WifiSecurity.WPA2_ENTERPRISE
            wep -> WifiSecurity.WEP
            wpa2 -> WifiSecurity.WPA2_CCMP
            wpa -> WifiSecurity.WPA_TKIP
            owe -> WifiSecurity.OWE
            c.isBlank() || c.contains("ESS") -> WifiSecurity.OPEN
            else -> WifiSecurity.UNKNOWN
        }
    }

    /** Construit la liste dédupliquée (par BSSID) à partir des résultats système. */
    fun toNetworks(results: List<android.net.wifi.ScanResult>): List<WifiNetwork> {
        val seen = mutableSetOf<String>()
        return results.mapNotNull { sr ->
            val bssid = sr.BSSID ?: ""
            val ssid = sr.SSID ?: ""
            val key = bssid.ifBlank { ssid }
            if (!seen.add(key)) null
            else WifiNetwork(
                ssid = ssid,
                bssid = bssid,
                rssi = sr.level,
                frequency = sr.frequency,
                capabilities = sr.capabilities ?: ""
            )
        }.sortedByDescending { it.rssi }
    }

    /**
     * Lance un scan Wi-Fi. [onResults] est appelé avec les réseaux triés par
     * signal descendant (ou une liste vide au timeout de 12 s).
     */
    fun startScan(context: Context, onResults: (List<WifiNetwork>) -> Unit, timeoutMs: Long = 12_000) {
        val ctx = context.applicationContext
        val wifi = ctx.getSystemService(Context.WIFI_SERVICE) as WifiManager
        unregister(ctx)
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, intent: Intent?) {
                if (intent?.action == WifiManager.SCAN_RESULTS_AVAILABLE_ACTION) {
                    unregister(ctx)
                    onResults(readResults(wifi))
                }
            }
        }
        receiver = r
        runCatching {
            ctx.registerReceiver(r, IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION))
        }
        runCatching { wifi.startScan() }
        Handler(Looper.getMainLooper()).postDelayed({
            unregister(ctx)
        }, timeoutMs)
    }

    /** Lit les résultats du scan système (vide si permission localisation manquante). */
    private fun readResults(wifi: WifiManager): List<WifiNetwork> {
        val list = runCatching { wifi.scanResults }.getOrDefault(emptyList())
        return toNetworks(list)
    }

    private fun unregister(context: Context) {
        receiver?.let { runCatching { context.unregisterReceiver(it) } }
        receiver = null
    }
}

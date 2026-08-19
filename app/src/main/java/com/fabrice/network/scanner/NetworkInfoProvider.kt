package com.fabrice.network.scanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.wifi.WifiManager

/**
 * Infos du réseau Wi-Fi actuel (comme l'onglet « Réseau » de Fing) :
 * SSID, BSSID, passerelle, DNS, masque, bande, débit de liaison.
 */
object NetworkInfoProvider {

    data class NetworkInfo(
        val ssid: String = "",
        val bssid: String = "",
        val gateway: String = "",
        val dns: List<String> = emptyList(),
        val networkAddress: String = "",
        val mask: String = "",
        val frequencyMhz: Int = 0,
        val linkSpeedMbps: Int = 0
    ) {
        val band: String
            get() = bandForFrequency(frequencyMhz)
    }
    /** Lit toutes les infos réseau Android. */
    fun read(context: Context): NetworkInfo {
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val info = runCatching { wifi.connectionInfo }.getOrNull()

        val subnet = NetworkScanner.detectSubnet()
        val (networkAddr, mask) = if (subnet != null) {
            NetworkScanner.intToIp(NetworkScanner.networkAddress(subnet.first, subnet.second)) to
                maskForPrefix(subnet.second)
        } else "" to ""

        val dns = readDns(context)

        return NetworkInfo(
            ssid = info?.ssid?.trim('"') ?: "",
            bssid = info?.bssid ?: "",
            gateway = readGateway(),
            dns = dns,
            networkAddress = networkAddr,
            mask = mask,
            frequencyMhz = info?.frequency ?: 0,
            linkSpeedMbps = info?.linkSpeed ?: 0
        )
    }

    /** Passerelle par défaut depuis /proc/net/route (destination 00000000). */
    fun readGateway(): String {
        return try {
            val text = java.io.File("/proc/net/route").readText()
            text.lineSequence().forEach { line ->
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size >= 3 && parts[1] == "00000000" && parts[2] != "00000000") {
                    return parseRouteHex(parts[2])
                }
            }
            ""
        } catch (e: Exception) {
            ""
        }
    }

    /** Convertit l'hex little-endian de /proc/net/route en IP (0102000A → 10.0.2.1). */
    fun parseRouteHex(hex: String): String {
        if (hex.length != 8) return ""
        return try {
            val b0 = hex.substring(6, 8).toInt(16)
            val b1 = hex.substring(4, 6).toInt(16)
            val b2 = hex.substring(2, 4).toInt(16)
            val b3 = hex.substring(0, 2).toInt(16)
            "$b0.$b1.$b2.$b3"
        } catch (e: Exception) {
            ""
        }
    }

    /** DNS via ConnectivityManager (LinkProperties). */
    fun readDns(context: Context): List<String> {
        return try {
            val cm = context.applicationContext
                .getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.getLinkProperties(cm.activeNetwork)?.dnsServers?.map { it.hostAddress ?: "" }
                ?.filter { it.isNotBlank() } ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Masque de sous-réseau pour un préfixe (24 → 255.255.255.0). */
    fun maskForPrefix(prefix: Int): String {
        if (prefix !in 0..32) return ""
        val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        return NetworkScanner.intToIp(mask)
    }

    /** Bande Wi-Fi depuis la fréquence (MHz). */
    fun bandForFrequency(mhz: Int): String = when {
        mhz in 2400..2500 -> "2,4 GHz"
        mhz in 4900..5900 -> "5 GHz"
        mhz in 5901..7125 -> "6 GHz"
        else -> ""
    }

    /** Infos géographiques d'une IP (via ipinfo.io). */
    data class GeoIpInfo(
        val city: String = "",
        val region: String = "",
        val country: String = "",
        val org: String = ""
    )

    /** Récupère l'adresse IP publique (WAN) via une API. null si hors-ligne. */
    fun fetchPublicIp(timeoutMs: Int = 8_000): String? {
        val apis = listOf(
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://ipinfo.io/ip"
        )
        for (api in apis) {
            try {
                val conn = java.net.URL(api).openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = timeoutMs
                conn.readTimeout = timeoutMs
                conn.setRequestProperty("User-Agent", "NetworkScanner/1.0")
                if (conn.responseCode == 200) {
                    val ip = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }.trim()
                    conn.disconnect()
                    if (ip.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) return ip
                } else {
                    conn.disconnect()
                }
            } catch (e: Exception) {
                // essaie l'API suivante
            }
        }
        return null
    }

    /**
     * Récupère les infos GeoIP d'une IP publique (ville, région, pays, FAI)
     * via `https://ipinfo.io/<ip>/json` (pas de clé pour un usage léger).
     * null si l'IP est vide ou si la requête échoue.
     */
    fun fetchGeoIp(ip: String, timeoutMs: Int = 4_000): GeoIpInfo? {
        if (ip.isBlank()) return null
        return try {
            val conn = java.net.URL("https://ipinfo.io/$ip/json").openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.setRequestProperty("User-Agent", "NetworkScanner/1.0")
            if (conn.responseCode != 200) {
                conn.disconnect()
                return null
            }
            val text = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            conn.disconnect()
            parseGeoIp(text)
        } catch (e: Exception) {
            null
        }
    }

    /** Parse une réponse ipinfo.io JSON → GeoIpInfo, ou null si invalide. */
    fun parseGeoIp(json: String): GeoIpInfo? {
        return runCatching {
            val o = org.json.JSONObject(json)
            GeoIpInfo(
                city = o.optString("city", ""),
                region = o.optString("region", ""),
                country = o.optString("country", ""),
                org = o.optString("org", "")
            )
        }.getOrNull()
    }
}

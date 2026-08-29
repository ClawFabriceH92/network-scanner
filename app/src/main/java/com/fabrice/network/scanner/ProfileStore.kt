package com.fabrice.network.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Profils de « lieu de connexion » : chaque réseau (identifié par son SSID
 * Wi-Fi, à défaut sa passerelle) est mémorisé avec un instantané des appareils
 * qui y ont été vus — consultable plus tard, même hors de ce réseau.
 *
 * Stockage : un fichier JSON par profil dans `filesDir/profiles/`.
 */
class ProfileStore(context: Context) {

    private val dir = java.io.File(context.filesDir, "profiles").apply { mkdirs() }

    /** Métadonnées d'un profil (sans la liste d'appareils). */
    data class Profile(
        val id: String,
        val name: String,
        val ssid: String,
        val bssid: String,
        val gateway: String,
        val networkAddress: String,
        val createdAt: Long,
        val lastSeen: Long,
        val deviceCount: Int
    )

    /** Appareil mémorisé dans un profil (sous-ensemble consultable). */
    data class ProfileDevice(
        val ip: String,
        val mac: String,
        val vendor: String,
        val name: String,
        val type: String,
        val ports: List<Int>
    )

    /** Identifiant stable d'un lieu : SSID en priorité, sinon passerelle/réseau. */
    fun idFor(net: NetworkInfoProvider.NetworkInfo): String? = when {
        net.ssid.isNotBlank() && net.ssid != "<unknown ssid>" && net.ssid != "0x" ->
            "ssid:${net.ssid}"
        net.gateway.isNotBlank() -> "gw:${net.gateway}"
        net.networkAddress.isNotBlank() -> "net:${net.networkAddress}"
        else -> null
    }

    private fun fileFor(id: String): java.io.File {
        val safe = id.replace(Regex("[^A-Za-z0-9_.-]"), "_")
        return java.io.File(dir, "$safe.json")
    }

    /**
     * Crée ou met à jour le profil du réseau courant avec un instantané des
     * appareils. Conserve la date de création et le nom personnalisé s'ils
     * existent déjà. Retourne l'id du profil, ou null si le réseau n'est pas
     * identifiable.
     */
    fun upsertCurrent(
        net: NetworkInfoProvider.NetworkInfo,
        devices: List<Device>,
        deviceStore: DeviceStore?,
        now: Long,
        nameOverride: String? = null
    ): String? {
        val id = idFor(net) ?: return null
        val existing = loadProfile(id)
        val defaultName = when {
            net.ssid.isNotBlank() && net.ssid != "<unknown ssid>" -> net.ssid
            net.gateway.isNotBlank() -> "Réseau ${net.gateway}"
            else -> "Réseau"
        }
        // Nom choisi par l'utilisateur au lancement du scan > nom déjà mémorisé >
        // nom par défaut (SSID/passerelle).
        val name = nameOverride?.takeIf { it.isNotBlank() }
            ?: existing?.name?.takeIf { it.isNotBlank() }
            ?: defaultName
        val createdAt = existing?.createdAt ?: now

        val snapshot = devices.filter { it.alive }.map { d ->
            val key = ScanHistory.identityKey(d)
            val display = deviceStore?.customName(key)?.takeIf { it.isNotBlank() }
                ?: d.hostname.ifBlank { d.product.ifBlank { d.vendor } }
            ProfileDevice(
                ip = d.ip,
                mac = d.mac,
                vendor = d.vendor,
                name = display.ifBlank { d.ip },
                type = d.type,
                ports = d.ports
            )
        }
        save(
            Profile(
                id = id,
                name = name,
                ssid = net.ssid,
                bssid = net.bssid,
                gateway = net.gateway,
                networkAddress = net.networkAddress,
                createdAt = createdAt,
                lastSeen = now,
                deviceCount = snapshot.size
            ),
            snapshot
        )
        return id
    }

    /** Liste des profils (métadonnées), du plus récemment vu au plus ancien. */
    fun list(): List<Profile> =
        (dir.listFiles { f -> f.extension == "json" } ?: emptyArray())
            .mapNotNull { f -> runCatching { readProfile(f.readText()) }.getOrNull() }
            .sortedByDescending { it.lastSeen }

    /** Métadonnées d'un profil par id, ou null. */
    fun loadProfile(id: String): Profile? {
        val f = fileFor(id)
        if (!f.exists()) return null
        return runCatching { readProfile(f.readText()) }.getOrNull()
    }

    /** Appareils mémorisés d'un profil. */
    fun loadDevices(id: String): List<ProfileDevice> {
        val f = fileFor(id)
        if (!f.exists()) return emptyList()
        return try {
            val o = JSONObject(f.readText())
            val arr = o.optJSONArray("devices") ?: return emptyList()
            (0 until arr.length()).map { i ->
                val d = arr.getJSONObject(i)
                val ports = mutableListOf<Int>()
                d.optJSONArray("ports")?.let { for (j in 0 until it.length()) ports.add(it.getInt(j)) }
                ProfileDevice(
                    ip = d.optString("ip", ""),
                    mac = d.optString("mac", ""),
                    vendor = d.optString("vendor", ""),
                    name = d.optString("name", ""),
                    type = d.optString("type", "Inconnu"),
                    ports = ports
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** Renomme un profil (nom personnalisé). */
    fun rename(id: String, name: String) {
        val p = loadProfile(id) ?: return
        save(p.copy(name = name), loadDevices(id))
    }

    /** Supprime un profil. */
    fun delete(id: String) {
        runCatching { fileFor(id).delete() }
    }

    private fun readProfile(json: String): Profile {
        val o = JSONObject(json)
        return Profile(
            id = o.getString("id"),
            name = o.optString("name", ""),
            ssid = o.optString("ssid", ""),
            bssid = o.optString("bssid", ""),
            gateway = o.optString("gateway", ""),
            networkAddress = o.optString("networkAddress", ""),
            createdAt = o.optLong("createdAt"),
            lastSeen = o.optLong("lastSeen"),
            deviceCount = o.optInt("deviceCount")
        )
    }

    private fun save(profile: Profile, devices: List<ProfileDevice>) {
        val o = JSONObject()
        o.put("id", profile.id)
        o.put("name", profile.name)
        o.put("ssid", profile.ssid)
        o.put("bssid", profile.bssid)
        o.put("gateway", profile.gateway)
        o.put("networkAddress", profile.networkAddress)
        o.put("createdAt", profile.createdAt)
        o.put("lastSeen", profile.lastSeen)
        o.put("deviceCount", profile.deviceCount)
        val arr = JSONArray()
        devices.forEach { d ->
            arr.put(
                JSONObject()
                    .put("ip", d.ip)
                    .put("mac", d.mac)
                    .put("vendor", d.vendor)
                    .put("name", d.name)
                    .put("type", d.type)
                    .put("ports", JSONArray(d.ports))
            )
        }
        o.put("devices", arr)
        runCatching { fileFor(profile.id).writeText(o.toString()) }
    }
}

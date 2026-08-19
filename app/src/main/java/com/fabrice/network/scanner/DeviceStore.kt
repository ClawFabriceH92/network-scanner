package com.fabrice.network.scanner

import android.content.Context
import android.content.SharedPreferences

/**
 * Persistance des préférences par appareil : nom personnalisé et favori.
 * Clé = identifiant stable (MAC si possible, sinon IP).
 */
class DeviceStore(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("device_store", Context.MODE_PRIVATE)

    fun customName(key: String): String = prefs.getString("name_$key", "") ?: ""

    fun setCustomName(key: String, name: String) {
        prefs.edit().putString("name_$key", name.trim()).apply()
    }

    fun isFavorite(key: String): Boolean = prefs.getBoolean("fav_$key", false)

    fun setFavorite(key: String, fav: Boolean) {
        prefs.edit().putBoolean("fav_$key", fav).apply()
    }

    /** Résultat du test Wake-on-LAN pour une MAC : true=OK, false=absent, null=non testé. */
    fun wolResult(mac: String): Boolean? {
        val v = prefs.getString("wol_$mac", null) ?: return null
        return v == "true"
    }

    /** Mémorise le résultat d'un test WoL (true = le réveil fonctionne). */
    fun setWolResult(mac: String, works: Boolean) {
        prefs.edit().putString("wol_$mac", if (works) "true" else "false").apply()
    }

    fun displayName(device: Device): String {
        val custom = customName(ScanHistory.identityKey(device))
        return custom.ifBlank { device.hostname.ifBlank { device.ip } }
    }
}

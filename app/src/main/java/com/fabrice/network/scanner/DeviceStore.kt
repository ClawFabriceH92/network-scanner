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

    fun displayName(device: Device): String {
        val custom = customName(ScanHistory.identityKey(device))
        return custom.ifBlank { device.hostname.ifBlank { device.ip } }
    }
}

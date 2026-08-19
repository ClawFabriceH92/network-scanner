package com.fabrice.network.scanner

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONObject

/**
 * Annuaire des boxes connues : nom personnalisé + type, persistés en JSON dans
 * les SharedPreferences `box_prefs`, keyés par la passerelle (`box_<gateway>`).
 *
 * La logique JSON est séparée des SharedPreferences pour rester testable en
 * JUnit sans appareil (voir `read`/`BoxData`).
 */
object BoxStore {

    const val PREFS = "box_prefs"

    /** Données stockées pour une box (nom + type + horodatage). */
    data class BoxData(val name: String, val type: String, val savedAt: Long)

    /** Clé d'identité d'une box : `box_<gateway>` (gateway IP). */
    fun boxKey(gateway: String): String = "box_$gateway"

    /** Mémorise une box (nom + type), écrasant toute entrée existante. */
    fun saveBox(prefs: SharedPreferences, gateway: String, name: String, type: String) {
        val json = JSONObject().apply {
            put("name", name)
            put("type", type)
            put("savedAt", System.currentTimeMillis())
        }.toString()
        prefs.edit().putString(boxKey(gateway), json).apply()
    }

    /** Nom personnalisé d'une box, ou null si inconnue / sans nom. */
    fun getBoxName(prefs: SharedPreferences, gateway: String): String? =
        read(prefs, gateway)?.name?.takeIf { it.isNotBlank() }

    /** Type mémorisé d'une box (ex: « Freebox »), ou null si inconnue. */
    fun getBoxType(prefs: SharedPreferences, gateway: String): String? =
        read(prefs, gateway)?.type?.takeIf { it.isNotBlank() }

    /** Renomme une box existante sans perdre son type ni son horodatage. */
    fun setBoxName(prefs: SharedPreferences, gateway: String, name: String) {
        val existing = read(prefs, gateway)
        val json = JSONObject().apply {
            put("name", name)
            put("type", existing?.type ?: "")
            put("savedAt", existing?.savedAt ?: System.currentTimeMillis())
        }.toString()
        prefs.edit().putString(boxKey(gateway), json).apply()
    }

    /** Lit et décode l'entrée JSON d'une box (null si absente ou corrompue). */
    private fun read(prefs: SharedPreferences, gateway: String): BoxData? {
        val raw = prefs.getString(boxKey(gateway), null) ?: return null
        return try {
            val o = JSONObject(raw)
            BoxData(
                name = o.optString("name", ""),
                type = o.optString("type", ""),
                savedAt = o.optLong("savedAt", 0)
            )
        } catch (e: Exception) {
            null
        }
    }
}

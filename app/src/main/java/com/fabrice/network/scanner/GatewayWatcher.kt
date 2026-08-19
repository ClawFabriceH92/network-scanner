package com.fabrice.network.scanner

import android.content.Context
import android.content.SharedPreferences

/**
 * Détecte un changement de passerelle (nouvelle box / nouveau réseau).
 *
 * La logique est pure (injecte les SharedPreferences) pour rester testable en
 * JUnit sans appareil ; les surcharges `Context` servent de façade Android.
 *
 * Mémorise la dernière passerelle vue dans `box_prefs` (clé `last_gateway`) et
 * retourne `true` si la passerelle courante diffère (changement de réseau).
 */
object GatewayWatcher {

    const val PREFS = "box_prefs"
    const val KEY_LAST_GATEWAY = "last_gateway"

    /** Dernière passerelle mémorisée, ou null si jamais mémorisée. */
    fun lastGateway(prefs: SharedPreferences): String? =
        prefs.getString(KEY_LAST_GATEWAY, null)

    /**
     * Mémorise [gateway] et retourne true si elle diffère de la valeur déjà
     * mémorisée (changement de réseau détecté). Ne mémorise pas une valeur vide.
     */
    fun remember(prefs: SharedPreferences, gateway: String): Boolean {
        val last = lastGateway(prefs)
        return if (gateway.isNotBlank() && gateway != last) {
            prefs.edit().putString(KEY_LAST_GATEWAY, gateway).apply()
            true
        } else {
            false
        }
    }

    /** Efface la passerelle mémorisée (utile pour les tests / reset). */
    fun clear(prefs: SharedPreferences) {
        prefs.edit().remove(KEY_LAST_GATEWAY).apply()
    }

    // --- Façades Context (confort d'appel côté UI) ---

    private fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun lastGateway(context: Context): String? = lastGateway(prefs(context))

    fun remember(context: Context, gateway: String): Boolean = remember(prefs(context), gateway)

    fun clear(context: Context) = clear(prefs(context))
}

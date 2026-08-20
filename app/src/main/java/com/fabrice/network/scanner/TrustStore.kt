package com.fabrice.network.scanner

import android.content.Context
import android.content.SharedPreferences

/**
 * Appareils de confiance (v1.9.3) : un appareil marqué de confiance n'apparaît
 * PLUS dans les « nouveaux appareils » ni dans les alertes de départ.
 *
 * Clé = identifiant stable (MAC si possible, sinon ip:<ip>) — voir
 * [ScanHistory.identityKey]. Stocké en SharedPreferences (un booléen par clé).
 * Le constructeur [SharedPreferences] permet l'injection d'un FakePrefs en JUnit.
 */
class TrustStore(private val prefs: SharedPreferences) {

    constructor(context: Context) : this(
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    )

    companion object {
        const val PREFS = "trust_store"
        const val KEY_PREFIX = "trusted_"
    }

    /** Cet appareil est-il de confiance ? */
    fun isTrusted(key: String): Boolean = prefs.getBoolean(KEY_PREFIX + key, false)

    /** Marque / démarque un appareil de confiance. */
    fun setTrusted(key: String, trusted: Boolean) {
        prefs.edit().putBoolean(KEY_PREFIX + key, trusted).apply()
    }

    /** Bascule l'état de confiance et retourne le nouvel état. */
    fun toggle(key: String): Boolean {
        val next = !isTrusted(key)
        setTrusted(key, next)
        return next
    }

    /**
     * Ensemble des clés d'identité de confiance. Passe en paramètre aux
     * fonctions pures ([ScanHistory.detectNewDevices], [DepartureAlert.detectDepartures])
     * — elles ne lisent jamais les prefs.
     */
    fun trustedKeys(): Set<String> =
        prefs.all.keys
            .filter { it.startsWith(KEY_PREFIX) && prefs.getBoolean(it, false) }
            .map { it.removePrefix(KEY_PREFIX) }
            .toSet()
}

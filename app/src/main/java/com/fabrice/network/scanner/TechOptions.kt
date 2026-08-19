package com.fabrice.network.scanner

import android.content.Context
import android.content.SharedPreferences

/**
 * Options techniques (v1.9.0) — toggles SharedPreferences `settings` :
 * - `scan_fast` (défaut ON) : ordre de scan optimisé (ARP + multicast d'abord,
 *   ping en parallèle ensuite) — optimisation d'ordre, pas de réduction de couverture.
 * - `scan_economy` (défaut OFF) : limite les scans lourds (SNMP, creds, SMB) à
 *   l'action manuelle « Analyse complète ».
 * - `a11y_large` (défaut OFF) : augmente la taille des textes et les contrastes.
 *
 * Les fonctions `*From(prefs)` sont pures (testables JVM avec un FakePrefs) ;
 * les fonctions `Context` sont de simples façades.
 */
object TechOptions {

    const val PREFS = "settings"
    const val KEY_SCAN_FAST = "scan_fast"
    const val KEY_SCAN_ECONOMY = "scan_economy"
    const val KEY_A11Y_LARGE = "a11y_large"

    const val DEFAULT_SCAN_FAST = true
    const val DEFAULT_SCAN_ECONOMY = false
    const val DEFAULT_A11Y_LARGE = false

    // --- Lecture pure (testable) ---

    fun scanFastFrom(prefs: SharedPreferences): Boolean =
        prefs.getBoolean(KEY_SCAN_FAST, DEFAULT_SCAN_FAST)

    fun scanEconomyFrom(prefs: SharedPreferences): Boolean =
        prefs.getBoolean(KEY_SCAN_ECONOMY, DEFAULT_SCAN_ECONOMY)

    fun largeTextFrom(prefs: SharedPreferences): Boolean =
        prefs.getBoolean(KEY_A11Y_LARGE, DEFAULT_A11Y_LARGE)

    // --- Facades Context (Android) ---

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun scanFast(context: Context): Boolean = scanFastFrom(prefs(context))
    fun scanEconomy(context: Context): Boolean = scanEconomyFrom(prefs(context))
    fun largeText(context: Context): Boolean = largeTextFrom(prefs(context))

    fun setScanFast(context: Context, value: Boolean) =
        prefs(context).edit().putBoolean(KEY_SCAN_FAST, value).apply()

    fun setScanEconomy(context: Context, value: Boolean) =
        prefs(context).edit().putBoolean(KEY_SCAN_ECONOMY, value).apply()

    fun setLargeText(context: Context, value: Boolean) =
        prefs(context).edit().putBoolean(KEY_A11Y_LARGE, value).apply()
}

package com.fabrice.network.scanner

import android.content.Context

/**
 * Mémorise le résultat des tests Wake-on-LAN par appareil (clé d'identité) :
 * un appareil dont le WoL a été confirmé une fois est marqué « WoL confirmé ».
 * On ne peut PAS détecter le WoL passivement — seul un test réel fait foi.
 */
class WolStore(context: Context) {

    private val prefs = context.getSharedPreferences("wol_results", Context.MODE_PRIVATE)

    /** true = WoL confirmé, false = testé sans succès, null = jamais testé. */
    fun works(key: String): Boolean? =
        if (prefs.contains(key)) prefs.getBoolean(key, false) else null

    fun setResult(key: String, works: Boolean) {
        prefs.edit().putBoolean(key, works).apply()
    }
}

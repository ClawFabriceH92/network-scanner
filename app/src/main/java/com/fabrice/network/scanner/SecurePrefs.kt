package com.fabrice.network.scanner

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Coffre chiffré pour les secrets box (v1.9.38) : jetons d'application Freebox,
 * mot de passe admin Livebox. Repose sur EncryptedSharedPreferences (clé
 * maître AES-256-GCM dans le Keystore Android). Les valeurs historiques
 * stockées en clair dans `box_prefs` sont migrées puis effacées au premier
 * accès. Si le coffre ne peut pas être créé (Keystore corrompu, rare), on se
 * rabat sur des préférences privées classiques pour ne jamais bloquer l'app.
 */
object SecurePrefs {

    private const val FILE = "box_secure_prefs"
    private const val LEGACY = "box_prefs"
    private const val KEY_MIGRATED = "__migrated_v1"

    @Volatile private var cached: SharedPreferences? = null

    /** Clés à migrer depuis `box_prefs` : jetons Freebox, mot de passe Livebox. */
    fun isSecretKey(key: String): Boolean =
        key.startsWith(FreeboxBoxClient.TOKEN_PREFIX) || key == "pending_token" ||
            key == "pending_track" || key == LiveboxBoxClient.PASSWORD_KEY

    fun get(context: Context): SharedPreferences {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val app = context.applicationContext
            val prefs = runCatching {
                val master = MasterKey.Builder(app).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
                EncryptedSharedPreferences.create(
                    app, FILE, master,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
            }.getOrElse {
                AppLog.e("SecurePrefs", "Coffre chiffré indisponible (${it.message}) — repli en clair")
                app.getSharedPreferences("${FILE}_fallback", Context.MODE_PRIVATE)
            }
            migrate(app, prefs)
            cached = prefs
            return prefs
        }
    }

    /** Copie les secrets historiques dans le coffre, puis les efface du fichier en clair. */
    private fun migrate(context: Context, secure: SharedPreferences) {
        if (secure.getBoolean(KEY_MIGRATED, false)) return
        val legacy = context.getSharedPreferences(LEGACY, Context.MODE_PRIVATE)
        val edit = secure.edit()
        val clean = legacy.edit()
        var moved = 0
        legacy.all.forEach { (k, v) ->
            if (isSecretKey(k) && v is String) {
                if (!secure.contains(k)) edit.putString(k, v)
                clean.remove(k); moved++
            }
        }
        edit.putBoolean(KEY_MIGRATED, true).apply()
        clean.apply()
        if (moved > 0) AppLog.i("SecurePrefs", "$moved secret(s) box migré(s) vers le coffre chiffré")
    }
}

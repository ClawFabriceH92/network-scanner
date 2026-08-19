package com.fabrice.network.scanner

import android.content.Context
import java.security.MessageDigest

/**
 * Verrouillage de l'app (v1.9.0) : PIN 4 chiffres (hash SHA-256, JAMAIS en
 * clair) ou empreinte digitale (BiometricPrompt, voir AppLockScreen).
 *
 * Sécurité : 5 échecs → blocage 30 s. La logique de comptage/verrouillage est
 * pure (clock injectable via `Attempts`) et testable en JVM ; la persistance
 * SharedPreferences (`settings`, clé `lock_pin_hash`) n'est touchée que par les
 * fonctions Context.
 */
object AppLock {

    const val PREFS = "settings"
    const val KEY_PIN_HASH = "lock_pin_hash"
    const val KEY_ATTEMPTS = "lock_attempts"
    const val KEY_LOCKED_UNTIL = "lock_locked_until"
    const val MAX_ATTEMPTS = 5
    const val LOCKOUT_MS = 30_000L

    /**
     * État de comptage d'échecs + verrouillage — pur, horloge injectable.
     * `lockedUntil` = timestamp epoch ms jusqu'auquel l'app est verrouillée (0 = libre).
     */
    data class Attempts(val count: Int, val lockedUntil: Long) {
        /** Enregistre un échec. Au 5e échec : reset du compteur + verrouillage 30 s. */
        fun onFailure(nowMs: Long): Attempts {
            val c = count + 1
            return if (c >= MAX_ATTEMPTS) Attempts(0, nowMs + LOCKOUT_MS)
            else Attempts(c, lockedUntil)
        }

        fun onSuccess(): Attempts = Attempts(0, 0L)

        fun remainingMs(nowMs: Long): Long =
            if (lockedUntil <= 0L || nowMs >= lockedUntil) 0L else lockedUntil - nowMs

        fun isLocked(nowMs: Long): Boolean = remainingMs(nowMs) > 0L
    }

    /** Hash SHA-256 hexadécimal du PIN. */
    fun hashPin(pin: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(pin.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    /** Comparaison d'un PIN saisi contre le hash stocké. */
    fun matches(pin: String, storedHash: String): Boolean =
        storedHash.isNotBlank() && hashPin(pin) == storedHash

    // --- Persistance SharedPreferences (Android) ---

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Le verrou est-il actif (un PIN est configuré) ? */
    fun isEnabled(context: Context): Boolean =
        prefs(context).getString(KEY_PIN_HASH, null).orEmpty().isNotBlank()

    /** Configure (ou remplace) le PIN. Stocke uniquement le hash SHA-256. */
    fun setPin(context: Context, pin: String) {
        if (pin.isBlank()) return
        prefs(context).edit()
            .putString(KEY_PIN_HASH, hashPin(pin))
            .putInt(KEY_ATTEMPTS, 0)
            .putLong(KEY_LOCKED_UNTIL, 0L)
            .apply()
    }

    /** Désactive le verrou (supprime le hash + l'état d'échecs). */
    fun disable(context: Context) {
        prefs(context).edit()
            .remove(KEY_PIN_HASH)
            .remove(KEY_ATTEMPTS)
            .remove(KEY_LOCKED_UNTIL)
            .apply()
    }

    /** Résultat d'une tentative de déverrouillage. */
    sealed class VerifyResult {
        object Success : VerifyResult()
        object WrongPin : VerifyResult()
        data class Locked(val remainingMs: Long) : VerifyResult()
    }

    /** Vérifie un PIN (met à jour le compteur d'échecs / le verrouillage). */
    fun verify(context: Context, pin: String, nowMs: Long = System.currentTimeMillis()): VerifyResult {
        val p = prefs(context)
        val stored = p.getString(KEY_PIN_HASH, null).orEmpty()
        if (stored.isBlank()) return VerifyResult.Success
        val state = Attempts(p.getInt(KEY_ATTEMPTS, 0), p.getLong(KEY_LOCKED_UNTIL, 0L))
        if (state.isLocked(nowMs)) return VerifyResult.Locked(state.remainingMs(nowMs))
        if (matches(pin, stored)) {
            val s = state.onSuccess()
            p.edit().putInt(KEY_ATTEMPTS, s.count).putLong(KEY_LOCKED_UNTIL, s.lockedUntil).apply()
            return VerifyResult.Success
        }
        val s = state.onFailure(nowMs)
        p.edit().putInt(KEY_ATTEMPTS, s.count).putLong(KEY_LOCKED_UNTIL, s.lockedUntil).apply()
        return if (s.lockedUntil > 0L) VerifyResult.Locked(s.remainingMs(nowMs)) else VerifyResult.WrongPin
    }
}

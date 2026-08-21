package com.fabrice.network.scanner

import android.content.Context
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

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

    /**
     * Hash SHA-256 hexadécimal du PIN (format HÉRITÉ, non salé). Conservé pour
     * vérifier les PIN stockés par les anciennes versions ; les nouveaux PIN
     * utilisent [newHash] (PBKDF2 salé). Ne plus utiliser pour stocker un PIN.
     */
    fun hashPin(pin: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(pin.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    /** Préfixe des hachages salés PBKDF2 : "pbkdf2:<selHex>:<hashHex>". */
    private const val PBKDF2_PREFIX = "pbkdf2:"
    private const val PBKDF2_ITERATIONS = 120_000
    private const val PBKDF2_BITS = 256

    /** Hash salé (PBKDF2-HMAC-SHA256, sel aléatoire par PIN) prêt à stocker. */
    fun newHash(pin: String): String {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        return PBKDF2_PREFIX + toHex(salt) + ":" + pbkdf2Hex(pin, salt)
    }

    private fun pbkdf2Hex(pin: String, salt: ByteArray): String {
        val spec = PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_BITS)
        val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return toHex(skf.generateSecret(spec).encoded)
    }

    private fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun fromHex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte() }

    /**
     * Compare un PIN saisi au hash stocké. Accepte le format salé PBKDF2 ET le
     * format hérité SHA-256 (migré au prochain déverrouillage réussi, cf. verify).
     */
    fun matches(pin: String, storedHash: String): Boolean {
        if (storedHash.isBlank()) return false
        return if (storedHash.startsWith(PBKDF2_PREFIX)) {
            val parts = storedHash.removePrefix(PBKDF2_PREFIX).split(":")
            if (parts.size != 2) return false
            val salt = runCatching { fromHex(parts[0]) }.getOrNull() ?: return false
            pbkdf2Hex(pin, salt) == parts[1]
        } else {
            // Format hérité (SHA-256 non salé) des versions antérieures.
            hashPin(pin) == storedHash
        }
    }

    // --- Persistance SharedPreferences (Android) ---

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Le verrou est-il actif (un PIN est configuré) ? */
    fun isEnabled(context: Context): Boolean =
        prefs(context).getString(KEY_PIN_HASH, null).orEmpty().isNotBlank()

    /** Configure (ou remplace) le PIN. Stocke uniquement un hash salé PBKDF2. */
    fun setPin(context: Context, pin: String) {
        if (pin.isBlank()) return
        prefs(context).edit()
            .putString(KEY_PIN_HASH, newHash(pin))
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
            val edit = p.edit().putInt(KEY_ATTEMPTS, s.count).putLong(KEY_LOCKED_UNTIL, s.lockedUntil)
            // Migration transparente : un PIN encore au format hérité (SHA-256) est
            // re-haché en PBKDF2 salé au premier déverrouillage réussi.
            if (!stored.startsWith(PBKDF2_PREFIX)) edit.putString(KEY_PIN_HASH, newHash(pin))
            edit.apply()
            return VerifyResult.Success
        }
        val s = state.onFailure(nowMs)
        p.edit().putInt(KEY_ATTEMPTS, s.count).putLong(KEY_LOCKED_UNTIL, s.lockedUntil).apply()
        return if (s.lockedUntil > 0L) VerifyResult.Locked(s.remainingMs(nowMs)) else VerifyResult.WrongPin
    }
}

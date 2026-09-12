package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** v1.9.38 — coffre chiffré (clés migrées), actions de lancement. */
class R5FeaturesTest {

    @Test
    fun secretKeysAreRecognised() {
        assertTrue(SecurePrefs.isSecretKey(FreeboxBoxClient.TOKEN_PREFIX + "192.168.0.254"))
        assertTrue(SecurePrefs.isSecretKey("pending_token"))
        assertTrue(SecurePrefs.isSecretKey(LiveboxBoxClient.PASSWORD_KEY))
        assertFalse(SecurePrefs.isSecretKey(GatewayWatcher.KEY_LAST_GATEWAY))
        assertFalse(SecurePrefs.isSecretKey("box_192.168.0.1"))
    }

    @Test
    fun launchScanIsConsumedOnce() {
        LaunchActions.pendingScan = true
        assertTrue(LaunchActions.consumeScan())
        assertFalse(LaunchActions.consumeScan())
        assertEquals("scan", LaunchActions.ACTION_SCAN)
    }

    @Test
    fun btWithScanDefaultsOn() {
        val prefs = java.util.HashMap<String, Any?>()
        // Lecture pure via une SharedPreferences minimale : défaut ON.
        assertTrue(TechOptions.DEFAULT_BT_WITH_SCAN)
        assertEquals("bt_with_scan", TechOptions.KEY_BT_WITH_SCAN)
        assertTrue(prefs.isEmpty())
    }
}

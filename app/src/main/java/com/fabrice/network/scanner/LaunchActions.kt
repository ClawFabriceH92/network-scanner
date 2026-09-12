package com.fabrice.network.scanner

import android.content.Context
import android.content.Intent

/**
 * Actions de lancement (v1.9.38) : la tuile Quick Settings, le widget et les
 * notifications ouvrent l'app avec un extra `action=scan` ; MainActivity le
 * dépose ici et ScannerScreen le consomme au démarrage (ou à onNewIntent).
 */
object LaunchActions {
    const val EXTRA_ACTION = "launch_action"
    const val ACTION_SCAN = "scan"

    @Volatile var pendingScan: Boolean = false

    fun scanIntent(context: Context): Intent =
        Intent(context, MainActivity::class.java)
            .putExtra(EXTRA_ACTION, ACTION_SCAN)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)

    fun consume(intent: Intent?) {
        if (intent?.getStringExtra(EXTRA_ACTION) == ACTION_SCAN) {
            pendingScan = true
            intent.removeExtra(EXTRA_ACTION)
        }
    }

    /** True une seule fois si un scan a été demandé au lancement. */
    fun consumeScan(): Boolean {
        val v = pendingScan
        pendingScan = false
        return v
    }
}

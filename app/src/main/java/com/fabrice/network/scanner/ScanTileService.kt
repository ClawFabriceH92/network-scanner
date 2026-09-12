package com.fabrice.network.scanner

import android.app.PendingIntent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/**
 * Tuile Quick Settings « Scanner le réseau » (v1.9.38) : un tap dans le volet
 * de notifications ouvre l'app et lance un scan. Le sous-titre affiche le
 * nombre d'appareils du dernier scan.
 */
class ScanTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        val tile = qsTile ?: return
        tile.state = Tile.STATE_ACTIVE
        tile.label = getString(R.string.tile_scan_label)
        val saved = runCatching { ScanPersistence.load(this) }.getOrNull()
        val age = ScanPersistence.ageMs(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (saved.isNullOrEmpty() || age == null) getString(R.string.tile_scan_never)
            else getString(R.string.tile_scan_subtitle, saved.size, ScanPersistence.ageLabel(age))
        }
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        val intent = LaunchActions.scanIntent(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pi = PendingIntent.getActivity(
                this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}

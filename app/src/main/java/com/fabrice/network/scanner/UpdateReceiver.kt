package com.fabrice.network.scanner

import android.app.DownloadManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Reçoit la fin d'un téléchargement via DownloadManager et délègue à
 * [DownloadUpdate.onDownloadComplete]. Enregistré dans le manifest avec
 * `exported=false` (les broadcasts système arrivent quand même).
 */
class UpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != DownloadManager.ACTION_DOWNLOAD_COMPLETE) return
        val id = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1L)
        if (id == -1L) return
        DownloadUpdate.onDownloadComplete(context, id)
    }
}

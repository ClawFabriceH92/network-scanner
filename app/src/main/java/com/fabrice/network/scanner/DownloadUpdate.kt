package com.fabrice.network.scanner

import android.app.DownloadManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.content.FileProvider
import java.io.File

/**
 * Téléchargement + installation de la mise à jour (auto-update GitHub Releases).
 *
 * Le fichier est téléchargé via [DownloadManager] (notification native, pas de
 * permission stockage) vers `getExternalFilesDir(DOWNLOADS)/network-scanner-update.apk`.
 * À la fin, [UpdateReceiver] appelle [onDownloadComplete] qui installe l'APK via
 * FileProvider si l'autorisation d'installer des apps inconnues est accordée,
 * sinon poste une notification redirigeant vers les réglages d'autorisation.
 */
object DownloadUpdate {

    const val PREFS = "update_prefs"
    const val KEY_DOWNLOAD_ID = "download_id"
    const val CHANNEL_ID = "updates"
    const val FILE_NAME = "network-scanner-update.apk"
    const val NOTIF_ID = 1001

    /** Lance le téléchargement de [url] et mémorise l'id pour le receiver. */
    fun start(context: Context, url: String): Long {
        val dm = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
        val request = DownloadManager.Request(Uri.parse(url))
            .setTitle("Mise à jour Scan Réseau")
            .setDescription("Téléchargement de la nouvelle version…")
            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            .setDestinationInExternalFilesDir(context, Environment.DIRECTORY_DOWNLOADS, FILE_NAME)
        val id = dm.enqueue(request)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putLong(KEY_DOWNLOAD_ID, id).apply()
        return id
    }

    /**
     * Appelé par [UpdateReceiver] quand le téléchargement attendu se termine :
     * installe via FileProvider, ou demande l'autorisation d'installation.
     */
    fun onDownloadComplete(context: Context, downloadId: Long) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getLong(KEY_DOWNLOAD_ID, -1L) != downloadId) return

        val file = File(context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS), FILE_NAME)
        if (!file.exists()) return

        if (context.packageManager.canRequestPackageInstalls()) {
            installApk(context, file)
        } else {
            notifyPermissionNeeded(context)
        }
    }

    /** Installe l'APK [file] via FileProvider (ACTION_VIEW package-archive). */
    fun installApk(context: Context, file: File) {
        // try/catch : appelé depuis un BroadcastReceiver — une exception
        // (ActivityNotFound / FileProvider) ne doit jamais s'échapper de onReceive
        // et faire planter le process.
        runCatching {
            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                file
            )
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        }
    }

    /** Notification « autorise l'installation » avec action vers les réglages. */
    fun notifyPermissionNeeded(context: Context) {
        createChannel(context)
        val settingsIntent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).apply {
            data = Uri.parse("package:${context.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val pi = PendingIntent.getActivity(
            context,
            0,
            settingsIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("Mise à jour téléchargée")
            .setContentText("Autorise l'installation d'apps inconnues pour installer la mise à jour.")
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, notification)
    }

    private fun createChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "Mises à jour",
                    NotificationManager.IMPORTANCE_DEFAULT
                )
            )
        }
    }
}

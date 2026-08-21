package com.fabrice.network.scanner.update

import android.content.Context
import com.fabrice.network.scanner.DownloadUpdate
import com.fabrice.network.scanner.UpdateChecker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Auto-update au lancement de l'application.
 *
 * Vérifie GitHub Releases une fois au démarrage ; si une version PLUS récente
 * existe et que l'installation d'apps inconnues est autorisée, télécharge l'APK
 * (DownloadManager) — sinon poste une notification invitant à autoriser
 * l'installation. L'installation finale est gérée par [DownloadUpdate] et son
 * BroadcastReceiver (`.UpdateReceiver`) à la fin du téléchargement.
 *
 * Système de mise à jour UNIQUE : partage le même vérificateur ([UpdateChecker])
 * et le même téléchargeur ([DownloadUpdate]) que la vérification manuelle de
 * l'écran Réglages — plus de double pile ni de double appel réseau au lancement.
 *
 * NB : plus de boucle de sondage quotidienne (elle ne se déclenchait quasiment
 * jamais et réveillait le process toutes les 30 s). La vérification au
 * lancement suffit pour ce type d'app ; l'UI permet un contrôle manuel.
 */
object UpdateManager {

    private const val PREFS = "network-scannerupdate"
    private const val KEY_AUTO = "autoUpdate"

    private var started = false
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    fun autoUpdateEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_AUTO, true)

    fun setAutoUpdate(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_AUTO, enabled).apply()
    }

    /** À appeler une fois depuis le onCreate de l'activité principale. */
    fun start(context: Context) {
        if (started) return
        started = true
        val appContext = context.applicationContext
        if (autoUpdateEnabled(appContext)) checkOnce(appContext)
    }

    /** Vérification manuelle « Vérifier maintenant » (auto-télécharge si possible). */
    fun checkNow(context: Context) = checkOnce(context.applicationContext)

    private fun checkOnce(context: Context) {
        scope.launch {
            // UpdateChecker.check() ne renvoie une info que si une version PLUS
            // récente est disponible (comparaison numérique interne).
            val info = withContext(Dispatchers.IO) { UpdateChecker.check() } ?: return@launch
            if (context.packageManager.canRequestPackageInstalls()) {
                withContext(Dispatchers.IO) { DownloadUpdate.start(context, info.url) }
            } else {
                DownloadUpdate.notifyPermissionNeeded(context)
            }
        }
    }
}

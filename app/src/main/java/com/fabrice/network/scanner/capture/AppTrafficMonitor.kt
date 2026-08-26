package com.fabrice.network.scanner.capture

import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.os.Process
import android.provider.Settings

/**
 * Statistiques de trafic par application via [NetworkStatsManager] — SANS VPN.
 *
 * C'est le recoupement fiable avec PCAPdroid : « quelle app a consommé combien
 * de données » (Wi-Fi + mobile), sur une période. Nécessite l'accès « usage »
 * (PACKAGE_USAGE_STATS), accordé par l'utilisateur dans les Réglages système.
 */
object AppTrafficMonitor {

    data class AppUsage(
        val uid: Int,
        val label: String,
        val packageName: String?,
        val rxBytes: Long,
        val txBytes: Long
    ) {
        val total: Long get() = rxBytes + txBytes
    }

    /** L'utilisateur a-t-il accordé l'accès aux statistiques d'usage ? */
    fun hasUsageAccess(context: Context): Boolean {
        return try {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val mode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                appOps.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName
                )
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName
                )
            }
            mode == AppOpsManager.MODE_ALLOWED
        } catch (e: Exception) {
            false
        }
    }

    fun usageAccessSettingsIntent(): Intent =
        Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /**
     * Consommation par application depuis [sinceMs] jusqu'à maintenant,
     * agrégée Wi-Fi + mobile, triée par volume total décroissant.
     */
    fun query(context: Context, sinceMs: Long, nowMs: Long): List<AppUsage> {
        val nsm = context.getSystemService(Context.NETWORK_STATS_SERVICE) as? NetworkStatsManager
            ?: return emptyList()
        val perUid = HashMap<Int, LongArray>()   // uid -> [rx, tx]

        @Suppress("DEPRECATION")
        val types = intArrayOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)
        for (type in types) {
            val stats: NetworkStats = try {
                nsm.querySummary(type, null, sinceMs, nowMs)
            } catch (e: Exception) {
                continue
            }
            val bucket = NetworkStats.Bucket()
            try {
                while (stats.hasNextBucket()) {
                    stats.getNextBucket(bucket)
                    val e = perUid.getOrPut(bucket.uid) { longArrayOf(0L, 0L) }
                    e[0] += bucket.rxBytes
                    e[1] += bucket.txBytes
                }
            } catch (e: Exception) {
                // buckets illisibles : on garde ce qu'on a
            } finally {
                runCatching { stats.close() }
            }
        }

        val pm = context.packageManager
        return perUid.entries
            .filter { it.value[0] + it.value[1] > 0 }
            .map { (uid, v) ->
                val (pkg, label) = labelForUid(context, pm, uid)
                AppUsage(uid, label, pkg, v[0], v[1])
            }
            .sortedByDescending { it.total }
    }

    private fun labelForUid(
        context: Context,
        pm: android.content.pm.PackageManager,
        uid: Int
    ): Pair<String?, String> {
        // UID spéciaux de NetworkStats.
        when (uid) {
            NetworkStats.Bucket.UID_ALL -> return null to "Tout"
            NetworkStats.Bucket.UID_REMOVED -> return null to "Apps désinstallées"
            NetworkStats.Bucket.UID_TETHERING -> return null to "Partage de connexion"
            Process.SYSTEM_UID -> return "android" to "Système Android"
        }
        val pkgs = pm.getPackagesForUid(uid)
        if (pkgs.isNullOrEmpty()) return null to "uid $uid"
        return try {
            val info = pm.getApplicationInfo(pkgs[0], 0)
            pkgs[0] to pm.getApplicationLabel(info).toString()
        } catch (e: Exception) {
            pkgs[0] to (pkgs[0])
        }
    }

    fun formatBytes(b: Long): String {
        if (b < 1024) return "$b o"
        val kb = b / 1024.0
        if (kb < 1024) return String.format("%.1f Ko", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format("%.1f Mo", mb)
        return String.format("%.2f Go", mb / 1024.0)
    }
}

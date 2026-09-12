package com.fabrice.network.scanner.capture

import android.content.Context

/** Réglages de la capture réseau (v1.9.34) : apps capturées, IPv6, GeoIP. */
object CapturePrefs {

    private const val PREFS = "capture_prefs"
    private const val KEY_ALLOWED = "allowed_pkgs"
    private const val KEY_IPV6 = "ipv6"
    private const val KEY_GEO = "geo"
    private const val KEY_TRACKER_AUTO = "tracker_last_auto"

    private fun p(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Packages capturés (vide = toutes les applications). */
    fun allowedPackages(context: Context): Set<String> =
        p(context).getStringSet(KEY_ALLOWED, emptySet())?.toSet() ?: emptySet()

    fun setAllowedPackages(context: Context, pkgs: Set<String>) {
        p(context).edit().putStringSet(KEY_ALLOWED, pkgs.toSet()).apply()
    }

    /** Capture IPv6 (si le réseau réel a une IPv6 globale). Défaut ON. */
    fun ipv6(context: Context): Boolean = p(context).getBoolean(KEY_IPV6, true)
    fun setIpv6(context: Context, on: Boolean) = p(context).edit().putBoolean(KEY_IPV6, on).apply()

    /** GeoIP des IP distantes (opt-in : envoie les IP à ipinfo.io). Défaut OFF. */
    fun geo(context: Context): Boolean = p(context).getBoolean(KEY_GEO, false)
    fun setGeo(context: Context, on: Boolean) = p(context).edit().putBoolean(KEY_GEO, on).apply()

    fun trackerLastAuto(context: Context): Long = p(context).getLong(KEY_TRACKER_AUTO, 0L)
    fun setTrackerLastAuto(context: Context, ms: Long) = p(context).edit().putLong(KEY_TRACKER_AUTO, ms).apply()
}

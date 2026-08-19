package com.fabrice.network.scanner.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper

/**
 * Remonte la chaîne de ContextWrapper jusqu'à l'Activity englobante (ou null).
 * Remplace `LocalActivity` (retiré de activity-compose 1.9).
 */
fun Context.findActivity(): Activity? {
    var c: Context? = this
    while (c != null) {
        if (c is Activity) return c
        c = if (c is ContextWrapper) c.baseContext else null
    }
    return null
}

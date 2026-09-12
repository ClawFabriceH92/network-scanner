package com.fabrice.network.scanner

import android.content.Context

/**
 * Exposition Internet (v1.9.36) : réunit les redirections de ports de la box
 * (API Freebox `/fw/redir/`) et les mappages UPnP-IGD, puis signale toute
 * NOUVELLE redirection par rapport à la dernière vérification (notification
 * + timeline d'audit). Logique de diff pure ; la persistance est en prefs.
 */
object ExposureMonitor {

    private const val PREFS = "exposure_prefs"
    private const val KEY_KNOWN = "known_forwards"

    /** Ports internes dont l'exposition sur Internet est dangereuse. */
    val RISKY_INTERNAL_PORTS = setOf(21, 22, 23, 25, 53, 80, 139, 445, 161, 389, 1433, 1900, 3306, 3389, 5900, 5901, 6379, 8080, 8443, 9100, 27017)

    /** Signature stable d'une redirection (pour le diff entre vérifications). */
    fun signature(f: BoxPortForward): String =
        "${f.protocol.lowercase()}:${f.externalPort}>${f.internalIp}:${f.internalPort}"

    /** Redirections de [current] absentes de [known]. Pure. */
    fun newForwards(known: Set<String>, current: List<BoxPortForward>): List<BoxPortForward> =
        current.filter { it.enabled && signature(it) !in known }

    /** Niveau de risque d'une redirection : 2 = dangereux, 1 = à surveiller, 0 = ok. */
    fun risk(f: BoxPortForward): Int = when {
        !f.enabled -> 0
        f.internalPort in RISKY_INTERNAL_PORTS || f.externalPort in RISKY_INTERNAL_PORTS -> 2
        else -> 1
    }

    fun riskLabel(f: BoxPortForward): String = when (risk(f)) {
        2 -> "⚠️ service sensible exposé"
        1 -> "exposé"
        else -> "désactivée"
    }

    /** Convertit un mappage UPnP en redirection (source « UPnP »). */
    fun fromUpnp(m: IgdProbe.PortMapping): BoxPortForward = BoxPortForward(
        externalPort = m.externalPort,
        internalIp = m.internalClient,
        internalPort = m.internalPort,
        protocol = m.protocol,
        enabled = m.enabled,
        comment = m.description,
        source = "UPnP"
    )

    fun knownSignatures(context: Context): Set<String> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getStringSet(KEY_KNOWN, emptySet())?.toSet() ?: emptySet()

    fun saveKnown(context: Context, current: List<BoxPortForward>) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putStringSet(KEY_KNOWN, current.map { signature(it) }.toSet()).apply()
    }

    fun hasBaseline(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).contains(KEY_KNOWN)

    /**
     * Compare [current] à la dernière vérification, notifie les nouvelles
     * redirections (sauf toute première vérification : pas de référence),
     * journalise et mémorise l'état. Retourne les nouvelles redirections.
     */
    fun checkAndNotify(context: Context, current: List<BoxPortForward>): List<BoxPortForward> {
        val baseline = hasBaseline(context)
        val fresh = newForwards(knownSignatures(context), current)
        if (baseline && fresh.isNotEmpty()) {
            val audit = AuditLogStore(context)
            fresh.forEach { f -> runCatching { audit.append("🔓 Nouvelle redirection ${describe(f)} (${f.source})") } }
            val worst = fresh.maxByOrNull { risk(it) }!!
            NewDeviceNotifier.notifySecurity(
                context,
                if (fresh.size == 1) "🔓 Nouvelle redirection de port" else "🔓 ${fresh.size} nouvelles redirections de port",
                describe(worst) + (if (risk(worst) >= 2) " — service sensible exposé sur Internet !" else "") +
                    (if (fresh.size > 1) " (+${fresh.size - 1} autre(s))" else ""),
                3002
            )
        }
        if (current.isNotEmpty() || !baseline) saveKnown(context, current)
        return if (baseline) fresh else emptyList()
    }

    fun describe(f: BoxPortForward): String =
        "${f.externalPort}/${f.protocol.lowercase()} → ${f.internalIp}:${f.internalPort}" +
            (if (f.comment.isNotBlank()) " (${f.comment})" else "")
}

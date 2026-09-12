package com.fabrice.network.scanner.capture

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Pare-feu de la capture (v1.9.34) — logique PURE, testable en JVM.
 *
 * Deux sortes de règles :
 *  - `app`    : bloque tout le trafic d'une application (par package) ;
 *  - `domain` : bloque un domaine et ses sous-domaines (correspondance par
 *               suffixe : « doubleclick.net » couvre « ads.doubleclick.net »).
 *
 * Application dans le [CaptureVpnService] : une connexion bloquée reçoit un
 * RST (TCP) ou est simplement jetée (UDP) ; une requête DNS vers un domaine
 * bloqué reçoit une réponse NXDOMAIN synthétique. Le blocage n'agit que
 * PENDANT la capture (c'est le VPN local qui filtre), comme PCAPdroid.
 */
object FirewallRules {

    const val KIND_APP = "app"
    const val KIND_DOMAIN = "domain"

    data class Rule(val kind: String, val value: String, val label: String = "") {
        val isApp get() = kind == KIND_APP
        val isDomain get() = kind == KIND_DOMAIN
    }

    /** Normalise un domaine saisi (minuscules, sans schéma/chemin/point final). */
    fun normalizeDomain(input: String): String {
        var s = input.trim().lowercase()
        s = s.substringAfter("://")
        s = s.substringBefore('/').substringBefore(':').substringBefore('?')
        s = s.trim('.').trim()
        if (s.startsWith("*.")) s = s.removePrefix("*.")
        return s
    }

    /** True si [host] est [domain] ou un sous-domaine de [domain]. */
    fun hostMatches(host: String, domain: String): Boolean {
        if (host.isBlank() || domain.isBlank()) return false
        val h = host.lowercase().trimEnd('.')
        return h == domain || h.endsWith(".$domain")
    }

    /** Premier domaine de [domains] couvrant [host], ou null. */
    fun matchingDomain(domains: Collection<String>, host: String): String? =
        domains.firstOrNull { hostMatches(host, it) }

    // ---- Sérialisation ------------------------------------------------------

    fun toJson(rules: List<Rule>): String {
        val arr = JSONArray()
        rules.forEach { r ->
            arr.put(JSONObject().put("kind", r.kind).put("value", r.value).put("label", r.label))
        }
        return arr.toString()
    }

    fun fromJson(json: String?): List<Rule> {
        if (json.isNullOrBlank()) return emptyList()
        return runCatching {
            val arr = JSONArray(json)
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                val kind = o.optString("kind"); val value = o.optString("value")
                if (kind.isBlank() || value.isBlank()) null
                else Rule(kind, value, o.optString("label", ""))
            }
        }.getOrDefault(emptyList())
    }

    // ---- Persistance (SharedPreferences) -----------------------------------

    private const val PREFS = "firewall_prefs"
    private const val KEY_RULES = "rules"
    private const val KEY_BLOCK_TRACKERS = "block_trackers"

    fun load(context: Context): List<Rule> =
        fromJson(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_RULES, null))

    fun save(context: Context, rules: List<Rule>) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY_RULES, toJson(rules.distinct())).apply()
        FirewallRuntime.apply(context)
    }

    fun blockTrackers(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_BLOCK_TRACKERS, false)

    fun setBlockTrackers(context: Context, on: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_BLOCK_TRACKERS, on).apply()
        FirewallRuntime.apply(context)
    }
}

/**
 * Instantané des règles résolu pour le service (uid des apps bloquées, liste
 * des domaines, blocage des trackers). Singleton process-wide comme
 * [CaptureState] : l'UI l'actualise, le service le consulte à chaque paquet.
 */
object FirewallRuntime {

    @Volatile var blockedUids: Set<Int> = emptySet(); private set
    @Volatile var blockedPackages: Set<String> = emptySet(); private set
    val blockedDomains = CopyOnWriteArrayList<String>()
    @Volatile var blockTrackers: Boolean = false; private set
    @Volatile private var trackerLookup: ((String) -> String?)? = null

    /** Recharge les règles depuis les prefs et résout les uid des packages. */
    fun apply(context: Context) {
        val rules = FirewallRules.load(context)
        val pm = context.packageManager
        val pkgs = rules.filter { it.isApp }.map { it.value }.toSet()
        blockedPackages = pkgs
        blockedUids = pkgs.mapNotNull { p ->
            runCatching { pm.getApplicationInfo(p, 0).uid }.getOrNull()
        }.toSet()
        val doms = rules.filter { it.isDomain }.map { FirewallRules.normalizeDomain(it.value) }
            .filter { it.isNotBlank() }
        blockedDomains.clear(); blockedDomains.addAll(doms)
        blockTrackers = FirewallRules.blockTrackers(context)
        val db = TrackerDatabase.load(context)
        trackerLookup = { host -> db.lookup(host)?.category }
    }

    fun isUidBlocked(uid: Int): Boolean = uid >= 0 && uid in blockedUids

    /** Motif de blocage d'un hôte (règle domaine ou tracker), ou null. */
    fun domainBlockReason(host: String): String? {
        if (host.isBlank()) return null
        FirewallRules.matchingDomain(blockedDomains, host)?.let { return "règle $it" }
        if (blockTrackers) trackerLookup?.invoke(host)?.let { return "tracker ($it)" }
        return null
    }

    /** Pour les tests : injecte un état sans Context. */
    fun setForTest(uids: Set<Int>, domains: List<String>, trackers: Boolean, lookup: ((String) -> String?)?) {
        blockedUids = uids
        blockedDomains.clear(); blockedDomains.addAll(domains)
        blockTrackers = trackers
        trackerLookup = lookup
    }
}

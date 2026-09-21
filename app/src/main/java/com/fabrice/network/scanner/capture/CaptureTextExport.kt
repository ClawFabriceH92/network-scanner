package com.fabrice.network.scanner.capture

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Export TEXTE d'une session de capture (v1.9.42), pensé pour être collé dans
 * un LLM : Markdown compact, sans jargon d'UI, agrégé par application puis
 * par hôte, avec les points d'attention (trackers, blocages, pays, DNS/SNI).
 * Aucun contenu de paquet n'est inclus — uniquement des métadonnées.
 * Fonction pure, testable.
 */
object CaptureTextExport {

    data class Session(
        val startMs: Long?,
        val endMs: Long?,
        val packets: Long,
        val bytesOut: Long,
        val bytesIn: Long,
        val blockedPackets: Long,
        val rules: List<FirewallRules.Rule>,
        val blockTrackers: Boolean,
        val allowedApps: Set<String>,
        val ipv6: Boolean,
        /** Description de l'environnement (modèle, Android, version app) — v1.9.43. */
        val deviceInfo: String = "",
        /** Lignes du journal technique (AppLog) de la session — v1.9.43. */
        val techLogs: List<String> = emptyList(),
        /** Contexte réseau au moment de l'export (SSID, passerelle, DNS…) — v1.9.44. */
        val networkContext: List<String> = emptyList()
    )

    /** Provenance de chaque donnée, pour que le LLM sache ce qu'il lit — v1.9.44. */
    val METHOD_LINES: List<String> = listOf(
        "- Capture : un VpnService Android crée une interface TUN locale (10.111.222.1/32, route 0.0.0.0/0, IPv6 seulement si le réseau a une adresse globale) ; l'app lit chaque paquet IP émis par le téléphone, le journalise (PCAP) puis le RÉÉMET elle-même vers la vraie destination via des sockets TCP/UDP protégés. Le téléphone garde donc Internet, mais tout passe par l'app : aucun contenu n'est déchiffré, seuls les en-têtes sont lus.",
        "- Connexion : un 5-uplet (protocole, port local, IP distante, port distant) agrégé sur la session. « actif » = flux encore ouvert, « fermé » = FIN/RST vu ou délai d'inactivité UDP (60 s), « bloqué » = refusé par le pare-feu de l'app.",
        "- Octets : volume des CHARGES UTILES TCP/UDP (en-têtes IP/TCP exclus) ; ↑ = du téléphone vers le distant, ↓ = l'inverse. Les paquets comptent les segments/datagrammes vus dans les deux sens.",
        "- Application : uid propriétaire du socket demandé à Android (ConnectivityManager.getConnectionOwnerUid, Android 10+) puis libellé du package ; « app inconnue » = uid non résolu (flux très court, système, ou Android < 10). uid 0/1000 = système.",
        "- Hôte : nom obtenu SANS connexion supplémentaire, par deux voies passives : (1) réponses DNS vues sur le port 53 (table IP → nom) ; (2) champ SNI du ClientHello TLS (nom du site en clair au début de chaque connexion HTTPS). Sans ces indices (DNS chiffré DoH/DoT, IP en dur, ECH), seule l'IP est connue.",
        "- Classification tracker : correspondance par suffixe du nom d'hôte avec la liste Disconnect Tracking Protection (Publicité, Analytique, Réseau social, Empreinte navigateur, Cryptominage, Pistage e-mail), mise à jour quotidiennement. Un hôte absent de la liste n'est pas forcément sain.",
        "- Localisation : pays/ville/opérateur de l'IP publique fournis par ipinfo.io (option explicite « GeoIP »), donc précision approximative (opérateur du bloc IP, CDN possible). Vide si l'option est désactivée ou l'IP privée.",
        "- Pare-feu : règles par application (uid) ou domaine (suffixe) et option « bloquer les trackers » ; un flux bloqué reçoit un RST TCP, une requête DNS bloquée reçoit une réponse NXDOMAIN synthétique, l'UDP est jeté. Le blocage n'existe que pendant la capture.",
        "- Journal technique : lignes horodatées émises par l'app (tag « Capture » = moteur de capture ; autres tags = scan, box, mises à jour) depuis une minute avant la session.",
        "- Limites : trafic des autres VPN non visible ; IPv6 absent si le réseau n'en fournit pas ; paquets IPv6 avec en-têtes d'extension ignorés ; la session s'arrête d'elle-même après 30 min ou 200 Mo ; l'app elle-même est exclue de la capture."
    )

    /** Plafond de lignes de journal et de connexions brutes dans l'export. */
    const val MAX_LOG_LINES = 400
    const val MAX_RAW_CONNS = 600

    /** Limite de lignes par section pour rester digeste (les plus gros flux d'abord). */
    const val MAX_HOSTS_PER_APP = 25
    const val MAX_APPS = 30

    fun build(conns: List<CaptureState.Conn>, session: Session, nowMs: Long = System.currentTimeMillis()): String {
        val fmt = SimpleDateFormat("dd/MM/yyyy HH:mm:ss", Locale.FRENCH)
        val sb = StringBuilder()
        sb.appendLine("# Capture réseau Android (Scan Réseau)")
        sb.appendLine()
        sb.appendLine("Contexte : capture locale via VPN sur un téléphone Android ; chaque « connexion » est un flux TCP/UDP vu depuis le téléphone vers Internet ou le LAN. Aucun contenu n'a été lu, seulement les métadonnées (adresses, ports, noms DNS/SNI, volumes).")
        sb.appendLine()
        if (session.networkContext.isNotEmpty()) {
            sb.appendLine("## Contexte réseau")
            session.networkContext.forEach { sb.appendLine("- $it") }
            sb.appendLine()
        }
        sb.appendLine("## Session")
        session.startMs?.let { sb.appendLine("- Début : ${fmt.format(Date(it))}") }
        val end = session.endMs ?: nowMs
        session.startMs?.let { sb.appendLine("- Durée : ${formatDuration(end - it)}") }
        sb.appendLine("- Paquets : ${session.packets} · émis ${AppTrafficMonitor.formatBytes(session.bytesOut)} · reçus ${AppTrafficMonitor.formatBytes(session.bytesIn)}")
        sb.appendLine("- Connexions : ${conns.size} (${conns.count { it.protocol == "TCP" }} TCP, ${conns.count { it.protocol == "UDP" }} UDP)")
        sb.appendLine("- IPv6 capturé : ${if (session.ipv6) "oui" else "non"}")
        if (session.allowedApps.isNotEmpty()) sb.appendLine("- Filtre : uniquement ${session.allowedApps.joinToString(", ")}")
        val ruleText = buildList {
            if (session.blockTrackers) add("trackers/publicité bloqués")
            session.rules.forEach { add((if (it.isApp) "app " else "domaine ") + it.label.ifBlank { it.value }) }
        }
        sb.appendLine("- Pare-feu : " + (if (ruleText.isEmpty()) "aucune règle" else ruleText.joinToString(", ")) +
            (if (session.blockedPackets > 0) " · ${session.blockedPackets} paquet(s) bloqué(s)" else ""))
        sb.appendLine()

        // ---- Points d'attention ---------------------------------------------
        val trackers = conns.filter { it.category.isNotBlank() }
        val blocked = conns.filter { it.blocked }
        val countries = conns.mapNotNull { c -> c.geo.takeIf { it.isNotBlank() }?.let { countryOf(it) } }
            .filter { it.isNotBlank() }.groupingBy { it }.eachCount().toList().sortedByDescending { it.second }
        val unresolved = conns.filter { it.hostname.isBlank() && GeoCache.isPublic(it.remoteIp) }
        sb.appendLine("## Points d'attention")
        if (trackers.isEmpty() && blocked.isEmpty() && unresolved.isEmpty() && countries.isEmpty()) {
            sb.appendLine("- Rien de particulier.")
        }
        if (trackers.isNotEmpty()) {
            sb.appendLine("- ${trackers.size} connexion(s) vers des trackers/publicité : " +
                trackers.groupBy { it.category }.entries.sortedByDescending { it.value.size }
                    .joinToString(", ") { "${it.key} (${it.value.size})" })
        }
        if (blocked.isNotEmpty()) {
            sb.appendLine("- ${blocked.size} connexion(s) bloquée(s) par le pare-feu : " +
                blocked.groupBy { it.blockReason }.entries.joinToString(", ") { "${it.key} (${it.value.size})" })
        }
        if (countries.isNotEmpty()) {
            sb.appendLine("- Pays contactés : " + countries.joinToString(", ") { "${it.first} (${it.second})" })
        }
        if (unresolved.isNotEmpty()) {
            sb.appendLine("- ${unresolved.size} connexion(s) vers des IP publiques sans nom connu (ni DNS ni SNI) : à identifier.")
        }
        sb.appendLine()

        // ---- Par application ------------------------------------------------
        sb.appendLine("## Connexions par application")
        sb.appendLine("Colonnes : hôte (ou IP) · port/protocole · émis/reçus · statut · classification · localisation")
        val byApp = conns.groupBy { it.appLabel.ifBlank { "app inconnue" } }
            .entries.sortedByDescending { e -> e.value.sumOf { it.bytesOut + it.bytesIn } }
        byApp.take(MAX_APPS).forEach { (app, list) ->
            val tot = list.sumOf { it.bytesOut + it.bytesIn }
            sb.appendLine()
            sb.appendLine("### $app — ${list.size} connexion(s), ${AppTrafficMonitor.formatBytes(tot)}")
            // Agrégation par hôte + port + protocole.
            val hosts = list.groupBy { Triple(it.hostname.ifBlank { it.remoteIp }, it.remotePort, it.protocol) }
                .entries.sortedByDescending { e -> e.value.sumOf { it.bytesOut + it.bytesIn } }
            hosts.take(MAX_HOSTS_PER_APP).forEach { (k, group) ->
                val (host, port, proto) = k
                val out = group.sumOf { it.bytesOut }; val inn = group.sumOf { it.bytesIn }
                val first = group.first()
                val ip = if (first.hostname.isNotBlank()) " [${first.remoteIp}]" else ""
                val status = when {
                    group.any { it.blocked } -> "BLOQUÉ (${group.first { it.blocked }.blockReason})"
                    group.any { it.status == "actif" } -> "actif"
                    else -> "fermé"
                }
                val extras = listOfNotNull(
                    first.category.takeIf { it.isNotBlank() }?.let { "🎯 $it" },
                    first.geo.takeIf { it.isNotBlank() }
                )
                sb.append("- $host$ip · $port/$proto · ↑${AppTrafficMonitor.formatBytes(out)} ↓${AppTrafficMonitor.formatBytes(inn)} · $status")
                if (group.size > 1) sb.append(" · ${group.size} flux")
                if (extras.isNotEmpty()) sb.append(" · " + extras.joinToString(" · "))
                sb.appendLine()
            }
            if (hosts.size > MAX_HOSTS_PER_APP) sb.appendLine("- … et ${hosts.size - MAX_HOSTS_PER_APP} autre(s) hôte(s)")
        }
        if (byApp.size > MAX_APPS) sb.appendLine("\n… et ${byApp.size - MAX_APPS} autre(s) application(s)")
        sb.appendLine()

        // ---- Noms de domaine vus ------------------------------------------
        val domains = conns.mapNotNull { it.hostname.takeIf { h -> h.isNotBlank() } }
            .map { rootDomain(it) }.groupingBy { it }.eachCount().toList().sortedByDescending { it.second }
        if (domains.isNotEmpty()) {
            sb.appendLine("## Domaines contactés (${domains.size})")
            sb.appendLine(domains.take(80).joinToString(", ") { if (it.second > 1) "${it.first} (${it.second})" else it.first })
            if (domains.size > 80) sb.appendLine("… et ${domains.size - 80} autres")
            sb.appendLine()
        }

        // ---- Méthode --------------------------------------------------------
        sb.appendLine("## Méthode : comment ces informations ont été obtenues")
        METHOD_LINES.forEach { sb.appendLine(it) }
        sb.appendLine()

        // ---- Logs techniques ------------------------------------------------
        sb.appendLine("## Logs techniques")
        if (session.deviceInfo.isNotBlank()) sb.appendLine("Environnement : ${session.deviceInfo}")
        sb.appendLine()
        sb.appendLine("### Connexions brutes (${conns.size})")
        sb.appendLine("Format : heure_début→heure_fin proto :port_local → ip:port_distant [hôte] app statut ↑octets ↓octets paquets [motif] [classification] [géo]")
        val tf = SimpleDateFormat("HH:mm:ss", Locale.FRENCH)
        sb.appendLine("```")
        conns.sortedBy { it.firstSeenMs }.take(MAX_RAW_CONNS).forEach { c ->
            sb.append("${tf.format(Date(c.firstSeenMs))}→${tf.format(Date(c.lastSeenMs))} ${c.protocol} :${c.localPort} → ${c.remoteIp}:${c.remotePort}")
            if (c.hostname.isNotBlank()) sb.append(" [${c.hostname}]")
            sb.append(" ${c.appLabel.ifBlank { "?" }}" + (if (c.uid >= 0) "(uid ${c.uid})" else ""))
            sb.append(" ${c.status} ↑${c.bytesOut} ↓${c.bytesIn} ${c.packetsOut}/${c.packetsIn}pk")
            if (c.blockReason.isNotBlank()) sb.append(" [${c.blockReason}]")
            if (c.category.isNotBlank()) sb.append(" [${c.category}]")
            if (c.geo.isNotBlank()) sb.append(" [${c.geo}]")
            sb.appendLine()
        }
        if (conns.size > MAX_RAW_CONNS) sb.appendLine("… ${conns.size - MAX_RAW_CONNS} connexion(s) supplémentaire(s) omise(s)")
        sb.appendLine("```")
        sb.appendLine()
        sb.appendLine("### Journal du moteur de capture (${session.techLogs.size} ligne(s))")
        if (session.techLogs.isEmpty()) sb.appendLine("Aucune ligne (journal vide ou session non démarrée dans cette instance de l'app).")
        else {
            sb.appendLine("```")
            session.techLogs.takeLast(MAX_LOG_LINES).forEach { sb.appendLine(it) }
            if (session.techLogs.size > MAX_LOG_LINES) sb.appendLine("… ${session.techLogs.size - MAX_LOG_LINES} ligne(s) plus ancienne(s) omise(s)")
            sb.appendLine("```")
        }
        sb.appendLine()

        sb.appendLine("## Question suggérée")
        sb.appendLine("Analyse ces connexions : quelles applications parlent à des services inattendus, quels trackers sont présents, y a-t-il des flux vers des pays ou des hôtes suspects, et que devrais-je bloquer ?")
        return sb.toString()
    }

    /** « ads.doubleclick.net » → « doubleclick.net » (deux derniers labels, trois si TLD à 2 lettres composé). */
    fun rootDomain(host: String): String {
        val parts = host.trimEnd('.').split('.')
        if (parts.size <= 2) return host
        val tld = parts.last()
        val sld = parts[parts.size - 2]
        val composite = tld.length == 2 && sld.length <= 3 && sld in setOf("co", "com", "net", "org", "gov", "ac", "edu")
        return if (composite && parts.size >= 3) parts.takeLast(3).joinToString(".") else parts.takeLast(2).joinToString(".")
    }

    /** Code pays d'un libellé GeoCache (« 🇫🇷FR · Paris · Orange » → « FR »). */
    fun countryOf(geo: String): String {
        val first = geo.substringBefore(" · ").trim()
        return first.filter { it in 'A'..'Z' }.take(2)
    }

    fun formatDuration(ms: Long): String {
        val s = ms / 1000
        return when {
            s < 60 -> "$s s"
            s < 3600 -> "${s / 60} min ${s % 60} s"
            else -> "${s / 3600} h ${(s % 3600) / 60} min"
        }
    }
}

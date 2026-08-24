package com.fabrice.network.scanner

import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Un périphérique détecté sur le réseau. */
data class Device(
    val ip: String,
    val mac: String = "",
    val vendor: String = "",
    val hostname: String = "",
    val alive: Boolean = true,
    val isSelf: Boolean = false,
    val isGateway: Boolean = false,
    val ports: List<Int> = emptyList(),
    val os: String = "",
    val ttl: Int? = null,
    val type: String = "Inconnu",
    val banner: String = "",
    val latencyMs: Int? = null,
    val upnp: UpnpProbe.UpnpInfo? = null,
    val smbShares: List<SmbShareScanner.SmbShare> = emptyList(),
    val model: String = "",
    val product: String = "",
    val mdnsName: String = "",
    val isRandomizedMac: Boolean = false,
    val mdnsServices: List<String> = emptyList(),
    val snmpDescr: String? = null,
    val snmpName: String? = null,
    val snmpLocation: String? = null,
    val snmpUptime: Long? = null,
    val defaultCred: String? = null,
    val credTested: Boolean = false,
    /** « WiFi » / « Ethernet » si connu (via les interfaces de la box), sinon null. */
    val connectionType: String? = null,
    /** Infos/statistiques imprimante (IPP + SNMP), null si non-imprimante. Non
     *  persisté dans le dernier scan — les stats sont historisées à part
     *  (PrinterStatsStore). */
    val printer: PrinterProbe.PrinterInfo? = null
)

/** Résultat d'un ping : vivant ? + TTL de la réponse (pour l'OS) + latence. */
data class PingResult(val alive: Boolean, val ttl: Int?, val latencyMs: Int? = null)

/**
 * Scanner réseau local (type Fing).
 *
 * Stratégie (validée par tests sur réseau réel) :
 * 1. Détection du sous-réseau (NetworkInterface + masque)
 * 2. Ping sweep parallèle (binaire /system/bin/ping, fiable sans root)
 * 3. Fusion avec la table ARP (/proc/net/arp) — attrape les appareils qui
 *    ne répondent pas à l'ICMP mais ont un échange ARP récent. Double lecture
 *    espacée de ~500 ms car la table ARP Android ne garde que les échanges
 *    récents (beaucoup de MAC manquent sur une seule lecture).
 * 4. Reverse DNS pour le hostname
 * 5. Fabricant via la base OUI embarquée (assets/oui.txt), avec repli en
 *    ligne (api.macvendors.com) si le préfixe est inconnu localement.
 */
object NetworkScanner {

    fun ipToInt(ip: String): Long {
        val parts = ip.split(".").map { it.toLong() }
        return (parts[0] shl 24) or (parts[1] shl 16) or (parts[2] shl 8) or parts[3]
    }

    fun intToIp(value: Long): String =
        "${(value shr 24) and 0xFF}.${(value shr 16) and 0xFF}.${(value shr 8) and 0xFF}.${value and 0xFF}"

    /** Adresse réseau d'une IP + préfixe. */
    fun networkAddress(ip: String, prefix: Int): Long =
        if (prefix >= 32) ipToInt(ip) else (ipToInt(ip) and (0xFFFFFFFFL shl (32 - prefix)))

    /** Liste des adresses hôtes d'un sous-réseau (exclut réseau + broadcast). */
    fun hostList(ip: String, prefix: Int): List<String> {
        val net = networkAddress(ip, prefix)
        val size = 1L shl (32 - prefix)
        if (size <= 2) return emptyList()
        return (1 until size - 1).map { intToIp(net + it) }
    }

    /** Parse la table ARP : "IP MAC" pour les entrées valides. */
    fun parseArp(text: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        val ipRegex = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
        text.lineSequence().forEach { line ->
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size >= 4 && ipRegex.matches(parts[0]) &&
                parts[3] != "00:00:00:00:00:00" && parts[3] != "incomplete"
            ) {
                result[parts[0]] = parts[3].lowercase()
            }
        }
        return result
    }

    /** Lit la table ARP système et la parse (vide si le fichier est indisponible). */
    private fun readArp(): Map<String, String> =
        parseArp(runCatching { java.io.File("/proc/net/arp").readText() }.getOrDefault(""))

    /** Fusionne deux tables ARP (IP → MAC) ; la seconde est prioritaire en cas de conflit. */
    fun mergeArp(first: Map<String, String>, second: Map<String, String>): Map<String, String> {
        val merged = HashMap<String, String>(first)
        merged.putAll(second)
        return merged
    }

    /** Parse une ligne de la base OUI : "f4cae5\tVENDOR". */
    fun parseOuiLine(line: String): Pair<String, String>? {
        val idx = line.indexOf('\t')
        if (idx <= 0) return null
        val mac = line.substring(0, idx)
        if (mac.length != 6 || !mac.all { it.isDigit() || it in 'a'..'f' }) return null
        return mac to line.substring(idx + 1)
    }

    /** Préfixe OUI (6 hex) d'une MAC normalisée, ou null si la MAC est invalide. */
    fun macPrefix(mac: String): String? {
        val clean = mac.replace(":", "").replace("-", "").lowercase()
        if (clean.length < 6) return null
        val prefix = clean.substring(0, 6)
        if (!prefix.all { it.isDigit() || it in 'a'..'f' }) return null
        return prefix
    }

    /** Normalise un MAC (aa:bb:cc:dd:ee:ff → aabbcc) et cherche le fabricant. */
    fun vendorFor(mac: String, oui: Map<String, String>): String {
        val prefix = macPrefix(mac) ?: return ""
        return oui[prefix] ?: ""
    }

    /**
     * Détecte une adresse MAC localement administrée (privée / aléatoire).
     * Le bit 0x02 du premier octet (U/L) est à 1 sur les MAC randomisées
     * (Android/iOS/Win 11), jamais présentes dans les bases OUI fabricant.
     */
    fun isRandomizedMac(mac: String): Boolean {
        val p = macPrefix(mac) ?: return false
        val o = p.substring(0, 2).toIntOrNull(16) ?: return false
        return (o and 0x02) != 0
    }

    /**
     * Détecte un conteneur Docker à sa MAC : Docker attribue par défaut des
     * adresses du préfixe 02:42:xx (bridge et macvlan). Ce bit « localement
     * administré » les ferait passer pour des MAC aléatoires — on les
     * reconnaît AVANT pour les étiqueter « Docker » plutôt qu'« Adresse privée ».
     */
    fun isDockerMac(mac: String): Boolean =
        macPrefix(mac)?.startsWith("0242") == true

    /** Détecte l'IP locale + préfixe du réseau actif (Android). */
    fun detectSubnet(): Pair<String, Int>? {
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: return null
        // Interfaces VPN / mobile / tunnel à ignorer : elles masqueraient le
        // vrai sous-réseau Wi-Fi/Ethernet local quand un VPN est actif.
        val ignoredPrefixes = listOf("tun", "ppp", "rmnet", "wg", "tap", "ipsec", "pptp")
        for (iface in interfaces) {
            if (!iface.isUp || iface.isLoopback) continue
            val name = iface.name?.lowercase() ?: ""
            if (ignoredPrefixes.any { name.startsWith(it) }) continue
            for (addr in iface.interfaceAddresses) {
                val ipv4 = addr.address as? Inet4Address ?: continue
                if (ipv4.isLoopbackAddress) continue
                val prefix = addr.networkPrefixLength
                if (prefix in 16..30) return ipv4.hostAddress to prefix.toInt()
            }
        }
        return null
    }

    /** Adresse de broadcast d'un sous-réseau (IP + préfixe). */
    fun broadcastAddress(ip: String, prefix: Int): String {
        val net = networkAddress(ip, prefix)
        val size = (1L shl (32 - prefix)) - 1
        return intToIp(net or size)
    }

    /**
     * Scan complet du réseau local. Ping parallèle (64 threads), puis fusion
     * avec l'ARP (triple lecture), reverse DNS, lookup fabricant et scan de
     * ports pour les appareils en ligne.
     *
     * @param prefs SharedPreferences facultatif servant de cache persistant pour
     *   le lookup fabricant en ligne (clé « vendor_cache_<prefixe6> »). Passé
     *   par la couche UI ; null en test ou hors contexte Android.
     * @param portsToScan Liste des ports à tester (défaut : PortScanner.COMMON_PORTS).
     */
    suspend fun scan(
        oui: Map<String, String>,
        scanPorts: Boolean = true,
        prefs: SharedPreferences? = null,
        portsToScan: List<Int> = PortScanner.COMMON_PORTS.map { it.first },
        scanFast: Boolean = true,
        scanEconomy: Boolean = false,
        onProgress: (done: Int, total: Int) -> Unit
    ): List<Device> = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val subnet = detectSubnet() ?: return@withContext emptyList()
        val (ip, prefix) = subnet
        val hosts = hostList(ip, prefix)
        if (hosts.isEmpty()) return@withContext emptyList()

        val alive = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
        // Hôtes découverts par sonde de vivacité TCP (filtrent l'ICMP mais
        // exposent un port) : conteneurs Docker, serveurs/VM pare-feu, IoT.
        val tcpAlive = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
        val ttlMap = java.util.concurrent.ConcurrentHashMap<String, Int>()
        val latencyMap = java.util.concurrent.ConcurrentHashMap<String, Int>()
        val broadcastIp = broadcastAddress(ip, prefix)

        // Option « scan rapide » (scanFast, défaut ON) : lecture ANTICIPÉE de
        // l'ARP (les échanges récents sont déjà dans la table avant le ping) et
        // découvertes multicast lancées EN PARALLÈLE du ping. Optimisation
        // d'ordre seulement — la couverture finale est identique (mêmes lectures).
        val earlyArp = if (scanFast) readArp() else emptyMap<String, String>()

        // Progression sur 3 phases pour que la barre reflète le vrai travail
        // (le scan fait plus de choses qu'avant : vivacité TCP + scan de ports
        // élargi). Total = 2 vagues de ping + sonde de vivacité + enrichissement
        // (scan de ports/bannières par hôte). Les phases non exécutées (mode
        // économie) ne sont pas comptées, donc la barre atteint bien 100 %.
        val doLiveness = scanPorts && !scanEconomy
        val doEnrich = scanPorts
        val totalProbes = hosts.size * 2 +
            (if (doLiveness) hosts.size else 0) +
            (if (doEnrich) hosts.size else 0)
        val probed = java.util.concurrent.atomic.AtomicInteger(0)

        fun pingSweep() {
            // 2 vagues : la 2e rattrape les appareils lents/endormis (1re réponse
            // souvent perdue).
            repeat(2) { wave ->
                val executor = Executors.newFixedThreadPool(64)
                try {
                    hosts.forEach { host ->
                        executor.execute {
                            val r = pingHost(host)
                            if (r.alive) {
                                alive.add(host)
                                if (r.ttl != null) ttlMap[host] = r.ttl
                                if (r.latencyMs != null) latencyMap[host] = r.latencyMs
                            }
                            val done = probed.incrementAndGet()
                            if (done % 32 == 0 || done == totalProbes) {
                                onProgress(done, totalProbes)
                            }
                        }
                    }
                    executor.shutdown()
                    executor.awaitTermination(120, TimeUnit.SECONDS)
                } finally {
                    // isTerminated (et non isShutdown, déjà vrai après shutdown()) :
                    // si awaitTermination expire, on force réellement l'arrêt des
                    // threads de ping encore actifs.
                    if (!executor.isTerminated) executor.shutdownNow()
                }
                if (wave == 0) {
                    // Laisse les réponses lentes arriver avant la 2e vague.
                    Thread.sleep(1_500)
                }
            }
        }

        // Sonde de vivacité TCP : un hôte qui filtre l'ICMP (conteneur Docker,
        // serveur/VM derrière un pare-feu, IoT) n'apparaît dans AUCUNE des
        // découvertes existantes s'il n'a ni ARP récent ni service multicast.
        // Une connexion TCP acceptée sur un port courant prouve qu'il est
        // vivant — et déclenche au passage un échange ARP, donc la lecture ARP
        // qui suit récupère sa MAC. Ignore les hôtes déjà trouvés par ping.
        // Reporté en mode économie d'énergie (comme le scan de ports).
        fun tcpLivenessSweep() {
            if (!scanPorts || scanEconomy) return
            val executor = Executors.newFixedThreadPool(128)
            try {
                hosts.forEach { host ->
                    executor.execute {
                        if (host !in alive && PortScanner.isAnyPortOpen(host)) {
                            tcpAlive.add(host)
                        }
                        val done = probed.incrementAndGet()
                        if (done % 32 == 0 || done == totalProbes) onProgress(done, totalProbes)
                    }
                }
                executor.shutdown()
                executor.awaitTermination(60, TimeUnit.SECONDS)
            } finally {
                if (!executor.isTerminated) executor.shutdownNow()
            }
        }

        // Découverte multicast (UPnP/SSDP + mDNS + WS-Discovery + NetBIOS
        // broadcast) : le broadcast NetBIOS trouve les PC Windows qui filtrent
        // le ping et n'ont ni mDNS ni WSD actifs — leur IP n'était connue nulle part.
        val upnpByIp: Map<String, UpnpProbe.UpnpInfo>
        val mdnsByIp: Map<String, MdnsResolver.MdnsInfo>
        val wsdByIp: Map<String, WsdResolver.WsdInfo>
        val nbnsByIp: Map<String, NbnsResolver.NbnsInfo>
        coroutineScope {
            val upnp = async(Dispatchers.IO) { UpnpProbe.discover() }
            val mdns = async(Dispatchers.IO) { MdnsResolver.discover() }
            val wsd = async(Dispatchers.IO) { WsdResolver.discover() }
            val nbns = async(Dispatchers.IO) { NbnsResolver.discover(broadcastIp) }
            if (scanFast) {
                // Multicast déjà lancé → ping en parallèle.
                pingSweep()
            }
            upnpByIp = upnp.await()
            mdnsByIp = mdns.await()
            wsdByIp = wsd.await()
            nbnsByIp = nbns.await()
            if (!scanFast) {
                // Ordre historique : découvertes multicast d'abord, ping ensuite.
                pingSweep()
            }
            // Après le ping (avant les lectures ARP décalées ci-dessous) : la
            // sonde TCP peuple la table ARP pour les hôtes ICMP-silencieux.
            tcpLivenessSweep()
        }

        // Fusion ping + table ARP — TRIPLE lecture espacée : la table ARP
        // Android ne contient que les échanges récents, et un appareil qui
        // filtre ICMP n'apparaît qu'après un échange ARP. Trois lectures à
        // ~700 ms captent plus de MAC que deux (périphériques cachés). En scan
        // rapide, la lecture anticipée compte pour la première.
        val arp = if (scanFast) {
            mergeArp(mergeArp(earlyArp, run {
                kotlinx.coroutines.delay(700)
                readArp()
            }), run {
                kotlinx.coroutines.delay(700)
                readArp()
            })
        } else {
            mergeArp(mergeArp(readArp(), run {
                kotlinx.coroutines.delay(700)
                readArp()
            }), run {
                kotlinx.coroutines.delay(700)
                readArp()
            })
        }
        // Table ARP de la PASSERELLE via SNMP (ipNetToMediaPhysAddress) :
        // agnostique à la marque, elle donne IP→MAC pour tout le réseau si le
        // routeur expose SNMP — comble le vide de /proc/net/arp sur Android 10+.
        // La table système reste prioritaire ; le SNMP comble les manques.
        val gatewayForArp = NetworkInfoProvider.readGateway()
        val snmpArp = if (scanPorts && !scanEconomy && gatewayForArp.isNotBlank()) {
            runCatching { gatewayArpViaSnmp(gatewayForArp) }.getOrDefault(emptyMap())
        } else emptyMap()
        val arpAll = mergeArp(snmpArp, arp)

        val allIps = (alive + tcpAlive + arpAll.keys + mdnsByIp.keys + wsdByIp.keys + upnpByIp.keys + nbnsByIp.keys).toSortedSet()

        // Cache en mémoire des fabricants résolus en ligne : évite d'interroger
        // deux fois le même préfixe OUI au cours d'un même scan.
        val vendorCache = HashMap<String, String>()

        val localIp = ip
        val gatewayIp = NetworkInfoProvider.readGateway()
        val baseDevices = allIps.map { host ->
            var mac = arpAll[host] ?: ""
            var hostname = reverseDns(host)
            // Hôte « vivant » : a répondu au ping OU à une découverte multicast
            // (mDNS/WSD/UPnP) OU au broadcast NetBIOS. Un appareil qui répond
            // est forcément en ligne — il mérite le scan de ports et le statut.
            val responded = alive.contains(host) || tcpAlive.contains(host) ||
                host in mdnsByIp || host in wsdByIp || host in upnpByIp || host in nbnsByIp
            // Toujours inclure les ports web/conteneurs (TCP_PING_PORTS) en plus
            // du mode choisi : un serveur web conteneurisé sur 5000/8096/8123…
            // doit apparaître même en mode Standard (16 ports), sinon l'hôte est
            // listé « sans service » et le conteneur passe inaperçu.
            val effectivePorts = if (scanPorts && responded) {
                (portsToScan + PortScanner.TCP_PING_PORTS).distinct()
            } else emptyList()
            val ports = if (effectivePorts.isNotEmpty()) {
                PortScanner.scanPorts(host, effectivePorts)
            } else emptyList()

            // NBNS : d'abord le résultat du broadcast (déjà connu), puis une
            // requête unicast ciblée si besoin. Complète hostname + MAC.
            val broadcastNbns = nbnsByIp[host]
            val nbns = broadcastNbns ?: if (responded && (hostname.isBlank() || 137 in ports || 139 in ports)) {
                runCatching { NbnsResolver.query(host) }.getOrNull()
            } else null
            if (nbns != null) {
                if (mac.isBlank() && nbns.mac.isNotBlank()) mac = nbns.mac
                if (hostname.isBlank() && nbns.name.isNotBlank()) hostname = nbns.name
            }

            // MAC via SNMP (ifPhysAddress) quand elle manque encore : sur Android
            // 10+ la table ARP système est vide, mais un appareil qui expose SNMP
            // (imprimante, NAS, routeur pro…) publie sa MAC. Seulement si le port
            // 161 est ouvert, jamais bloquant, reporté en mode économie.
            if (mac.isBlank() && responded && 161 in ports && !scanEconomy) {
                mac = runCatching { snmpMac(host) }.getOrNull().orEmpty()
            }

            // MAC Docker (02:42) → fabricant « Docker » : détecté AVANT le test
            // « aléatoire » (le bit localement administré est aussi à 1 sur ces
            // MAC) et jamais résolu en ligne (préfixe absent des bases OUI).
            // Sinon MAC localement administrée → « Adresse privée ».
            val docker = isDockerMac(mac)
            val randomized = !docker && isRandomizedMac(mac)
            var vendor = when {
                docker -> "Docker"
                randomized -> "Adresse privée"
                else -> vendorFor(mac, oui)
            }
            if (!docker && !randomized && vendor.isBlank() && mac.isNotBlank()) {
                vendor = VendorLookup.lookup(mac, vendorCache, prefs) ?: ""
            }

            // Banner grab : interroge les services ouverts (HTTP/SSH/FTP/SMTP…)
            // pour préciser l'OS réel et enrichir la fiche appareil.
            val banner = if (responded) grabService(host, ports) else ""
            val os = OsFingerprint.guess(ttlMap[host], ports, hostname, banner.ifBlank { null })
            // Partages SMB (dossiers partagés, y compris cachés $) — seulement si
            // le port 445 est ouvert, jamais bloquant (runCatching). Économie
            // d'énergie (scanEconomy) : reporté à l'analyse complète manuelle.
            val smbShares = if (responded && 445 in ports && !scanEconomy) {
                runCatching { SmbShareScanner.scanShares(host, timeoutMs = 1_500) }
                    .getOrDefault(emptyList())
            } else emptyList()
            // SNMPv1 (sysDescr/sysName/sysLocation/uptime) — seulement si le port
            // 161 est ouvert (détecté par le scan de ports élargi). runCatching +
            // timeout court, jamais bloquant. Économie d'énergie : reporté.
            val snmp = if (responded && 161 in ports && !scanEconomy) {
                runCatching { SnmpScanner.probeBlocking(host) }.getOrNull()
            } else null
            // Infos UPnP éventuelles (friendlyName, fabricant, modèle…)
            var upnp = upnpByIp[host]
            if (upnp != null && upnp.location.isNotBlank() && !upnp.hasInfo) {
                upnp = UpnpProbe.fetchDescription(upnp.location)
            }

            // mDNS + fingerprint banner + WS-Discovery : enrichissent le
            // produit/modèle/nom et le type d'appareil.
            val md = mdnsByIp[host]
            val wsd = wsdByIp[host]
            val fp = ServiceFingerprint.identify(banner)
            val nmap = NmapSignatures.identify(listOf(banner))
            // Imprimante : IPP (modèle exact « printer-make-and-model ») + SNMP
            // (compteur de pages, consommables). Seulement si un port imprimante
            // est ouvert, jamais bloquant. Reporté en mode économie d'énergie.
            val printer = if (responded && !scanEconomy &&
                (631 in ports || 9100 in ports || 515 in ports)
            ) {
                runCatching { PrinterProbe.probe(host) }.getOrNull()?.takeIf { it.hasData }
            } else null
            val product = firstNonBlank(
                printer?.makeAndModel, fp?.product, nmap?.displayName(), md?.model, upnp?.modelName
            ).orEmpty()
            val model = firstNonBlank(md?.model, upnp?.modelName, printer?.makeAndModel).orEmpty()
            if (hostname.isBlank()) {
                hostname = firstNonBlank(md?.name, upnp?.friendlyName).orEmpty()
            }
            val classified = DeviceType.classify(vendor, hostname, ports, os)
            val type = if (classified == "Inconnu") {
                firstNonBlank(md?.deviceHint, wsd?.deviceHint, fp?.type).orEmpty()
                    .ifBlank { classified }
            } else classified

            val built = Device(
                ip = host,
                mac = mac,
                vendor = vendor,
                hostname = hostname,
                alive = responded,
                isSelf = host == localIp,
                isGateway = host == gatewayIp,
                ports = ports,
                ttl = ttlMap[host],
                os = os,
                type = type,
                banner = banner,
                latencyMs = latencyMap[host],
                upnp = upnp,
                smbShares = smbShares,
                model = model,
                product = product,
                mdnsName = md?.name ?: "",
                isRandomizedMac = randomized,
                mdnsServices = md?.services ?: emptyList(),
                snmpDescr = snmp?.descr,
                snmpName = snmp?.name,
                snmpLocation = snmp?.location,
                snmpUptime = snmp?.uptimeSeconds,
                printer = printer
            )
            // Progression de la phase d'enrichissement (un hôte traité).
            if (doEnrich) {
                val done = probed.incrementAndGet()
                if (done % 4 == 0 || done >= totalProbes) {
                    onProgress(done.coerceAtMost(totalProbes), totalProbes)
                }
            }
            built
            // Tri : le périphérique qui lance le scan (isSelf) TOUT EN HAUT,
            // puis les autres par IP.
        }.sortedWith(
            compareByDescending<Device> { it.isSelf }
                .thenBy { it.ip }
        )
        // La phase d'enrichissement ne traite que les hôtes vivants (≤ hosts.size)
        // → on force la barre à 100 % une fois la liste construite.
        onProgress(totalProbes, totalProbes)

        // --- Feature 7 : test des mots de passe par défaut (services web) ---
        // Après le scan, en parallèle, pour chaque appareil vivant avec un port
        // web ouvert. Non-bloquant : runCatching + Dispatchers.IO. Économie
        // d'énergie (scanEconomy) : reporté à l'analyse complète manuelle.
        val webDevices = if (scanEconomy) emptyList()
        else baseDevices.filter { it.alive && DefaultCredsChecker.webPort(it) != null }
        val credsByIp: Map<String, String?> = if (webDevices.isEmpty()) emptyMap() else {
            coroutineScope {
                webDevices.map { d ->
                    async(Dispatchers.IO) {
                        val found = runCatching {
                            DefaultCredsChecker.checkDevice(d) { ip, port, u, p ->
                                DefaultCredsChecker.basicAuthStatus(ip, port, u, p)
                            }
                        }.getOrNull()
                        d.ip to found
                    }
                }.associate { it.await() }
            }
        }
        baseDevices.map { d ->
            when {
                d.ip in credsByIp -> d.copy(defaultCred = credsByIp[d.ip], credTested = true)
                d.alive && DefaultCredsChecker.webPort(d) != null -> d.copy(credTested = true)
                else -> d
            }
        }
    }

    /**
     * Interroge les services ouverts pour lire une bannière identifiante.
     * Priorité : HTTP (en-tête Server) puis SSH puis services texte (FTP…).
     * Retourne la bannière brute (« Server: nginx/1.18 », « SSH-2.0-… »…).
     */
    private fun grabService(host: String, ports: List<Int>): String {
        // HTTP : essaie les ports web connus parmi ceux ouverts
        for (port in BannerGrab.HTTP_PORTS) {
            if (port in ports) {
                BannerGrab.httpServerHeader(host, port)?.let { return "Server: $it" }
            }
        }
        // SSH : bannière d'identification
        if (22 in ports) {
            BannerGrab.sshBanner(host)?.let { return it }
        }
        // Services texte : FTP, SMTP, POP3, IMAP, Telnet
        for ((port, _) in BannerGrab.OTHER_SERVICES) {
            if (port in ports) {
                BannerGrab.textBanner(host, port)?.let { return it }
            }
        }
        // Imprimantes : IPP (631) / JetDirect (9100) → le modèle de l'imprimante
        // (ex: « HP LaserJet MFP E57540 ») — c'est ce qui permet d'identifier
        // l'appareil précisément comme Fing.
        if (BannerGrab.PRINTER_PORTS.any { it in ports }) {
            BannerGrab.printerBanner(host)?.let { return "Imprimante: $it" }
        }
        return ""
    }

    private fun pingHost(host: String): PingResult {
        return try {
            val process = ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "3", host)
                .redirectErrorStream(true)
                .start()
            // Lire la sortie AVANT waitFor : un tampon plein peut bloquer le
            // process si on attend d'abord sa terminaison. Avec -c 1 -W 1 le
            // ping sort en ~1 s max, donc readText() ne peut pas pendre.
            val output = runCatching {
                process.inputStream.bufferedReader().use { it.readText() }
            }.getOrDefault("")
            val ok = runCatching { process.waitFor(3, TimeUnit.SECONDS) && process.exitValue() == 0 }
                .getOrDefault(false)
            runCatching { process.destroy() }
            val ttl = parseTtl(output)
            val latency = parseLatency(output)
            PingResult(ok, ttl, latency)
        } catch (e: Exception) {
            PingResult(false, null)
        }
    }

    /** Extrait le TTL de la sortie ping (« ttl=64 »). */
    fun parseTtl(pingOutput: String): Int? =
        Regex("ttl=(\\d+)").find(pingOutput)?.groupValues?.get(1)?.toIntOrNull()

    /** Extrait la latence de la sortie ping (« time=2.34 ms », « time<1 ms »). */
    fun parseLatency(pingOutput: String): Int? {
        val m = Regex("time[=<]([0-9.]+)").find(pingOutput) ?: return null
        val v = m.groupValues[1].toDoubleOrNull() ?: return null
        return if (v < 1) 1 else v.toInt()
    }

    // Pool dédié (threads démons) pour borner chaque résolution PTR : sans nom
    // inverse, InetAddress.getHostName() bloque plusieurs secondes (retries du
    // resolver système). Multiplié par des dizaines d'IP en série, cela ajoutait
    // des minutes au scan.
    private val dnsExecutor = Executors.newCachedThreadPool { r ->
        Thread(r, "revdns").apply { isDaemon = true }
    }

    private fun reverseDns(host: String): String {
        return try {
            val future = dnsExecutor.submit(java.util.concurrent.Callable {
                val name = InetAddress.getByName(host).hostName ?: ""
                if (name == host) "" else name
            })
            try {
                future.get(700, TimeUnit.MILLISECONDS)
            } catch (e: Exception) {
                future.cancel(true)
                ""
            }
        } catch (e: Exception) {
            ""
        }
    }

    /** Premier élément non vide/non blanc d'une liste de valeurs, ou null. */
    private fun firstNonBlank(vararg values: String?): String? =
        values.firstOrNull { !it.isNullOrBlank() }?.trim()

    /**
     * MAC via SNMP (OID ifPhysAddress `1.3.6.1.2.1.2.2.1.6.<ifIndex>`). Interroge
     * les premiers index d'interface et retourne la première MAC valide. « » si
     * l'agent ne répond pas ou n'expose pas de MAC. À appeler depuis un thread IO.
     */
    private fun snmpMac(host: String): String {
        val oids = listOf(
            "1.3.6.1.2.1.2.2.1.6.1",
            "1.3.6.1.2.1.2.2.1.6.2",
            "1.3.6.1.2.1.2.2.1.6.3"
        )
        val vbs = SnmpScanner.getOids(host, oids, 1_500)
        for (oid in oids) {
            val raw = vbs[oid]?.raw ?: continue
            formatMac(raw)?.let { return it }
        }
        return ""
    }

    /** Formate 6 octets bruts en MAC « aa:bb:cc:dd:ee:ff » ; null si invalide/nulle. */
    fun formatMac(raw: ByteArray): String? {
        if (raw.size != 6) return null
        if (raw.all { it.toInt() == 0 }) return null
        return raw.joinToString(":") { "%02x".format(it.toInt() and 0xFF) }
    }

    /** OID SNMP de la table ARP (ipNetToMediaPhysAddress) : IP → MAC. */
    const val OID_IP_NET_TO_MEDIA = "1.3.6.1.2.1.4.22.1.2"

    /**
     * Lit la table ARP de la passerelle via SNMP (walk de ipNetToMediaPhysAddress)
     * → map IP → MAC. Agnostique à la marque. Vide si le routeur n'expose pas
     * SNMP. À appeler depuis un thread IO.
     */
    private fun gatewayArpViaSnmp(gatewayIp: String): Map<String, String> {
        val rows = SnmpScanner.walk(gatewayIp, OID_IP_NET_TO_MEDIA)
        val out = HashMap<String, String>()
        for (vb in rows) {
            parseArpRow(vb.oid, vb.raw)?.let { (ip, mac) -> out[ip] = mac }
        }
        return out
    }

    /**
     * Extrait (IP, MAC) d'une ligne ipNetToMediaPhysAddress : l'OID se termine
     * par « .<ifIndex>.a.b.c.d » et la valeur est la MAC (6 octets). null si
     * la ligne n'est pas exploitable. Fonction pure — testable.
     */
    fun parseArpRow(oid: String, raw: ByteArray): Pair<String, String>? {
        if (!oid.startsWith("$OID_IP_NET_TO_MEDIA.")) return null
        val suffix = oid.removePrefix("$OID_IP_NET_TO_MEDIA.").split(".")
        if (suffix.size < 5) return null
        val ipParts = suffix.takeLast(4)
        if (ipParts.any { (it.toIntOrNull() ?: -1) !in 0..255 }) return null
        val mac = formatMac(raw) ?: return null
        return ipParts.joinToString(".") to mac
    }
}

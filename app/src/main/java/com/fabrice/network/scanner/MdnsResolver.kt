package com.fabrice.network.scanner

import java.net.DatagramPacket
import java.net.InetAddress
import java.net.MulticastSocket
import java.net.NetworkInterface

/**
 * Découverte mDNS / Bonjour / DNS-SD (comme Fing).
 *
 * C'est la technique qui manquait le plus par rapport à Fing : la plupart des
 * appareils grand public annoncent leur NOM et leur MODÈLE en multicast DNS
 * (224.0.0.251:5353) — iPhone/Mac, Apple TV, imprimantes, Chromecast/Google TV,
 * enceintes, NAS, HomeKit… Le scan de ports ou l'ARP ne donnent jamais ça.
 *
 * Fonctionnement (une seule salve, non intrusif, sans root) :
 * 1. Envoi d'UNE requête multicast contenant plusieurs questions PTR pour les
 *    types de service les plus courants (_googlecast, _airplay, _ipp, _smb…).
 * 2. Écoute des réponses pendant [timeoutMs]. Chaque appareil répond avec un
 *    paquet groupant PTR + SRV + TXT + A. La clé fiable est l'IP SOURCE du
 *    paquet UDP.
 * 3. Extraction, par IP : nom convivial, modèle, type d'appareil déduit.
 *
 * ⚠️ Android : l'appelant DOIT tenir un MulticastLock actif pendant l'appel
 *    (WifiManager.createMulticastLock(...).acquire()), sinon le noyau filtre
 *    les paquets multicast entrants.
 *
 * Les fonctions de parsing (parseMessage / extract) sont pures et testables.
 */
object MdnsResolver {

    private const val MDNS_ADDR = "224.0.0.251"
    private const val MDNS_PORT = 5353

    /** Résultat mDNS agrégé pour une IP. */
    data class MdnsInfo(
        val name: String = "",        // nom convivial (ex: « Salon », « HP LaserJet »)
        val model: String = "",       // modèle matériel (ex: « MacBookPro18,1 », « Chromecast »)
        val services: List<String> = emptyList(), // types de service annoncés
        val deviceHint: String = ""   // type déduit (Imprimante, TV / Media, NAS…)
    ) {
        val hasInfo: Boolean get() = name.isNotBlank() || model.isNotBlank()
    }

    /**
     * Types de service DNS-SD interrogés en une seule requête.
     * Choisis pour couvrir le maximum d'appareils domestiques identifiables.
     */
    private val SERVICE_TYPES = listOf(
        "_googlecast._tcp.local",       // Chromecast, Google/Android TV, Nest
        "_airplay._tcp.local",          // Apple TV, AirPlay
        "_raop._tcp.local",             // AirPlay audio (enceintes, HomePod)
        "_companion-link._tcp.local",   // appareils Apple (iPhone/iPad/Mac)
        "_device-info._tcp.local",      // macOS/iOS : modèle exact (TXT model=)
        "_homekit._tcp.local",          // accessoires HomeKit
        "_hap._tcp.local",              // HomeKit Accessory Protocol
        "_ipp._tcp.local",             // imprimantes (IPP)
        "_ipps._tcp.local",            // imprimantes (IPP sécurisé)
        "_pdl-datastream._tcp.local",   // imprimantes (JetDirect 9100)
        "_printer._tcp.local",          // imprimantes (LPD)
        "_scanner._tcp.local",          // scanners/MFP
        "_smb._tcp.local",             // partages Windows / NAS
        "_afpovertcp._tcp.local",       // partages Apple / NAS
        "_nvstream._tcp.local",         // NVIDIA Shield / GeForce
        "_spotify-connect._tcp.local",  // enceintes Spotify Connect
        "_sonos._tcp.local",           // Sonos
        "_amzn-wplay._tcp.local",       // Amazon Fire TV / Echo
        "_workstation._tcp.local",      // hôtes Linux (avahi)
        "_http._tcp.local",            // interfaces web (box, NAS, IoT)
        "_ssh._tcp.local",             // hôtes SSH annoncés
        "_googlezone._tcp.local"        // groupes Google/Nest
    )

    /** Types de requête DNS utilisés. */
    private const val TYPE_A = 1
    private const val TYPE_PTR = 12
    private const val TYPE_TXT = 16
    private const val TYPE_SRV = 33

    /**
     * Lance la découverte. Retourne les infos par IP source.
     * Ne lève jamais d'exception (retourne une map éventuellement vide).
     */
    fun discover(timeoutMs: Int = 3_000): Map<String, MdnsInfo> {
        val perIp = HashMap<String, MutableRecord>()
        var socket: MulticastSocket? = null
        try {
            // Socket non lié → reuseAddress AVANT bind (sinon le port 5353,
            // souvent tenu par le résolveur mDNS système, refuse le partage).
            socket = MulticastSocket(null as java.net.SocketAddress?).apply {
                reuseAddress = true
                bind(java.net.InetSocketAddress(MDNS_PORT))
                soTimeout = 400
                // Rejoint le groupe sur l'interface Wi-Fi active si possible.
                runCatching {
                    val iface = activeMulticastInterface()
                    if (iface != null) networkInterface = iface
                }
                runCatching { joinGroup(InetAddress.getByName(MDNS_ADDR)) }
            }

            val query = buildQuery(SERVICE_TYPES)
            runCatching {
                socket.send(DatagramPacket(query, query.size, InetAddress.getByName(MDNS_ADDR), MDNS_PORT))
            }

            val buffer = ByteArray(9000)
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(packet)
                } catch (e: java.net.SocketTimeoutException) {
                    continue // on relance jusqu'au deadline (réponses tardives)
                }
                val ip = packet.address?.hostAddress ?: continue
                val records = runCatching {
                    parseMessage(packet.data.copyOf(packet.length))
                }.getOrNull() ?: continue
                val acc = perIp.getOrPut(ip) { MutableRecord() }
                acc.absorb(records)
            }
        } catch (e: Exception) {
            // socket 5353 indisponible (NsdManager système) ou pas de réseau :
            // on rend ce qu'on a déjà collecté.
        } finally {
            runCatching { socket?.leaveGroup(InetAddress.getByName(MDNS_ADDR)) }
            runCatching { socket?.close() }
        }

        return perIp.mapValues { (_, rec) -> extract(rec) }
            .filterValues { it.hasInfo || it.services.isNotEmpty() }
    }

    // ----------------------------------------------------------------------
    //  Construction de la requête DNS (multi-questions)
    // ----------------------------------------------------------------------

    /** Encode une requête mDNS PTR pour tous les [types] en un seul paquet. */
    fun buildQuery(types: List<String>): ByteArray {
        val out = ArrayList<Byte>(512)
        fun u16(v: Int) { out.add((v ushr 8).toByte()); out.add(v.toByte()) }
        // En-tête : ID=0, flags=0, QDCOUNT=types.size, AN/NS/AR=0
        u16(0); u16(0); u16(types.size); u16(0); u16(0); u16(0)
        for ((i, t) in types.withIndex()) {
            for (label in t.split(".")) {
                if (label.isEmpty()) continue
                val bytes = label.toByteArray(Charsets.UTF_8)
                out.add(bytes.size.toByte())
                out.addAll(bytes.toList())
            }
            out.add(0) // fin du nom
            u16(TYPE_PTR)
            // QCLASS IN (0x0001) ; bit QU (0x8000) sur la 1re question pour
            // encourager une réponse unicast (meilleure réception sur Android).
            u16(if (i == 0) 0x8001 else 0x0001)
        }
        return out.toByteArray()
    }

    // ----------------------------------------------------------------------
    //  Parsing des réponses DNS (avec décompression de noms)
    // ----------------------------------------------------------------------

    /** Un enregistrement DNS décodé (le minimum utile). */
    data class DnsRecord(val name: String, val type: Int, val data: RecordData)

    sealed interface RecordData {
        data class A(val ip: String) : RecordData
        data class Ptr(val target: String) : RecordData
        data class Srv(val target: String, val port: Int) : RecordData
        data class Txt(val pairs: Map<String, String>) : RecordData
        object Other : RecordData
    }

    /** Parse un message DNS complet → liste d'enregistrements exploitables. */
    fun parseMessage(msg: ByteArray): List<DnsRecord> {
        if (msg.size < 12) return emptyList()
        fun u16(off: Int) = ((msg[off].toInt() and 0xFF) shl 8) or (msg[off + 1].toInt() and 0xFF)
        val qd = u16(4); val an = u16(6); val ns = u16(8); val ar = u16(10)
        var off = 12
        // Sauter les questions
        repeat(qd) {
            val (_, next) = readName(msg, off)
            off = next + 4 // QTYPE + QCLASS
        }
        val records = ArrayList<DnsRecord>()
        val totalRr = an + ns + ar
        repeat(totalRr) {
            if (off + 10 > msg.size) return records
            val (name, afterName) = readName(msg, off)
            var p = afterName
            // Le nom est de longueur variable : re-vérifier la borne sur l'offset
            // réel de lecture (p) avant de lire les 10 octets TYPE/CLASS/TTL/RDLEN,
            // sinon un paquet forgé/tronqué provoque un IndexOutOfBounds.
            if (p + 10 > msg.size) return records
            val type = u16(p); p += 2
            p += 2 // CLASS
            p += 4 // TTL
            val rdlen = u16(p); p += 2
            if (p + rdlen > msg.size) return records
            val data: RecordData = when (type) {
                TYPE_A -> if (rdlen == 4)
                    RecordData.A("${msg[p].toInt() and 0xFF}.${msg[p + 1].toInt() and 0xFF}." +
                        "${msg[p + 2].toInt() and 0xFF}.${msg[p + 3].toInt() and 0xFF}")
                else RecordData.Other
                TYPE_PTR -> RecordData.Ptr(readName(msg, p).first)
                TYPE_SRV -> {
                    val port = u16(p + 4)
                    RecordData.Srv(readName(msg, p + 6).first, port)
                }
                TYPE_TXT -> RecordData.Txt(parseTxt(msg, p, rdlen))
                else -> RecordData.Other
            }
            records.add(DnsRecord(name, type, data))
            off = p + rdlen
        }
        return records
    }

    /** Lit un nom DNS (avec pointeurs de compression 0xC0). Retourne (nom, offset après le nom dans le flux). */
    private fun readName(msg: ByteArray, start: Int): Pair<String, Int> {
        val labels = ArrayList<String>()
        var off = start
        var jumped = false
        var afterPointer = start
        var guard = 0
        while (off < msg.size && guard++ < 128) {
            val len = msg[off].toInt() and 0xFF
            when {
                len == 0 -> { off += 1; if (!jumped) afterPointer = off; break }
                len and 0xC0 == 0xC0 -> {
                    if (off + 1 >= msg.size) break
                    val ptr = ((len and 0x3F) shl 8) or (msg[off + 1].toInt() and 0xFF)
                    if (!jumped) afterPointer = off + 2
                    jumped = true
                    off = ptr
                }
                else -> {
                    if (off + 1 + len > msg.size) break
                    labels.add(String(msg, off + 1, len, Charsets.UTF_8))
                    off += 1 + len
                }
            }
        }
        return labels.joinToString(".") to afterPointer
    }

    /** Parse une valeur TXT (suite de chaînes « clé=valeur » longueur-préfixées). */
    private fun parseTxt(msg: ByteArray, start: Int, len: Int): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        var off = start
        val end = start + len
        while (off < end) {
            val l = msg[off].toInt() and 0xFF
            off += 1
            if (l == 0 || off + l > end) { off += l; continue }
            val s = String(msg, off, l, Charsets.UTF_8)
            off += l
            val eq = s.indexOf('=')
            if (eq > 0) map[s.substring(0, eq).lowercase()] = s.substring(eq + 1)
            else if (s.isNotBlank()) map[s.lowercase()] = ""
        }
        return map
    }

    // ----------------------------------------------------------------------
    //  Agrégation par IP → infos exploitables
    // ----------------------------------------------------------------------

    /** Accumulateur mutable des enregistrements reçus pour une IP. */
    class MutableRecord {
        val ptrTargets = ArrayList<String>()
        val txt = LinkedHashMap<String, String>()
        val serviceTypes = LinkedHashSet<String>()

        fun absorb(records: List<DnsRecord>) {
            for (r in records) {
                when (val d = r.data) {
                    is RecordData.Ptr -> {
                        ptrTargets.add(d.target)
                        serviceTypeOf(r.name)?.let { serviceTypes.add(it) }
                        serviceTypeOf(d.target)?.let { serviceTypes.add(it) }
                    }
                    is RecordData.Srv -> serviceTypeOf(r.name)?.let { serviceTypes.add(it) }
                    is RecordData.Txt -> {
                        d.pairs.forEach { (k, v) -> if (k !in txt) txt[k] = v }
                        serviceTypeOf(r.name)?.let { serviceTypes.add(it) }
                    }
                    else -> {}
                }
                serviceTypeOf(r.name)?.let { serviceTypes.add(it) }
            }
        }
    }

    /** Extrait le nom de service court (_ipp, _googlecast…) d'un nom DNS complet. */
    private fun serviceTypeOf(name: String): String? {
        val m = Regex("(_[a-z0-9-]+)\\._(tcp|udp)").find(name.lowercase()) ?: return null
        return m.groupValues[1]
    }

    /** Instance conviviale : 1er label avant le type de service (« Salon._googlecast… » → « Salon »). */
    private fun instanceNameOf(target: String): String {
        val idx = target.indexOf("._")
        val raw = if (idx > 0) target.substring(0, idx) else target.substringBefore(".local").substringBefore(".")
        // DNS-SD échappe les espaces en « \032 » et les points en « \. »
        return raw.replace("\\032", " ").replace("\\.", ".").replace("\\ ", " ").trim()
    }

    /** Calcule les infos finales à partir des enregistrements accumulés. */
    fun extract(rec: MutableRecord): MdnsInfo {
        val t = rec.txt
        // Modèle : clés TXT connues, par ordre de fiabilité selon le type d'appareil.
        val model = firstNonBlank(
            t["model"],        // macOS/iOS _device-info : « MacBookPro18,1 »
            t["md"],           // Chromecast / Google : « Chromecast », « Google Nest… »
            t["am"],           // AirPlay : modèle Apple (« AppleTV6,2 »)
            t["ty"],           // imprimantes IPP : « HP LaserJet MFP M28w »
            t["usb_mdl"],      // imprimantes : modèle USB
            t["product"]?.trim('(', ')')
        )
        // Nom convivial : TXT fn/n, sinon 1re instance PTR lisible.
        val name = firstNonBlank(
            t["fn"],           // Chromecast : nom donné par l'utilisateur (« Salon »)
            t["n"],            // certains appareils : nom
            rec.ptrTargets.map { instanceNameOf(it) }.firstOrNull { it.isNotBlank() && !it.startsWith("_") }
        )
        val hint = deviceHint(rec.serviceTypes)
        return MdnsInfo(
            name = name.orEmpty().take(60),
            model = model.orEmpty().take(60),
            services = rec.serviceTypes.toList(),
            deviceHint = hint
        )
    }

    /** Déduit un type d'appareil (aligné sur DeviceType) depuis les services annoncés. */
    fun deviceHint(services: Set<String>): String = when {
        services.any { it in setOf("_ipp", "_ipps", "_pdl-datastream", "_printer", "_scanner") } -> "Imprimante"
        services.any { it in setOf("_googlecast", "_airplay", "_amzn-wplay", "_nvstream") } -> "TV / Media"
        services.any { it in setOf("_raop", "_spotify-connect", "_sonos") } -> "Enceinte"
        services.any { it in setOf("_smb", "_afpovertcp") } -> "NAS"
        services.any { it in setOf("_homekit", "_hap") } -> "IoT"
        services.contains("_workstation") -> "Ordinateur"
        else -> ""
    }

    private fun firstNonBlank(vararg values: String?): String? =
        values.firstOrNull { !it.isNullOrBlank() }?.trim()

    /** Interface multicast active (Wi-Fi de préférence). */
    private fun activeMulticastInterface(): NetworkInterface? {
        return try {
            NetworkInterface.getNetworkInterfaces().toList().firstOrNull { iface ->
                iface.isUp && !iface.isLoopback && iface.supportsMulticast() &&
                    iface.interfaceAddresses.any { it.address is java.net.Inet4Address }
            }
        } catch (e: Exception) {
            null
        }
    }
}

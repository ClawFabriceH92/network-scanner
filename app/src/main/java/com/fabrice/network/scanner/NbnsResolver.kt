package com.fabrice.network.scanner

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Résolution de nom NetBIOS (NBNS) — récupère le nom des machines Windows
 * (et la MAC de l'adaptateur en bonus) via une requête NBSTAT unicast sur
 * le port UDP 137.
 *
 * C'est le complément idéal de l'ARP sur Android 10+ : quand la table ARP ne
 * livre pas la MAC, la réponse NBSTAT contient l'adresse de l'adaptateur dans
 * son bloc de statistiques.
 *
 * Le parsing (parseNbstatResponse) et l'encodage (encodeNetbiosName /
 * buildNbstatQuery) sont PURS et testables ; seule query() fait de l'I/O et ne
 * lève jamais d'exception (retourne null en cas d'échec).
 */
object NbnsResolver {

    /** Résultat d'une requête NBSTAT. */
    data class NbnsInfo(val name: String = "", val mac: String = "") {
        val hasInfo: Boolean get() = name.isNotBlank() || mac.isNotBlank()
    }

    private const val PORT = 137
    private const val QTYPE_NBSTAT = 0x0021
    private const val QCLASS_IN = 0x0001

    /**
     * Encode un nom NetBIOS de 16 octets en « premier niveau » (32 octets) :
     * chaque octet est éclaté en deux demi-octets, chacun décalé de 'A'.
     */
    fun encodeNetbiosName(name: ByteArray): ByteArray {
        require(name.size == 16) { "Un nom NetBIOS fait exactement 16 octets" }
        val out = ByteArray(32)
        for (i in 0 until 16) {
            val b = name[i].toInt() and 0xFF
            out[i * 2] = ((b shr 4) + 'A'.code).toByte()
            out[i * 2 + 1] = ((b and 0x0F) + 'A'.code).toByte()
        }
        return out
    }

    /**
     * Construit la requête NBSTAT (node status) pour le nom « * » (tous les
     * noms de la machine). En-tête DNS-like : TransactionID, Flags 0, QDCOUNT=1,
     * puis le nom encodé (longueur 0x20 + 32 octets + 0x00), QTYPE NBSTAT.
     */
    fun buildNbstatQuery(transactionId: Int = 0x1234): ByteArray {
        val out = ArrayList<Byte>(50)
        fun u16(v: Int) {
            out.add((v ushr 8).toByte())
            out.add(v.toByte())
        }
        u16(transactionId)          // Transaction ID
        u16(0x0000)                 // Flags
        u16(0x0001)                 // QDCOUNT = 1
        u16(0); u16(0); u16(0)      // ANCOUNT / NSCOUNT / ARCOUNT = 0
        val name = ByteArray(16)
        name[0] = '*'.code.toByte() // « * » = n'importe quel nom
        val encoded = encodeNetbiosName(name)
        out.add(0x20)               // longueur du nom encodé (32 octets)
        for (b in encoded) out.add(b)
        out.add(0)                  // fin du nom
        u16(QTYPE_NBSTAT)           // QTYPE NBSTAT
        u16(QCLASS_IN)              // QCLASS IN
        return out.toByteArray()
    }

    /**
     * Parse une réponse NBSTAT brute et en extrait :
     *  - le premier nom UNIQUE (bit « group » à 0) portant le suffixe <00>
     *    (station de travail) ou <20> (serveur de fichiers) → nom machine ;
     *  - en bonus, la MAC de l'adaptateur (6 derniers octets du bloc de
     *    statistiques).
     * Retourne null si le paquet est invalide ou sans nom exploitable.
     */
    fun parseNbstatResponse(data: ByteArray): NbnsInfo? {
        if (data.size < 12) return null
        fun u16(off: Int) =
            ((data[off].toInt() and 0xFF) shl 8) or (data[off + 1].toInt() and 0xFF)
        val qd = u16(4)
        val an = u16(6)
        if (an < 1) return null

        var off = 12
        repeat(qd) {
            val (_, next) = skipName(data, off)
            off = next + 4 // QTYPE + QCLASS
        }
        // Réponse : nom (souvent pointeur de compression) + TYPE/CLASS/TTL/RDLEN
        val (_, afterName) = skipName(data, off)
        var p = afterName
        if (p + 10 > data.size) return null
        val type = u16(p)
        p += 2
        p += 2 // CLASS
        p += 4 // TTL
        val rdlen = u16(p)
        p += 2
        if (type != QTYPE_NBSTAT || rdlen < 1 || p + rdlen > data.size) return null

        val nameCount = data[p].toInt() and 0xFF
        var q = p + 1
        var machineName: String? = null
        var i = 0
        while (i < nameCount && q + 18 <= p + rdlen) {
            val nameBytes = data.copyOfRange(q, q + 16)
            val suffix = nameBytes[15].toInt() and 0xFF
            val flags = u16(q + 16)
            val isGroup = (flags and 0x8000) != 0
            val name = String(nameBytes, 0, 15, Charsets.US_ASCII)
                .trim { it == ' ' || it == '\u0000' }
            if (machineName == null && !isGroup && (suffix == 0x00 || suffix == 0x20) && name.isNotBlank()) {
                machineName = name
            }
            q += 18
            i++
        }

        val mac = extractAdapterMac(data, p, rdlen, nameCount)
        val name = machineName.orEmpty()
        if (name.isBlank() && mac.isBlank()) return null
        return NbnsInfo(name = name, mac = mac)
    }

    /**
     * Bonus : MAC de l'adaptateur = 6 derniers octets du bloc de statistiques
     * (après les entrées de noms). Best-effort, ignorée si nulle ou en FF.
     */
    private fun extractAdapterMac(data: ByteArray, rdataStart: Int, rdlen: Int, nameCount: Int): String {
        val statsLen = rdlen - 1 - nameCount * 18
        if (statsLen < 6) return ""
        val macStart = rdataStart + 1 + nameCount * 18 + statsLen - 6
        val bytes = data.copyOfRange(macStart, macStart + 6)
        if (bytes.all { it == 0.toByte() } || bytes.all { it == 0xFF.toByte() }) return ""
        return bytes.joinToString(":") { "%02x".format(it.toInt() and 0xFF) }
    }

    /** Lit un nom DNS (labels ou pointeur de compression). Retourne (nom, offset après). */
    private fun skipName(data: ByteArray, start: Int): Pair<String, Int> {
        var off = start
        var jumped = false
        var after = start
        var guard = 0
        while (off < data.size && guard++ < 64) {
            val len = data[off].toInt() and 0xFF
            when {
                len == 0 -> {
                    off += 1
                    if (!jumped) after = off
                    break
                }
                len and 0xC0 == 0xC0 -> {
                    if (off + 1 >= data.size) break
                    if (!jumped) after = off + 2
                    jumped = true
                    off = ((len and 0x3F) shl 8) or (data[off + 1].toInt() and 0xFF)
                }
                else -> {
                    off += 1 + len
                    if (!jumped) after = off
                }
            }
        }
        return "" to after
    }

    /**
     * Envoie une requête NBSTAT unicast vers [ip]:137 et attend [timeoutMs].
     * Retourne null en cas d'échec ou d'absence de réponse (jamais d'exception).
     */
    fun query(ip: String, timeoutMs: Int = 800): NbnsInfo? {
        if (ip.isBlank()) return null
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = timeoutMs
                val req = buildNbstatQuery()
                socket.send(DatagramPacket(req, req.size, InetAddress.getByName(ip), PORT))
                val buf = ByteArray(1024)
                val pkt = DatagramPacket(buf, buf.size)
                socket.receive(pkt)
                parseNbstatResponse(pkt.data.copyOf(pkt.length))
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Découverte NetBIOS par BROADCAST — la technique qui trouve les PC Windows
     * dont on ne connaît pas encore l'IP (ping filtré, pas de mDNS/WSD, ARP vide
     * sur Android 10+). Envoie UNE requête NBSTAT vers l'adresse broadcast du
     * sous-réseau (ex. 192.168.0.255:137) ; chaque machine NetBIOS active répond
     * depuis son IP source avec son nom (+ MAC de l'adaptateur).
     *
     * @return nom/MAC par IP source. Jamais d'exception (map vide en échec).
     */
    fun discover(broadcastIp: String, timeoutMs: Int = 1_200): Map<String, NbnsInfo> {
        if (broadcastIp.isBlank()) return emptyMap()
        val perIp = HashMap<String, NbnsInfo>()
        try {
            DatagramSocket().use { socket ->
                socket.soTimeout = 250
                val req = buildNbstatQuery()
                socket.send(
                    DatagramPacket(req, req.size, InetAddress.getByName(broadcastIp), PORT)
                )
                val buf = ByteArray(2048)
                val deadline = System.currentTimeMillis() + timeoutMs
                while (System.currentTimeMillis() < deadline) {
                    val pkt = DatagramPacket(buf, buf.size)
                    try {
                        socket.receive(pkt)
                    } catch (e: java.net.SocketTimeoutException) {
                        continue
                    }
                    val ip = pkt.address?.hostAddress ?: continue
                    val info = parseNbstatResponse(pkt.data.copyOf(pkt.length)) ?: continue
                    // Ne pas se noter soi-même ni fusionner du vide par-dessus du connu.
                    if (info.hasInfo && ip != broadcastIp) {
                        perIp[ip] = info
                    }
                }
            }
        } catch (e: Exception) {
            // broadcast refusé (certains OEM) → on rend ce qu'on a déjà.
        }
        return perIp
    }
}

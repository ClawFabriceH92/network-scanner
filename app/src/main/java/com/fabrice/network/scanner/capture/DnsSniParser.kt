package com.fabrice.network.scanner.capture

/**
 * Extraction des noms d'hôtes pour rendre la capture lisible (comme PCAPdroid) :
 *  - [parseDnsResponses] : lit les réponses DNS (A/AAAA) pour bâtir une table
 *    IP → nom de domaine (le téléphone a demandé « example.com » → 93.184.x.y) ;
 *  - [parseSni] : lit le champ SNI du ClientHello TLS (le nom du site apparaît
 *    en clair dans la poignée de main, avant le chiffrement).
 *
 * Tout est défensif (paquets tronqués/malformés → liste vide / null) et pur,
 * donc testable en JVM.
 */
object DnsSniParser {

    // ---- DNS ----------------------------------------------------------------

    /** Réponses DNS → paires (IP, nom). data[0..len) = message DNS brut. */
    fun parseDnsResponses(data: ByteArray, len: Int): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        try {
            if (len < 12) return out
            val flags = IpPacket.u16(data, 2)
            if ((flags and 0x8000) == 0) return out          // pas une réponse
            val qd = IpPacket.u16(data, 4)
            val an = IpPacket.u16(data, 6)
            if (an == 0 || qd == 0) return out
            var off = 12
            val (qname, afterName) = readName(data, off, len)
            off = afterName + 4                               // qtype(2) + qclass(2)
            // Sauter les questions supplémentaires éventuelles.
            for (q in 1 until qd) {
                off = readName(data, off, len).second + 4
            }
            val hostname = qname
            if (hostname.isBlank()) return out
            for (a in 0 until an) {
                off = readName(data, off, len).second
                if (off + 10 > len) break
                val type = IpPacket.u16(data, off); off += 2
                off += 2                                       // class
                off += 4                                       // ttl
                val rdlen = IpPacket.u16(data, off); off += 2
                if (off + rdlen > len) break
                when (type) {
                    1 -> if (rdlen == 4) out.add(IpPacket.ipv4String(data, off) to hostname)   // A
                    28 -> if (rdlen == 16) out.add(ipv6(data, off) to hostname)                // AAAA
                }
                off += rdlen
            }
        } catch (e: Exception) {
            // message tronqué / malformé → on renvoie ce qu'on a
        }
        return out
    }

    /** Lit un nom DNS (avec compression) → (nom, offset suivant hors saut). */
    private fun readName(data: ByteArray, start: Int, len: Int): Pair<String, Int> {
        val sb = StringBuilder()
        var off = start
        var next = start
        var jumped = false
        var guard = 0
        while (off < len && guard++ < 128) {
            val b = data[off].toInt() and 0xFF
            if (b == 0) { if (!jumped) next = off + 1; break }
            if ((b and 0xC0) == 0xC0) {                        // pointeur de compression
                if (off + 1 >= len) break
                val ptr = ((b and 0x3F) shl 8) or (data[off + 1].toInt() and 0xFF)
                if (!jumped) next = off + 2
                jumped = true
                off = ptr
                continue
            }
            val l = b
            if (off + 1 + l > len) break
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(data, off + 1, l, Charsets.US_ASCII))
            off += 1 + l
        }
        if (!jumped) return sb.toString() to next
        return sb.toString() to next
    }

    private fun ipv6(data: ByteArray, off: Int): String {
        val sb = StringBuilder()
        for (i in 0 until 8) {
            if (i > 0) sb.append(':')
            val v = ((data[off + i * 2].toInt() and 0xFF) shl 8) or (data[off + i * 2 + 1].toInt() and 0xFF)
            sb.append(Integer.toHexString(v))
        }
        return sb.toString()
    }

    // ---- TLS SNI ------------------------------------------------------------

    /**
     * Nom d'hôte SNI d'un ClientHello TLS, ou null. [start] pointe le début du
     * payload TCP (premier octet 0x16 = handshake).
     */
    fun parseSni(data: ByteArray, start: Int, len: Int): String? {
        try {
            val end = start + len
            var p = start
            if (p + 5 > end) return null
            if ((data[p].toInt() and 0xFF) != 0x16) return null   // TLS handshake
            p += 5                                                // record header
            if (p + 4 > end) return null
            if ((data[p].toInt() and 0xFF) != 0x01) return null   // ClientHello
            p += 4                                                // msg type(1) + length(3)
            p += 2                                                // client version
            p += 32                                               // random
            if (p >= end) return null
            val sidLen = data[p].toInt() and 0xFF; p += 1 + sidLen
            if (p + 2 > end) return null
            val csLen = IpPacket.u16(data, p); p += 2 + csLen
            if (p + 1 > end) return null
            val compLen = data[p].toInt() and 0xFF; p += 1 + compLen
            if (p + 2 > end) return null
            val extTotal = IpPacket.u16(data, p); p += 2
            val extEnd = minOf(end, p + extTotal)
            while (p + 4 <= extEnd) {
                val etype = IpPacket.u16(data, p); p += 2
                val elen = IpPacket.u16(data, p); p += 2
                if (etype == 0) {                                 // server_name
                    var q = p
                    if (q + 5 > extEnd) return null
                    q += 2                                        // server_name_list length
                    val nameType = data[q].toInt() and 0xFF; q += 1
                    val nameLen = IpPacket.u16(data, q); q += 2
                    if (nameType == 0 && q + nameLen <= extEnd && nameLen > 0) {
                        return String(data, q, nameLen, Charsets.US_ASCII)
                    }
                    return null
                }
                p += elen
            }
        } catch (e: Exception) {
            // handshake fragmenté / malformé
        }
        return null
    }
}

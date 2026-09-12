package com.fabrice.network.scanner.capture

import java.net.InetAddress

/**
 * Utilitaires bas niveau IPv4 / IPv6 / TCP / UDP : parsing, construction et
 * sommes de contrôle. Tout est en « network byte order » (big-endian).
 *
 * IPv6 (v1.9.34) : en-tête fixe de 40 octets, sans en-têtes d'extension (un
 * paquet avec extension est ignoré par le service — cas marginal sur un lien
 * TUN local). Les fonctions « version-aware » ([l4Offset], [l4Protocol],
 * [srcIp], [dstIp], [packetEnd], [buildUdp], [buildTcp]) choisissent le format
 * d'après le premier quartet (version) ou la présence de « : » dans l'adresse.
 */
object IpPacket {

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    private const val V6_HDR = 40

    // ---- Lecture big-endian -------------------------------------------------
    fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xFF
    fun u16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
    fun u32(b: ByteArray, i: Int): Long =
        ((b[i].toLong() and 0xFF) shl 24) or
        ((b[i + 1].toLong() and 0xFF) shl 16) or
        ((b[i + 2].toLong() and 0xFF) shl 8) or
        (b[i + 3].toLong() and 0xFF)

    fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = ((v ushr 8) and 0xFF).toByte()
        b[i + 1] = (v and 0xFF).toByte()
    }

    fun put32(b: ByteArray, i: Int, v: Long) {
        b[i] = ((v ushr 24) and 0xFF).toByte()
        b[i + 1] = ((v ushr 16) and 0xFF).toByte()
        b[i + 2] = ((v ushr 8) and 0xFF).toByte()
        b[i + 3] = (v and 0xFF).toByte()
    }

    fun ipv4String(b: ByteArray, i: Int): String =
        "${u8(b, i)}.${u8(b, i + 1)}.${u8(b, i + 2)}.${u8(b, i + 3)}"

    fun ipv4Bytes(ip: String): ByteArray {
        val out = ByteArray(4)
        val parts = ip.split(".")
        for (k in 0 until 4) out[k] = (parts[k].toInt() and 0xFF).toByte()
        return out
    }

    /**
     * Forme textuelle canonique (RFC 5952) d'une IPv6 : 16 octets à partir de
     * [i], hexa minuscule sans zéros de tête, plus longue suite de zéros
     * compressée en « :: » (Java renvoie la forme longue non compressée).
     */
    fun ipv6String(b: ByteArray, i: Int): String {
        val groups = IntArray(8) { g -> u16(b, i + g * 2) }
        var bestStart = -1; var bestLen = 0
        var curStart = -1; var curLen = 0
        for (g in 0 until 8) {
            if (groups[g] == 0) {
                if (curStart < 0) { curStart = g; curLen = 1 } else curLen++
                if (curLen > bestLen) { bestStart = curStart; bestLen = curLen }
            } else { curStart = -1; curLen = 0 }
        }
        if (bestLen < 2) bestStart = -1
        val sb = StringBuilder()
        var g = 0
        while (g < 8) {
            if (g == bestStart) {
                sb.append("::"); g += bestLen
                continue
            }
            if (sb.isNotEmpty() && !sb.endsWith("::")) sb.append(':')
            sb.append(Integer.toHexString(groups[g]))
            g++
        }
        return sb.toString()
    }

    /** Octets d'une adresse IP (4 ou 16) depuis sa forme textuelle. */
    fun ipBytes(ip: String): ByteArray =
        if (ip.contains(':')) InetAddress.getByName(ip).address else ipv4Bytes(ip)

    fun isV6(ip: String): Boolean = ip.contains(':')

    // ---- En-tête IPv4 -------------------------------------------------------
    fun version(pkt: ByteArray): Int = (u8(pkt, 0) ushr 4)
    fun ihl(pkt: ByteArray): Int = (u8(pkt, 0) and 0x0F) * 4
    fun totalLength(pkt: ByteArray): Int = u16(pkt, 2)
    fun protocol(pkt: ByteArray): Int = u8(pkt, 9)

    // ---- Accès « version-aware » -------------------------------------------
    /** Offset du début de l'en-tête L4 (TCP/UDP), ou -1 si non exploitable. */
    fun l4Offset(pkt: ByteArray): Int = when (version(pkt)) {
        4 -> ihl(pkt)
        6 -> if (l4Protocol(pkt) == PROTO_TCP || l4Protocol(pkt) == PROTO_UDP) V6_HDR else -1
        else -> -1
    }

    /** Protocole L4 (v4 : champ protocol ; v6 : next header). */
    fun l4Protocol(pkt: ByteArray): Int = when (version(pkt)) {
        4 -> protocol(pkt)
        6 -> u8(pkt, 6)
        else -> -1
    }

    /** Fin du paquet IP (offset exclusif) d'après l'en-tête. */
    fun packetEnd(pkt: ByteArray): Int = when (version(pkt)) {
        4 -> totalLength(pkt)
        6 -> V6_HDR + u16(pkt, 4)
        else -> 0
    }

    fun srcIp(pkt: ByteArray): String = if (version(pkt) == 6) ipv6String(pkt, 8) else ipv4String(pkt, 12)
    fun dstIp(pkt: ByteArray): String = if (version(pkt) == 6) ipv6String(pkt, 24) else ipv4String(pkt, 16)

    /** Somme de contrôle Internet (ones-complement 16 bits) sur [off, off+len). */
    fun checksum(data: ByteArray, off: Int, len: Int, initial: Long = 0): Int {
        var sum = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += u16(data, i).toLong()
            i += 2
        }
        if (i < end) sum += ((data[i].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    /** Recalcule le checksum de l'en-tête IPv4 en place. */
    fun fixIpv4Checksum(pkt: ByteArray) {
        val hl = ihl(pkt)
        put16(pkt, 10, 0)
        val cs = checksum(pkt, 0, hl)
        put16(pkt, 10, cs)
    }

    /**
     * Somme de contrôle TCP/UDP avec pseudo-en-tête (IPv4 ou IPv6 selon le
     * paquet). @param pkt paquet IP complet (l'en-tête L4 commence à [l4Off]).
     */
    fun l4Checksum(pkt: ByteArray, l4Off: Int, l4Len: Int, proto: Int): Int {
        var sum = 0L
        if (version(pkt) == 6) {
            // Pseudo-en-tête v6 : src(16) dst(16) length(4) zeros(3) next header(1)
            var i = 8
            while (i < 40) { sum += u16(pkt, i).toLong(); i += 2 }
            sum += (l4Len ushr 16).toLong(); sum += (l4Len and 0xFFFF).toLong()
            sum += proto.toLong()
        } else {
            // Pseudo-en-tête v4 : src(4) dst(4) zero(1) proto(1) length(2)
            sum += u16(pkt, 12).toLong(); sum += u16(pkt, 14).toLong()
            sum += u16(pkt, 16).toLong(); sum += u16(pkt, 18).toLong()
            sum += proto.toLong()
            sum += l4Len.toLong()
        }
        var i = l4Off
        val end = l4Off + l4Len
        while (i + 1 < end) {
            sum += u16(pkt, i).toLong()
            i += 2
        }
        if (i < end) sum += ((pkt[i].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    /** Écrit un en-tête IP (v4 ou v6 selon les adresses) et retourne l'offset L4. */
    private fun writeIpHeader(p: ByteArray, srcIp: String, dstIp: String, proto: Int, l4Len: Int): Int {
        if (isV6(srcIp)) {
            p[0] = 0x60.toByte()            // version 6, traffic class 0
            p[1] = 0; p[2] = 0; p[3] = 0    // flow label 0
            put16(p, 4, l4Len)              // payload length
            p[6] = proto.toByte()           // next header
            p[7] = 64                       // hop limit
            System.arraycopy(ipBytes(srcIp), 0, p, 8, 16)
            System.arraycopy(ipBytes(dstIp), 0, p, 24, 16)
            return V6_HDR
        }
        p[0] = 0x45.toByte()                // version 4, IHL 5
        p[1] = 0                            // DSCP/ECN
        put16(p, 2, 20 + l4Len)
        put16(p, 4, 0)                      // id
        put16(p, 6, 0x4000)                 // flags = DF
        p[8] = 64                           // TTL
        p[9] = proto.toByte()
        System.arraycopy(ipv4Bytes(srcIp), 0, p, 12, 4)
        System.arraycopy(ipv4Bytes(dstIp), 0, p, 16, 4)
        fixIpv4Checksum(p)
        return 20
    }

    /**
     * Construit un paquet IP + UDP (v4 ou v6 selon [srcIp]).
     * @param srcIp/dstIp adresses textuelles, ports en clair, payload octets.
     */
    fun buildUdp(srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, payload: ByteArray, payloadLen: Int): ByteArray =
        buildUdp(srcIp, srcPort, dstIp, dstPort, payload, 0, payloadLen)

    fun buildUdp(srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, payload: ByteArray, payloadOff: Int, payloadLen: Int): ByteArray {
        val udpHdr = 8
        val ipHdr = if (isV6(srcIp)) V6_HDR else 20
        val p = ByteArray(ipHdr + udpHdr + payloadLen)
        val o = writeIpHeader(p, srcIp, dstIp, PROTO_UDP, udpHdr + payloadLen)
        put16(p, o, srcPort)
        put16(p, o + 2, dstPort)
        put16(p, o + 4, udpHdr + payloadLen)
        put16(p, o + 6, 0)                 // checksum provisoire
        if (payloadLen > 0) System.arraycopy(payload, payloadOff, p, o + 8, payloadLen)
        var cs = l4Checksum(p, o, udpHdr + payloadLen, PROTO_UDP)
        if (cs == 0) cs = 0xFFFF           // UDP : 0 signifie « pas de checksum »
        put16(p, o + 6, cs)
        return p
    }

    /** Construit un paquet IP + TCP (avec drapeaux et éventuel payload). */
    fun buildTcp(
        srcIp: String, srcPort: Int, dstIp: String, dstPort: Int,
        seq: Long, ack: Long, flags: Int, window: Int,
        payload: ByteArray?, payloadOff: Int, payloadLen: Int
    ): ByteArray {
        val tcpHdr = 20
        val ipHdr = if (isV6(srcIp)) V6_HDR else 20
        val p = ByteArray(ipHdr + tcpHdr + payloadLen)
        val o = writeIpHeader(p, srcIp, dstIp, PROTO_TCP, tcpHdr + payloadLen)
        put16(p, o, srcPort)
        put16(p, o + 2, dstPort)
        put32(p, o + 4, seq)
        put32(p, o + 8, ack)
        p[o + 12] = (5 shl 4).toByte()     // data offset = 5 (20 octets), pas d'options
        p[o + 13] = (flags and 0xFF).toByte()
        put16(p, o + 14, window)
        put16(p, o + 16, 0)                // checksum provisoire
        put16(p, o + 18, 0)                // urgent pointer
        if (payload != null && payloadLen > 0) System.arraycopy(payload, payloadOff, p, o + 20, payloadLen)
        val cs = l4Checksum(p, o, tcpHdr + payloadLen, PROTO_TCP)
        put16(p, o + 16, cs)
        return p
    }

    // Drapeaux TCP
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}

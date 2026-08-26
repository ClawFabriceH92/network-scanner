package com.fabrice.network.scanner.capture

/**
 * Utilitaires bas niveau IPv4 / TCP / UDP : parsing, construction et sommes de
 * contrôle. Tout est en « network byte order » (big-endian). On ne gère que
 * l'IPv4 ici : l'IPv6 n'est volontairement pas routé dans le TUN (il continue
 * de passer par l'interface réelle → pas capturé mais pas cassé non plus).
 */
object IpPacket {

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

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

    // ---- En-tête IPv4 -------------------------------------------------------
    fun version(pkt: ByteArray): Int = (u8(pkt, 0) ushr 4)
    fun ihl(pkt: ByteArray): Int = (u8(pkt, 0) and 0x0F) * 4
    fun totalLength(pkt: ByteArray): Int = u16(pkt, 2)
    fun protocol(pkt: ByteArray): Int = u8(pkt, 9)
    fun srcIp(pkt: ByteArray): String = ipv4String(pkt, 12)
    fun dstIp(pkt: ByteArray): String = ipv4String(pkt, 16)

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
     * Somme de contrôle TCP/UDP avec pseudo-en-tête.
     * @param pkt paquet IPv4 complet (l'en-tête L4 commence à [l4Off]).
     */
    fun l4Checksum(pkt: ByteArray, l4Off: Int, l4Len: Int, proto: Int): Int {
        // Pseudo-en-tête : src(4) dst(4) zero(1) proto(1) length(2)
        var sum = 0L
        sum += u16(pkt, 12).toLong(); sum += u16(pkt, 14).toLong() // src
        sum += u16(pkt, 16).toLong(); sum += u16(pkt, 18).toLong() // dst
        sum += proto.toLong()
        sum += l4Len.toLong()
        // Corps L4
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

    /**
     * Construit un paquet IPv4 + UDP.
     * @param srcIp/dstIp adresses décimales pointées, ports en clair, payload octets.
     */
    fun buildUdp(srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, payload: ByteArray, payloadLen: Int): ByteArray {
        val ipHdr = 20
        val udpHdr = 8
        val total = ipHdr + udpHdr + payloadLen
        val p = ByteArray(total)
        // IPv4
        p[0] = 0x45.toByte()          // version 4, IHL 5
        p[1] = 0                       // DSCP/ECN
        put16(p, 2, total)
        put16(p, 4, 0)                 // id
        put16(p, 6, 0x4000)            // flags = DF
        p[8] = 64                      // TTL
        p[9] = PROTO_UDP.toByte()
        System.arraycopy(ipv4Bytes(srcIp), 0, p, 12, 4)
        System.arraycopy(ipv4Bytes(dstIp), 0, p, 16, 4)
        fixIpv4Checksum(p)
        // UDP
        put16(p, 20, srcPort)
        put16(p, 22, dstPort)
        put16(p, 24, udpHdr + payloadLen)
        put16(p, 26, 0)                // checksum provisoire
        if (payloadLen > 0) System.arraycopy(payload, 0, p, 28, payloadLen)
        var cs = l4Checksum(p, 20, udpHdr + payloadLen, PROTO_UDP)
        if (cs == 0) cs = 0xFFFF       // UDP : 0 signifie « pas de checksum »
        put16(p, 26, cs)
        return p
    }

    /** Construit un paquet IPv4 + TCP (avec drapeaux et éventuel payload). */
    fun buildTcp(
        srcIp: String, srcPort: Int, dstIp: String, dstPort: Int,
        seq: Long, ack: Long, flags: Int, window: Int,
        payload: ByteArray?, payloadOff: Int, payloadLen: Int
    ): ByteArray {
        val ipHdr = 20
        val tcpHdr = 20
        val total = ipHdr + tcpHdr + payloadLen
        val p = ByteArray(total)
        // IPv4
        p[0] = 0x45.toByte()
        p[1] = 0
        put16(p, 2, total)
        put16(p, 4, 0)
        put16(p, 6, 0x4000)            // DF
        p[8] = 64
        p[9] = PROTO_TCP.toByte()
        System.arraycopy(ipv4Bytes(srcIp), 0, p, 12, 4)
        System.arraycopy(ipv4Bytes(dstIp), 0, p, 16, 4)
        fixIpv4Checksum(p)
        // TCP
        put16(p, 20, srcPort)
        put16(p, 22, dstPort)
        put32(p, 24, seq)
        put32(p, 28, ack)
        p[32] = (5 shl 4).toByte()     // data offset = 5 (20 octets), pas d'options
        p[33] = (flags and 0xFF).toByte()
        put16(p, 34, window)
        put16(p, 36, 0)                // checksum provisoire
        put16(p, 38, 0)                // urgent pointer
        if (payload != null && payloadLen > 0) System.arraycopy(payload, payloadOff, p, 40, payloadLen)
        val cs = l4Checksum(p, 20, tcpHdr + payloadLen, PROTO_TCP)
        put16(p, 36, cs)
        return p
    }

    // Drapeaux TCP
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}

package com.fabrice.network.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Scan SNMPv1 en UDP brut (port 161), sans dépendance : encodage/décodage BER
 * fait main pour lire sysDescr / sysName / sysLocation / sysUpTime des
 * périphériques qui exposent un agent SNMP (routeurs, NAS, imprimantes pro…).
 *
 * Communautés testées : « public » puis « private » (défauts fréquents).
 */
object SnmpScanner {

    // OID standard MIB-II system group (1.3.6.1.2.1.1.x.0)
    const val OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
    const val OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
    const val OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
    const val OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

    val OIDS = listOf(OID_SYS_DESCR, OID_SYS_NAME, OID_SYS_LOCATION, OID_SYS_UPTIME)

    private const val PORT = 161

    /** Résultat d'un probe SNMP (champs null si absents de la réponse). */
    data class SnmpResult(
        val descr: String?,
        val name: String?,
        val location: String?,
        val uptimeSeconds: Long?
    )

    /** Varbind décodé : OID (dotted string) + type BER + valeur brute. */
    data class Varbind(val oid: String, val tag: Int, val raw: ByteArray) {
        /** Valeur texte si OCTET STRING (0x04), sinon null. */
        fun textOrNull(): String? =
            if (tag == 0x04) raw.toString(Charsets.UTF_8) else null

        /** Valeur entière si INTEGER (0x02) ou TimeTicks (0x43), sinon null. */
        fun longOrNull(): Long? = when (tag) {
            0x02, 0x43 -> {
                var v = 0L
                for (b in raw) v = (v shl 8) or (b.toInt() and 0xFF).toLong()
                v
            }
            else -> null
        }
    }

    // ------------------------------------------------------------------ BER
    // --- Encodage ---

    /** Longueur BER : forme courte (<128) ou longue (0x80 | n octets, big-endian). */
    fun encodeLength(len: Int): ByteArray {
        if (len < 128) return byteArrayOf(len.toByte())
        val bytes = mutableListOf<Byte>()
        var v = len
        while (v > 0) {
            bytes.add(0, (v and 0xFF).toByte())
            v = v ushr 8
        }
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }

    /** INTEGER BER (complément à deux minimal, big-endian). */
    fun encodeInteger(value: Long): ByteArray {
        val bytes = mutableListOf<Byte>()
        var v = value
        do {
            bytes.add(0, (v and 0xFF).toByte())
            v = v shr 8
        } while (v != 0L && v != -1L)
        return bytes.toByteArray()
    }

    /** OCTET STRING BER (contenu brut, sans tag ni longueur). */
    fun encodeOctetString(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

    /** OID complet (tag 0x06 + longueur + sous-identifiants). */
    fun encodeOid(oid: String): ByteArray = tlv(0x06, encodeOidValue(oid))

    /** Sous-identifiants d'un OID (contenu sans tag/longueur). */
    private fun encodeOidValue(oid: String): ByteArray {
        val parts = oid.trim().trimStart('.').split(".").map { it.toLong() }
        val out = mutableListOf<Byte>()
        // Première paire compressée : 40 * premier + second.
        out.addAll(encodeSubId(40 * parts[0] + parts[1]))
        for (i in 2 until parts.size) out.addAll(encodeSubId(parts[i]))
        return out.toByteArray()
    }

    /** Sous-identifiant en base 128 (7 bits par octet, bit fort = continuation). */
    private fun encodeSubId(value: Long): List<Byte> {
        val bytes = mutableListOf<Byte>()
        var v = value
        bytes.add(0, (v and 0x7F).toByte())
        v = v ushr 7
        while (v > 0) {
            bytes.add(0, ((v and 0x7F) or 0x80).toByte())
            v = v ushr 7
        }
        return bytes
    }

    /** Construit la valeur TLV : tag + longueur + contenu. */
    private fun tlv(tag: Int, content: ByteArray): ByteArray =
        byteArrayOf(tag.toByte()) + encodeLength(content.size) + content

    /**
     * Construit un GetRequest SNMPv1 complet :
     * SEQUENCE { INTEGER version=0, OCTET STRING community,
     *   [0] GetRequest { INTEGER request-id, INTEGER error=0, INTEGER index=0,
     *     SEQUENCE of varbinds } }.
     */
    fun buildGetRequest(
        oids: List<String>,
        community: String = "public",
        requestId: Int = 1,
        pduTag: Int = 0xA0
    ): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (oid in oids) {
            val vb = tlv(0x30, encodeOid(oid) + tlv(0x05, ByteArray(0)))
            out.write(vb)
        }
        val varbindList = tlv(0x30, out.toByteArray())
        val pdu = tlv(
            pduTag,
            tlv(0x02, encodeInteger(requestId.toLong())) +
                tlv(0x02, encodeInteger(0)) +
                tlv(0x02, encodeInteger(0)) +
                varbindList
        )
        val message = tlv(
            0x30,
            tlv(0x02, encodeInteger(0)) +
                tlv(0x04, encodeOctetString(community)) +
                pdu
        )
        return message
    }

    // --- Décodage ---

    /** Décode un OID (contenu sans tag/longueur) en dotted string. */
    fun decodeOid(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val subIds = mutableListOf<Long>()
        var v = 0L
        for (b in bytes) {
            v = (v shl 7) or (b.toInt() and 0x7F).toLong()
            if ((b.toInt() and 0x80) == 0) {
                subIds.add(v)
                v = 0L
            }
        }
        if (subIds.size < 2) return subIds.joinToString(".")
        val parts = mutableListOf<Long>()
        parts.add(subIds[0] / 40)
        parts.add(subIds[0] % 40)
        for (i in 1 until subIds.size) parts.add(subIds[i])
        return parts.joinToString(".")
    }

    /** Parse le premier varbind (SEQUENCE { OID, valeur }) d'un buffer. */
    fun parseVarbind(buffer: ByteArray): Varbind? {
        return try {
            val r = BerReader(buffer)
            readVarbind(r)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Parse une réponse GetResponse SNMPv1 complète et retourne les 4 champs
     * système. Retourne null si la réponse est invalide ou porte une erreur.
     */
    fun parseResponse(buffer: ByteArray): SnmpResult? {
        return try {
            val r = BerReader(buffer)
            if (r.readByte() != 0x30) return null
            r.readLength()
            if (r.readByte() != 0x02) return null
            r.readBytes(r.readLength()) // version
            if (r.readByte() != 0x04) return null
            r.readBytes(r.readLength()) // community
            val pduTag = r.readByte()
            if (pduTag != 0xA2 && pduTag != 0xA0) return null
            r.readLength()
            if (r.readByte() != 0x02) return null
            r.readBytes(r.readLength()) // request-id
            if (r.readByte() != 0x02) return null
            val errStatus = r.readIntegerBytes(r.readLength())
            if (r.readByte() != 0x02) return null
            r.readBytes(r.readLength()) // error-index
            if (errStatus != 0L) return null
            if (r.readByte() != 0x30) return null
            r.readLength() // varbind list

            var descr: String? = null
            var name: String? = null
            var location: String? = null
            var uptime: Long? = null
            while (r.hasMore()) {
                val vb = readVarbind(r) ?: break
                when (vb.oid) {
                    OID_SYS_DESCR -> descr = vb.textOrNull()
                    OID_SYS_NAME -> name = vb.textOrNull()
                    OID_SYS_LOCATION -> location = vb.textOrNull()
                    OID_SYS_UPTIME -> uptime = vb.longOrNull()?.let { it / 100 }
                }
            }
            SnmpResult(descr, name, location, uptime)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Parse une réponse GetResponse et retourne TOUTES les varbinds (générique,
     * pour interroger des OID arbitraires — ex. compteurs d'imprimante). null si
     * la réponse est invalide ou porte une erreur SNMP.
     */
    fun parseAllVarbinds(buffer: ByteArray): List<Varbind>? {
        return try {
            val r = BerReader(buffer)
            if (r.readByte() != 0x30) return null
            r.readLength()
            if (r.readByte() != 0x02) return null
            r.readBytes(r.readLength()) // version
            if (r.readByte() != 0x04) return null
            r.readBytes(r.readLength()) // community
            val pduTag = r.readByte()
            if (pduTag != 0xA2 && pduTag != 0xA0) return null
            r.readLength()
            if (r.readByte() != 0x02) return null
            r.readBytes(r.readLength()) // request-id
            if (r.readByte() != 0x02) return null
            val errStatus = r.readIntegerBytes(r.readLength())
            if (r.readByte() != 0x02) return null
            r.readBytes(r.readLength()) // error-index
            if (errStatus != 0L) return null
            if (r.readByte() != 0x30) return null
            r.readLength() // varbind list
            val out = mutableListOf<Varbind>()
            while (r.hasMore()) {
                val vb = readVarbind(r) ?: break
                out.add(vb)
            }
            out
        } catch (e: Exception) {
            null
        }
    }

    /**
     * GetRequest générique multi-OID → map OID → Varbind (communautés « public »
     * puis « private »). Vide si l'agent ne répond pas. À appeler depuis un
     * thread IO.
     */
    fun getOids(ip: String, oids: List<String>, timeoutMs: Int = 1_500): Map<String, Varbind> {
        for (community in listOf("public", "private")) {
            val m = getOidsCommunity(ip, oids, community, timeoutMs)
            if (m.isNotEmpty()) return m
        }
        return emptyMap()
    }

    /**
     * Parcourt (SNMP walk, via GetNextRequest) tous les objets sous [baseOid] et
     * retourne les varbinds. Communautés « public » puis « private ». Borné en
     * lignes et en temps. À appeler depuis un thread IO.
     */
    fun walk(ip: String, baseOid: String, timeoutMs: Int = 1_500, maxRows: Int = 1_024): List<Varbind> {
        for (community in listOf("public", "private")) {
            val rows = walkCommunity(ip, baseOid, community, timeoutMs, maxRows)
            if (rows.isNotEmpty()) return rows
        }
        return emptyList()
    }

    private fun walkCommunity(
        ip: String,
        baseOid: String,
        community: String,
        timeoutMs: Int,
        maxRows: Int
    ): List<Varbind> {
        val out = mutableListOf<Varbind>()
        try {
            DatagramSocket().use { socket ->
                socket.soTimeout = timeoutMs
                val addr = InetAddress.getByName(ip)
                var current = baseOid
                var reqId = (System.currentTimeMillis() and 0x7FFFFFFF).toInt()
                var i = 0
                while (i < maxRows) {
                    val req = buildGetRequest(listOf(current), community, reqId++, pduTag = 0xA1)
                    socket.send(DatagramPacket(req, req.size, addr, PORT))
                    val buf = ByteArray(4096)
                    socket.receive(DatagramPacket(buf, buf.size))
                    val vb = parseAllVarbinds(buf)?.firstOrNull() ?: break
                    // Fin de sous-arbre : l'OID retourné sort de la branche.
                    if (vb.oid != baseOid && !vb.oid.startsWith("$baseOid.")) break
                    // endOfMibView (tag 0x82) / pas de valeur → stop.
                    if (vb.tag == 0x82) break
                    out.add(vb)
                    current = vb.oid
                    i++
                }
            }
        } catch (e: Exception) {
            // timeout / agent absent : on retourne ce qu'on a
        }
        return out
    }

    private fun getOidsCommunity(
        ip: String,
        oids: List<String>,
        community: String,
        timeoutMs: Int
    ): Map<String, Varbind> {
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = timeoutMs
                val req = buildGetRequest(oids, community, (System.currentTimeMillis() and 0x7FFFFFFF).toInt())
                val addr = InetAddress.getByName(ip)
                socket.send(DatagramPacket(req, req.size, addr, PORT))
                val buf = ByteArray(4096)
                socket.receive(DatagramPacket(buf, buf.size))
                parseAllVarbinds(buf)?.associateBy { it.oid } ?: emptyMap()
            }
        } catch (e: Exception) {
            emptyMap()
        }
    }

    /** Lit un varbind SEQUENCE { OID, valeur } depuis le lecteur courant. */
    private fun readVarbind(r: BerReader): Varbind? {
        if (r.readByte() != 0x30) return null
        r.readLength()
        if (r.readByte() != 0x06) return null
        val oidBytes = r.readBytes(r.readLength())
        val tag = r.readByte()
        val raw = r.readBytes(r.readLength())
        return Varbind(decodeOid(oidBytes), tag, raw)
    }

    /** Uptime lisible : « Xj Yh Zm », « Xh Ym Zs », « Xm Zs » ou « Xs ». */
    fun formatUptime(totalSeconds: Long): String {
        val d = totalSeconds / 86_400
        val h = (totalSeconds % 86_400) / 3_600
        val m = (totalSeconds % 3_600) / 60
        val s = totalSeconds % 60
        return when {
            d > 0 -> "${d}j ${h}h ${m}m"
            h > 0 -> "${h}h ${m}m ${s}s"
            m > 0 -> "${m}m ${s}s"
            else -> "${s}s"
        }
    }

    // ------------------------------------------------------------- Réseau

    /**
     * Interroge un agent SNMP sur le port 161 (communautés public puis private).
     * Suspend/IO : à appeler hors du thread principal. null si pas de réponse.
     */
    suspend fun probe(ip: String, timeoutMs: Int = 1_500): SnmpResult? =
        withContext(Dispatchers.IO) { probeBlocking(ip, timeoutMs) }

    /** Version bloquante (à appeler depuis un thread IO, ex. dans scan()). */
    internal fun probeBlocking(ip: String, timeoutMs: Int = 1_500): SnmpResult? {
        for (community in listOf("public", "private")) {
            val result = probeCommunity(ip, community, timeoutMs)
            if (result != null) return result
        }
        return null
    }

    private fun probeCommunity(ip: String, community: String, timeoutMs: Int): SnmpResult? {
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = timeoutMs
                val req = buildGetRequest(OIDS, community, (System.currentTimeMillis() and 0x7FFFFFFF).toInt())
                val addr = InetAddress.getByName(ip)
                socket.send(DatagramPacket(req, req.size, addr, PORT))
                val buf = ByteArray(2048)
                socket.receive(DatagramPacket(buf, buf.size))
                parseResponse(buf)
            }
        } catch (e: Exception) {
            null
        }
    }

    /** Port 161 joignable : une requête « public » reçoit une réponse (même une erreur). */
    fun isSnmpOpen(ip: String, timeoutMs: Int = 1_000): Boolean {
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = timeoutMs
                val req = buildGetRequest(listOf(OID_SYS_NAME), "public", 1)
                val addr = InetAddress.getByName(ip)
                socket.send(DatagramPacket(req, req.size, addr, PORT))
                val buf = ByteArray(2048)
                socket.receive(DatagramPacket(buf, buf.size))
                true
            }
        } catch (e: Exception) {
            false
        }
    }

    /** Lecteur BER minimal, borné (échoue proprement sur buffer tronqué). */
    private class BerReader(val buf: ByteArray) {
        var pos = 0

        fun hasMore(): Boolean = pos < buf.size

        fun readByte(): Int {
            if (pos >= buf.size) throw IndexOutOfBoundsException("BER buffer épuisé")
            return buf[pos++].toInt() and 0xFF
        }

        fun readLength(): Int {
            val b = readByte()
            if (b < 0x80) return b
            val n = b and 0x7F
            if (n > 4) throw IndexOutOfBoundsException("Longueur BER invalide")
            var len = 0
            repeat(n) { len = (len shl 8) or readByte() }
            return len
        }

        fun readBytes(n: Int): ByteArray {
            if (pos + n > buf.size) throw IndexOutOfBoundsException("BER buffer tronqué")
            val out = buf.copyOfRange(pos, pos + n)
            pos += n
            return out
        }

        fun readIntegerBytes(n: Int): Long {
            var v = 0L
            repeat(n) { v = (v shl 8) or readByte().toLong() }
            return v
        }
    }
}

package com.fabrice.network.scanner.capture

import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream

/**
 * Écrivain de fichier .pcap (format classique libpcap), lisible par Wireshark
 * ou tcpdump. Link-type 101 = LINKTYPE_RAW (paquets IP bruts : la version IPv4/6
 * est déduite du premier octet). Écriture en little-endian (magic a1b2c3d4).
 *
 * Thread-safe : plusieurs threads de forwarding écrivent leurs paquets ici.
 */
class PcapWriter(val file: File, private val snaplen: Int = 65535) {

    private val out = BufferedOutputStream(FileOutputStream(file), 1 shl 16)
    private val lock = Any()
    @Volatile private var closed = false
    @Volatile var bytesWritten: Long = 0
        private set

    init {
        writeGlobalHeader()
    }

    private fun le16(v: Int) { out.write(v and 0xFF); out.write((v ushr 8) and 0xFF) }
    private fun le32(v: Long) {
        out.write((v and 0xFF).toInt())
        out.write(((v ushr 8) and 0xFF).toInt())
        out.write(((v ushr 16) and 0xFF).toInt())
        out.write(((v ushr 24) and 0xFF).toInt())
    }

    private fun writeGlobalHeader() {
        synchronized(lock) {
            le32(0xa1b2c3d4L)   // magic (µs)
            le16(2); le16(4)    // version 2.4
            le32(0)             // thiszone
            le32(0)             // sigfigs
            le32(snaplen.toLong())
            le32(101)           // LINKTYPE_RAW
            out.flush()
            bytesWritten = 24
        }
    }

    /** Ajoute un paquet IP brut (les [len] premiers octets de [pkt]). */
    fun write(pkt: ByteArray, len: Int, nowMs: Long) {
        if (closed) return
        val incl = if (len > snaplen) snaplen else len
        synchronized(lock) {
            if (closed) return
            le32(nowMs / 1000)                    // ts_sec
            le32((nowMs % 1000) * 1000)           // ts_usec
            le32(incl.toLong())                   // incl_len
            le32(len.toLong())                    // orig_len
            out.write(pkt, 0, incl)
            bytesWritten += 16 + incl
        }
    }

    fun flush() { synchronized(lock) { if (!closed) out.flush() } }

    fun close() {
        synchronized(lock) {
            if (closed) return
            closed = true
            runCatching { out.flush() }
            runCatching { out.close() }
        }
    }
}

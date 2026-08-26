package com.fabrice.network.scanner.capture

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * Forwarding TCP en espace utilisateur.
 *
 * Notre endpoint « joue » le serveur distant vis-à-vis de l'app, et relaie les
 * octets via un vrai [Socket] protégé vers le serveur réel. Simplification clé :
 * le chemin app ↔ TUN est LOCAL et sans perte, donc pas besoin de gérer
 * retransmissions/fenêtrage de ce côté — il suffit de produire des numéros de
 * séquence/acquittement corrects et de gérer poignée de main + fermeture.
 *
 * Sens serveur→app : un thread lit le Socket réel et émet des segments PSH/ACK.
 * Sens app→serveur : le service nous passe les paquets, on écrit dans le Socket.
 */
class TcpForwarder(private val bridge: TunBridge) {

    private val MSS = 1460

    private inner class Conn(
        val appIp: String,
        val appPort: Int,
        val serverIp: String,
        val serverPort: Int
    ) {
        var mySeq: Long = 1L                 // séquence de NOTRE côté (serveur→app)
        var clientAck: Long = 0L             // prochain octet attendu de l'app (= notre ack)
        @Volatile var established = false
        @Volatile var closed = false
        @Volatile var appFin = false
        @Volatile var serverFin = false
        var socket: Socket? = null
        var srvOut: OutputStream? = null
        // Données app→serveur reçues AVANT que la connexion réelle soit établie
        // (ex : ClientHello TLS juste après le handshake) — mises en attente puis
        // vidées à la connexion, pour ne pas les perdre après les avoir ACK.
        private val pending = java.io.ByteArrayOutputStream()

        val lock = Any()

        fun sendSegment(flags: Int, payload: ByteArray?, off: Int, len: Int) {
            synchronized(lock) {
                if (closed) return
                val pkt = IpPacket.buildTcp(
                    serverIp, serverPort, appIp, appPort,
                    mySeq, clientAck, flags, 65535,
                    payload, off, len
                )
                bridge.emit(pkt, pkt.size)
                // FIN et SYN consomment 1 numéro de séquence ; les données len octets.
                var consumed = len.toLong()
                if (flags and IpPacket.SYN != 0) consumed += 1
                if (flags and IpPacket.FIN != 0) consumed += 1
                mySeq = (mySeq + consumed) and 0xFFFFFFFFL
            }
        }

        fun startServer() {
            Thread({
                val s = Socket()
                try {
                    bridge.protect(s)
                    s.tcpNoDelay = true
                    s.connect(InetSocketAddress(serverIp, serverPort), 10_000)
                } catch (e: Exception) {
                    // Connexion refusée / injoignable → RST vers l'app.
                    synchronized(lock) {
                        if (!closed) {
                            val rst = IpPacket.buildTcp(
                                serverIp, serverPort, appIp, appPort,
                                mySeq, clientAck, IpPacket.RST or IpPacket.ACK, 0,
                                null, 0, 0
                            )
                            bridge.emit(rst, rst.size)
                        }
                    }
                    close()
                    return@Thread
                }
                var flushFailed = false
                synchronized(lock) {
                    if (closed) { runCatching { s.close() }; return@Thread }
                    socket = s
                    srvOut = s.getOutputStream()
                    established = true
                    val pend = pending.toByteArray()
                    pending.reset()
                    if (pend.isNotEmpty()) {
                        try { srvOut!!.write(pend); srvOut!!.flush() }
                        catch (e: Exception) { flushFailed = true }
                    }
                }
                if (flushFailed) { reset(); return@Thread }
                readLoop(s.getInputStream())
            }, "tcp-$appPort-$serverPort").apply { isDaemon = true }.start()
        }

        private fun readLoop(input: InputStream) {
            val buf = ByteArray(MSS)
            while (bridge.isRunning() && !closed) {
                val n = try {
                    input.read(buf)
                } catch (e: Exception) {
                    break
                }
                if (n < 0) break
                if (n == 0) continue
                sendSegment(IpPacket.PSH or IpPacket.ACK, buf, 0, n)
                CaptureState.onInbound("TCP", appPort, serverIp, serverPort, n, System.currentTimeMillis())
            }
            // EOF côté serveur → FIN vers l'app.
            serverFin = true
            if (!closed) sendSegment(IpPacket.FIN or IpPacket.ACK, null, 0, 0)
            if (appFin) close()
        }

        fun writeToServer(data: ByteArray, off: Int, len: Int) {
            var fail = false
            synchronized(lock) {
                if (closed) return
                val o = srvOut
                if (o == null) {
                    // Pas encore connecté : on met en file (borné par le timeout connect).
                    pending.write(data, off, len)
                    return
                }
                try {
                    o.write(data, off, len)
                    o.flush()
                } catch (e: Exception) {
                    fail = true
                }
            }
            if (fail) reset()
        }

        fun reset() {
            synchronized(lock) {
                if (!closed) {
                    val rst = IpPacket.buildTcp(
                        serverIp, serverPort, appIp, appPort,
                        mySeq, clientAck, IpPacket.RST or IpPacket.ACK, 0, null, 0, 0
                    )
                    bridge.emit(rst, rst.size)
                }
            }
            close()
        }

        fun close() {
            if (closed) return
            closed = true
            runCatching { socket?.close() }
            conns.remove(key(appPort, serverIp, serverPort))
            CaptureState.onClosed("TCP", appPort, serverIp, serverPort)
        }
    }

    private val conns = ConcurrentHashMap<String, Conn>()

    private fun key(appPort: Int, serverIp: String, serverPort: Int) = "$appPort>$serverIp:$serverPort"

    /** Traite un paquet IPv4/TCP sortant. */
    fun handleOutbound(pkt: ByteArray) {
        val ipHdr = IpPacket.ihl(pkt)
        val appIp = IpPacket.srcIp(pkt)
        val serverIp = IpPacket.dstIp(pkt)
        val appPort = IpPacket.u16(pkt, ipHdr)
        val serverPort = IpPacket.u16(pkt, ipHdr + 2)
        val seq = IpPacket.u32(pkt, ipHdr + 4)
        val dataOff = ((IpPacket.u8(pkt, ipHdr + 12) ushr 4) and 0x0F) * 4
        val flags = IpPacket.u8(pkt, ipHdr + 13)
        val total = IpPacket.totalLength(pkt)
        val payloadOff = ipHdr + dataOff
        val payloadLen = (total - payloadOff).coerceAtLeast(0)

        val k = key(appPort, serverIp, serverPort)

        // --- SYN : nouvelle connexion -------------------------------------
        if (flags and IpPacket.SYN != 0 && flags and IpPacket.ACK == 0) {
            // Nouvelle (ou ré-ouverture) : on repart propre.
            conns[k]?.close()
            val c = Conn(appIp, appPort, serverIp, serverPort)
            c.clientAck = (seq + 1) and 0xFFFFFFFFL     // le SYN consomme 1
            c.mySeq = 1L
            conns[k] = c
            // SYN-ACK optimiste, puis connexion réelle en arrière-plan.
            c.sendSegment(IpPacket.SYN or IpPacket.ACK, null, 0, 0)
            c.startServer()
            return
        }

        val c = conns[k] ?: run {
            // Paquet hors connexion connue : on ignore (sauf RST, sans effet).
            return
        }

        // --- RST de l'app -------------------------------------------------
        if (flags and IpPacket.RST != 0) {
            c.close()
            return
        }

        // --- Données app→serveur ------------------------------------------
        if (payloadLen > 0) {
            synchronized(c.lock) {
                val expected = c.clientAck
                if (seq == expected) {
                    c.writeToServer(pkt, payloadOff, payloadLen)
                    c.clientAck = (c.clientAck + payloadLen) and 0xFFFFFFFFL
                    c.sendSegment(IpPacket.ACK, null, 0, 0)
                } else {
                    // Retransmission / hors-ordre (rare en local) : ré-ACK.
                    c.sendSegment(IpPacket.ACK, null, 0, 0)
                }
            }
        }

        // --- FIN de l'app -------------------------------------------------
        if (flags and IpPacket.FIN != 0) {
            synchronized(c.lock) {
                c.appFin = true
                c.clientAck = (c.clientAck + 1) and 0xFFFFFFFFL   // le FIN consomme 1
                c.sendSegment(IpPacket.ACK, null, 0, 0)
            }
            runCatching { c.socket?.shutdownOutput() }
            if (c.serverFin) c.close()
        }
    }

    fun closeAll() {
        conns.values.toList().forEach { it.close() }
        conns.clear()
    }
}

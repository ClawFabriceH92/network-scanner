package com.fabrice.network.scanner.capture

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Forwarding UDP en espace utilisateur.
 *
 * Chaque flux (appPort → serverIp:serverPort) obtient un [DatagramSocket]
 * « protégé » (hors VPN) connecté au serveur. Un thread lecteur renvoie les
 * réponses vers l'app en reconstruisant un paquet IPv4/UDP. Les datagrammes
 * de l'app arrivent forcément dans l'ordre côté TUN (lien local fiable).
 */
class UdpForwarder(private val bridge: TunBridge) {

    private inner class Flow(
        val appIp: String,
        val appPort: Int,
        val serverIp: String,
        val serverPort: Int
    ) {
        val socket = DatagramSocket()
        @Volatile var closed = false

        init {
            bridge.protect(socket)
            socket.soTimeout = 60_000   // ferme le flux après 60 s d'inactivité
            socket.connect(InetSocketAddress(InetAddress.getByName(serverIp), serverPort))
            Thread({ readLoop() }, "udp-$appPort-$serverPort").apply { isDaemon = true }.start()
        }

        fun send(payload: ByteArray, off: Int, len: Int) {
            if (closed) return
            runCatching { socket.send(DatagramPacket(payload, off, len)) }
                .onFailure { close() }
        }

        private fun readLoop() {
            val buf = ByteArray(65535)
            while (bridge.isRunning() && !closed) {
                val dp = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(dp)
                } catch (e: java.net.SocketTimeoutException) {
                    break
                } catch (e: Exception) {
                    break
                }
                val len = dp.length
                val pkt = IpPacket.buildUdp(serverIp, serverPort, appIp, appPort, buf, len)
                bridge.emit(pkt, pkt.size)
                CaptureState.onInbound("UDP", appPort, serverIp, serverPort, len, System.currentTimeMillis())
            }
            close()
        }

        fun close() {
            if (closed) return
            closed = true
            runCatching { socket.close() }
            flows.remove(key(appPort, serverIp, serverPort))
        }
    }

    private val flows = ConcurrentHashMap<String, Flow>()

    private fun key(appPort: Int, serverIp: String, serverPort: Int) = "$appPort>$serverIp:$serverPort"

    /** Traite un paquet IPv4/UDP sortant (déjà validé comme UDP par le service). */
    fun handleOutbound(pkt: ByteArray) {
        val ipHdr = IpPacket.ihl(pkt)
        val appIp = IpPacket.srcIp(pkt)
        val serverIp = IpPacket.dstIp(pkt)
        val appPort = IpPacket.u16(pkt, ipHdr)
        val serverPort = IpPacket.u16(pkt, ipHdr + 2)
        val udpLen = IpPacket.u16(pkt, ipHdr + 4)          // en-tête + données
        val payloadLen = (udpLen - 8).coerceAtLeast(0)
        val payloadOff = ipHdr + 8

        val flow = try {
            flows.getOrPut(key(appPort, serverIp, serverPort)) {
                Flow(appIp, appPort, serverIp, serverPort)
            }
        } catch (e: Exception) {
            return
        }
        flow.send(pkt, payloadOff, payloadLen)
    }

    fun closeAll() {
        flows.values.toList().forEach { it.close() }
        flows.clear()
    }
}

package com.fabrice.network.scanner.capture

import java.net.DatagramSocket
import java.net.Socket

/**
 * Pont entre les forwarders (UDP/TCP) et le [CaptureVpnService] :
 *  - [protect] exclut un socket du VPN (sinon boucle infinie : le trafic
 *    sortant repasserait par notre propre TUN) ;
 *  - [emit] renvoie un paquet IP reconstruit vers l'app (écrit dans le TUN et
 *    dans le fichier PCAP) ;
 *  - [isRunning] permet aux threads de forwarding de s'arrêter proprement.
 */
interface TunBridge {
    fun protect(socket: Socket): Boolean
    fun protect(socket: DatagramSocket): Boolean
    fun emit(pkt: ByteArray, len: Int)
    fun isRunning(): Boolean
}

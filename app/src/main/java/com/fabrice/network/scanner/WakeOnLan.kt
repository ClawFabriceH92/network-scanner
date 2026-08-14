package com.fabrice.network.scanner

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Wake-on-LAN : envoi d'un « magic packet » UDP pour réveiller une machine
 * du réseau local.
 *
 * Magic packet = 6 octets 0xFF + 16 × l'adresse MAC de la carte cible.
 * Envoyé en broadcast sur le port 9 (ou 7). La carte réseau, maintenue
 * alimentée à l'arrêt, détecte le paquet et déclenche le démarrage.
 */
object WakeOnLan {

    /**
     * Construit le magic packet à partir d'un MAC (aa:bb:cc:dd:ee:ff,
     * AA-BB-… ou aabbccddeeff). Retourne null si le MAC est invalide.
     */
    fun magicPacket(mac: String): ByteArray? {
        val clean = mac.replace(":", "").replace("-", "").replace(".", "").lowercase()
        if (clean.length != 12 || !clean.all { it.isDigit() || it in 'a'..'f' }) return null
        val macBytes = ByteArray(6)
        for (i in 0 until 6) {
            macBytes[i] = clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        val packet = ByteArray(6 + 16 * 6)
        for (i in 0 until 6) packet[i] = 0xFF.toByte()
        for (i in 0 until 16) {
            System.arraycopy(macBytes, 0, packet, 6 + i * 6, 6)
        }
        return packet
    }

    /**
     * Envoie le magic packet en broadcast sur le port 9.
     * Retourne true si l'envoi a réussi.
     */
    fun send(mac: String, broadcastIp: String = "255.255.255.255", port: Int = 9): Boolean {
        val packet = magicPacket(mac) ?: return false
        return try {
            DatagramSocket().use { socket ->
                socket.send(DatagramPacket(packet, packet.size, InetAddress.getByName(broadcastIp), port))
            }
            true
        } catch (e: Exception) {
            false
        }
    }
}

package com.fabrice.network.scanner

import com.fabrice.network.scanner.capture.IpPacket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests des primitives de paquets IPv4/TCP/UDP utilisées par la capture réseau
 * (VpnService). On vérifie surtout que les sommes de contrôle sont correctes :
 * un paquet dont le checksum est juste se re-vérifie à 0.
 */
class CaptureIpPacketTest {

    @Test
    fun ipv4AndUdpChecksumsAreValid() {
        val payload = "hello-dns".toByteArray()
        val pkt = IpPacket.buildUdp("192.168.1.50", 44321, "8.8.8.8", 53, payload, payload.size)

        // Champs IPv4.
        assertEquals(4, IpPacket.version(pkt))
        assertEquals(20, IpPacket.ihl(pkt))
        assertEquals(IpPacket.PROTO_UDP, IpPacket.protocol(pkt))
        assertEquals("192.168.1.50", IpPacket.srcIp(pkt))
        assertEquals("8.8.8.8", IpPacket.dstIp(pkt))
        assertEquals(20 + 8 + payload.size, IpPacket.totalLength(pkt))

        // Ports UDP.
        assertEquals(44321, IpPacket.u16(pkt, 20))
        assertEquals(53, IpPacket.u16(pkt, 22))
        assertEquals(8 + payload.size, IpPacket.u16(pkt, 24))

        // Un en-tête IPv4 correct se re-vérifie à 0.
        assertEquals(0, IpPacket.checksum(pkt, 0, 20))
        // Idem pour le checksum UDP (pseudo-en-tête inclus).
        assertEquals(0, IpPacket.l4Checksum(pkt, 20, 8 + payload.size, IpPacket.PROTO_UDP))
    }

    @Test
    fun tcpSegmentFieldsAndChecksumAreValid() {
        val data = ByteArray(100) { (it and 0xFF).toByte() }
        val seq = 0x11223344L
        val ack = 0x55667788L
        val flags = IpPacket.PSH or IpPacket.ACK
        val pkt = IpPacket.buildTcp(
            "10.0.0.2", 5000, "93.184.216.34", 443,
            seq, ack, flags, 65535, data, 0, data.size
        )

        assertEquals(IpPacket.PROTO_TCP, IpPacket.protocol(pkt))
        assertEquals(5000, IpPacket.u16(pkt, 20))
        assertEquals(443, IpPacket.u16(pkt, 22))
        assertEquals(seq, IpPacket.u32(pkt, 24))
        assertEquals(ack, IpPacket.u32(pkt, 28))
        assertEquals(flags, IpPacket.u8(pkt, 33))

        // Checksums valides.
        assertEquals(0, IpPacket.checksum(pkt, 0, 20))
        assertEquals(0, IpPacket.l4Checksum(pkt, 20, 20 + data.size, IpPacket.PROTO_TCP))
    }

    @Test
    fun synAckIsPurelyControl() {
        val pkt = IpPacket.buildTcp(
            "1.2.3.4", 80, "10.0.0.2", 40000,
            1L, 99L, IpPacket.SYN or IpPacket.ACK, 65535, null, 0, 0
        )
        assertEquals(20 + 20, IpPacket.totalLength(pkt))
        assertTrue(IpPacket.u8(pkt, 33) and IpPacket.SYN != 0)
        assertTrue(IpPacket.u8(pkt, 33) and IpPacket.ACK != 0)
        assertEquals(0, IpPacket.l4Checksum(pkt, 20, 20, IpPacket.PROTO_TCP))
    }

    @Test
    fun ipv4BytesRoundTrip() {
        val b = IpPacket.ipv4Bytes("172.16.254.1")
        assertEquals(172, b[0].toInt() and 0xFF)
        assertEquals(16, b[1].toInt() and 0xFF)
        assertEquals(254, b[2].toInt() and 0xFF)
        assertEquals(1, b[3].toInt() and 0xFF)
    }
}

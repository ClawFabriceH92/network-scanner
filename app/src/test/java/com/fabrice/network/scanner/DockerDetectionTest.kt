package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * v1.9.9 — détection des conteneurs Docker (et hôtes filtrant l'ICMP).
 */
class DockerDetectionTest {

    // --- Reconnaissance de la MAC Docker (préfixe 02:42) ---

    @Test
    fun isDockerMac_recognizesDockerPrefix() {
        assertTrue(NetworkScanner.isDockerMac("02:42:ac:11:00:02"))
        assertTrue(NetworkScanner.isDockerMac("02-42-AC-11-00-05"))
        assertTrue(NetworkScanner.isDockerMac("0242ac110002"))
    }

    @Test
    fun isDockerMac_rejectsNonDocker() {
        assertFalse(NetworkScanner.isDockerMac("f4:ca:e5:4d:d3:e9")) // Freebox
        assertFalse(NetworkScanner.isDockerMac("06:11:22:33:44:55")) // aléatoire, autre préfixe
        assertFalse(NetworkScanner.isDockerMac(""))                  // vide
    }

    @Test
    fun dockerMac_isNotTreatedAsRandomized() {
        // La MAC Docker a le bit « localement administré » à 1 (donc « aléatoire »
        // au sens brut), mais on doit la reconnaître comme Docker en priorité.
        assertTrue(NetworkScanner.isRandomizedMac("02:42:ac:11:00:02"))
        assertTrue(NetworkScanner.isDockerMac("02:42:ac:11:00:02"))
    }

    // --- Classification du type ---

    @Test
    fun classify_dockerVendor_isContainer() {
        // Même avec des ports « ordinateur » ouverts, le fabricant Docker prime.
        val type = DeviceType.classify(
            vendor = "Docker",
            hostname = "",
            ports = listOf(22, 80, 443),
            os = "Linux"
        )
        assertEquals("Serveur / Conteneur", type)
    }

    @Test
    fun classify_dockerVendor_hostnameStillWins() {
        // Un hostname explicite reste prioritaire sur le signal conteneur.
        val type = DeviceType.classify(
            vendor = "Docker",
            hostname = "camera-hikvision",
            ports = emptyList(),
            os = ""
        )
        assertEquals("Caméra", type)
    }

    @Test
    fun containerType_hasIcon() {
        assertEquals("🐳", DeviceType.icon("Serveur / Conteneur"))
    }

    // --- Sonde de vivacité TCP ---

    @Test
    fun isAnyPortOpen_trueWhenAServiceListens() {
        ServerSocket().use { server ->
            server.bind(InetSocketAddress("127.0.0.1", 0)) // port libre attribué par l'OS
            val port = server.localPort
            assertTrue(PortScanner.isAnyPortOpen("127.0.0.1", listOf(port), timeoutMs = 500))
        }
    }

    @Test
    fun isAnyPortOpen_falseWhenNothingListens() {
        // Port fermé sur loopback → connexion refusée immédiatement.
        assertFalse(PortScanner.isAnyPortOpen("127.0.0.1", listOf(1), timeoutMs = 300))
    }

    // --- Ports des applications conteneurisées (Docker bridge) ---

    @Test
    fun allPorts_includeCommonContainerPorts() {
        val ports = PortScanner.ALL_PORTS.map { it.first }.toSet()
        // Quelques services conteneurisés très répandus doivent être couverts.
        assertTrue(9443 in ports)  // Portainer
        assertTrue(8096 in ports)  // Jellyfin
        assertTrue(8123 in ports)  // Home Assistant
        assertTrue(2375 in ports)  // Docker API
    }

    @Test
    fun allPorts_hasNoDuplicatePortNumbers() {
        val nums = PortScanner.ALL_PORTS.map { it.first }
        assertEquals(nums.size, nums.distinct().size)
    }

    @Test
    fun tcpPingPorts_coverCommonWebContainerPorts() {
        val p = PortScanner.TCP_PING_PORTS.toSet()
        // La sonde de vivacité doit couvrir les ports web/conteneurs courants,
        // sinon un hôte qui filtre l'ICMP et n'expose qu'un tel service reste
        // invisible (ex. Synology/Flask sur 5000, Jellyfin 8096, HA 8123).
        assertTrue(5000 in p)
        assertTrue(8096 in p)
        assertTrue(8123 in p)
        assertTrue(9443 in p)
    }

    @Test
    fun serviceName_resolvesContainerPort() {
        assertEquals("Portainer", PortScanner.serviceName(9443))
        assertEquals("Jellyfin", PortScanner.serviceName(8096))
    }

    // --- Détection des sites web ---

    @Test
    fun webUrl_buildsCorrectUrls() {
        assertEquals("http://192.168.0.180:5000", PortScanner.webUrl("192.168.0.180", 5000))
        assertEquals("http://192.168.0.1", PortScanner.webUrl("192.168.0.1", 80))
        assertEquals("https://192.168.0.5", PortScanner.webUrl("192.168.0.5", 443))
        assertEquals("https://192.168.0.5:9443", PortScanner.webUrl("192.168.0.5", 9443))
    }

    @Test
    fun webUrl_nullForNonWebPorts() {
        assertNull(PortScanner.webUrl("192.168.0.5", 22))   // SSH
        assertNull(PortScanner.webUrl("192.168.0.5", 445))  // SMB
        assertNull(PortScanner.webUrl("192.168.0.5", 3306)) // MySQL
    }

    @Test
    fun isWebPort_flagsWebServices() {
        assertTrue(PortScanner.isWebPort(5000))
        assertTrue(PortScanner.isWebPort(8096))
        assertFalse(PortScanner.isWebPort(22))
    }

    // --- Scan complet à la demande ---

    @Test
    fun scanAllPorts_findsAListeningPort() {
        ServerSocket().use { server ->
            server.bind(InetSocketAddress("127.0.0.1", 0))
            val port = server.localPort
            // Plage réduite autour du port en écoute : évite d'épuiser les ports
            // éphémères du runner CI (le comportement par défaut reste 1..65535).
            val from = (port - 20).coerceAtLeast(1)
            val to = (port + 20).coerceAtMost(65535)
            val open = PortScanner.scanAllPorts("127.0.0.1", timeoutMs = 200, range = from..to)
            assertTrue("le port en écoute $port doit être trouvé", port in open)
        }
    }
}

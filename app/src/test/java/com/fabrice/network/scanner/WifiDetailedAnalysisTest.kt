package com.fabrice.network.scanner

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests de WifiVulnAnalyzer.analyzeDetailed — l'analyse « avant de se connecter »
 * pour les Wi-Fi captifs/publics (ouvert, evil-twin, WPS, recommandations).
 */
class WifiDetailedAnalysisTest {

    private fun net(ssid: String, bssid: String, caps: String) =
        WifiScanner.WifiNetwork(ssid, bssid, -50, 2437, caps)

    @Test
    fun openPublicNetworkFlagsClearTrafficAndVpn() {
        val open = net("Hotel_Guest", "aa:bb:cc:dd:ee:01", "[ESS]")
        val d = WifiVulnAnalyzer.analyzeDetailed(open, listOf(open))
        assertTrue(d.publicOrOpen)
        assertTrue(d.risks.any { it.contains("clair") })
        assertTrue(d.recommendations.any { it.contains("VPN") })
    }

    @Test
    fun evilTwinDetectedForSameSsidTwoBssids() {
        val a = net("MyNet", "aa:11:22:33:44:55", "[WPA2-PSK-CCMP][ESS]")
        val b = net("MyNet", "bb:11:22:33:44:66", "[WPA2-PSK-CCMP][ESS]")
        val d = WifiVulnAnalyzer.analyzeDetailed(a, listOf(a, b))
        assertTrue(d.evilTwin)
        assertTrue(d.risks.any { it.contains("evil twin") })
    }

    @Test
    fun singleSecuredNetworkNoEvilTwinNoOpenRisk() {
        val a = net("Maison", "aa:11:22:33:44:55", "[WPA3-SAE][ESS]")
        val d = WifiVulnAnalyzer.analyzeDetailed(a, listOf(a))
        assertFalse(d.evilTwin)
        assertFalse(d.publicOrOpen)
    }

    @Test
    fun wpsFlaggedWhenAdvertised() {
        val a = net("Box-1234", "aa:11:22:33:44:55", "[WPA2-PSK-CCMP][WPS][ESS]")
        val d = WifiVulnAnalyzer.analyzeDetailed(a, listOf(a))
        assertTrue(d.wps)
        assertTrue(d.risks.any { it.contains("WPS") })
    }
}

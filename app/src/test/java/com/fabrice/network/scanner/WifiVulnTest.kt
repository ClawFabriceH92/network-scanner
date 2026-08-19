package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests Feature 5/5bis — WiFi : parse capabilities, analyse de vulnérabilité
 * (score par chiffrement + heuristiques SSID) et analyse réseau public.
 */
class WifiVulnTest {

    @Test
    fun parseCapabilities_mapsToSecurity() {
        assertEquals(WifiScanner.WifiSecurity.OPEN, WifiScanner.parseCapabilities("[ESS]"))
        assertEquals(WifiScanner.WifiSecurity.OPEN, WifiScanner.parseCapabilities(""))
        assertEquals(WifiScanner.WifiSecurity.WEP, WifiScanner.parseCapabilities("[WEP][ESS]"))
        assertEquals(WifiScanner.WifiSecurity.WPA_TKIP, WifiScanner.parseCapabilities("[WPA-PSK-TKIP][ESS]"))
        assertEquals(WifiScanner.WifiSecurity.WPA2_CCMP, WifiScanner.parseCapabilities("[WPA2-PSK-CCMP][ESS]"))
        assertEquals(WifiScanner.WifiSecurity.WPA3_SAE, WifiScanner.parseCapabilities("[WPA3-SAE][ESS]"))
        assertEquals(
            WifiScanner.WifiSecurity.WPA2_WPA3_MIXED,
            WifiScanner.parseCapabilities("[WPA2-PSK-CCMP][WPA3-SAE][ESS]")
        )
        assertEquals(WifiScanner.WifiSecurity.WPA2_ENTERPRISE, WifiScanner.parseCapabilities("[WPA2-EAP-CCMP][ESS]"))
        assertEquals(WifiScanner.WifiSecurity.OWE, WifiScanner.parseCapabilities("[OWE][ESS]"))
        assertEquals(WifiScanner.WifiSecurity.UNKNOWN, WifiScanner.parseCapabilities("[WPS]"))
    }

    @Test
    fun analyze_scoresPerSecurity() {
        assertEquals(100, WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.OPEN, "MyWifi").score)
        assertEquals(95, WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WEP, "MyWifi").score)
        assertEquals(70, WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WPA_TKIP, "MyWifi").score)
        assertEquals(45, WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WPA2_CCMP, "MyWifi").score)
        assertEquals(25, WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WPA2_WPA3_MIXED, "MyWifi").score)
        assertEquals(10, WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WPA3_SAE, "MyWifi").score)
        assertEquals(30, WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WPA2_ENTERPRISE, "MyWifi").score)
        assertEquals(10, WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WPA3_ENTERPRISE, "MyWifi").score)
        assertEquals(15, WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.OWE, "MyWifi").score)
        assertEquals(50, WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.UNKNOWN, "MyWifi").score)
    }

    @Test
    fun analyze_fonSsid_raisesToElevated() {
        val v = WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WPA2_CCMP, "SFR WiFi FON")
        assertEquals(60, v.score)
        assertEquals("Élevé", v.label)
        assertTrue(v.risks.contains("Réseau public/portail captif"))
    }

    @Test
    fun analyze_defaultSsid_raisesToLow() {
        val v = WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WPA3_SAE, "TP-LINK_5G")
        assertEquals(20, v.score)
        assertTrue(v.risks.contains("SSID par défaut"))
    }

    @Test
    fun analyze_labels() {
        assertEquals("Critique", WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.OPEN, "X").label)
        assertEquals("Modéré", WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WPA2_CCMP, "X").label)
        assertEquals("Faible", WifiVulnAnalyzer.analyze(WifiScanner.WifiSecurity.WPA3_SAE, "X").label)
    }

    // ---------- PublicWifiAnalyzer ----------

    @Test
    fun detect_204_noCaptive() {
        val s = PublicWifiAnalyzer.detectCaptivePortal {
            PublicWifiAnalyzer.PortalFetch(204, "http://connectivitycheck.gstatic.com/generate_204", "")
        }
        assertEquals(PublicWifiAnalyzer.CaptiveStatus.NONE, s.status)
    }

    @Test
    fun detect_redirect_captive() {
        val s = PublicWifiAnalyzer.detectCaptivePortal {
            PublicWifiAnalyzer.PortalFetch(302, "http://wifi.hotel.com/login")
        }
        assertEquals(PublicWifiAnalyzer.CaptiveStatus.CAPTIVE, s.status)
        assertEquals("http://wifi.hotel.com/login", s.portalUrl)
        assertFalse(s.portalHttps)
    }

    @Test
    fun detect_200login_captive() {
        val body = "<html><form><input type='password' name='pass'></form></html>"
        val s = PublicWifiAnalyzer.detectCaptivePortal {
            PublicWifiAnalyzer.PortalFetch(200, "http://connectivitycheck.gstatic.com/generate_204", body)
        }
        assertEquals(PublicWifiAnalyzer.CaptiveStatus.CAPTIVE, s.status)
    }

    @Test
    fun detect_error_unknown() {
        val s = PublicWifiAnalyzer.detectCaptivePortal { null }
        assertEquals(PublicWifiAnalyzer.CaptiveStatus.UNKNOWN, s.status)
    }

    @Test
    fun analyze_openHttpCaptive() {
        val captive = PublicWifiAnalyzer.CaptivePortalStatus(
            PublicWifiAnalyzer.CaptiveStatus.CAPTIVE, "http://login.hotel.com", false, "login.hotel.com"
        )
        val v = PublicWifiAnalyzer.analyzePublicNetwork("HotelWifi", WifiScanner.WifiSecurity.OPEN, captive)
        assertTrue(v.score >= 75)
        assertTrue(v.risks.contains("Le portail est en HTTP : ton identifiant/mot de passe circule en clair"))
        assertEquals(3, v.recommendations.size)
    }

    @Test
    fun analyze_openHttpsCaptive() {
        val captive = PublicWifiAnalyzer.CaptivePortalStatus(
            PublicWifiAnalyzer.CaptiveStatus.CAPTIVE, "https://login.hotel.com", true, "login.hotel.com"
        )
        val v = PublicWifiAnalyzer.analyzePublicNetwork("HotelWifi", WifiScanner.WifiSecurity.OPEN, captive)
        assertTrue(v.score >= 75)
        assertTrue(v.risks.contains("Portail HTTPS — vérifie le certificat"))
    }

    @Test
    fun analyze_wpa2_noCaptive_lowScore() {
        val none = PublicWifiAnalyzer.CaptivePortalStatus(PublicWifiAnalyzer.CaptiveStatus.NONE)
        val v = PublicWifiAnalyzer.analyzePublicNetwork("HomeWifi", WifiScanner.WifiSecurity.WPA2_CCMP, none)
        assertTrue(v.score < 50)
    }

    @Test
    fun evilTwinHint_sameSsidDifferentBssid() {
        val a = WifiScanner.WifiNetwork("MyWifi", "aa:bb:cc:dd:ee:01", -50, 2437, "[WPA2-PSK-CCMP][ESS]")
        val b = WifiScanner.WifiNetwork("MyWifi", "aa:bb:cc:dd:ee:02", -60, 2437, "[WPA2-PSK-CCMP][ESS]")
        val c = WifiScanner.WifiNetwork("Other", "aa:bb:cc:dd:ee:03", -70, 2437, "[WPA2-PSK-CCMP][ESS]")
        assertTrue(PublicWifiAnalyzer.evilTwinHint(listOf(a, b)))
        assertFalse(PublicWifiAnalyzer.evilTwinHint(listOf(a, c)))
    }
}

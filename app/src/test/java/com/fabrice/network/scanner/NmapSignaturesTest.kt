package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests Feature 1 — Signatures Nmap : parse de l'asset JSON + identification
 * sur bannières réelles (Apache, OpenSSH, ProFTPD, nginx) + no-match.
 */
class NmapSignaturesTest {

    private fun loadAsset() {
        val json = javaClass.classLoader!!.getResource("nmap_signatures.json")!!.readText()
        NmapSignatures.load(json)
    }

    @Test
    fun load_parsesRules() {
        val rules = NmapSignatures.load(
            javaClass.classLoader!!.getResource("nmap_signatures.json")!!.readText()
        )
        assertTrue(rules.size >= 50)
        assertTrue(rules.all { it.service.isNotBlank() && it.product.isNotBlank() && it.regex.pattern.isNotBlank() })
    }

    @Test
    fun identify_apache() {
        loadAsset()
        val m = NmapSignatures.identify(listOf("Server: Apache/2.4.6 (Ubuntu)"))
        assertNotNull(m)
        assertEquals("Apache httpd", m!!.product)
        assertEquals("2.4.6", m.version)
        assertEquals("Apache httpd 2.4.6", m.displayName())
    }

    @Test
    fun identify_openssh() {
        loadAsset()
        val m = NmapSignatures.identify(listOf("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"))
        assertNotNull(m)
        assertEquals("OpenSSH", m!!.product)
        assertEquals("8.9p1", m.version)
    }

    @Test
    fun identify_proftpd() {
        loadAsset()
        val m = NmapSignatures.identify(listOf("220 ProFTPD 1.3.5e Server (Debian)"))
        assertNotNull(m)
        assertEquals("ProFTPD", m!!.product)
        assertEquals("1.3.5e", m.version)
    }

    @Test
    fun identify_nginx() {
        loadAsset()
        val m = NmapSignatures.identify(listOf("Server: nginx/1.18.0"))
        assertNotNull(m)
        assertEquals("nginx", m!!.product)
        assertEquals("1.18.0", m.version)
    }

    @Test
    fun identify_noMatch_returnsNull() {
        loadAsset()
        assertNull(NmapSignatures.identify(listOf("some totally unknown banner")))
        assertNull(NmapSignatures.identify(emptyList()))
    }

    @Test
    fun identify_invalidJson_returnsEmpty() {
        val rules = NmapSignatures.load("{not json")
        assertTrue(rules.isEmpty())
    }
}

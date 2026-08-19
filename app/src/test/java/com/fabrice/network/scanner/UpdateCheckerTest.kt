package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests v1.6.1 : auto-update GitHub Releases — UpdateChecker (comparaison de
 * versions numérique + parsing du JSON de l'API GitHub).
 */
class UpdateCheckerTest {

    // ---------- shouldUpdate : comparaison segment par segment (Int) ----------

    @Test
    fun shouldUpdate_numericNotLexical() {
        assertTrue(UpdateChecker.shouldUpdate("0.9.0", "1.0.0"))
        assertTrue(UpdateChecker.shouldUpdate("1.6.0", "1.6.1"))
        // 1.10.0 > 1.9.0 — une comparaison lexicale dirait l'inverse
        assertTrue(UpdateChecker.shouldUpdate("1.9.0", "1.10.0"))
    }

    @Test
    fun shouldUpdate_equalOrLowerIsFalse() {
        assertFalse(UpdateChecker.shouldUpdate("1.6.1", "1.6.1"))
        assertFalse(UpdateChecker.shouldUpdate("1.6.1", "1.6.0"))
        assertFalse(UpdateChecker.shouldUpdate("2.0.0", "1.9.9"))
    }

    @Test
    fun shouldUpdate_differentSegmentCount() {
        assertTrue(UpdateChecker.shouldUpdate("1.6", "1.6.1"))
        assertFalse(UpdateChecker.shouldUpdate("1.6.1", "1.6"))
        assertTrue(UpdateChecker.shouldUpdate("0.10", "0.10.1"))
    }

    // ---------- parseReleases ----------

    @Test
    fun parseReleases_invalidJsonReturnsNull() {
        assertNull(UpdateChecker.parseReleases("{not json", "1.6.1"))
        assertNull(UpdateChecker.parseReleases("", "1.6.1"))
        assertNull(UpdateChecker.parseReleases("null", "1.6.1"))
    }

    @Test
    fun parseReleases_picksHighestVersionWithApk() {
        val json = """
            [
              {"tag_name":"v1.6.0","draft":false,"assets":[
                {"name":"network-scanner-v1.6.0.apk","browser_download_url":"https://example.com/a.apk"}
              ]},
              {"tag_name":"v1.6.1","draft":false,"assets":[
                {"name":"network-scanner-v1.6.1.apk","browser_download_url":"https://example.com/b.apk"}
              ]},
              {"tag_name":"v1.5.9","draft":false,"assets":[
                {"name":"network-scanner-v1.5.9.apk","browser_download_url":"https://example.com/c.apk"}
              ]}
            ]
        """.trimIndent()
        val info = UpdateChecker.parseReleases(json, "1.6.0")
        assertEquals("1.6.1", info!!.version)
        assertEquals("https://example.com/b.apk", info.url)
    }

    @Test
    fun parseReleases_ignoresDrafts() {
        val json = """
            [
              {"tag_name":"v1.7.0","draft":true,"assets":[
                {"name":"network-scanner-v1.7.0.apk","browser_download_url":"https://example.com/draft.apk"}
              ]},
              {"tag_name":"v1.6.1","draft":false,"assets":[
                {"name":"network-scanner-v1.6.1.apk","browser_download_url":"https://example.com/b.apk"}
              ]}
            ]
        """.trimIndent()
        val info = UpdateChecker.parseReleases(json, "1.6.0")
        assertEquals("1.6.1", info!!.version)
    }

    @Test
    fun parseReleases_requiresApkAsset() {
        val json = """
            [
              {"tag_name":"v1.7.0","draft":false,"assets":[
                {"name":"source.zip","browser_download_url":"https://example.com/src.zip"}
              ]},
              {"tag_name":"v1.6.1","draft":false,"assets":[
                {"name":"network-scanner-v1.6.1.apk","browser_download_url":"https://example.com/b.apk"}
              ]}
            ]
        """.trimIndent()
        val info = UpdateChecker.parseReleases(json, "1.6.0")
        assertEquals("1.6.1", info!!.version)
    }

    @Test
    fun parseReleases_upToDateReturnsNull() {
        val json = """
            [
              {"tag_name":"v1.6.0","draft":false,"assets":[
                {"name":"network-scanner-v1.6.0.apk","browser_download_url":"https://example.com/a.apk"}
              ]}
            ]
        """.trimIndent()
        assertNull(UpdateChecker.parseReleases(json, "1.6.1"))
    }
}

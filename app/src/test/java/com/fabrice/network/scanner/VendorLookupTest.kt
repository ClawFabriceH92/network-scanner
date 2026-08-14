package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Tests des nouveaux comportements : fusion ARP (double lecture),
 * parsing de la réponse macvendors.com et cache du lookup en ligne.
 */
class VendorLookupTest {

    // ---------- mergeArp ----------

    @Test
    fun mergeArp_unionsTwoTables() {
        val first = mapOf(
            "192.168.0.1" to "aa:bb:cc:dd:ee:01",
            "192.168.0.2" to "aa:bb:cc:dd:ee:02"
        )
        val second = mapOf(
            "192.168.0.2" to "aa:bb:cc:dd:ee:02",
            "192.168.0.3" to "aa:bb:cc:dd:ee:03"
        )
        val merged = NetworkScanner.mergeArp(first, second)
        assertEquals(3, merged.size)
        assertEquals("aa:bb:cc:dd:ee:01", merged["192.168.0.1"])
        assertEquals("aa:bb:cc:dd:ee:02", merged["192.168.0.2"])
        assertEquals("aa:bb:cc:dd:ee:03", merged["192.168.0.3"])
    }

    @Test
    fun mergeArp_secondWinsOnConflict() {
        val merged = NetworkScanner.mergeArp(
            mapOf("192.168.0.1" to "aa:bb:cc:dd:ee:01"),
            mapOf("192.168.0.1" to "aa:bb:cc:dd:ee:ff")
        )
        assertEquals("aa:bb:cc:dd:ee:ff", merged["192.168.0.1"])
    }

    @Test
    fun mergeArp_emptyFirstKeepsSecond() {
        val merged = NetworkScanner.mergeArp(emptyMap(), mapOf("192.168.0.1" to "aa:bb:cc:dd:ee:01"))
        assertEquals(1, merged.size)
    }

    // ---------- parseMacvendorsResponse ----------

    @Test
    fun parseMacvendorsResponse_validName() {
        assertEquals("Dell Inc.", VendorLookup.parseMacvendorsResponse(200, "Dell Inc."))
        // Le nom peut contenir des espaces superflus → trim.
        assertEquals("Dell Inc.", VendorLookup.parseMacvendorsResponse(200, "  Dell Inc.  "))
    }

    @Test
    fun parseMacvendorsResponse_unknown() {
        assertNull(VendorLookup.parseMacvendorsResponse(404, "Not Found"))
        assertNull(VendorLookup.parseMacvendorsResponse(500, "error"))
    }

    @Test
    fun parseMacvendorsResponse_emptyBody() {
        assertNull(VendorLookup.parseMacvendorsResponse(200, ""))
        assertNull(VendorLookup.parseMacvendorsResponse(200, "   "))
    }

    // ---------- lookup : cache ----------

    @Test
    fun lookup_cacheAvoidsRefetch() {
        var calls = 0
        val fetcher: (String) -> String? = { calls++; "Dell Inc." }
        val cache = mutableMapOf<String, String>()

        val first = VendorLookup.lookup("64:00:6a:12:34:56", cache, fetcher = fetcher)
        val second = VendorLookup.lookup("64:00:6a:12:34:56", cache, fetcher = fetcher)

        assertEquals("Dell Inc.", first)
        assertEquals("Dell Inc.", second)
        assertEquals("une seule requête réseau", 1, calls)
    }

    @Test
    fun lookup_samePrefixSharesCacheEntry() {
        // Deux MAC du même fabricant (même préfixe 64006a) → une seule requête.
        var calls = 0
        val fetcher: (String) -> String? = { calls++; "Dell Inc." }
        val cache = mutableMapOf<String, String>()

        VendorLookup.lookup("64:00:6a:11:11:11", cache, fetcher = fetcher)
        val second = VendorLookup.lookup("64:00:6a:22:22:22", cache, fetcher = fetcher)

        assertEquals("Dell Inc.", second)
        assertEquals("le préfixe est déjà en cache", 1, calls)
    }

    @Test
    fun lookup_unknownNotRetried() {
        // Valeur « » (inconnu) est mise en cache → pas de seconde requête.
        var calls = 0
        val fetcher: (String) -> String? = { calls++; null }
        val cache = mutableMapOf<String, String>()

        assertNull(VendorLookup.lookup("64:00:6a:12:34:56", cache, fetcher = fetcher))
        assertNull(VendorLookup.lookup("64:00:6a:12:34:56", cache, fetcher = fetcher))

        assertEquals("l'inconnu ne doit pas être re-tenté", 1, calls)
    }

    @Test
    fun lookup_invalidMacReturnsNullWithoutFetch() {
        var calls = 0
        val fetcher: (String) -> String? = { calls++; "X" }
        val cache = mutableMapOf<String, String>()

        assertNull(VendorLookup.lookup("", cache, fetcher = fetcher))
        assertNull(VendorLookup.lookup("zz:zz:zz:zz:zz:zz", cache, fetcher = fetcher))

        assertEquals("aucune requête pour une MAC invalide", 0, calls)
    }

    @Test
    fun lookup_fetchFailureIsSilent() {
        // Une exception dans le fetcher ne doit pas remonter → null.
        val fetcher: (String) -> String? = { throw RuntimeException("boom") }
        val cache = mutableMapOf<String, String>()
        assertNull(VendorLookup.lookup("64:00:6a:12:34:56", cache, fetcher = fetcher))
    }
}

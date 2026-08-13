package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Valide le chargement complet de la base OUI réelle (39 933 fabricants)
 * et les lookups sur les préfixes vus sur le réseau de test.
 */
class OuiDatabaseTest {

    private fun loadOui(): Map<String, String> {
        val resource = javaClass.classLoader!!.getResource("oui.txt")!!
        val m = HashMap<String, String>()
        File(resource.toURI()).bufferedReader().useLines { lines ->
            lines.forEach { line ->
                NetworkScanner.parseOuiLine(line)?.let { (mac, vendor) -> m[mac] = vendor }
            }
        }
        return m
    }

    @Test
    fun ouiDatabase_loadsAndResolves() {
        val oui = loadOui()
        assertTrue("la base doit contenir au moins 30 000 OUIs", oui.size > 30_000)

        // Préfixes observés sur le réseau de test du Pi
        assertEquals("FREEBOX SAS", NetworkScanner.vendorFor("f4:ca:e5:4d:d3:e9", oui))
        assertEquals("Xiaomi Communications Co Ltd", NetworkScanner.vendorFor("8c:7a:3d:c6:6c:68", oui))
        assertEquals("Hewlett Packard", NetworkScanner.vendorFor("b4:b5:2f:bd:b3:d9", oui))
        assertEquals("Synology Incorporated", NetworkScanner.vendorFor("00:11:32:c9:20:e4", oui))
    }

    @Test
    fun ouiDatabase_noDuplicateKeys() {
        val oui = loadOui()
        val duplicates = oui.size
        val unique = HashSet<String>()
        javaClass.classLoader!!.getResource("oui.txt")!!.let { res ->
            File(res.toURI()).bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    NetworkScanner.parseOuiLine(line)?.let { unique.add(it.first) }
                }
            }
        }
        assertEquals("aucun doublon de préfixe", unique.size, duplicates)
    }
}

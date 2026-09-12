package com.fabrice.network.scanner

import android.content.Context
import com.fabrice.network.scanner.capture.DnsSniParser
import com.fabrice.network.scanner.capture.IpPacket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ThreadLocalRandom

/**
 * Test de détournement DNS (v1.9.37) — utile sur un Wi-Fi captif/public :
 *  1. domaine SENTINELLE (example.com) : la réponse du DNS de la box est-elle
 *     cohérente avec celles de Cloudflare (1.1.1.1) et Quad9 (9.9.9.9) ?
 *  2. domaine INEXISTANT aléatoire : un résolveur honnête répond NXDOMAIN ;
 *     une IP à la place = détournement (publicité, portail, hameçonnage) ;
 *  3. même test vers 1.1.1.1 : si LUI aussi répond une IP, le réseau
 *     intercepte tout le port 53 (interception transparente) ;
 *  4. latence de chaque résolveur (benchmark).
 * Construction/analyse des messages DNS et verdict = fonctions pures.
 */
object DnsHijackTest {

    const val SENTINEL = "example.com"

    data class ResolverResult(
        val server: String,
        val label: String,
        val latencyMs: Int?,
        val sentinelIps: List<String>,
        val nxRcode: Int?,
        val nxIps: List<String>,
        val error: String? = null
    )

    data class Verdict(val level: Int, val summary: String, val details: List<String>)

    /** Message DNS : requête A IN pour [name], flag RD. */
    fun buildQuery(id: Int, name: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write((id ushr 8) and 0xFF); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00)          // RD
        out.write(0); out.write(1)                // QDCOUNT
        repeat(6) { out.write(0) }                // AN/NS/AR
        name.trimEnd('.').split('.').forEach { l ->
            val b = l.toByteArray(Charsets.US_ASCII)
            out.write(b.size); out.write(b)
        }
        out.write(0)
        out.write(0); out.write(1)                // QTYPE A
        out.write(0); out.write(1)                // QCLASS IN
        return out.toByteArray()
    }

    /** (rcode, IPs A) d'une réponse ; null si l'ID ne correspond pas / message invalide. */
    fun parseResponse(data: ByteArray, len: Int, expectedId: Int): Pair<Int, List<String>>? {
        if (len < 12) return null
        if (IpPacket.u16(data, 0) != expectedId) return null
        val flags = IpPacket.u16(data, 2)
        if (flags and 0x8000 == 0) return null
        val rcode = flags and 0x000F
        val ips = DnsSniParser.parseDnsResponses(data, len).map { it.first }.filter { !it.contains(':') }
        return rcode to ips
    }

    /** Interroge [server] pour [name] en UDP/53 → (rcode, ips, latence) ou null. */
    fun query(server: String, name: String, timeoutMs: Int = 3_000): Triple<Int, List<String>, Int>? {
        val id = ThreadLocalRandom.current().nextInt(1, 0xFFFF)
        val q = buildQuery(id, name)
        return runCatching {
            DatagramSocket().use { s ->
                s.soTimeout = timeoutMs
                val t0 = System.currentTimeMillis()
                s.send(DatagramPacket(q, q.size, InetSocketAddress(InetAddress.getByName(server), 53)))
                val buf = ByteArray(1500)
                val p = DatagramPacket(buf, buf.size)
                s.receive(p)
                val lat = (System.currentTimeMillis() - t0).toInt()
                val parsed = parseResponse(buf, p.length, id) ?: return@runCatching null
                Triple(parsed.first, parsed.second, lat)
            }
        }.getOrNull()
    }

    fun randomNxDomain(): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        val r = ThreadLocalRandom.current()
        val s = (1..12).map { alphabet[r.nextInt(alphabet.length)] }.joinToString("")
        return "nx$s.example.net"
    }

    private fun test(server: String, label: String, nx: String): ResolverResult {
        val sent = query(server, SENTINEL)
        if (sent == null) return ResolverResult(server, label, null, emptyList(), null, emptyList(), "pas de réponse")
        val nxr = query(server, nx)
        return ResolverResult(
            server, label, sent.third, sent.second,
            nxr?.first, nxr?.second.orEmpty(),
            if (nxr == null) "pas de réponse (domaine inexistant)" else null
        )
    }

    /** Exécute le test : DNS de la box (premier DNS IPv4 du lien) + Cloudflare + Quad9. */
    fun run(context: Context): List<ResolverResult> {
        val nx = randomNxDomain()
        val boxDns = NetworkInfoProvider.readDns(context).firstOrNull { !it.contains(':') && it != "127.0.0.1" }
        val out = mutableListOf<ResolverResult>()
        if (boxDns != null) out.add(test(boxDns, "DNS du réseau", nx))
        out.add(test("1.1.1.1", "Cloudflare", nx))
        out.add(test("9.9.9.9", "Quad9", nx))
        return out
    }

    /** Verdict pur : 0 = OK, 1 = à vérifier, 2 = détournement. */
    fun evaluate(results: List<ResolverResult>): Verdict {
        val details = mutableListOf<String>()
        var level = 0
        val box = results.firstOrNull { it.label == "DNS du réseau" }
        val publics = results.filter { it.label != "DNS du réseau" }

        results.forEach { r ->
            details.add("${r.label} (${r.server}) : " + (r.latencyMs?.let { "$it ms" } ?: r.error ?: "—"))
        }
        if (box == null) {
            details.add("DNS du réseau introuvable (pas de lien actif ?).")
            level = maxOf(level, 1)
        } else if (box.error != null && box.latencyMs == null) {
            details.add("Le DNS du réseau ne répond pas : résolution impossible sans résolveur tiers.")
            level = maxOf(level, 1)
        } else {
            if (box.nxRcode == 0 && box.nxIps.isNotEmpty()) {
                details.add("🚨 Le DNS du réseau répond une IP (${box.nxIps.first()}) pour un domaine INEXISTANT : détournement NXDOMAIN (publicité, portail ou hameçonnage).")
                level = 2
            }
            val pubIps = publics.flatMap { it.sentinelIps }.toSet()
            if (box.sentinelIps.isNotEmpty() && pubIps.isNotEmpty() && box.sentinelIps.none { it in pubIps }) {
                details.add("⚠️ $SENTINEL : le réseau répond ${box.sentinelIps.joinToString()} alors que les résolveurs publics répondent ${pubIps.joinToString()} — possible détournement.")
                level = maxOf(level, 1)
            }
        }
        publics.forEach { p ->
            if (p.nxRcode == 0 && p.nxIps.isNotEmpty()) {
                details.add("🚨 ${p.label} répond une IP pour un domaine inexistant : le réseau INTERCEPTE tout le port 53 (DNS transparent).")
                level = 2
            }
        }
        val okPublics = publics.count { it.latencyMs != null }
        if (okPublics == 0 && box != null && box.latencyMs != null) {
            details.add("⚠️ Les résolveurs publics sont injoignables en UDP/53 : le réseau force son propre DNS.")
            level = maxOf(level, 1)
        }
        val fastest = results.filter { it.latencyMs != null }.minByOrNull { it.latencyMs!! }
        if (fastest != null) details.add("Le plus rapide : ${fastest.label} (${fastest.latencyMs} ms).")
        val summary = when (level) {
            2 -> "Détournement DNS détecté"
            1 -> "DNS à vérifier"
            else -> "DNS sain : réponses cohérentes, NXDOMAIN respecté"
        }
        return Verdict(level, summary, details)
    }
}

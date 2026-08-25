package com.fabrice.network.scanner

import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Sonde d'imprimante réseau via IPP (Internet Printing Protocol, port 631) +
 * SNMP (Printer-MIB, port 161).
 *
 * IPP `Get-Printer-Attributes` renvoie le modèle commercial exact
 * (`printer-make-and-model`, ex. « HP Color LaserJet MFP E57540 »), l'état, et
 * les niveaux de consommables (toner/encre). Le compteur de pages total est lu
 * en SNMP (`prtMarkerLifeCount`), non exposé de façon standard en IPP.
 *
 * Encodage/décodage IPP faits main (binaire), sans dépendance.
 */
object PrinterProbe {

    /** Un consommable (toner/encre) : nom, couleur, type, niveau 0-100 (ou null). */
    data class Supply(
        val name: String,
        val color: String = "",
        val type: String = "",
        val levelPercent: Int? = null
    )

    /** Instantané des infos/statistiques d'une imprimante. */
    data class PrinterInfo(
        val makeAndModel: String = "",
        val info: String = "",
        val location: String = "",
        val state: String = "",
        val stateReasons: List<String> = emptyList(),
        val supplies: List<Supply> = emptyList(),
        val pageCount: Long? = null,
        val scanCount: Long? = null,
        val copyCount: Long? = null,
        val uptimeSeconds: Long? = null,
        val firmware: String = ""
    ) {
        val hasData: Boolean
            get() = makeAndModel.isNotBlank() || supplies.isNotEmpty() ||
                pageCount != null || scanCount != null || state.isNotBlank()
    }

    /** Compteurs d'usage lus sur la page EWS HP (impressions/scans/copies). */
    data class UsageCounters(
        val printImpressions: Long? = null,
        val scanImages: Long? = null,
        val copyImpressions: Long? = null
    )

    // OID Printer-MIB : compteur de pages « à vie » du marqueur principal.
    private const val OID_MARKER_LIFE_COUNT = "1.3.6.1.2.1.43.10.2.1.4.1.1"

    /** Chemins IPP les plus courants (varient selon fabricant). */
    private val IPP_PATHS = listOf("/ipp/print", "/ipp/printer", "/", "/ipp")

    // ------------------------------------------------------------- IPP tags
    private const val TAG_OPERATION = 0x01
    private const val TAG_PRINTER = 0x04
    private const val TAG_END = 0x03
    private const val TAG_CHARSET = 0x47
    private const val TAG_NATURAL_LANG = 0x48
    private const val TAG_URI = 0x45
    private const val TAG_KEYWORD = 0x44
    private const val TAG_INTEGER = 0x21
    private const val TAG_ENUM = 0x23

    /**
     * Interroge une imprimante et retourne ses infos/stats, ou null si aucune
     * donnée exploitable (ni IPP ni SNMP ne répondent). Bloquant (IO).
     */
    fun probe(ip: String, timeoutMs: Int = 2_500): PrinterInfo? {
        val ipp = runCatching { ippGetPrinterAttributes(ip, timeoutMs) }.getOrNull()
        val snmpPages = runCatching { snmpPageCount(ip, timeoutMs) }.getOrNull()
        // Page d'usage EWS grand public (HP « Ink ») : XML DevMgmt.
        val usage = runCatching { fetchUsageCounters(ip, timeoutMs) }.getOrNull()
        // Page d'usage EWS Enterprise (FutureSmart, ex. E57540) : HTML — c'est là
        // que vivent les compteurs de scans/copies (absents du SNMP).
        val html = if (usage?.scanImages == null || usage.copyImpressions == null) {
            runCatching { fetchHpUsageHtml(ip, timeoutMs) }.getOrNull()
        } else null

        // Pages : SNMP (source confirmée) > usage XML > usage HTML > IPP.
        val pageCount = snmpPages ?: usage?.printImpressions ?: html?.printImpressions ?: ipp?.pageCount
        val scanCount = usage?.scanImages ?: html?.scanImages
        val copyCount = usage?.copyImpressions ?: html?.copyImpressions
        // Consommables : IPP (marker-levels) sinon SNMP (markerSuppliesLevel).
        val supplies = ipp?.supplies?.takeIf { it.isNotEmpty() }
            ?: runCatching { snmpSupplies(ip, timeoutMs) }.getOrNull()
            ?: emptyList()

        if (ipp != null) {
            return ipp.copy(
                pageCount = pageCount, scanCount = scanCount, copyCount = copyCount,
                supplies = supplies
            )
        }
        // Repli SNMP : modèle via sysDescr si l'IPP est muet (631 fermé).
        val snmp = runCatching { SnmpScanner.probeBlocking(ip, timeoutMs) }.getOrNull()
        if (snmp?.descr.isNullOrBlank() && pageCount == null && scanCount == null && supplies.isEmpty()) return null
        return PrinterInfo(
            makeAndModel = snmp?.descr?.take(120)?.trim().orEmpty(),
            uptimeSeconds = snmp?.uptimeSeconds,
            pageCount = pageCount,
            scanCount = scanCount,
            copyCount = copyCount,
            supplies = supplies
        )
    }

    // Colonnes SNMP des consommables (Printer-MIB, RFC 3805).
    private const val OID_SUPPLY_DESC = "1.3.6.1.2.1.43.11.1.1.6.1"
    private const val OID_SUPPLY_MAX = "1.3.6.1.2.1.43.11.1.1.8.1"
    private const val OID_SUPPLY_LEVEL = "1.3.6.1.2.1.43.11.1.1.9.1"

    /** Niveaux de consommables via SNMP (markerSupplies), en % 0-100. */
    private fun snmpSupplies(ip: String, timeoutMs: Int): List<Supply> {
        fun idx(oid: String) = oid.substringAfterLast('.').toIntOrNull() ?: -1
        val desc = SnmpScanner.walk(ip, OID_SUPPLY_DESC, timeoutMs)
            .associate { idx(it.oid) to it.textOrNull().orEmpty() }
        val max = SnmpScanner.walk(ip, OID_SUPPLY_MAX, timeoutMs)
            .associate { idx(it.oid) to (it.longOrNull() ?: -1L) }
        val level = SnmpScanner.walk(ip, OID_SUPPLY_LEVEL, timeoutMs)
            .associate { idx(it.oid) to (it.longOrNull() ?: -1L) }
        if (level.isEmpty()) return emptyList()
        return level.keys.sorted().map { i ->
            val lv = level[i] ?: -1L
            val mx = max[i] ?: -1L
            val pct = when {
                lv < 0 -> null                                   // -1/-2/-3 = inconnu
                mx > 0 -> ((lv * 100) / mx).toInt().coerceIn(0, 100)
                lv in 0..100 -> lv.toInt()
                else -> null
            }
            Supply(name = desc[i].orEmpty().ifBlank { "Consommable $i" }, levelPercent = pct)
        }
    }

    /** Page d'usage HTML des HP Enterprise (FutureSmart). */
    private const val HP_USAGE_HTML = "/hp/device/InternalPages/Index?id=UsagePage"

    /** Récupère et parse la page d'usage HTML FutureSmart (HTTPS puis HTTP). */
    private fun fetchHpUsageHtml(ip: String, timeoutMs: Int): UsageCounters? {
        for (scheme in listOf("https", "http")) {
            val html = runCatching { httpGet("$scheme://$ip$HP_USAGE_HTML", timeoutMs) }.getOrNull()
            if (!html.isNullOrBlank() && html.contains("Counts", ignoreCase = true)) {
                return parseHpUsageHtml(html)
            }
        }
        return null
    }

    /**
     * Parse la page d'usage HTML FutureSmart. Pour chaque section (« Scan Counts »,
     * « Copy Counts », « Print Counts »/« Equivalent Impressions »), on lit le
     * « Grand Total » qui suit. Réplique la logique du script Python de référence.
     * Fonction pure — testable.
     */
    fun parseHpUsageHtml(html: String): UsageCounters {
        val lines = htmlToLines(html)
        return UsageCounters(
            printImpressions = sectionGrandTotal(lines, "Print Counts")
                ?: sectionGrandTotal(lines, "Equivalent Impressions"),
            scanImages = sectionGrandTotal(lines, "Scan Counts"),
            copyImpressions = sectionGrandTotal(lines, "Copy Counts")
        )
    }

    /** Convertit un HTML en lignes texte (balises → sauts de ligne, entités décodées). */
    private fun htmlToLines(html: String): List<String> {
        var t = html.replace(Regex("<script.*?</script>", setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.IGNORE_CASE)), " ")
        t = t.replace(Regex("<style.*?</style>", setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.IGNORE_CASE)), " ")
        t = t.replace(Regex("<[^>]+>"), "\n")
        t = t.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<")
            .replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'")
        return t.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
    }

    /**
     * Cherche la 1re ligne contenant [sectionTitle], puis le « Grand Total »
     * suivant (dans les ~30 lignes), puis la 1re valeur numérique après lui.
     */
    private fun sectionGrandTotal(lines: List<String>, sectionTitle: String): Long? {
        val start = lines.indexOfFirst { it.contains(sectionTitle, ignoreCase = true) }
        if (start < 0) return null
        var gt = -1
        for (i in start until minOf(start + 30, lines.size)) {
            if (lines[i].equals("Grand Total", ignoreCase = true)) { gt = i; break }
        }
        if (gt < 0) return null
        for (i in (gt + 1) until minOf(gt + 6, lines.size)) {
            val m = Regex("^[\\d,]+$").find(lines[i])
            if (m != null) return m.value.replace(",", "").toLongOrNull()
        }
        return null
    }

    /** Colonne SNMP prtMarkerLifeCount (indexée par périphérique.marqueur). */
    private const val OID_MARKER_LIFE_COLUMN = "1.3.6.1.2.1.43.10.2.1.4"

    /**
     * Compteur de pages total via SNMP. GET direct sur l'index usuel (.1.1),
     * puis, si vide, WALK de toute la colonne prtMarkerLifeCount en prenant la
     * plus grande valeur — robuste aux index variables selon les modèles.
     */
    private fun snmpPageCount(ip: String, timeoutMs: Int): Long? {
        val direct = SnmpScanner.getOids(ip, listOf(OID_MARKER_LIFE_COUNT), timeoutMs)[OID_MARKER_LIFE_COUNT]
            ?.longOrNull()
        if (direct != null && direct > 0) return direct
        val rows = SnmpScanner.walk(ip, OID_MARKER_LIFE_COLUMN, timeoutMs)
        return rows.mapNotNull { it.longOrNull() }.filter { it >= 0 }.maxOrNull()
    }

    // ---------------------------------------------- Compteurs d'usage (EWS HP)

    /** Endpoint d'usage standard des imprimantes HP (FutureSmart et web JetDirect). */
    private const val HP_USAGE_PATH = "/DevMgmt/ProductUsageDyn.xml"

    /**
     * Récupère les compteurs d'usage via la page EWS HP `ProductUsageDyn.xml`
     * (impressions / scans / copies). Essaie HTTP puis HTTPS (certificat
     * auto-signé accepté pour cette lecture locale). null si indisponible
     * (imprimante non-HP ou page absente).
     */
    private fun fetchUsageCounters(ip: String, timeoutMs: Int): UsageCounters? {
        for (scheme in listOf("http", "https")) {
            val xml = runCatching { httpGet("$scheme://$ip$HP_USAGE_PATH", timeoutMs) }.getOrNull()
            if (!xml.isNullOrBlank()) {
                val counters = parseHpUsage(xml)
                if (counters != null) return counters
            }
        }
        return null
    }

    /** GET simple. En HTTPS, accepte les certificats auto-signés (EWS local). */
    private fun httpGet(url: String, timeoutMs: Int): String? {
        val conn = URL(url).openConnection() as HttpURLConnection
        return try {
            if (conn is javax.net.ssl.HttpsURLConnection) {
                val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
                val trustAll = arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
                    override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
                    override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>?, a: String?) {}
                    override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
                })
                ctx.init(null, trustAll, java.security.SecureRandom())
                conn.sslSocketFactory = ctx.socketFactory
                conn.setHostnameVerifier { _, _ -> true }
            }
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.setRequestProperty("User-Agent", "NetworkScanner")
            if (conn.responseCode != 200) return null
            conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        } catch (e: Exception) {
            null
        } finally {
            runCatching { conn.disconnect() }
        }
    }

    /**
     * Parse la page HP `ProductUsageDyn.xml` et extrait les compteurs d'usage.
     * Robuste aux préfixes de namespace (pudyn:/dd:) : on cible les noms locaux.
     * Fonction pure — testable. null si aucun compteur trouvé.
     */
    fun parseHpUsage(xml: String): UsageCounters? {
        // Impressions : TotalImpressions du sous-unité imprimante.
        val printerBlock = extractBlock(xml, "PrinterSubunit") ?: xml
        val print = extractLong(printerBlock, "TotalImpressions")

        // Scans : ScanImages, sinon somme AdfImages + FlatbedImages.
        val scanBlock = extractBlock(xml, "ScannerEngineSubunit")
            ?: extractBlock(xml, "ScannerSubunit")
        val scan = if (scanBlock != null) {
            extractLong(scanBlock, "ScanImages")
                ?: run {
                    val adf = extractLong(scanBlock, "AdfImages")
                    val fb = extractLong(scanBlock, "FlatbedImages")
                    if (adf != null || fb != null) (adf ?: 0L) + (fb ?: 0L) else null
                }
        } else null

        // Copies : TotalImpressions du sous-unité copie.
        val copy = extractBlock(xml, "CopyApplicationSubunit")?.let {
            extractLong(it, "TotalImpressions")
        }

        if (print == null && scan == null && copy == null) return null
        return UsageCounters(printImpressions = print, scanImages = scan, copyImpressions = copy)
    }

    /** Extrait le contenu d'un élément par nom LOCAL (ignore le préfixe ns). */
    private fun extractBlock(xml: String, localName: String): String? {
        val re = Regex("<(?:\\w+:)?$localName\\b[^>]*>(.*?)</(?:\\w+:)?$localName>", RegexOption.DOT_MATCHES_ALL)
        return re.find(xml)?.groupValues?.get(1)
    }

    /** Extrait la première valeur entière d'un élément par nom LOCAL. */
    private fun extractLong(xml: String, localName: String): Long? {
        val re = Regex("<(?:\\w+:)?$localName\\b[^>]*>\\s*(\\d+)")
        return re.find(xml)?.groupValues?.get(1)?.toLongOrNull()
    }

    // --------------------------------------------------------------- IPP I/O

    /** Tente l'IPP sur les chemins connus jusqu'à une réponse exploitable. */
    private fun ippGetPrinterAttributes(ip: String, timeoutMs: Int): PrinterInfo? {
        for (path in IPP_PATHS) {
            val resp = runCatching { ippRequest(ip, path, timeoutMs) }.getOrNull() ?: continue
            val info = runCatching { parseIppResponse(resp) }.getOrNull()
            if (info != null && info.hasData) return info
        }
        return null
    }

    /** Envoie une requête IPP Get-Printer-Attributes et retourne la réponse brute. */
    private fun ippRequest(ip: String, path: String, timeoutMs: Int): ByteArray? {
        val url = URL("http://$ip:631$path")
        val conn = url.openConnection() as HttpURLConnection
        return try {
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/ipp")
            val body = buildGetPrinterAttributes("ipp://$ip$path")
            conn.outputStream.use { it.write(body); it.flush() }
            if (conn.responseCode != 200) return null
            conn.inputStream.use { it.readBytes() }
        } catch (e: Exception) {
            null
        } finally {
            runCatching { conn.disconnect() }
        }
    }

    // ----------------------------------------------------------- IPP encode

    /** Construit une requête IPP/1.1 Get-Printer-Attributes (operation 0x000B). */
    fun buildGetPrinterAttributes(printerUri: String, requestId: Int = 1): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x01); out.write(0x01)          // version 1.1
        out.write(0x00); out.write(0x0B)          // operation-id : Get-Printer-Attributes
        out.write((requestId ushr 24) and 0xFF)
        out.write((requestId ushr 16) and 0xFF)
        out.write((requestId ushr 8) and 0xFF)
        out.write(requestId and 0xFF)             // request-id
        out.write(TAG_OPERATION)                  // operation-attributes-tag
        writeAttr(out, TAG_CHARSET, "attributes-charset", "utf-8")
        writeAttr(out, TAG_NATURAL_LANG, "attributes-natural-language", "en")
        writeAttr(out, TAG_URI, "printer-uri", printerUri)
        // requested-attributes : « all » suffit sur la quasi-totalité des modèles.
        writeAttr(out, TAG_KEYWORD, "requested-attributes", "all")
        out.write(TAG_END)                        // end-of-attributes-tag
        return out.toByteArray()
    }

    /** Écrit un attribut IPP : value-tag, name-length, name, value-length, value. */
    private fun writeAttr(out: ByteArrayOutputStream, tag: Int, name: String, value: String) {
        out.write(tag)
        val n = name.toByteArray(Charsets.US_ASCII)
        out.write((n.size ushr 8) and 0xFF); out.write(n.size and 0xFF)
        out.write(n)
        val v = value.toByteArray(Charsets.UTF_8)
        out.write((v.size ushr 8) and 0xFF); out.write(v.size and 0xFF)
        out.write(v)
    }

    // ----------------------------------------------------------- IPP decode

    /** Attribut IPP décodé : tag de valeur + valeur brute. */
    private data class IppValue(val tag: Int, val bytes: ByteArray) {
        fun text(): String = bytes.toString(Charsets.UTF_8)
        fun int(): Int {
            var v = 0
            for (b in bytes) v = (v shl 8) or (b.toInt() and 0xFF)
            return v
        }
    }

    /**
     * Parse une réponse IPP et extrait les attributs imprimante utiles.
     * Retourne un PrinterInfo (éventuellement vide) ou null si le buffer n'est
     * pas une réponse IPP valide. Fonction pure — testable.
     */
    fun parseIppResponse(resp: ByteArray): PrinterInfo? {
        if (resp.size < 8) return null
        // version(2) + status-code(2) + request-id(4), puis groupes d'attributs.
        var pos = 8
        val attrs = LinkedHashMap<String, MutableList<IppValue>>()
        var lastName: String? = null
        try {
            while (pos < resp.size) {
                val tag = resp[pos].toInt() and 0xFF
                pos++
                if (tag == TAG_END) break
                // Tags délimiteurs de groupe (0x00-0x05) : pas d'attribut.
                if (tag <= 0x05) { lastName = null; continue }
                val nameLen = ((resp[pos].toInt() and 0xFF) shl 8) or (resp[pos + 1].toInt() and 0xFF)
                pos += 2
                val name = if (nameLen > 0) {
                    val s = String(resp, pos, nameLen, Charsets.US_ASCII); pos += nameLen; s
                } else lastName
                val valLen = ((resp[pos].toInt() and 0xFF) shl 8) or (resp[pos + 1].toInt() and 0xFF)
                pos += 2
                val value = resp.copyOfRange(pos, (pos + valLen).coerceAtMost(resp.size))
                pos += valLen
                if (name != null) {
                    attrs.getOrPut(name) { mutableListOf() }.add(IppValue(tag, value))
                    lastName = name
                }
            }
        } catch (e: Exception) {
            // buffer tronqué : on retourne ce qu'on a pu extraire
        }
        return buildInfo(attrs)
    }

    private fun buildInfo(attrs: Map<String, List<IppValue>>): PrinterInfo {
        fun text(key: String): String = attrs[key]?.firstOrNull()?.text()?.trim().orEmpty()
        fun texts(key: String): List<String> = attrs[key]?.map { it.text().trim() } ?: emptyList()
        fun ints(key: String): List<Int> = attrs[key]?.map { it.int() } ?: emptyList()

        val names = texts("marker-names")
        val levels = ints("marker-levels")
        val colors = texts("marker-colors")
        val types = texts("marker-types")
        val supplies = names.mapIndexed { i, nm ->
            val lvl = levels.getOrNull(i)
            Supply(
                name = nm,
                color = colors.getOrNull(i).orEmpty(),
                type = types.getOrNull(i).orEmpty(),
                levelPercent = if (lvl != null && lvl in 0..100) lvl else null
            )
        }
        return PrinterInfo(
            makeAndModel = text("printer-make-and-model"),
            info = text("printer-info"),
            location = text("printer-location"),
            state = stateLabel(attrs["printer-state"]?.firstOrNull()?.int()),
            stateReasons = texts("printer-state-reasons").filter { it.isNotBlank() && it != "none" },
            supplies = supplies,
            uptimeSeconds = attrs["printer-up-time"]?.firstOrNull()?.int()?.toLong(),
            firmware = text("printer-firmware-string-version")
        )
    }

    /** Libellé lisible de l'état IPP (printer-state : 3=idle, 4=processing, 5=stopped). */
    fun stateLabel(state: Int?): String = when (state) {
        3 -> "Prête"
        4 -> "Impression en cours"
        5 -> "Arrêtée"
        else -> ""
    }
}

package com.fabrice.network.scanner

import org.json.JSONArray
import org.json.JSONObject

/**
 * Base CVE embarquée (assets/cve_db.json), générée par tools/build_cve_db.py
 * depuis CISA KEV + NVD API 2.0. Lisible hors-ligne, datée à la génération.
 *
 * Chaque CVE : {id, product, sev, cvss, desc, kev, ransomware, ranges:[...]}
 *   ranges = bornes de versions vulnérables (NVD CPE match criteria) :
 *     s  = versionStartIncluding, e  = versionEndExcluding
 *     si = versionStartExcluding, ei = versionEndIncluding
 *   ranges vides → alerte produit-level uniquement (typiquement KEV).
 */
data class CveRange(
    val startIncluding: String? = null,
    val endExcluding: String? = null,
    val startExcluding: String? = null,
    val endIncluding: String? = null
) {
    companion object {
        fun fromJson(o: JSONObject): CveRange = CveRange(
            startIncluding = o.optString("s").ifBlank { null },
            endExcluding = o.optString("e").ifBlank { null },
            startExcluding = o.optString("si").ifBlank { null },
            endIncluding = o.optString("ei").ifBlank { null }
        )
    }
}

data class CveEntry(
    val id: String,
    val product: String,
    val severity: String,      // CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    val cvss: Double?,
    val description: String,
    val kev: Boolean,          // activement exploitée (CISA KEV)
    val ransomware: Boolean,
    val ranges: List<CveRange>
) {
    companion object {
        fun fromJson(o: JSONObject): CveEntry {
            val ranges = JSONArray()
            val raw = o.optJSONArray("ranges") ?: ranges
            return CveEntry(
                id = o.getString("id"),
                product = o.getString("product"),
                severity = o.optString("sev", "UNKNOWN"),
                cvss = if (o.has("cvss") && !o.isNull("cvss")) o.optDouble("cvss") else null,
                description = o.optString("desc", ""),
                kev = o.optBoolean("kev", false),
                ransomware = o.optBoolean("ransomware", false),
                ranges = (0 until raw.length()).map { CveRange.fromJson(raw.getJSONObject(it)) }
            )
        }
    }
}

/** Base CVE chargée : indexée par produit pour un matching rapide. */
class CveDatabase(
    val generated: String,
    val productLabels: Map<String, String>,
    val byProduct: Map<String, List<CveEntry>>
) {
    val allCount: Int = byProduct.values.sumOf { it.size }

    fun entriesFor(product: String): List<CveEntry> = byProduct[product] ?: emptyList()

    companion object {
        fun load(jsonText: String): CveDatabase {
            val root = JSONObject(jsonText)
            val labels = mutableMapOf<String, String>()
            val labelsObj = root.optJSONObject("product_labels") ?: JSONObject()
            labelsObj.keys().forEach { k -> labels[k] = labelsObj.getString(k) }
            val byProduct = HashMap<String, List<CveEntry>>()
            val arr = root.getJSONArray("cves")
            for (i in 0 until arr.length()) {
                val e = CveEntry.fromJson(arr.getJSONObject(i))
                byProduct.merge(e.product, listOf(e)) { a, b -> a + b }
            }
            return CveDatabase(
                generated = root.optString("generated", ""),
                productLabels = labels,
                byProduct = byProduct
            )
        }
    }
}

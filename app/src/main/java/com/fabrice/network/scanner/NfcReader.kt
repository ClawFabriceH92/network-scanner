package com.fabrice.network.scanner

import android.nfc.Tag
import android.nfc.tech.Ndef

/**
 * Lecteur NFC (v1.9.0) — mode lecteur au premier plan uniquement (aucune
 * consommation d'arrière-plan, pas de foreground service).
 *
 * Limite honnête : Android n'expose PAS d'historique système des tags touchés et
 * les paiements NFC sont invisibles aux apps. On n'enregistre que les tags que
 * NOTRE app lit, quand l'écran NFC est ouvert au premier plan.
 *
 * `NdefParser` et `uidToHex` sont purs (testables JVM) ; `buildEntry`/`readPayload`
 * touchent l'API Android `NfcAdapter`/`Ndef`.
 */
object NfcReader {

    data class NfcLogEntry(
        val uid: String,
        val techs: List<String>,
        val payload: String?,
        val ts: Long
    )

    /** UID du tag en hexadécimal (ex: « 04A1B2C3D4E5 »). Pur. */
    fun uidToHex(id: ByteArray?): String =
        id?.joinToString("") { "%02X".format(it) } ?: ""

    /** Construit l'entrée de log depuis un tag découvert. */
    fun buildEntry(tag: Tag, nowMs: Long = System.currentTimeMillis()): NfcLogEntry =
        NfcLogEntry(
            uid = uidToHex(tag.id),
            techs = tag.techList.toList(),
            payload = readPayload(tag),
            ts = nowMs
        )

    /** Lit le contenu NDEF (URI/texte) du tag, ou null si absent/illisible. */
    fun readPayload(tag: Tag): String? {
        val ndef = Ndef.get(tag) ?: return null
        return try {
            ndef.connect()
            try {
                val msg = ndef.ndefMessage ?: return null
                val records = msg.records.map { NdefParser.Record(it.tnf, it.type, it.payload) }
                NdefParser.parse(records).ifBlank { null }
            } finally {
                runCatching { ndef.close() }
            }
        } catch (e: Exception) {
            null
        }
    }
}

/**
 * Parseur NDEF pur (records URI/texte) — indépendant d'Android pour être testé
 * en JVM. On mappe `NdefRecord` → `Record(tnf, type, payload)` côté Android.
 */
object NdefParser {

    const val TNF_WELL_KNOWN = 0x01
    const val RTD_TEXT = 0x54  // 'T'
    const val RTD_URI = 0x55   // 'U'

    data class Record(val tnf: Short, val type: ByteArray, val payload: ByteArray)

    private val URI_PREFIXES = arrayOf(
        "", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:",
        "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://",
        "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://", "urn:",
        "pop:", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://",
        "tcpobex://", "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:",
        "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:"
    )

    /** Parse une liste de records NDEF en une chaîne lisible (« a · b »). */
    fun parse(records: List<Record>): String =
        records.mapNotNull { parseRecord(it) }.joinToString(" · ")

    private fun parseRecord(r: Record): String? {
        if ((r.tnf.toInt() and 0xFF) != TNF_WELL_KNOWN) return null
        return when (r.type.firstOrNull()?.toInt()?.and(0xFF)) {
            RTD_URI -> parseUri(r.payload)
            RTD_TEXT -> parseText(r.payload)
            else -> null
        }
    }

    /** Record URI : payload[0] = code de préfixe, puis l'URI. */
    fun parseUri(payload: ByteArray): String? {
        if (payload.isEmpty()) return null
        val code = payload[0].toInt() and 0xFF
        val prefix = URI_PREFIXES.getOrNull(code) ?: ""
        return prefix + String(payload, 1, payload.size - 1, Charsets.UTF_8)
    }

    /** Record texte : payload[0] = statut (bit 7 UTF-16, bits 0-5 longueur langue). */
    fun parseText(payload: ByteArray): String? {
        if (payload.isEmpty()) return null
        val status = payload[0].toInt() and 0xFF
        val langLen = status and 0x3F
        val offset = 1 + langLen
        if (offset >= payload.size) return null
        val isUtf16 = (status and 0x80) != 0
        val charset = if (isUtf16) Charsets.UTF_16BE else Charsets.UTF_8
        return String(payload, offset, payload.size - offset, charset)
    }
}

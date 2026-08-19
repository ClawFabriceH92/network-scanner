package com.fabrice.network.scanner

import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.session.Session
import com.hierynomus.smbj.share.DiskShare
import java.util.concurrent.TimeUnit

/**
 * Énumération des partages SMB (dossiers partagés) d'un appareil.
 *
 * On teste en accès invité (guest) les partages par défaut — y compris les
 * partages administratifs CACHÉS de Windows (C$, D$, ADMIN$, IPC$) — et les
 * partages courants (public, share, data, backup, media…).
 *
 * Limite assumée : sans identifiants, on ne voit que les partages autorisés
 * au guest. Un partage protégé par mot de passe apparaîtra comme « protégé »
 * (le port 445 est ouvert mais l'énumération échoue) — déjà une info utile.
 */
object SmbShareScanner {

    /** Partages testés en guest : administratifs cachés + noms courants. */
    val DEFAULT_SHARES = listOf(
        // Partages administratifs cachés de Windows ($)
        "C\$", "D\$", "ADMIN\$", "IPC\$",
        // Partages courants
        "public", "Public", "share", "Share", "data", "Data",
        "backup", "Backup", "media", "Media", "photos", "Photos",
        "music", "Music", "videos", "Videos", "downloads", "Downloads",
        "home", "Home", "users", "Users", "documents", "Documents"
    )

    /** Un partage accessible (ou non) sur un appareil. */
    data class SmbShare(
        val name: String,
        val accessible: Boolean,
        val note: String = ""
    )

    /** Un partage NON VIDE : nom + nombre d'éléments + premiers noms (max 5). */
    data class SmbShareEntry(
        val shareName: String,
        val itemCount: Int,
        val firstItems: List<String>
    )

    /**
     * Construit un `SmbShareEntry` à partir du nom du partage et de la liste
     * des entrées racine. Pur et testable (aucun accès réseau) : tronque à 5
     * premiers noms.
     */
    fun summarize(shareName: String, entries: List<String>): SmbShareEntry =
        SmbShareEntry(shareName = shareName, itemCount = entries.size, firstItems = entries.take(5))

    /**
     * Teste les partages SMB d'un hôte en guest. Retourne la liste triée :
     * partages accessibles d'abord (nom + note), puis partages testés mais
     * refusés (marqués protégés) — utile pour voir qu'il y a un serveur SMB.
     *
     * @param host IP de l'appareil
     * @param timeoutMs timeout de connexion global par partage
     * @return partages détectés (vide si pas de serveur SMB joignable)
     */
    fun scanShares(host: String, timeoutMs: Int = 3_000): List<SmbShare> {
        val config = SmbConfig.builder()
            .withTimeout(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            .build()
        val client = SMBClient(config)
        val connection = try {
            client.connect(host, 445)
        } catch (e: Exception) {
            return emptyList() // pas de SMB joignable (port fermé / filtré)
        }
        val session = try {
            // Authentification invité (guest) : domaine vide, user "guest"
            connection.authenticate(AuthenticationContext.guest())
        } catch (e: Exception) {
            runCatching { connection.close() }
            return emptyList()
        }
        val found = mutableListOf<SmbShare>()
        try {
            DEFAULT_SHARES.forEach { shareName ->
                val result = probeShare(session, shareName, timeoutMs)
                if (result != null) found.add(result)
            }
        } finally {
            runCatching { connection.close() }
        }
        return found.sortedWith(compareByDescending<SmbShare> { it.accessible }.thenBy { it.name })
    }

    /** Teste un partage : accessible (listable) ou protégé (refusé). */
    private fun probeShare(session: Session, name: String, timeoutMs: Int): SmbShare? {
        val share = try {
            session.connectShare(name) as? DiskShare
        } catch (e: Exception) {
            // Connexion refusée → partage existe probablement mais protégé,
            // OU partage inexistant. On garde une trace pour les noms connus.
            return if (name.endsWith("\$")) SmbShare(name, accessible = false, note = "protégé")
            else null
        } ?: return null
        return try {
            // Accessible = on peut lister le contenu racine
            share.list("")
            share.close()
            SmbShare(name, accessible = true, note = "accessible")
        } catch (e: Exception) {
            share.close()
            SmbShare(name, accessible = false, note = "protégé")
        }
    }

    /**
     * Liste les partages SMB NON VIDES d'un hôte en accès invité (v1.8.0).
     * Pour chaque partage listable, compte les entrées racine et ne garde que
     * les partages avec au moins un élément. Les partages protégés/vides sont
     * ignorés silencieusement. Jamais bloquant (runCatching + timeout).
     *
     * @param host IP de l'appareil
     * @return partages non vides triés par nombre d'éléments décroissant
     */
    fun nonEmptyShares(host: String, timeoutMs: Int = 3_000): List<SmbShareEntry> {
        val config = SmbConfig.builder()
            .withTimeout(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            .build()
        val client = SMBClient(config)
        val connection = try {
            client.connect(host, 445)
        } catch (e: Exception) {
            return emptyList()
        }
        val session = try {
            connection.authenticate(AuthenticationContext.guest())
        } catch (e: Exception) {
            runCatching { connection.close() }
            return emptyList()
        }
        val entries = mutableListOf<SmbShareEntry>()
        try {
            DEFAULT_SHARES.forEach { shareName ->
                val names = listShareEntries(session, shareName)
                if (!names.isNullOrEmpty()) {
                    entries.add(summarize(shareName, names))
                }
            }
        } finally {
            runCatching { connection.close() }
        }
        return entries.sortedByDescending { it.itemCount }
    }

    /** Liste les entrées racine d'un partage (noms de fichiers/dossiers), null si refusé. */
    private fun listShareEntries(session: Session, name: String): List<String>? {
        val share = try {
            session.connectShare(name) as? DiskShare
        } catch (e: Exception) {
            return null
        } ?: return null
        return try {
            val list = share.list("")
            share.close()
            list.mapNotNull { it.fileName?.takeIf { n -> n != "." && n != ".." } }
        } catch (e: Exception) {
            runCatching { share.close() }
            null
        }
    }
}

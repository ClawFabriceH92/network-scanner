package com.fabrice.network.scanner

/**
 * Comparaison STRUCTURÉE entre deux scans (v1.9.35) — logique pure, testable.
 *
 * Là où la timeline d'audit ne stocke que du texte libre, ce diff produit des
 * changements typés : ports apparus/disparus, appareil dont la MAC a changé
 * pour une même IP (signal d'ARP spoofing, surtout sur la passerelle), une MAC
 * vue sur plusieurs IP (l'attaquant répond pour lui ET pour la passerelle),
 * changement d'IP d'une MAC connue, apparitions/disparitions.
 *
 * Sévérité : 0 = info, 1 = à vérifier, 2 = alerte (notification push).
 */
object ScanDiff {

    enum class Kind { NEW_DEVICE, GONE, PORT_OPENED, PORT_CLOSED, IP_CHANGED, MAC_CHANGED, DUPLICATE_MAC }

    data class Change(
        val kind: Kind,
        val ip: String,
        val mac: String,
        val name: String,
        val detail: String,
        val severity: Int
    ) {
        val icon: String
            get() = when (kind) {
                Kind.NEW_DEVICE -> "🆕"
                Kind.GONE -> "📴"
                Kind.PORT_OPENED -> "🔓"
                Kind.PORT_CLOSED -> "🔒"
                Kind.IP_CHANGED -> "🔀"
                Kind.MAC_CHANGED -> if (severity >= 2) "🚨" else "⚠️"
                Kind.DUPLICATE_MAC -> if (severity >= 2) "🚨" else "⚠️"
            }

        /** Ligne lisible pour la timeline d'audit / la notification. */
        val message: String get() = "$icon ${name.ifBlank { ip }} ($ip) : $detail"
    }

    private fun label(d: Device): String = d.hostname.ifBlank { d.vendor }.ifBlank { d.ip }

    /**
     * Diff complet. [portsKnown] = les deux scans ont scanné les ports (sinon
     * les changements de ports ne sont pas calculés — un scan de surveillance
     * sans ports ne doit pas faire croire que tout s'est fermé).
     */
    fun compute(previous: List<Device>, current: List<Device>, portsKnown: Boolean = true): List<Change> {
        if (previous.isEmpty()) return emptyList()
        val out = mutableListOf<Change>()
        val prevByKey = previous.associateBy { ScanHistory.identityKey(it) }
        val curByKey = current.associateBy { ScanHistory.identityKey(it) }

        // Apparitions / disparitions (par identité MAC ou IP).
        curByKey.forEach { (k, d) ->
            if (k !in prevByKey) out.add(Change(Kind.NEW_DEVICE, d.ip, d.mac, label(d), "nouvel appareil", 0))
        }
        prevByKey.forEach { (k, d) ->
            if (k !in curByKey && d.alive && !d.isSelf) out.add(Change(Kind.GONE, d.ip, d.mac, label(d), "ne répond plus", 0))
        }

        // Même identité : IP changée, ports ouverts/fermés.
        curByKey.forEach { (k, cur) ->
            val prev = prevByKey[k] ?: return@forEach
            if (prev.ip != cur.ip) {
                out.add(Change(Kind.IP_CHANGED, cur.ip, cur.mac, label(cur), "IP ${prev.ip} → ${cur.ip}", 0))
            }
            if (portsKnown && prev.alive && cur.alive) {
                val opened = cur.ports.toSet() - prev.ports.toSet()
                val closed = prev.ports.toSet() - cur.ports.toSet()
                if (opened.isNotEmpty()) {
                    val risky = opened.any { it in RISKY_PORTS }
                    out.add(Change(Kind.PORT_OPENED, cur.ip, cur.mac, label(cur),
                        "port(s) ouvert(s) : ${opened.sorted().joinToString(", ") { portName(it) }}", if (risky) 1 else 0))
                }
                if (closed.isNotEmpty()) {
                    out.add(Change(Kind.PORT_CLOSED, cur.ip, cur.mac, label(cur),
                        "port(s) fermé(s) : ${closed.sorted().joinToString(", ") { portName(it) }}", 0))
                }
            }
        }
        out.addAll(arpAlerts(previous, current))
        return out.sortedByDescending { it.severity }
    }

    /**
     * Signaux d'usurpation ARP uniquement (utilisable par la surveillance en
     * arrière-plan, qui n'a pas les ports) :
     *  - même IP, MAC différente (les deux connues) — alerte si passerelle ;
     *  - une MAC (non aléatoire) présente sur plusieurs IP — alerte si l'une
     *    est la passerelle, sinon « à vérifier » (alias IP légitime possible).
     */
    fun arpAlerts(previous: List<Device>, current: List<Device>): List<Change> {
        val out = mutableListOf<Change>()
        val prevByIp = previous.filter { it.mac.isNotBlank() }.associateBy { it.ip }
        current.filter { it.mac.isNotBlank() }.forEach { cur ->
            val prev = prevByIp[cur.ip] ?: return@forEach
            if (!prev.mac.equals(cur.mac, ignoreCase = true)) {
                val gw = cur.isGateway || prev.isGateway
                out.add(Change(
                    Kind.MAC_CHANGED, cur.ip, cur.mac, label(cur),
                    (if (gw) "MAC de la PASSERELLE changée " else "MAC changée ") +
                        "${prev.mac} → ${cur.mac}" +
                        (if (gw) " : usurpation ARP possible (man-in-the-middle)" else " : nouvel appareil sur cette IP ou usurpation"),
                    if (gw) 2 else 1
                ))
            }
        }
        current.filter { it.mac.isNotBlank() && !it.isRandomizedMac }
            .groupBy { it.mac.lowercase() }
            .filter { it.value.size >= 2 }
            .forEach { (mac, devs) ->
                val gw = devs.any { it.isGateway }
                val ips = devs.map { it.ip }.sorted()
                val ref = devs.firstOrNull { it.isGateway } ?: devs.first()
                out.add(Change(
                    Kind.DUPLICATE_MAC, ref.ip, mac, label(ref),
                    "même MAC sur ${ips.size} IP (${ips.joinToString(", ")})" +
                        (if (gw) " dont la passerelle : usurpation ARP possible" else " : alias IP ou usurpation à vérifier"),
                    if (gw) 2 else 1
                ))
            }
        return out
    }

    /** Résumé court pour un bandeau : « 5 changements (2 alertes) ». */
    fun summary(changes: List<Change>): String {
        if (changes.isEmpty()) return ""
        val alerts = changes.count { it.severity >= 2 }
        val warns = changes.count { it.severity == 1 }
        val n = changes.size
        val base = if (n == 1) "1 changement" else "$n changements"
        val extra = buildList {
            if (alerts > 0) add(if (alerts == 1) "1 alerte" else "$alerts alertes")
            if (warns > 0) add("$warns à vérifier")
        }
        return if (extra.isEmpty()) base else "$base (${extra.joinToString(", ")})"
    }

    /** Ports dont l'ouverture soudaine mérite un regard (admin / accès distant). */
    val RISKY_PORTS = setOf(21, 22, 23, 445, 3389, 5900, 5901, 1433, 3306, 5432, 6379, 27017, 161, 8080, 8443, 9100)

    private fun portName(p: Int): String {
        val name = PortScanner.ALL_PORTS.firstOrNull { it.first == p }?.second
        return if (name.isNullOrBlank()) p.toString() else "$p ($name)"
    }
}

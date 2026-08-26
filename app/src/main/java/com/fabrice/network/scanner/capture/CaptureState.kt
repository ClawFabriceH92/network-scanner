package com.fabrice.network.scanner.capture

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * État partagé de la capture réseau (VPN) — observable par l'UI.
 *
 * Le [CaptureVpnService] écrit ici (connexions vues, octets, chemin du PCAP) et
 * l'écran « Capture réseau » lit les [StateFlow]. C'est un singleton car un
 * VpnService est un composant système : l'UI et le service ne partagent pas
 * d'instance, seulement ce state process-wide.
 */
object CaptureState {

    /** Une connexion suivie (5-uplet), agrégée pour l'affichage. */
    data class Conn(
        val protocol: String,          // "TCP" / "UDP"
        val localPort: Int,
        val remoteIp: String,
        val remotePort: Int,
        val uid: Int,
        val appLabel: String,
        val bytesOut: Long,
        val bytesIn: Long,
        val packetsOut: Long,
        val packetsIn: Long,
        val firstSeenMs: Long,
        val lastSeenMs: Long,
        val status: String             // "actif" / "fermé"
    )

    private class Mutable(
        val protocol: String,
        val localPort: Int,
        val remoteIp: String,
        val remotePort: Int,
        val firstSeenMs: Long
    ) {
        @Volatile var uid: Int = -1
        @Volatile var appLabel: String = ""
        val bytesOut = AtomicLong(0)
        val bytesIn = AtomicLong(0)
        val packetsOut = AtomicLong(0)
        val packetsIn = AtomicLong(0)
        @Volatile var lastSeenMs: Long = firstSeenMs
        @Volatile var closed: Boolean = false
    }

    private val conns = ConcurrentHashMap<String, Mutable>()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _connections = MutableStateFlow<List<Conn>>(emptyList())
    val connections: StateFlow<List<Conn>> = _connections.asStateFlow()

    private val _totalOut = MutableStateFlow(0L)
    val totalOut: StateFlow<Long> = _totalOut.asStateFlow()

    private val _totalIn = MutableStateFlow(0L)
    val totalIn: StateFlow<Long> = _totalIn.asStateFlow()

    private val _pcapPath = MutableStateFlow<String?>(null)
    val pcapPath: StateFlow<String?> = _pcapPath.asStateFlow()

    private val _packetCount = MutableStateFlow(0L)
    val packetCount: StateFlow<Long> = _packetCount.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    fun setRunning(on: Boolean) { _running.value = on }
    fun setPcapPath(path: String?) { _pcapPath.value = path }
    fun setError(msg: String?) { _error.value = msg }

    /** Réinitialise l'agrégat (nouvelle session de capture). */
    fun reset() {
        conns.clear()
        _connections.value = emptyList()
        _totalOut.value = 0
        _totalIn.value = 0
        _packetCount.value = 0
        _error.value = null
    }

    private fun key(proto: String, localPort: Int, remoteIp: String, remotePort: Int) =
        "$proto:$localPort>$remoteIp:$remotePort"

    private fun getOrCreate(
        proto: String, localPort: Int, remoteIp: String, remotePort: Int, nowMs: Long
    ): Mutable = conns.getOrPut(key(proto, localPort, remoteIp, remotePort)) {
        Mutable(proto, localPort, remoteIp, remotePort, nowMs)
    }

    fun onOutbound(
        proto: String, localPort: Int, remoteIp: String, remotePort: Int,
        payloadBytes: Int, nowMs: Long, uid: Int, appLabel: String
    ) {
        val c = getOrCreate(proto, localPort, remoteIp, remotePort, nowMs)
        if (uid >= 0 && c.uid < 0) { c.uid = uid; c.appLabel = appLabel }
        c.bytesOut.addAndGet(payloadBytes.toLong())
        c.packetsOut.incrementAndGet()
        c.lastSeenMs = nowMs
    }

    fun onInbound(
        proto: String, localPort: Int, remoteIp: String, remotePort: Int,
        payloadBytes: Int, nowMs: Long
    ) {
        val c = getOrCreate(proto, localPort, remoteIp, remotePort, nowMs)
        c.bytesIn.addAndGet(payloadBytes.toLong())
        c.packetsIn.incrementAndGet()
        c.lastSeenMs = nowMs
    }

    fun onClosed(proto: String, localPort: Int, remoteIp: String, remotePort: Int) {
        conns[key(proto, localPort, remoteIp, remotePort)]?.closed = true
    }

    /** Recalcule la liste triée exposée à l'UI (appelé périodiquement par le service). */
    fun publish() {
        var tOut = 0L; var tIn = 0L; var pkts = 0L
        for (c in conns.values) {
            tOut += c.bytesOut.get(); tIn += c.bytesIn.get()
            pkts += c.packetsOut.get() + c.packetsIn.get()
        }
        _totalOut.value = tOut
        _totalIn.value = tIn
        _packetCount.value = pkts

        val snapshot = conns.values
            .sortedByDescending { it.lastSeenMs }
            .take(300)
            .map {
                Conn(
                    protocol = it.protocol,
                    localPort = it.localPort,
                    remoteIp = it.remoteIp,
                    remotePort = it.remotePort,
                    uid = it.uid,
                    appLabel = it.appLabel,
                    bytesOut = it.bytesOut.get(),
                    bytesIn = it.bytesIn.get(),
                    packetsOut = it.packetsOut.get(),
                    packetsIn = it.packetsIn.get(),
                    firstSeenMs = it.firstSeenMs,
                    lastSeenMs = it.lastSeenMs,
                    status = if (it.closed) "fermé" else "actif"
                )
            }
        _connections.value = snapshot
    }
}

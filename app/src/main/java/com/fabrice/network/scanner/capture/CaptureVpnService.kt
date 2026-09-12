package com.fabrice.network.scanner.capture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import com.fabrice.network.scanner.MainActivity
import com.fabrice.network.scanner.R
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * Capture réseau à la PCAPdroid : un VpnService qui route le trafic IPv4 par un
 * TUN local, journalise les connexions et les octets, écrit un fichier .pcap
 * exportable, puis **réémet** chaque flux vers Internet via des sockets protégés
 * (TCP/UDP) — l'accès Internet reste donc fonctionnel pendant la capture.
 *
 * La capture est explicitement démarrée/arrêtée par l'utilisateur (comme
 * PCAPdroid) : couper la capture rétablit immédiatement le routage normal.
 *
 * v1.9.34 : IPv6 (si le réseau réel a une IPv6 globale), filtre par application
 * (addAllowedApplication), pare-feu (app / domaine / trackers → RST, drop ou
 * NXDOMAIN synthétique), classification trackers et GeoIP opt-in.
 */
class CaptureVpnService : VpnService(), TunBridge {

    companion object {
        const val ACTION_START = "com.fabrice.network.scanner.capture.START"
        const val ACTION_STOP = "com.fabrice.network.scanner.capture.STOP"
        private const val CHANNEL_ID = "capture_vpn"
        private const val NOTIF_ID = 4242
        private const val TUN_ADDR = "10.111.222.1"
        private const val TUN_ADDR6 = "fd00:6e65:7473:6361::1"
        private const val MTU = 1500
        // Garde-fous : arrêt automatique de la capture pour éviter le drain
        // batterie et la saturation du stockage si l'utilisateur oublie de couper.
        private const val MAX_CAPTURE_MS = 30L * 60_000            // 30 minutes
        private const val MAX_CAPTURE_BYTES = 200L * 1024 * 1024   // 200 Mo

        fun stop(context: Context) {
            val i = Intent(context, CaptureVpnService::class.java).setAction(ACTION_STOP)
            context.startService(i)
        }
    }

    @Volatile private var running = false
    private var tun: ParcelFileDescriptor? = null
    private var inStream: FileInputStream? = null
    private var outStream: FileOutputStream? = null
    private val outLock = Any()
    private var pcap: PcapWriter? = null
    private lateinit var tcp: TcpForwarder
    private lateinit var udp: UdpForwarder
    private var readerThread: Thread? = null
    private var publisherThread: Thread? = null
    @Volatile private var captureStartMs = 0L

    private val cm by lazy { getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager }
    private val uidCache = ConcurrentHashMap<String, Int>()
    private val labelCache = ConcurrentHashMap<Int, String>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { stopCapture(); stopSelf(); return START_NOT_STICKY }
            ACTION_START -> startCapture()
            else -> { stopSelf(); return START_NOT_STICKY }   // pas de redémarrage fantôme
        }
        return START_STICKY
    }

    private fun startCapture() {
        if (running) return
        goForeground()
        val builder = Builder()
            .setSession("Capture réseau")
            .setMtu(MTU)
            .addAddress(TUN_ADDR, 32)
            .addRoute("0.0.0.0", 0)
        // IPv6 : uniquement si le réseau réel a une adresse globale (sinon les
        // apps tenteraient l'IPv6 en premier et attendraient un RST à chaque fois).
        val v6 = CapturePrefs.ipv6(this) && hasGlobalIpv6()
        if (v6) {
            runCatching { builder.addAddress(TUN_ADDR6, 128); builder.addRoute("::", 0) }
        }
        // DNS : réutilise les serveurs DNS du réseau réel au lieu de forcer
        // 8.8.8.8 — préserve la résolution des noms locaux (mafreebox.freebox.fr,
        // *.local, box) et évite de détourner tout le DNS vers Google.
        addLinkDnsServers(builder, v6)
        // Filtre par application (vide = toutes). addAllowed et addDisallowed
        // sont exclusifs : sans filtre, on exclut seulement notre propre app.
        var allowedAdded = 0
        CapturePrefs.allowedPackages(this).filter { it != packageName }.forEach { pkg ->
            runCatching { builder.addAllowedApplication(pkg); allowedAdded++ }
        }
        if (allowedAdded == 0) runCatching { builder.addDisallowedApplication(packageName) }
        // Pare-feu + classification trackers + GeoIP (opt-in).
        FirewallRuntime.apply(this)
        val trackers = TrackerDatabase.load(this)
        CaptureState.trackerLookup = { h -> trackers.lookup(h)?.label }
        CaptureState.geoEnabled = CapturePrefs.geo(this)

        val fd = try {
            builder.establish()
        } catch (e: Exception) {
            CaptureState.setError("Échec établissement VPN : ${e.message}")
            stopSelf()
            return
        }
        if (fd == null) {
            CaptureState.setError("VPN refusé par le système")
            stopSelf()
            return
        }
        tun = fd
        inStream = FileInputStream(fd.fileDescriptor)
        outStream = FileOutputStream(fd.fileDescriptor)

        // Fichier PCAP dans filesDir (persistant, PAS le cache purgeable) —
        // exposé via FileProvider (files-path "captures/").
        val dir = File(filesDir, "captures").apply { mkdirs() }
        val pcapFile = File(dir, "capture_${System.currentTimeMillis()}.pcap")
        pcap = try { PcapWriter(pcapFile) } catch (e: Exception) { null }

        tcp = TcpForwarder(this)
        udp = UdpForwarder(this)

        CaptureState.reset()
        CaptureState.setPcapPath(pcap?.file?.absolutePath)
        CaptureState.setRunning(true)
        captureStartMs = System.currentTimeMillis()
        running = true

        readerThread = Thread({ readLoop() }, "capture-reader").apply { isDaemon = true; start() }
        publisherThread = Thread({ publishLoop() }, "capture-publish").apply { isDaemon = true; start() }
    }

    private fun readLoop() {
        val input = inStream ?: return
        val buf = ByteArray(32767)
        while (running) {
            val n = try {
                input.read(buf)
            } catch (e: Exception) {
                break
            }
            if (n <= 0) {
                if (n < 0) break else continue
            }
            val ver = IpPacket.version(buf)
            if (ver != 4 && ver != 6) continue
            val l4 = IpPacket.l4Offset(buf)
            if (l4 < 0) continue                              // extension v6 / autre
            val proto = IpPacket.l4Protocol(buf)
            if (proto != IpPacket.PROTO_TCP && proto != IpPacket.PROTO_UDP) continue

            val now = System.currentTimeMillis()
            pcap?.write(buf, n, now)

            val appIp = IpPacket.srcIp(buf)
            val serverIp = IpPacket.dstIp(buf)
            val appPort = IpPacket.u16(buf, l4)
            val serverPort = IpPacket.u16(buf, l4 + 2)
            val protoName = if (proto == IpPacket.PROTO_TCP) "TCP" else "UDP"

            // Longueur de payload L4 pour la comptabilité.
            val payloadOff: Int
            val payloadLen: Int
            if (proto == IpPacket.PROTO_UDP) {
                payloadOff = l4 + 8
                payloadLen = (IpPacket.u16(buf, l4 + 4) - 8).coerceAtLeast(0)
            } else {
                val dataOff = ((IpPacket.u8(buf, l4 + 12) ushr 4) and 0x0F) * 4
                payloadOff = l4 + dataOff
                payloadLen = (IpPacket.packetEnd(buf) - payloadOff).coerceAtLeast(0)
            }

            val uid = resolveUid(proto, appIp, appPort, serverIp, serverPort)

            // ---- Pare-feu ---------------------------------------------------
            val reason = firewallReason(uid, proto, serverIp, serverPort, buf, payloadOff, payloadLen)
            if (reason != null) {
                CaptureState.onBlocked(protoName, appPort, serverIp, serverPort, now, uid, labelFor(uid), reason)
                blockPacket(proto, buf, l4, appIp, appPort, serverIp, serverPort, payloadOff, payloadLen)
                continue
            }

            CaptureState.onOutbound(protoName, appPort, serverIp, serverPort, payloadLen, now, uid, labelFor(uid))

            try {
                if (proto == IpPacket.PROTO_TCP) tcp.handleOutbound(buf) else udp.handleOutbound(buf)
            } catch (e: Exception) {
                // Un flux qui échoue ne doit pas tuer la capture entière.
            }
        }
        stopCapture()
    }

    /**
     * Motif de blocage d'un paquet sortant, ou null s'il passe :
     *  - uid de l'app dans les règles « app » ;
     *  - requête DNS vers un domaine bloqué / tracker (→ NXDOMAIN synthétique) ;
     *  - IP distante déjà associée (sniff DNS) à un domaine bloqué.
     */
    private fun firewallReason(
        uid: Int, proto: Int, serverIp: String, serverPort: Int,
        pkt: ByteArray, payloadOff: Int, payloadLen: Int
    ): String? {
        if (FirewallRuntime.isUidBlocked(uid)) return "app"
        if (proto == IpPacket.PROTO_UDP && serverPort == 53 && payloadLen > 12) {
            val q = DnsSniParser.parseDnsQuestion(pkt, payloadOff, payloadLen)
            if (q != null) FirewallRuntime.domainBlockReason(q)?.let { return "DNS $it" }
        }
        CaptureState.hostFor(serverIp)?.let { host ->
            FirewallRuntime.domainBlockReason(host)?.let { return it }
        }
        return null
    }

    /** Applique le blocage : RST (TCP), NXDOMAIN (DNS) ou simple abandon (UDP). */
    private fun blockPacket(
        proto: Int, pkt: ByteArray, l4: Int, appIp: String, appPort: Int,
        serverIp: String, serverPort: Int, payloadOff: Int, payloadLen: Int
    ) {
        if (proto == IpPacket.PROTO_TCP) {
            val seq = IpPacket.u32(pkt, l4 + 4)
            val flags = IpPacket.u8(pkt, l4 + 13)
            if (flags and IpPacket.RST != 0) { tcp.drop(appPort, serverIp, serverPort); return }
            var ack = seq + payloadLen
            if (flags and IpPacket.SYN != 0) ack += 1
            if (flags and IpPacket.FIN != 0) ack += 1
            val rst = IpPacket.buildTcp(
                serverIp, serverPort, appIp, appPort,
                0L, ack and 0xFFFFFFFFL, IpPacket.RST or IpPacket.ACK, 0, null, 0, 0
            )
            emit(rst, rst.size)
            tcp.drop(appPort, serverIp, serverPort)
        } else if (serverPort == 53) {
            val nx = DnsSniParser.buildNxDomain(pkt, payloadOff, payloadLen) ?: return
            val reply = IpPacket.buildUdp(serverIp, serverPort, appIp, appPort, nx, nx.size)
            emit(reply, reply.size)
        }
        // UDP hors DNS : jeté silencieusement.
    }

    private fun publishLoop() {
        while (running) {
            try { Thread.sleep(1000) } catch (e: InterruptedException) { break }
            CaptureState.publish()
            pcap?.flush()
            // Arrêt automatique si la durée ou la taille max est atteinte.
            val elapsed = System.currentTimeMillis() - captureStartMs
            val bytes = pcap?.bytesWritten ?: 0L
            if (elapsed >= MAX_CAPTURE_MS || bytes >= MAX_CAPTURE_BYTES) {
                val reason = if (bytes >= MAX_CAPTURE_BYTES)
                    "taille max (${MAX_CAPTURE_BYTES / (1024 * 1024)} Mo)"
                else "durée max (${MAX_CAPTURE_MS / 60_000} min)"
                CaptureState.setNotice("Capture arrêtée automatiquement : $reason atteinte.")
                stopCapture()
                stopSelf()
                break
            }
        }
        CaptureState.publish()
    }

    /** Ajoute au TUN les serveurs DNS du réseau réel (v4, et v6 si routé) ; repli 8.8.8.8. */
    private fun addLinkDnsServers(builder: Builder, v6: Boolean) {
        var added = 0
        try {
            val lp = cm.getLinkProperties(cm.activeNetwork)
            lp?.dnsServers?.forEach { addr ->
                val ok = addr is Inet4Address || (v6 && addr is Inet6Address && !addr.isLinkLocalAddress)
                if (ok) {
                    val h = addr.hostAddress?.substringBefore('%')
                    if (!h.isNullOrBlank()) { runCatching { builder.addDnsServer(h); added++ } }
                }
            }
        } catch (e: Exception) {
            // repli ci-dessous
        }
        if (added == 0) builder.addDnsServer("8.8.8.8")
    }

    /** Le réseau réel a-t-il une IPv6 globale (ni link-local, ni ULA, ni loopback) ? */
    private fun hasGlobalIpv6(): Boolean = runCatching {
        cm.getLinkProperties(cm.activeNetwork)?.linkAddresses?.any { la ->
            val a = la.address
            a is Inet6Address && !a.isLinkLocalAddress && !a.isLoopbackAddress &&
                !a.isSiteLocalAddress && (a.address[0].toInt() and 0xFE) != 0xFC
        } ?: false
    }.getOrDefault(false)

    private fun resolveUid(proto: Int, appIp: String, appPort: Int, serverIp: String, serverPort: Int): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return -1
        val key = "$proto:$appPort>$serverIp:$serverPort"
        uidCache[key]?.let { return it }
        val ipProto = if (proto == IpPacket.PROTO_TCP) OsConstants.IPPROTO_TCP else OsConstants.IPPROTO_UDP
        val uid = try {
            cm.getConnectionOwnerUid(
                ipProto,
                InetSocketAddress(InetAddress.getByName(appIp), appPort),
                InetSocketAddress(InetAddress.getByName(serverIp), serverPort)
            )
        } catch (e: Exception) { -1 }
        if (uid >= 0) uidCache[key] = uid
        return uid
    }

    private fun labelFor(uid: Int): String {
        if (uid < 0) return "Inconnu"
        if (uid == 0) return "Système (root)"
        labelCache[uid]?.let { return it }
        val pm = packageManager
        val label = try {
            val pkgs = pm.getPackagesForUid(uid)
            if (pkgs.isNullOrEmpty()) "uid $uid"
            else pm.getApplicationLabel(pm.getApplicationInfo(pkgs[0], 0)).toString()
        } catch (e: Exception) { "uid $uid" }
        labelCache[uid] = label
        return label
    }

    // ---- TunBridge ----------------------------------------------------------
    override fun protect(socket: Socket): Boolean = super<VpnService>.protect(socket)
    override fun protect(socket: DatagramSocket): Boolean = super<VpnService>.protect(socket)
    override fun isRunning(): Boolean = running

    override fun emit(pkt: ByteArray, len: Int) {
        val o = outStream ?: return
        synchronized(outLock) {
            try {
                o.write(pkt, 0, len)
            } catch (e: Exception) {
                return
            }
        }
        pcap?.write(pkt, len, System.currentTimeMillis())
    }

    private fun stopCapture() {
        if (!running && tun == null) return
        running = false
        CaptureState.setRunning(false)
        runCatching { if (::tcp.isInitialized) tcp.closeAll() }
        runCatching { if (::udp.isInitialized) udp.closeAll() }
        runCatching { inStream?.close() }
        runCatching { outStream?.close() }
        runCatching { tun?.close() }
        tun = null; inStream = null; outStream = null
        runCatching { pcap?.close() }
        CaptureState.publish()
        stopForegroundCompat()
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    override fun onRevoke() {
        // L'utilisateur (ou un autre VPN) a révoqué notre autorisation.
        stopCapture()
        stopSelf()
        super.onRevoke()
    }

    // ---- Foreground / notification -----------------------------------------
    private fun goForeground() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Capture réseau", NotificationManager.IMPORTANCE_LOW)
                    .apply { description = "Capture du trafic réseau en cours" }
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, CaptureVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notif: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Capture réseau active")
            .setContentText("Le trafic est capturé et enregistré (PCAP).")
            .setSmallIcon(R.drawable.ic_pacman)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, "Arrêter", stopIntent)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    private fun stopForegroundCompat() {
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION") stopForeground(true)
            }
        }
    }
}

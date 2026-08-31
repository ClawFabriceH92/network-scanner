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
 * Portée : IPv4 uniquement (l'IPv6 n'est pas routé → non capturé mais intact).
 */
class CaptureVpnService : VpnService(), TunBridge {

    companion object {
        const val ACTION_START = "com.fabrice.network.scanner.capture.START"
        const val ACTION_STOP = "com.fabrice.network.scanner.capture.STOP"
        private const val CHANNEL_ID = "capture_vpn"
        private const val NOTIF_ID = 4242
        private const val TUN_ADDR = "10.111.222.1"
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
            .addRoute("0.0.0.0", 0)          // IPv4 uniquement
        // DNS : réutilise les serveurs DNS du réseau réel (IPv4) au lieu de forcer
        // 8.8.8.8 — préserve la résolution des noms locaux (mafreebox.freebox.fr,
        // *.local, box) et évite de détourner tout le DNS vers Google.
        addLinkDnsServers(builder)
        // Ne pas capturer notre propre app (évite tout risque de boucle).
        runCatching { builder.addDisallowedApplication(packageName) }

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
            if (IpPacket.version(buf) != 4) continue    // IPv6/autres : ignorés
            val proto = IpPacket.protocol(buf)
            if (proto != IpPacket.PROTO_TCP && proto != IpPacket.PROTO_UDP) continue

            val now = System.currentTimeMillis()
            pcap?.write(buf, n, now)

            val ipHdr = IpPacket.ihl(buf)
            val appIp = IpPacket.srcIp(buf)
            val serverIp = IpPacket.dstIp(buf)
            val appPort = IpPacket.u16(buf, ipHdr)
            val serverPort = IpPacket.u16(buf, ipHdr + 2)
            val protoName = if (proto == IpPacket.PROTO_TCP) "TCP" else "UDP"

            // Longueur de payload L4 pour la comptabilité.
            val payloadLen = if (proto == IpPacket.PROTO_UDP) {
                (IpPacket.u16(buf, ipHdr + 4) - 8).coerceAtLeast(0)
            } else {
                val dataOff = ((IpPacket.u8(buf, ipHdr + 12) ushr 4) and 0x0F) * 4
                (IpPacket.totalLength(buf) - ipHdr - dataOff).coerceAtLeast(0)
            }

            val uid = resolveUid(proto, appIp, appPort, serverIp, serverPort)
            CaptureState.onOutbound(protoName, appPort, serverIp, serverPort, payloadLen, now, uid, labelFor(uid))

            try {
                if (proto == IpPacket.PROTO_TCP) tcp.handleOutbound(buf) else udp.handleOutbound(buf)
            } catch (e: Exception) {
                // Un flux qui échoue ne doit pas tuer la capture entière.
            }
        }
        stopCapture()
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

    /** Ajoute au TUN les serveurs DNS IPv4 du réseau réel ; repli 8.8.8.8. */
    private fun addLinkDnsServers(builder: Builder) {
        var added = 0
        try {
            val lp = cm.getLinkProperties(cm.activeNetwork)
            lp?.dnsServers?.forEach { addr ->
                if (addr is Inet4Address) {
                    val h = addr.hostAddress
                    if (!h.isNullOrBlank()) { builder.addDnsServer(h); added++ }
                }
            }
        } catch (e: Exception) {
            // repli ci-dessous
        }
        if (added == 0) builder.addDnsServer("8.8.8.8")
    }

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

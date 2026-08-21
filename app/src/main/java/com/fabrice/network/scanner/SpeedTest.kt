package com.fabrice.network.scanner

import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * Test de vitesse Internet (comme Fing / Speedtest).
 *
 * Endpoints gratuits et fiables :
 * - Download : https://speed.cloudflare.com/__down?bytes=N
 * - Upload   : POST https://speed.cloudflare.com/__up
 * - Latence  : ping système vers 1.1.1.1 (Cloudflare)
 *
 * Résultats en Mbps (mégabits par seconde).
 */
object SpeedTest {

    data class Result(
        val downloadMbps: Double = 0.0,
        val uploadMbps: Double = 0.0,
        val latencyMs: Int = 0
    )

    /** Latence : ping système vers Cloudflare (moyenne de 3 essais). */
    fun latencyMs(): Int {
        var total = 0
        var count = 0
        for (i in 0 until 3) {
            val t = pingOnceMs()
            if (t >= 0) { total += t; count++ }
        }
        return if (count == 0) -1 else total / count
    }

    /** Débit descendant en Mbps (télécharge ~8 Mo depuis Cloudflare). */
    fun downloadMbps(bytes: Int = 8_000_000): Double {
        val start = System.nanoTime()
        val conn = URL("https://speed.cloudflare.com/__down?bytes=$bytes")
            .openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 5_000
            conn.readTimeout = 20_000
            conn.setRequestProperty("User-Agent", "NetworkScanner/0.2.5")
            var received = 0L
            conn.inputStream.use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    received += n
                }
            }
            val elapsedSec = (System.nanoTime() - start).toDouble() / 1e9
            if (elapsedSec <= 0 || received <= 0) return 0.0
            // Débit basé sur les octets RÉELLEMENT reçus, sans buffer intermédiaire.
            return (received.toDouble() * 8) / elapsedSec / 1_000_000.0
        } catch (e: Exception) {
            return -1.0
        } finally {
            conn.disconnect()
        }
    }

    /** Débit montant en Mbps (envoie ~4 Mo vers Cloudflare). */
    fun uploadMbps(bytes: Int = 4_000_000): Double {
        val payload = ByteArray(bytes) { 'x'.code.toByte() }
        val start = System.nanoTime()
        val conn = URL("https://speed.cloudflare.com/__up")
            .openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 5_000
            conn.readTimeout = 20_000
            conn.doOutput = true
            conn.setFixedLengthStreamingMode(bytes)
            conn.setRequestProperty("User-Agent", "NetworkScanner/0.2.5")
            conn.setRequestProperty("Content-Type", "application/octet-stream")
            conn.outputStream.use { it.write(payload) }
            val code = conn.responseCode
            val elapsedSec = (System.nanoTime() - start).toDouble() / 1e9
            if (elapsedSec <= 0 || code !in 200..299) return if (code !in 200..299) -1.0 else 0.0
            return (bytes.toDouble() * 8) / elapsedSec / 1_000_000.0
        } catch (e: Exception) {
            return -1.0
        } finally {
            conn.disconnect()
        }
    }

    /** Lance les trois mesures en séquence (à appeler depuis Dispatchers.IO). */
    fun runFullTest(): Result {
        val d = downloadMbps()
        val u = uploadMbps()
        val l = latencyMs()
        return Result(
            downloadMbps = if (d < 0) 0.0 else d,
            uploadMbps = if (u < 0) 0.0 else u,
            latencyMs = if (l < 0) 0 else l
        )
    }

    private fun pingOnceMs(): Int {
        return try {
            val process = ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "3", "1.1.1.1")
                .redirectErrorStream(true)
                .start()
            val ok = process.waitFor(4, TimeUnit.SECONDS) && process.exitValue() == 0
            val output = runCatching {
                process.inputStream.bufferedReader().use { it.readText() }
            }.getOrDefault("")
            process.destroy()
            if (!ok) return -1
            // « time=12.3 ms » ou « time<1 ms »
            Regex("time[=<]([0-9.]+)").find(output)?.groupValues?.get(1)?.toDoubleOrNull()?.toInt()
                ?: -1
        } catch (e: Exception) {
            -1
        }
    }

    /** Formatte un débit en Mbps (1 décimale, virgule française). */
    fun formatMbps(value: Double): String =
        if (value <= 0) "—" else String.format(java.util.Locale.FRENCH, "%.1f", value)
}

package com.fabrice.network.scanner

/**
 * Classification du TYPE d'appareil (comme Fing) : imprimante, ordinateur,
 * smartphone, NAS, routeur, caméra, TV, IoT…
 *
 * Règles croisées (priorité décroissante) : hostname → ports → fabricant → OS.
 */
object DeviceType {

    fun classify(
        vendor: String,
        hostname: String,
        ports: List<Int>,
        os: String
    ): String {
        fromHostname(hostname)?.let { return it }
        fromPorts(ports, vendor)?.let { return it }
        fromVendor(vendor)?.let { return it }
        fromOs(os)?.let { return it }
        return "Inconnu"
    }

    /** Emoji associé à un type. */
    fun icon(type: String): String = when (type) {
        "Imprimante" -> "🖨️"
        "Ordinateur" -> "🖥️"
        "Smartphone" -> "📱"
        "Tablette" -> "📱"
        "NAS" -> "💾"
        "Routeur / Box" -> "📶"
        "Caméra" -> "📷"
        "TV / Media" -> "📺"
        "Console" -> "🎮"
        "Montre" -> "⌚"
        "Enceinte" -> "🔊"
        "IoT" -> "💡"
        else -> "❓"
    }

    private fun fromHostname(hostname: String): String? {
        val h = hostname.lowercase()
        return when {
            h.contains("printer") || h.contains("imprimante") || h.contains("canon") ||
                h.contains("epson") || h.contains("brother") || h.startsWith("npif") ||
                h.startsWith("npi") -> "Imprimante"
            h.contains("synology") || h.contains("qnap") || h.contains("nas") ||
                h.contains("ds2") || h.contains("ds7") || h.contains("diskstation") -> "NAS"
            h.contains("ipad") || h.contains("tablet") || h.contains("tab") -> "Tablette"
            h.contains("watch") || h.contains("montre") || h.contains("fitbit") ||
                h.contains("garmin") -> "Montre"
            h.contains("speaker") || h.contains("enceinte") || h.contains("sonos") ||
                h.contains("echo") || h.contains("homepod") || h.contains("alexa") -> "Enceinte"
            h.contains("ps4") || h.contains("ps5") || h.contains("playstation") ||
                h.contains("xbox") || h.contains("nintendo") || h.contains("switch") ||
                h.contains("wii") -> "Console"
            h.contains("iphone") || h.contains("android") ||
                h.contains("xiaomi") || h.contains("galaxy") || h.contains("samsung") ||
                h.contains("pixel") || h.contains("oneplus") || h.contains("oppo") -> "Smartphone"
            h.contains("cam") || h.contains("camera") || h.contains("webcam") ||
                h.contains("hikvision") || h.contains("reolink") -> "Caméra"
            h.contains("tv") || h.contains("bravia") || h.contains("television") ||
                h.contains("chromecast") || h.contains("roku") || h.contains("firestick") -> "TV / Media"
            h.contains("freebox") || h.contains("livebox") || h.contains("box") ||
                h.contains("routeur") || h.contains("router") || h.contains("b-box") -> "Routeur / Box"
            h.contains("esp32") || h.contains("esp_") || h.contains("shelly") ||
                h.contains("tuya") || h.contains("tasmota") || h.contains("wemos") ||
                h.contains("sonoff") -> "IoT"
            h.startsWith("desktop-") || h.contains("windows") || h.contains("linux") ||
                h.contains("raspberry") || h.contains("ubuntu") -> "Ordinateur"
            else -> null
        }
    }

    private fun fromPorts(ports: List<Int>, vendor: String): String? {
        val s = ports.toSet()
        return when {
            // Imprimante : JetDirect 9100, IPP 631, LPD 515
            (9100 in s || 515 in s) -> "Imprimante"
            // NAS Synology : 5000/5001 (DSM), 6690 ; QNAP : 8080/443
            (5000 in s || 5001 in s) && (vendor.contains("synology", true)) -> "NAS"
            5000 in s || 5001 in s -> "NAS"
            // Caméra IP : RTSP 554
            554 in s -> "Caméra"
            // Windows : SMB 139/445 + RDP 3389
            139 in s && 445 in s -> "Ordinateur"
            3389 in s -> "Ordinateur"
            22 in s && 80 in s && 443 in s -> "Ordinateur"
            else -> null
        }
    }

    private fun fromVendor(vendor: String): String? {
        val v = vendor.lowercase()
        return when {
            v.contains("synology") || v.contains("qnap") || v.contains("asustor") -> "NAS"
            v.contains("canon") || v.contains("epson") || v.contains("brother") ||
                v.contains("hewlett packard") || v.contains("hp ") ||
                v.startsWith("hp") || v.contains("xerox") || v.contains("ricoh") -> "Imprimante"
            v.contains("freebox") || v.contains("sagemcom") || v.contains("livebox") ||
                v.contains("technicolor") || v.contains("tp-link") ||
                v.contains("netgear") || v.contains("asus") -> "Routeur / Box"
            v.contains("hikvision") || v.contains("reolink") || v.contains("dahua") -> "Caméra"
            v.contains("xiaomi") || v.contains("huawei") || v.contains("samsung") ||
                v.contains("apple") || v.contains("sony") || v.contains("oneplus") ||
                v.contains("oppo") || v.contains("google") -> "Smartphone"
            v.contains("lg electronics") || v.contains("tcl") ||
                v.contains("vestel") -> "TV / Media"
            v.contains("espressif") || v.contains("texas instruments") ||
                v.contains("silicon labs") -> "IoT"
            v.contains("dell") || v.contains("lenovo") || v.contains("acer") ||
                v.contains("msi") || v.contains("gigabyte") || v.contains("intel") ||
                v.contains("amd") || v.contains("gsd") -> "Ordinateur"
            else -> null
        }
    }

    private fun fromOs(os: String): String? = when {
        os.contains("Windows") || os.contains("Linux") || os.contains("macOS") -> "Ordinateur"
        os.contains("iOS") -> "Smartphone"
        os.contains("Imprimante") -> "Imprimante"
        os.contains("Routeur") -> "Routeur / Box"
        else -> null
    }
}

package com.fabrice.network.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests des fonctions pures de BluetoothServiceProbe : nommage des UUID assignés
 * et évaluation de risque à partir des profils exposés.
 */
class BluetoothServiceProbeTest {

    private fun svc(uuid16: String, kind: String = "SDP") =
        BluetoothServiceProbe.BtService("0000$uuid16-0000-1000-8000-00805f9b34fb", "", kind)

    @Test
    fun namesAssignedUuids() {
        assertEquals("Batterie", BluetoothServiceProbe.uuidName("0000180f-0000-1000-8000-00805f9b34fb"))
        assertEquals("Périphérique HID (clavier/souris)",
            BluetoothServiceProbe.uuidName("00001124-0000-1000-8000-00805f9b34fb"))
        assertEquals("Port série (SPP)",
            BluetoothServiceProbe.uuidName("00001101-0000-1000-8000-00805f9b34fb"))
    }

    @Test
    fun proprietaryUuidLabelled() {
        assertEquals("Service propriétaire",
            BluetoothServiceProbe.uuidName("12345678-1234-1234-1234-1234567890ab"))
    }

    @Test
    fun hidProfileFlaggedAsRisk() {
        val risks = BluetoothServiceProbe.assessRisks(listOf(svc("1124")))
        assertTrue(risks.any { it.contains("HID") })
    }

    @Test
    fun obexFileTransferFlagged() {
        val risks = BluetoothServiceProbe.assessRisks(listOf(svc("1106")))
        assertTrue(risks.any { it.contains("OBEX") })
    }

    @Test
    fun gattServicesAddBleNote() {
        val risks = BluetoothServiceProbe.assessRisks(listOf(svc("180f", "GATT")))
        assertTrue(risks.any { it.contains("BLE") })
    }
}

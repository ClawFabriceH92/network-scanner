package com.fabrice.network.scanner

import android.content.Context
import android.telephony.CellSignalStrength
import android.telephony.TelephonyManager

/**
 * Infos du réseau cellulaire (2G/3G/4G/5G) via TelephonyManager (v1.8.0).
 *
 * ⚠️ Limite Android 10+ : `getCellInfo()` (cellId / PCI) est restreint aux
 * apps système — on ne peut PAS récupérer la cellule exacte. On se limite à :
 * opérateur, type de réseau, signal (dBm/barres), roaming.
 *
 * Toute la logique de mapping / analyse est PURE (testable en JVM sans
 * appareil) : `networkTypeLabel`, `asuToDbm`, `signalBars`, `analyze`.
 */
object CellularInfo {

    /** État cellulaire lu depuis TelephonyManager. */
    data class CellularStatus(
        val operator: String = "",
        val operatorCode: String = "",
        val simOperator: String = "",
        /** Libellé lisible : « 2G » / « 3G » / « 4G » / « 5G » / « ? ». */
        val networkType: String = "?",
        val signalDbm: Int? = null,
        val signalBars: Int = 0,
        val roaming: Boolean = false
    )

    /** Résultat d'analyse de vulnérabilité du réseau cellulaire. */
    data class CellularVuln(
        val score: Int,
        val label: String,
        val risks: List<String>,
        val recommendations: List<String>
    )

    /**
     * Mappe un `TelephonyManager.dataNetworkType` (constante Android) vers un
     * libellé de génération. Les valeurs sont des littéraux (pas de référence
     * à TelephonyManager) pour rester testable en JVM.
     * GPRS/EDGE/CDMA/1xRTT/iDen → 2G ; UMTS/HSDPA/HSUPA/HSPA/HSPA+/EVDO/eHRPD → 3G ;
     * LTE → 4G ; NR → 5G ; inconnu → « ? ».
     */
    fun networkTypeLabel(type: Int): String = when (type) {
        1, 2, 4, 7, 11 -> "2G"                      // GPRS, EDGE, CDMA, 1xRTT, iDen
        3, 8, 9, 10, 15, 5, 6, 12, 14 -> "3G"       // UMTS, HSDPA, HSUPA, HSPA, HSPA+, EVDO, eHRPD
        13 -> "4G"                                   // LTE
        20 -> "5G"                                   // NR
        else -> "?"
    }

    /**
     * Convertit un niveau ASU en dBm (formules usuelles Android) :
     * 2G (GSM) : dBm = -113 + 2 × asu ; 3G/4G (UMTS/LTE) : dBm = -140 + asu.
     */
    fun asuToDbm(asu: Int, networkType: String): Int = when (networkType) {
        "2G" -> -113 + 2 * asu
        else -> -140 + asu
    }

    /** Nombre de barres (0-4) à partir d'un signal en dBm. */
    fun signalBars(dbm: Int): Int = when {
        dbm >= -85 -> 4
        dbm >= -95 -> 3
        dbm >= -105 -> 2
        dbm >= -115 -> 1
        else -> 0
    }

    /**
     * Analyse de vulnérabilité du réseau cellulaire (pur). Score 0..100 :
     * 2G→90, 3G→60, 4G→20, 5G→10, inconnu→40 ; roaming ajoute +10 (plafonné).
     */
    fun analyze(roaming: Boolean, networkType: String): CellularVuln {
        val base = when (networkType) {
            "2G" -> 90
            "3G" -> 60
            "4G" -> 20
            "5G" -> 10
            else -> 40
        }
        val score = (base + if (roaming) 10 else 0).coerceIn(0, 100)
        val risks = mutableListOf(riskFor(networkType))
        if (roaming) risks.add("Itinérance : vérifie le coût, opérateur étranger")
        return CellularVuln(
            score = score,
            label = labelForScore(score),
            risks = risks,
            recommendations = listOf(
                "Évite de saisir des données sensibles en 2G/3G",
                "Utilise le VPN pour les connexions sensibles"
            )
        )
    }

    private fun riskFor(networkType: String): String = when (networkType) {
        "2G" -> "Réseau 2G : interception possible (GSM cassé), évite les transactions"
        "3G" -> "3G obsolète : interception possible (UMTS faible)"
        "4G" -> "4G correct — attention IMSI catcher théorique"
        "5G" -> "5G : chiffrement renforcé"
        else -> "Réseau inconnu — prudence"
    }

    private fun labelForScore(score: Int): String = when {
        score >= 75 -> "Critique"
        score >= 50 -> "Élevé"
        score >= 25 -> "Modéré"
        else -> "Faible"
    }

    /**
     * Lit l'état cellulaire Android (opérateur, réseau, signal, roaming).
     * Chaque champ est lu défensivement (SecurityException si READ_PHONE_STATE
     * absent) — les champs illisibles restent vides.
     */
    fun read(context: Context): CellularStatus {
        return try {
            val tm = context.applicationContext
                .getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            val networkType = try {
                tm.dataNetworkType
            } catch (e: Exception) {
                TelephonyManager.NETWORK_TYPE_UNKNOWN
            }
            val label = networkTypeLabel(networkType)
            val dbm = readSignalDbm(tm, label)
            CellularStatus(
                operator = try { tm.networkOperatorName ?: "" } catch (e: Exception) { "" },
                operatorCode = try { tm.networkOperator ?: "" } catch (e: Exception) { "" },
                simOperator = try { tm.simOperatorName ?: "" } catch (e: Exception) { "" },
                networkType = label,
                signalDbm = dbm,
                signalBars = dbm?.let { signalBars(it) } ?: 0,
                roaming = try { tm.isNetworkRoaming } catch (e: Exception) { false }
            )
        } catch (e: Exception) {
            CellularStatus()
        }
    }

    /** Lit le signal en dBm (CellSignalStrength.getDbm sinon repli ASU). */
    private fun readSignalDbm(tm: TelephonyManager, label: String): Int? {
        val ss = try { tm.getSignalStrength() } catch (e: Exception) { return null } ?: return null
        val cell = try {
            ss.getCellSignalStrengths(CellSignalStrength::class.java).firstOrNull()
        } catch (e: Exception) {
            null
        }
        val direct = try { cell?.getDbm() ?: Int.MAX_VALUE } catch (e: Exception) { Int.MAX_VALUE }
        if (direct in -200..-1) return direct
        val asu = try { cell?.getAsuLevel() ?: return null } catch (e: Exception) { return null }
        return asuToDbm(asu, label)
    }
}

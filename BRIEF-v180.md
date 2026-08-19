# BRIEF v1.8.0 — network-scanner (Multi-box : Freebox + Bbox + Livebox + SFR)

À appliquer APRÈS la v1.7.0 (committée). Base : versionCode 27 / versionName "1.7.0". Cible : versionCode 28 / versionName "1.8.0".

## RÈGLES ABSOLUES
- NE PAS casser les signatures/features existantes (BoxClient, FreeboxBoxClient, BoxManager, Device, v1.6/v1.7 features).
- Pas de NOUVELLE dépendance Gradle (HTTP via HttpURLConnection, JSON via org.json — déjà utilisés).
- `./gradlew testDebugUnitTest --rerun-tasks` (0 failure) puis `./gradlew assembleDebug`.
- Commit final : `git add -A && git commit -m "v1.8.0: multi-box Bbox/Livebox, onglet Box, débit temps réel, WiFi/Ethernet"` — NE PAS push.
- Répondre en français dans le résumé.

## CONTEXTE MULTI-BOX (honnêteté d'abord)

| Box | API | Ce qu'on peut récupérer | Statut |
|---|---|---|---|
| **Freebox** | API v9 REST (token OAuth device) | TOUT : devices, leases DHCP, WiFi (SSID/canaux/clients), connection (IP pub, type, débit), bandwidth (temps réel), sys (firmware/uptime), switch ports | ✅ Déjà implémenté (étendre) |
| **Bbox Bouygues** | API sysbus locale (192.168.1.254) | devices LAN (si accessible sans token avancé), parfois baux DHCP — à tester sur box réelle | 🆕 À implémenter |
| **Livebox Orange** | TR-064/ws SOAP (192.168.1.1) | devices LAN via TR-064 (GetSpecificHostEntry), parfois WiFi — password device requis | 🆕 À implémenter |
| **SFR** | Pas d'API publique documentée | Rien de fiable — repli : scan direct seul | 📄 Documenter « non supporté » |

⚠️ Les API Bbox/Livebox ne sont PAS documentées officiellement (communauté). Le subagent doit :
1. Implémenter le client avec les endpoints documentés par la communauté (sysbus pour Bbox, TR-064 pour Livebox).
2. **NE PAS prétendre que ça marche** sans test réel : chaque méthode doit être protégée par runCatching + null si échec, et le brief UI affiche « non disponible » si l'appel échoue.
3. Documenter dans le code (commentaires) les endpoints supposés + ce qu'il faut tester sur la box réelle.

## FEATURE 1 — Élargir l'interface BoxClient (multi-box)

`BoxClient` actuelle : `name`, `baseUrl`, `fetchDevices()`, `isAvailable()`. L'élargir AVEC des méthodes par défaut (ne pas casser FreeboxBoxClient) :

```kotlin
interface BoxClient {
    val name: String
    val baseUrl: String
    suspend fun fetchDevices(): List<BoxDevice>?   // existant
    suspend fun isAvailable(): Boolean              // existant
    // NOUVEAUX (défauts = null/false → « non disponible » si non supporté)
    suspend fun fetchLeases(): List<BoxLease>? = null          // baux DHCP
    suspend fun fetchConnection(): BoxConnection? = null        // IP pub, type, débit contractuel
    suspend fun fetchBandwidth(): BoxBandwidth? = null          // débit temps réel
    suspend fun fetchWifi(): BoxWifi? = null                    // SSID, canaux, clients WiFi
    suspend fun fetchSystem(): BoxSystem? = null                // firmware, uptime, température
    suspend fun blockDevice(mac: String): Boolean = false       // v1.7 (feature 6)
    suspend fun unblockDevice(mac: String): Boolean = false
}
```

Nouvelles data classes (fichier BoxModels.kt) : `BoxLease(ip, mac, hostname, leaseTime, active)`, `BoxConnection(publicIp, connectionType, downloadRate, uploadRate)`, `BoxBandwidth(downloadBps, uploadBps, timestampMs)`, `BoxWifi(ssid, security, channel, band, clients: List<WifiClient>)`, `WifiClient(mac, ip, hostname, rssi, band)`, `BoxSystem(firmware, uptimeSeconds, temperatureC?)`.

### FreeboxBoxClient — implémenter les nouvelles méthodes (API v9)
- `/dhcp/leases/` → BoxLease[]
- `/connection/` → BoxConnection (ipv4, type, rate_down, rate_up)
- `/connection/bandwidth/` → BoxBandwidth (rate.download, rate.upload en B/s)
- `/wifi/` + `/wifi/ap/` → BoxWifi (SSID, canaux, clients)
- `/sys/` → BoxSystem (firmware_version, uptime)
- ⚠️ Tous les appels avec header `X-Fbx-App-Auth` (session_token) — pattern existant.

### BboxBoxClient (nouveau, sysbus)
- Détection : gateway == 192.168.1.254 OU OUI Sagemcom → `BboxBoxClient` (BoxManager.detect).
- Base `http://192.168.1.254/` — attention `usesCleartextTraffic` déjà activé.
- Endpoints documentés communauté : essayer `GET /sysbus/NeMo/intf:eth/` et les endpoints LAN (la forme exacte est à vérifier — mettre des commentaires TODO « endpoint à confirmer sur box réelle »). Auth : la Bbox sysbus demande parfois un token (`POST /sysbus/` avec password) — si requis, `fetchDevices()` retourne null + log « autorisation Bbox requise ».
- `isAvailable()` : GET `/sysbus/` répond 200.
- implémenter au moins `fetchDevices()` + `fetchConnection()` si accessible.

### LiveboxBoxClient (nouveau, TR-064)
- Détection : gateway == 192.168.1.1 OU OUI (Livebox/Sagemcom/Orange) → `LiveboxBoxClient`.
- TR-064 : `POST http://192.168.1.1/ws` SOAP/XML, service `urn:dslforum-org:service:Hosts:1`, action `GetHostNumberOfEntries` + `GetGenericHostEntry` (ou GetSpecificHostEntry). Auth : `Authorization` Basic avec le « password device » (à configurer dans l'app : champ « Mot de passe device » dans les réglages box, stocké en SharedPreferences).
- Parser XML avec XmlPullParser ou regex simple (noms courts : `NewMACAddress`, `NewIPAddress`, `NewHostName`, `NewActive`).
- Implémenter au moins `fetchDevices()`.
- ⚠️ Ne pas casser : si le password n'est pas configuré → null + message « configure le mot de passe device ».

### SFRBoxClient — pas d'implémentation API
- Ne PAS créer de client API (rien de fiable). BoxManager.detect : si OUI SFR → nom « Box SFR » mais `fetchDevices()` = null (documenter « API SFR non supportée — scan direct seulement »).

## FEATURE 2 — Onglet « Box » (nouvel écran)

- **NavigationBar 6 items** : Scanner / Réseau / Bluetooth / WiFi / **Box** / Aide.
- `BoxScreen.kt` : affiche selon ce que la box fournit (cards conditionnelles) :
  - **Connexion** : IP publique, type (FTTH/ADSL/câble), débit contractuel ↑↓ — si `fetchConnection()` non null.
  - **Bande passante temps réel** : graphique Canvas simple (2 lignes ↑↓, échantillon toutes les 2 s pendant 30 s, pattern RssiGraph) + valeurs Mo/s — si `fetchBandwidth()` non null.
  - **WiFi box** : SSID, sécurité, canal, clients connectés (liste MAC/IP/nom/rssi) — si `fetchWifi()` non null.
  - **Système** : firmware, uptime — si `fetchSystem()` non null.
  - **Baux DHCP** : compteur + liste (ip/mac/hostname) — si `fetchLeases()` non null.
  - Si TOUT est null → message « 📡 Box non accessible via API (SFR ?) — scan direct uniquement ».
- Réglages box : champ « Mot de passe device » (Livebox) + bouton « Ré-autoriser la box » (Freebox re-auth) — SharedPreferences `box_prefs` (pattern BoxStore).
- Après fetch, `BoxManager.reset()` pour forcer le re-détect si la box change.

## FEATURE 3 — Badge WiFi vs Ethernet sur les appareils

- `BoxDevice` et `Device` : le champ d'info « connexion » (WiFi/câblé) vient des interfaces box (`/lan/browser/pub/{id}/interfaces/` pour Freebox — liste avec `type` = eth/wifi).
- Enrichir `Device` avec `connectionType: String?` (« WiFi »/« Ethernet »/null).
- UI : badge « 📶 WiFi » / « 🔌 Ethernet » sur la carte du périphérique si connu (sinon rien).
- CSV : colonne « Connexion » si dispo (après SNMP — ordre vérifié avec les tests CSV).

## FEATURE 4 — Onglet « Cellulaire » (réseau mobile 2G/3G/4G/5G) — demande Fabrice

### CellularInfo.kt (nouveau, object)
- `read(context): CellularStatus` — via TelephonyManager (ACCESS_NETWORK_STATE) :
  - `operator` : `networkOperatorName` (ex: « F SFR »), `operatorCode` (MCC/MNC via `networkOperator`)
  - `networkType` : `dataNetworkType` → label lisible (2G/3G/4G/5G) — mapping pur, testable : EDGE/GPRS→2G, UMTS/HSDPA/HSPA→3G, LTE→4G, NR→5G, UNKNOWN→?
  - `signalDbm` : `getSignalStrength` → level asu → dBm (pur : `asuToDbm(asu)` : 2G = -113 + 2*asu ; 3G/4G = -140 + asu... formules à documenter) + `signalBars` (0-4)
  - `roaming` : `isNetworkRoaming`
  - `simOperator` : SIM operator name (si dispo)
- ⚠️ Android 10+ : `getCellInfo()` (cellId/PCI) RESTREINT aux apps normales → NE PAS implémenter (documenter). Seulement opérateur/réseau/signal/roaming.
- `analyze(roaming: Boolean, networkType: String): CellularVuln` — pur :
  - 2G → 90 Critique (« Réseau 2G : interception possible (GSM cassé), évite les transactions »)
  - 3G → 60 Élevé (« 3G obsolète : interception possible (UMTS faible) »)
  - 4G → 20 Faible (« 4G correct — attention IMSI catcher théorique »)
  - 5G → 10 Faible
  - UNKNOWN → 40 Modéré
  - Roaming → +10 risque (« Itinérance : vérifie le coût, opérateur étranger »)
  - Recommandations : « Évite de saisir des données sensibles en 2G/3G », « Utilise le VPN pour les connexions sensibles »
- Tests JUnit : mapping networkType (tous les types Android → label), asuToDbm (exemples connus), analyze 2G/3G/4G/5G/roaming.

### CellularScreen.kt (nouvel onglet)
- **NavigationBar 7 items** : Scanner / Réseau / Bluetooth / WiFi / Box / **Cellulaire** / Aide.
- UI : carte opérateur (nom + réseau + badges), jauge signal (bars + dBm, couleur selon force), indicateur roaming (🟡 si oui), badge vulnérabilité (score + label), recommandations. Bouton « 🔄 Actualiser ».
- Lecture en continu (LaunchedEffect + refresh périodique 5 s) OU au tap — au choix simple.

## FEATURE 5 — Animation de proximité de la box (RSSI tendance) — demande Fabrice

But : quand Fabrice se promène, voir s'il se RAPPROCHE ou s'ÉLOIGNE de la box.

### ProximityIndicator.kt (nouveau, object pur)
- `tendency(samples: List<Int>): Trend` — échantillons RSSI (dBm) consécutifs :
  - delta = dernier - premier (ou moyenne fenêtre) : delta > +2 dBm → APPROACHING (« Tu te rapproches 🟢 »), delta < -2 → LEAVING (« Tu t'éloignes 🔴 »), sinon NEUTRAL (« Stable 🟡 »)
  - `strength(samples)`: 0-4 (pattern level() existant de WifiQuality).
  - `trendLabel(trend)`: String FR.
- Tests JUnit : tendance croissante/décroissante/stable, seuils ±2.

### Intégration UI (NetworkScreen, à côté de la jauge RSSI existante)
- Échantillonner le RSSI toutes les 2 s (pattern WifiQuality LaunchedEffect existant), garder une fenêtre de 4 échantillons.
- Afficher une **flèche animée** : 🟢 ↑ (rapprochement) / 🔴 ↓ (éloignement) / 🟡 → (stable) + texte « Tu te rapproches de la box » / « Tu t'éloignes de la box ».
- Animation : rotation/fade de la flèche (animateFloatAsState — Compose standard, pas de nouvelle dépendance).
- Fonctionne aussi avec la jauge RSSI existante (mêmes données, tendance en plus).

## FEATURE 6 — Détection et test Wake-on-LAN — demande Fabrice

⚠️ Limite honnête : un appareil éteint est invisible (pas de ping/ARP) → on ne peut PAS détecter passivement le support WoL. On identifie les candidats (appareils connus éteints) et on TESTE le WoL en envoyant un magic packet puis en vérifiant le réveil.

### WoLDetector.kt (nouveau, object)
- `candidates(known: List<Device>, current: List<Device>): List<WolCandidate>` — pur :
  - Appareils de l'historique/box (known) NON présents dans le scan courant (current) ET avec MAC valide → candidats « 💤 éteints ».
  - `WolCandidate(device: Device, lastSeenLabel: String, wolTested: Boolean, wolWorks: Boolean)`.
- `testWol(mac: String, ip: String, broadcastIp: String, recheck: (String) -> Boolean): Boolean` — suspend/IO :
  1. Envoyer le magic packet (réutiliser `WakeOnLan.send(mac, broadcastIp)` existant — ne pas dupliquer).
  2. Attendre 60-90 s (`delay`).
  3. Re-ping l'IP (`recheck(ip)`) → si vivant → WoL fonctionne → retourne true (et l'appareil est réveillé).
  4. Si pas de réponse après 1 essai → false (WoL absent OU appareil non configuré pour).
- ⚠️ Anti-piège : ne JAMAIS tester automatiquement tous les candidats (60-90 s chacun) — test UNIQUEMENT sur action utilisateur (bouton « ⚡ Tester le WoL » sur un candidat).
- Tests JUnit : candidates (connus pas dans current, MAC valide seulement, lastSeenLabel), testWol via recheck injectable (recheck true → true, false → false).

### UI
- Nouvelle section « 💤 Appareils éteints (WoL possible) » dans l'écran Scanner (ou filtre type « Éteint ») :
  - Carte : nom/IP, « Vu il y a X », badge « ⚡ WoL ? » (non testé) ou « ⚡ WoL OK » (vert) / « ✖ WoL absent » (grisé, testé sans succès).
  - Bouton « ⚡ Réveiller » : envoie le magic packet immédiatement (avec Snackbar « magic packet envoyé — attente du réveil… ») puis, si l'appareil répond après 60-90 s, badge « WoL OK » + notification.
  - Bouton « Tester le WoL » : fait le test complet (magic packet + attente + re-ping) — résultat stocké dans DeviceStore (key `wol_<mac>`) pour ne pas re-tester.
- Persistance : résultat du test WoL dans SharedPreferences (DeviceStore existant — clé `wol_<mac>` : true/false).

## FEATURE 7 — Liste des partages SMB non vides — demande Fabrice

But : pour chaque appareil avec port 445 (SMB) ouvert, lister les DOSSIERS partagés NON VIDES (accès invité).

### SmbShareScanner (étendre l'existant, v1.1.0)
- L'existant teste les partages par défaut en guest et retourne les noms accessibles. Étendre :
  - Pour chaque partage accessible : `share.list("")` (déjà possible avec smbj 0.13.0) → compter les entrées → `SmbShareEntry(shareName, itemCount, firstItems: List<String>)` (max 5 premiers noms, items = fichiers OU dossiers).
  - `nonEmptyShares(host): List<SmbShareEntry>` — ne garde que les partages avec itemCount > 0.
- `SmbShareEntry` pur + testable (pas d'appel réseau dans les tests : helper `summarize(shareName, entries: List<String>)` pur → entry).
- ⚠️ Guest mode seulement (pas de credentials) — les partages protégés sont ignorés silencieusement. Ne pas bloquer le scan (runCatching + timeout).

### UI
- Dans la fiche détail d'un appareil (section « Partages SMB » existante) : afficher pour chaque partage NON VIDE :
  - `📁 <shareName> — <N> éléments` + sous-liste des 5 premiers (`fichier.txt`, `Documents/`…).
  - Les partages vides ou inaccessibles ne sont PAS listés.
- Option : dans la fiche, un bouton « 🔁 Actualiser les partages ».

### Tests JUnit
- summarize (0 entrée → non listé, 3 entrées → count + firstItems tronqués à 5), tri par itemCount DESC.

## LIVRABLES
- Code compilé : `./gradlew testDebugUnitTest --rerun-tasks` vert (compter les tests, 0 failures), `assembleDebug` OK.
- Bump : versionCode 28, versionName "1.8.0".
- Tests JUnit obligatoires : parsing Bbox/Livebox (réponses XML/JSON factices), mapping Freebox bandwidth, badge WiFi/Ethernet, détection BoxManager (gateway → client).
- Commit local (pas de push). Rapporter : fichiers créés/modifiés, nombre de tests, taille APK, et la liste des endpoints « à confirmer sur box réelle ».

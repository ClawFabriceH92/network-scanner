# BRIEF v1.6.0 — network-scanner

Implémente 4 features dans /root/projects/network-scanner (Android, Kotlin, Compose).
Version actuelle : versionCode 24 / versionName "1.5.2". Cible : versionCode 25 / versionName "1.6.0".

## RÈGLES ABSOLUES
- NE PAS modifier les signatures existantes (Device, VulnScanner.DeviceVulns, NetworkScanner.scan, BoxClient, FreeboxBoxClient…). Ajouts seulement.
- Pas de NOUVELLE dépendance Gradle (SNMP en UDP brut, zéro lib).
- Champs Device nouveaux = avec valeurs par défaut (backward-compatible).
- Tout le code doit compiler : `./gradlew testDebugUnitTest --rerun-tasks` (0 failure) puis `./gradlew assembleDebug`.
- Garder le style existant (objets purs + JUnit pour la logique, IO mince).
- Ne PAS toucher au dossier ui/ sauf pour les 2 modifications UI demandées (copier IP + renommer box).
- Commiter en fin de travail : `git add -A && git commit -m "v1.6.0: rescan auto routeur, annuaire box, copier IP publique, SNMP"` (NE PAS push).

## FEATURE 1 — Rescan auto au changement de routeur
But : si le gateway change (nouvelle box), l'app invalide la config box, rescane et prévient.
- Nouvel objet `GatewayWatcher.kt` (object) : `remember(context, gateway)` → SharedPreferences `box_prefs` key `last_gateway`.
  - `lastGateway(context)`: String? — lit la valeur mémorisée.
  - `remember(context, gateway)`: Boolean — si gateway != mémorisé → mémorise le nouveau et retourne true (changement détecté).
  - `clear(context)` pour les tests.
- Intégration : au démarrage de ScannerScreen (LaunchedEffect(Unit)) et après chaque scan réussi :
  - `val gw = NetworkInfoProvider.readGateway()`
  - si `GatewayWatcher.remember(context, gw)` → `BoxManager.reset()` + effacer les tokens box (SharedPreferences `box_prefs` keys `freebox_app_token`…) + afficher bannière « 📡 Nouveau réseau détecté — rescan automatique » + lancer un scan automatique.
- Tests JUnit (GatewayWatcher est pur si on injecte le prefs : `remember(prefs, gateway)`).

## FEATURE 2 — Annuaire des boxes (nom + config par box)
But : mémoriser les boxes connues avec un nom personnalisé et réutiliser leur token.
- Nouvel objet `BoxStore.kt` (object) : SharedPreferences `box_prefs`.
  - Clé d'identité : `box_<gateway>` (gateway IP).
  - `saveBox(prefs, gateway, name, type)`, `getBoxName(prefs, gateway): String?`, `getBoxType(prefs, gateway): String?`, `setBoxName(prefs, gateway, name)`.
  - Stockage JSON simple (JSONObject : name, type, savedAt).
- `BoxManager.detect(context)` : après avoir déterminé le type (OUI/gateway) :
  - si `BoxStore.getBoxName(prefs, gateway) != null` → renvoyer aussi ce nom (nouveau champ ou log ? → ajouter `displayName: String?` en paramètre du résultat — NE PAS casser l'interface BoxClient ; le nom peut être lu côté UI via BoxStore directement).
  - si inconnue → `BoxStore.saveBox(prefs, gateway, "Box " + type, type)` (nom par défaut).
- `FreeboxBoxClient` : le app_token doit être keyé par gateway (actuellement partagé). Key : `freebox_app_token_<gateway>`. Au authorize, sauvegarder avec le gateway courant. Au load, chercher par gateway.
- UI (modification mineure) : dans l'accordéon « Vu par la box », afficher le nom personnalisé (BoxStore.getBoxName) + un icône ✏️ qui ouvre une AlertDialog avec TextField pour renommer (pattern DeviceStore/renommage existant : dialog + setBoxName + refreshTick pour recomposer).

## FEATURE 3 — Copier l'IP publique
- `NetworkScreen.kt` affiche déjà « IP publique : … ». Ajouter un bouton « 📋 Copier » (TextButton) à côté :
  - `val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager`
  - `clipboard.setPrimaryClip(ClipData.newPlainText("ip", publicIp))`
  - Snackbar « IP publique copiée ».
- Si publicIp est null → bouton caché.

## FEATURE 4 — SNMP (sysDescr, sysName, sysLocation, uptime)
But : enrichir les infos des périphériques via SNMPv1 (communautés par défaut public/private), sans lib.
- Nouvel objet `SnmpScanner.kt` (object) :
  - `probe(ip: String): SnmpResult?` — suspend/IO, UDP DatagramSocket port 161, timeout 1500 ms.
  - Requête GET pour les 4 OID : sysDescr (.1.3.6.1.2.1.1.1.0), sysName (.1.3.6.1.2.1.1.5.0), sysLocation (.1.3.6.1.2.1.1.6.0), sysUpTime (.1.3.6.1.2.1.1.3.0).
  - Communautés : "public" puis "private" (si public ne répond pas).
  - **BER encoding** : construire le message SNMPv1 : SEQUENCE { INTEGER version=0, OCTET STRING community, SEQUENCE { INTEGER request-id, INTEGER 0 (error-status), INTEGER 0 (error-index), SEQUENCE of varbinds } }. Varbind = SEQUENCE { OID, NULL }. Implémenter les encodeurs : encodeLength (short form <128, long form), encodeOid (sub-identifiers, 7-bit grouping, first pair special), encodeInteger, encodeOctetString.
  - **Parse réponse** : BER decode minimal — parcourir le buffer, extraire la SEQUENCE response (INTEGER request-id, INTEGER error-status, INTEGER error-index, SEQUENCE varbinds), pour chaque varbind lire OID + type + valeur. Types : OCTET STRING (0x04) → texte ; INTEGER (0x02) ; TimeTicks (0x43) → centièmes de seconde → uptime lisible.
  - Résultat : `SnmpResult(descr, name, location, uptimeSeconds)` (uptime = TimeTicks / 100).
  - `isSnmpOpen(ip)`: Boolean — port 161 joignable (connexion UDP test : envoyer la requête public et voir une réponse, même une erreur).
- Intégration : dans `NetworkScanner.scan` ou après, pour les appareils vivants avec port 161 détecté par PortScanner → `SnmpScanner.probe(ip)` → enrichir `Device` avec nouveaux champs : `snmpDescr`, `snmpName`, `snmpLocation`, `snmpUptime` (tous String?/Long? par défaut null). ⚠️ Ne pas bloquer le scan : runCatching + timeout court, et NE PAS attendre le SNMP si le port 161 n'est pas dans les ports ouverts.
- UI : fiche détail — nouvelle section « SNMP » si snmpName/snmpDescr non null (affiche System Name, Description, Location, Uptime formaté « Xj Yh Zm »).
- CSV : ajouter colonnes « SNMP Nom;SNMP Description » (après Modèle — attention à l'ordre des colonnes, garder les tests CSV existants cohérents : vérifier CsvExporter tests).
- Tests JUnit (logique pure) :
  - encodeOid : .1.3.6.1.2.1.1.1.0 → octets corrects (vérifier avec un vecteur connu : 06 08 2b 06 01 02 01 01 01 00).
  - encodeLength : 0, 127, 128, 300 → short/long form corrects.
  - parseVarbind : construire un buffer de réponse SNMP factice et vérifier extraction OID + OCTET STRING.
  - uptime format : 366100 centièmes → "1h 1m 1s" (ou format défini) — pur.

## LIVRABLES
- Code compilé : `./gradlew testDebugUnitTest --rerun-tasks` vert (compter les tests au total + 0 failures), `assembleDebug` OK.
- Bump : versionCode 25, versionName "1.6.0" dans app/build.gradle.kts.
- Commit local (pas de push). Rapporter : fichiers créés/modifiés, nombre de tests, taille APK.

# BRIEF v1.7.0 — network-scanner (Nmap signatures + alertes + GeoIP + historique présence)

À appliquer APRÈS la v1.6.1 (committée). Base : versionCode 26 / versionName "1.6.1". Cible : versionCode 27 / versionName "1.7.0".

## RÈGLES ABSOLUES
- NE PAS casser les signatures/features des v1.6.x (GatewayWatcher, BoxStore, SnmpScanner, UpdateChecker, Device.snmp*).
- Pas de NOUVELLE dépendance Gradle.
- `./gradlew testDebugUnitTest --rerun-tasks` (0 failure) puis `./gradlew assembleDebug`.
- Commit final : `git add -A && git commit -m "v1.7.0: signatures Nmap, alertes nouveaux appareils, GeoIP, historique présence"` — NE PAS push.
- Répondre en français dans le résumé.

## FEATURE 1 — Signatures Nmap (identification façon Fing)

Le fichier source : https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes (~1.5 Mo).
But : identifier service/produit/version à partir des bannières (HTTP Server:, SSH, FTP, SMTP, Telnet…) bien mieux que les ~20 règles actuelles de ServiceFingerprint.

### Asset compact
- Script host-side (tools/) : télécharger nmap-service-probes, le parser en un asset JSON compact `assets/nmap_signatures.json` :
  - Garder les lignes `match` et `softmatch` (format : `match <service> m|^regex$|i <product> <version-info>`) et `probe` HTTP OPTIONS/GET avec les regex de fallback.
  - Transformer les regex Nmap en regex Java/Kotlin compatibles (attention : la syntaxe Nmap utilise `\x00` hex escapes → les convertir en `\u0000` ; les regex peuvent être complexes — tester avec des exemples réels).
  - Format JSON : `[{"service":"http","product":"Apache httpd","version":"2.4.6","regex":"^HTTP/1\\.1 200 OK\\r\\nServer: Apache/2\\.4\\.6", "flags":"i"}, ...]`.
  - Limiter à ~200-300 règles les plus utiles (HTTP/HTTPS Server:, SSH, FTP, SMTP, POP3, IMAP, Telnet, RTSP, SIP, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, VNC, SMB/NetBIOS…) pour garder l'asset < 100 Ko.
- Le script de génération doit être exécutable (`tools/build_nmap_signatures.py`).

### NmapSignatures.kt (nouveau, object pur)
- `load(json: String): List<NmapRule>` — parse le JSON.
- `identify(banners: List<String>): NmapMatch?` — pour chaque bannière (les bannières déjà grabées par BannerGrab : HTTP server header, SSH banner, FTP/SMTP/POP3/IMAP/Telnet text banners), tester chaque règle (Regex avec flags), retourner la première match (ordre du fichier : plus spécifique d'abord).
- `NmapMatch(service, product, version)` + `displayName()` = `"$product $version"` (trim).
- Priorité d'affichage : ServiceFingerprint (règles maison précises) d'abord, puis NmapSignatures, puis SNMP, puis mDNS model. (Voir Device.product / enrichment v1.5.0 — la résolution produit existe déjà : `product = firstNonBlank(fp.product, md.model, upnp.modelName)` → insérer nmap entre fp et md.)
- Tests JUnit : parse JSON, identify sur bannières réelles (Apache 2.4.6, OpenSSH 8.9p1, ProFTPD 1.3.5, nginx 1.18.0), no-match → null.

## FEATURE 2 — Alertes nouveaux appareils (notification push)

- ScanHistory.detectNewDevices(previous, current) existe déjà (v0.2.0).
- Nouveau : `NewDeviceNotifier.kt` :
  - `notify(context, newDevices: List<Device>)` : si liste non vide → NotificationManager, canal `new_devices` (importance DEFAULT), titre « 🆕 N nouvel(s) appareil(s) détecté(s) », texte = noms/IP des 3 premiers + « et X autres… », tap → ouvre l'app (MainActivity, PendingIntent FLAG_IMMUTABLE).
  - Toggle dans Réglages/Aide : `new_device_alerts` (SharedPreferences `settings`, défaut ON). Si OFF → ne pas notifier.
- Manifest : permission `POST_NOTIFICATIONS` (Android 13+), runtime request au 1er scan si alerte ON (rememberLauncherForActivityResult, pattern BluetoothScanner permissions).
- Intégration : après chaque scan réussi, SI nouveaux devices détectés ET toggle ON → notify. ⚠️ Ne pas notifier au tout premier scan (previous vide → tout est « nouveau ») : skip si l'historique précédent était vide.
- Tests JUnit : logique de skip (première fois), formatage du texte (1 vs 3+ devices) — pur via fonction `buildNotificationText(devices): String` testable.

## FEATURE 3 — GeoIP de l'IP publique

- `NetworkInfoProvider.fetchPublicIp()` existe. Ajouter `fetchGeoIp(ip: String): GeoIpInfo?` :
  - API : `https://ipinfo.io/<ip>/json` (pas de clé pour usage léger), timeout 4 s, try/catch → null.
  - `GeoIpInfo(city, region, country, org)` — parse org.json.
- UI NetworkScreen : sous « IP publique : … », afficher « 📍 <ville>, <région> — <FAI> » si dispo (sinon rien). Charger avec l'IP publique (même LaunchedEffect).
- Tests JUnit : parse réponse JSON valide/invalide → GeoIpInfo/null.

## FEATURE 4 — Historique de présence

- HistoryStore stocke les scans (format v1). Ajouter la logique :
  - `PresenceHistory.kt` (object pur) : `record(history: List<ScannedDevice>, devices: List<Device>)` → met à jour un registre par identité (MAC sinon ip:) : liste de timestamps (epoch seconds) où l'appareil a été vu.
  - Stockage : fichier `filesDir/presence_history.json` (JSONObject : key → [ts, ts, ts…]) — `PresenceHistoryStore.kt` (save/load, borné à 500 entrées max par device, rotation si > 30 jours).
  - `PresenceHistory.lastSeen(entry, now)` → label relatif (« il y a 2 h », « hier », « il y a 3 j ») — pur, testable (réutiliser le pattern ageLabel de ScanPersistence).
- UI : dans la fiche détail d'un device (DeviceDetailScreen), nouvelle section « Présence » si historique : « Vu il y a <label> » + petit graphique Canvas des 14 dernières apparitions (points sur une ligne temporelle — pattern RssiGraph, simple : 14 points, vert si online aujourd'hui, gris sinon). Simplifier : sans graphique si trop complexe → uniquement le label « Vu il y a X » + compteur d'apparitions.
- ⚠️ Ne pas alourdir le scan : l'enregistrement se fait APRÈS le scan (pas pendant), dans un withContext(IO), runCatching.
- Tests JUnit : record ajoute/déduplique les timestamps proches (< 60 s → merge), bornes 500, lastSeen labels (à l'instant, il y a 5 min, il y a 2 h, hier, il y a 3 j).

## FEATURE 5 — Scanner WiFi + analyse de vulnérabilité (nouvel onglet)

⚠️ Contraintes Android à respecter (pas de déconnexion possible sans root — le scan WiFi fonctionne connecté) :
- `WifiManager.startScan()` + BroadcastReceiver `SCAN_RESULTS_AVAILABLE` → `getScanResults()`.
- Permissions : `ACCESS_FINE_LOCATION` (déjà demandée), `ACCESS_WIFI_STATE`, `CHANGE_WIFI_STATE`. Localisation système DOIT être activée (message clair sinon).
- Android 10+ : BSSID randomisés — ne PAS afficher la MAC comme identifiant fiable.
- Le scan est limité par le système (~4 scans / 2 min sur Android 9+) → bouton scan avec debounce + message.

### WifiScanner.kt (nouveau)
- `startScan(context, onResults: (List<WifiNetwork>) -> Unit)` : enregistre le receiver, startScan, timeout 12 s.
- `WifiNetwork(ssid, bssid, rssi, frequency, band, capabilities, channelWidth?)` — band via frequency (2.4/5/6 GHz, pattern bandForFrequency existant).
- Parse `capabilities` (ScanResult.capabilities string : "WPA2-PSK", "WPA3-SAE", "WEP", "ESS", "WPA-EAP", "OWE"…) → `WifiSecurity` enum (OPEN, WEP, WPA_TKIP, WPA2_CCMP, WPA3_SAE, WPA2_ENTERPRISE, WPA3_ENTERPRISE, OWE, UNKNOWN) — pur, testable.

### WifiVulnAnalyzer.kt (object pur — cœur de la feature)
- `analyze(sec: WifiSecurity, ssid: String): WifiVuln` — score 0..100 + label (Aucune/Faible/Modéré/Élevé/Critique) + liste de risques `List<String>` :
  - OPEN → 100 Critique (« Réseau ouvert : trafic en clair »)
  - WEP → 95 Critique (« WEP cassé depuis 2001 (outils grand public) »)
  - WPA_TKIP → 70 Élevé (« WPA2-TKIP : KRACK + brute force offline »)
  - WPA2_CCMP → 45 Modéré (« KRACK partiel (patches 2017), attaque PMKID possible »)
  - MIXTE WPA2/WPA3 → 25 Faible (« Transition : les clients peuvent se rétrograder en WPA2 »)
  - WPA3_SAE → 10 Faible (« Dragonblood : attaques marginales, patchées »)
  - WPA2_ENTERPRISE → 30 Modéré (dépend du mode EAP)
  - WPA3_ENTERPRISE → 10 Faible
  - OWE (Enhanced Open) → 15 Faible
  - UNKNOWN → 50 Modéré
  - + règles heuristiques : SSID type « Freebox-XXX »/« Bbox-XXX »/« SFR WiFi FON » (réseaux FON = portail captif → 60 Élevé « Réseau public/portail captif »), SSID par défaut « default »/« TP-LINK » → 20 Faible « SSID par défaut ».
- `scoreColor(score)` : vert <25, jaune <50, orange <75, rouge ≥75 (pattern scoreColor existant).
- Tests JUnit : chaque WifiSecurity → score attendu ; heuristique SSID FON ; no-match UNKNOWN.

### WifiScreen.kt (nouvel onglet)
- **NavigationBar 5 items** : Scanner / Réseau / Bluetooth / **WiFi** / Aide (icône 📶 — pattern existant, vérifier l'ordre et que Aide reste accessible).
- UI : bouton « 🔍 Scanner les réseaux » (en haut), liste des réseaux triés par score DESC (les plus vulnérables en premier), carte par réseau : SSID (ou « (caché) » si vide), badge score coloré + label, bande (2.4/5/6 GHz), RSSI (barre de signal), chiffrement (texte : « WPA2-PSK »), risques (puces rouges).
- Tap → dialog/full-screen détail : tous les champs + liste des risques + recommandation (« Change ce réseau en WPA3/WPA2-CCMP »).
- Message d'erreur si localisation OFF (« 📡 Active la localisation pour scanner le WiFi »).
- Pas de persistance nécessaire (scan live), mais garder le dernier scan en mémoire de session (state).

### FEATURE 5bis — Analyse « réseau public » (portail captif) quand on est connecté

Objectif (demande Fabrice) : quand l'app est connectée à un WiFi public (hôtel, SNCF, gare, café), détecter et alerter sur les vulnérabilités du réseau + portail captif.

### PublicWifiAnalyzer.kt (object)
- `detectCaptivePortal(timeoutMs: Int = 4000): CaptivePortalStatus` — sur le réseau CONNECTÉ :
  - Requête `http://connectivitycheck.gstatic.com/generate_204` (HttpURLConnection, suivre les redirections, timeout 4 s) :
    - HTTP 204 → PAS de portail (connexion normale)
    - Redirection 3xx vers une autre URL OU réponse 200 avec HTML de login → **portail captif détecté**
    - Erreur réseau → `UNKNOWN` (pas de connectivité ou réseau coupé)
  - Retourner aussi `portalUrl: String?` (URL finale après redirection) + `portalHttps: Boolean` (l'URL finale commence par https://) + `portalHost: String`.
- `analyzePublicNetwork(ssid: String?, security: WifiSecurity, captive: CaptivePortalStatus): PublicWifiVuln` — pur, testable :
  - Score 0..100 + label + risques `List<String>` + recommandations `List<String>` :
    - Réseau Open + portail captif → score 75+ (« Trafic en clair sur le portail », « Login/CB visibles par tous si portail HTTP », « Pas d'isolation client/client (probable) », « Evil twin possible — vérifie le nom exact du réseau »)
    - Portail en HTTP (`portalHttps=false`) → risque + « Le portail est en HTTP : ton identifiant/mot de passe circule en clair »
    - Portail en HTTPS → risque réduit (« Portail HTTPS — vérifie le certificat »)
    - SSID connu public (hôtel/SNCF/FON/FREE_WIFI/TRAIN/gares…) → risque « Réseau public partagé »
    - Recommandations toujours : « Utilise un VPN (WireGuard/Proton) », « Ne saisis aucun identifiant sans VPN », « Vérifie le nom exact du réseau (evil twin) »
  - `evilTwinHint(scanResults: List<WifiNetwork>): Boolean` — pur : 2+ réseaux visibles avec le MÊME SSID (et BSSID différents) → soupçon d'evil twin → vrai.
- Tests JUnit : détection 204 vs redirection vs erreur (via injectable `fetcher`), analyse Open+HTTP / Open+HTTPS / WPA2 (pas de portail), evilTwinHint (2 mêmes SSID → true, SSIDs différents → false).

### Intégration
- Au lancement de l'onglet WiFi (et au scan) : si l'app est connectée à un réseau → `detectCaptivePortal()` en arrière-plan + `analyzePublicNetwork(...)` → **bannière d'alerte en haut de l'écran WiFi** si score ≥ 50 : « ⚠️ Réseau public <SSID> — portail captif, score 78/100 » + bouton « Détails » → full-screen avec la checklist des risques + recommandations.
- Bandeau discret si score < 50 (« ✅ Réseau vérifié — pas de portail »).
- Le tout non bloquant (Dispatchers.IO + runCatching) — le scan WiFi ne doit jamais être ralenti par ce test.

## FEATURE 6 — Déconnecter/bloquer un client via la box (légal, API box)

But : permettre de couper l'accès d'un périphérique vu par la box (équivalent du « bloquer » de Freebox Companion) — PAS de deauth (illégal et impossible sans root).

### Côté API (FreeboxBoxClient)
- Ajouter `blockDevice(mac: String): Boolean` / `unblockDevice(mac: String): Boolean` :
  - Freebox OS API v9 : endpoint de coupure d'accès. Vérifier l'endpoint réel (les pistes : `POST /lan/browser/pub/` avec action, ou le champ `reachable`/`active` toggle, ou le blocage via `/lan/browser/pub/{id}`). Si l'endpoint exact n'est pas trouvé dans la doc, implémenter ce qui est vérifiable : désactiver le client via l'interface LAN browser (le skill freebox-api-integration.md doit être consulté). En dernier recours : documenter l'endpoint à confirmer avec un test réel et implémenter le bouton avec un message « à tester sur la box ».
- L'interface `BoxClient` peut gagner des méthodes par défaut `blockDevice`/`unblockDevice` (retourner false par défaut — pas de casser les implémentations).

### UI
- Dans la section « 📋 Vu par la box », sur chaque périphérique : icône/action « ⛔ Bloquer » (si la box le supporte) → confirmation AlertDialog (« Bloquer <nom> ? Il perdra l'accès réseau/Internet ») → appel API → Snackbar résultat. Si bloqué → icône « ✅ Débloquer ».
- Afficher un état « bloqué » sur le périphérique.
- ⚠️ Message de prudence : « Le client se reconnectera s'il se reconnecte physiquement ou si la box est redémarrée » (le blocage par API n'est pas toujours persistant).

## FEATURE 7 — Test des mots de passe par défaut (services web) — demande Fabrice

But : pour chaque périphérique avec un service web (80/443/8080/8443 détectés), tenter les identifiants par défaut (Basic Auth + formulaires simples) et PRÉVENIR Fabrice si une combinaison fonctionne.

### DefaultCredsChecker.kt (object)
- Asset `assets/default_creds.json` (JSON compact) :
  - Combos génériques : `[["admin","admin"],["admin","1234"],["admin","password"],["root","root"],["admin",""],["user","user"],["admin","1111"],["admin","12345"],["admin","admin123"],["support","support"]]`
  - Combos par fabricant (exemples) : `{"hikvision":[["admin","12345"]], "dahua":[["admin","admin"]], "mikrotik":[["admin",""]], "ubiquiti":[["ubnt","ubnt"]], "synology":[["admin",""]], "tp-link":[["admin","admin"]], "netgear":[["admin","password"]], "dlink":[["admin","admin"]]}` — matcher par OUI fabricant (VendorLookup) ou hostname.
- `combosFor(device: Device): List<Pair<String,String>>` — pur : si fabricant connu → creds fabricant d'abord + génériques ensuite ; sinon génériques seuls. Max 8 combos par device.
- `testBasicAuth(ip, port, user, pass, timeoutMs=1500): Boolean` — GET / (ou /login) avec `Authorization: Basic base64(user:pass)` (HttpURLConnection, ne PAS suivre les redirections, ne PAS envoyer le body) : 200/302/204 = SUCCÈS, 401/403 = échec, erreur réseau = échec silencieux.
- `checkDevice(device: Device, fetcher: (ip, port, user, pass) -> Boolean?): String?` — itère les combos (limite 8, timeout total ~12 s max), retourne `"user/pass"` si trouvé, null sinon. Le fetcher injectable permet les tests JUnit.
- ⚠️ Limites (les documenter dans le code et l'UI) : Basic Auth + formulaires simples seulement ; les formulaires avec CSRF/JS sont marqués « non testé » ; jamais plus de 8 combos (légal, non intrusif) ; ne PAS réessayer si 403 après 2 tentatives (anti-lockout) ; ne JAMAIS tester hors du subnet détecté.

### Intégration
- Après le scan réseau (NetworkScanner.scan), pour chaque device vivant avec un port web ouvert → `checkDevice` en parallèle (coroutine scope, Dispatchers.IO, runCatching), résultat stocké dans `Device.defaultCred: String?` (null = aucun trouvé) + `Device.credTested: Boolean`.
- **Si FOUND** :
  - Badge 🔑 rouge sur la carte : « Credential par défaut : admin/admin »
  - Alerte push (même canal que NewDeviceNotifier — feature 2) : « 🚨 <IP> (<nom>) accessible avec admin/admin ! »
  - Score vulnérabilité : +50 (CRITIQUE) dans VulnScanner (nouveau champ `defaultCred` alimente le score).
  - Fiche détail : section « 🔑 Credentials par défaut » avec le combo trouvé + bouton « 🔗 Ouvrir » (ouvre l'URL dans le navigateur).
- CSV : colonne « Credential défaut » (combo ou vide) — ordre vérifié avec les tests CSV.

### Tests JUnit
- Parse du JSON asset, combosFor (fabricant prioritaire, max 8), testBasicAuth via fetcher (200 → true, 401 → false, erreur → false), checkDevice (trouvé au 2e essai, non trouvé, limite 8), anti-lockout (2×403 → stop).

## LIVRABLES
- Code compilé : `./gradlew testDebugUnitTest --rerun-tasks` vert (compter les tests, 0 failures), `assembleDebug` OK.
- Bump : versionCode 27, versionName "1.7.0".
- Commit local (pas de push). Rapporter : fichiers créés/modifiés, nombre de tests, taille APK.

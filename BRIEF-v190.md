# BRIEF v1.9.0 — network-scanner (sécurité app, surveillance, historique débits, rapport PDF pro)

À appliquer APRÈS la v1.8.0 (committée). Base : versionCode 28 / versionName "1.8.0". Cible : versionCode 29 / versionName "1.9.0".

## RÈGLES ABSOLUES
- NE PAS casser les signatures/features existantes (v1.6 → v1.8).
- Pas de NOUVELLE dépendance Gradle (ou justifiée et minimale — WorkManager OK pour la surveillance, BiometricPrompt = androidx nativement présent).
- `./gradlew testDebugUnitTest --rerun-tasks` (0 failure) puis `./gradlew assembleDebug`.
- Commit final : `git add -A && git commit -m "v1.9.0: verrouillage PIN/empreinte, logs exportables, surveillance planifiée, historique débits, rapport PDF pro, options techniques"` — NE PAS push.
- Répondre en français dans le résumé.

## FEATURE 1 — Verrouillage de l'app (PIN ou empreinte digitale)

- `AppLock.kt` (object) + `AppLockScreen.kt` (Compose) :
  - Au premier lancement : proposer de configurer un verrou (PIN 4 chiffres OU biométrie si dispo).
  - Activation/désactivation + changement dans À propos/Réglages. Stockage : hash SHA-256 du PIN dans SharedPreferences (`settings`, key `lock_pin_hash`) — JAMAIS le PIN en clair. PIN par défaut : désactivé (opt-in).
  - Au démarrage de l'app : si verrou actif → écran de verrouillage plein écran avant le contenu :
    - Saisie PIN (clavier numérique Compose) → vérifie le hash → déverrouille.
    - Ou bouton « 🔓 Empreinte » si biométrie dispo (`BiometricPrompt` androidx, manifest permission USE_BIOMETRIC) → succès = déverrouille.
    - ⚠️ Délai de sécurité : après 5 échecs PIN → blocage 30 s (countdown).
  - État `unlocked` en mémoire (var) — l'écran de verrouillage ne se réaffiche que si l'app est relancée (pas de re-lock à chaque onResume, sauf si temps écoulé > 5 min → re-lock — option simple).
- Tests JUnit : hash PIN (jamais stocké en clair), vérification (bon/mauvais PIN), délai après 5 échecs (pur via clock injectable).

## FEATURE 2 — Messages d'erreur clairs + logs exportables

- `AppLog.kt` (object) : logger mémoire en anneau (dernières 500 lignes, niveau, horodatage) :
  - `log(level, tag, msg)` — appelé dans les points clés (scan, box, SNMP, update, WoL, creds…).
  - `dump(): String` — exportable.
- UI : dans À propos, section « 🔧 Support » :
  - Bouton « 📋 Copier les logs » → ClipboardManager (copie le dump).
  - Bouton « 📤 Partager les logs » → ACTION_SEND (fichier texte `logs_network_scanner_v<version>.txt` via FileProvider existant).
- Messages d'erreur UX : passer en revue les erreurs courantes et les rendre explicites :
  - Scan : « Aucun réseau Wi-Fi détecté — connecte-toi puis réessaie » (déjà), « Localisation désactivée — active-la pour scanner » (déjà pour WiFi — généraliser).
  - Box : « Box non accessible — vérifie que tu es sur le réseau de la box ».
  - Auto-update : « ⚠️ API GitHub injoignable (HTTP …) » au lieu d'un faux « à jour » (pattern déjà documenté).
  - SNMP/WoL/creds : « Test impossible — appareil injoignable ».
- Tests JUnit : AppLog ring buffer (borne 500, FIFO), dump format.

## FEATURE 3 — Surveillance continue (scan planifié) — OPTION désactivée par défaut

⚠️ Avertissement énergie obligatoire dans l'UI : « Cette option consomme de la batterie — scans en arrière-plan ».
- `SurveillanceScheduler.kt` :
  - WorkManager (dépendance androidx.work:work-runtime-ktx — nouvelle dépendance, justifiée) périodique : intervalle configurable 1h/2h/6h (défaut 2h).
  - Le worker (CoroutineWorker) : lance un scan réseau léger (sans UI) → `ScanHistory.detectNewDevices` → si NOUVEAU device → notification push (canal `surveillance`) « 🆕 Nouvel appareil détecté : <nom/IP> » + optionnellement enregistre le résultat.
  - ⚠️ Contraintes : `Constraints.Builder().setRequiresBatteryNotLow(true)` + `setRequiresCharging(false)` + expéditif si nécessaire.
- Réglages (À propos → Réglages) : toggle « Surveillance continue » (OFF par défaut) + choix d'intervalle + **avertissement énergie** affiché quand ON. Persistance SharedPreferences (`settings`, keys `surveillance_enabled`, `surveillance_interval`).
- Le worker ne doit PAS se lancer si le toggle est OFF (vérifier dans doWork + annuler le périodique au toggle OFF).
- Tests JUnit : logique de sélection d'intervalle, pas de logique réseau testée (WorkManager mocké par interface injectable).

## FEATURE 4 — Historique des débits (speed tests dans le temps)

- `SpeedHistoryStore.kt` : fichier `filesDir/speed_history.json` (JSONArray d'entrées `{ts, downMbps, upMbps, latencyMs}`), borné à 200 entrées (rotation FIFO).
- `SpeedTest` existant → après chaque test complet, `SpeedHistoryStore.append(...)`.
- UI (NetworkScreen ou Réseau tab) : section « 📈 Historique des débits » :
  - Dernier test + mini-graphique Canvas (pattern RssiGraph) des débits down/up (les 20 derniers points).
  - Liste des 5 derniers tests (date + down/up/latence).
- Tests JUnit : append/rotation 200, parse JSON.

## FEATURE 5 — Rapport PDF « audit client » enrichi

- Étendre `PdfAuditReport` existant :
  - Page de garde : titre « Rapport d'audit réseau », date, SSID réseau, version app.
  - **Synthèse exécutive** : score global (existant) + nombre d'appareils + nb vulnérabilités critiques/élevées + nb credentials par défaut trouvés.
  - **Recommandations hiérarchisées** (générées depuis les données) : top 5 actions (ex: « Changer le mot de passe de <IP> (admin/admin) », « Passer le réseau en WPA3 », « Mettre à jour le firmware de la box »).
  - Sections existantes conservées (table des appareils + vulnérabilités).
  - Logos : pas d'asset externe — texte stylé suffit (titre + séparateurs).
- Le tout en pur/Android rendering existant (PdfDocument) — aucune nouvelle dépendance.
- Tests JUnit : génération des recommandations (top 5, ordre par sévérité), synthèse (compteurs).

## FEATURE 6 — Options techniques (toggle, défaut = actif sauf mention contraire)

Ajouter dans Réglages une section « ⚙️ Options techniques » (toggles SharedPreferences `settings`) :
- **Scan rapide (ARP-first)** : `scan_fast` — défaut ON. Active un ordre de scan optimisé : ARP + découvertes multicast d'abord, ping en parallèle ensuite (ne PAS casser le scan complet — c'est une optimisation d'ordre, pas une réduction de couverture).
- **Consommation réduite** : `scan_economy` — défaut OFF. Limite les scans réseau lourds (SNMP, creds, SMB) à l'action manuelle (bouton « Analyse complète ») au lieu du scan automatique.
- **Accessibilité** : `a11y_large` — défaut OFF. Augmente les tailles de texte (typography scale) et les contrastes.
- Chaque toggle a une courte description. Les fonctions existantes restent actives selon le toggle.
- Tests JUnit : lecture des toggles (défauts), pas de régression.

## FEATURE 7 — Lecteur NFC + historique local — demande Fabrice

⚠️ Limite honnête : Android n'expose PAS d'historique système des tags touchés, et les paiements NFC sont bloqués aux apps. On enregistre les tags que NOTRE app lit (mode lecteur au contact).

### NfcReader.kt (nouveau)
- Intégration : `NfcAdapter.enableReaderMode(activity, callback, FLAG_READER_NFC_A|NFC_B|NFC_F|ISO14443|NFC_V, null)` — au premier plan de l'écran NFC.
- Callback `onTagDiscovered(tag: Tag)` :
  - `tag.id` → UID hex.
  - `tag.techList` → technologies (NfcA, NfcB, NfcF, IsoDep, MifareClassic, Ndef…).
  - Ndef : `Ndef.get(tag)` + `ndef.ndefMessage` → records (URI/texte) → contenu lisible.
  - `NfcLogEntry(uid, techs: List<String>, payload: String?, ts: Long)`.
- Manifest : permission `NFC` + `uses-feature android.hardware.nfc required=false`.

### NfcHistoryStore.kt
- Fichier `filesDir/nfc_history.json` (JSONArray d'entrées, borné 200, rotation FIFO — pattern SpeedHistoryStore).
- `all(): List<NfcLogEntry>` (dédup par UID possible : nombre de vues + dernière vue).

### NfcScreen.kt (nouvel onglet)
- **NavigationBar 8 items** : Scanner / Réseau / Bluetooth / WiFi / Box / Cellulaire / **NFC** / Aide (⚠️ 8 items = beaucoup — si trop serré, mettre NFC dans le menu ⋮ ou dans un sous-écran accessible depuis Scanner ; au choix du subagent, l'important est que l'écran NFC soit accessible).
- UI : grande zone « 📱 Touche un tag NFC » (état lecteur actif 🟢), à chaque tag : carte avec UID, technologies, contenu NDEF, horodatage. Liste de l'historique (récent en premier) + bouton « 🗑 Effacer l'historique ».
- Indication si NFC désactivé : « 📴 NFC désactivé — active-le dans les réglages ».
- Pas de foreground service (consommation) — lecture au premier plan seulement (documenter dans l'UI « l'app doit être ouverte sur cet écran »).

### Tests JUnit
- Parsing NDEF (records URI/texte — via helpers purs injectables), dédup par UID, rotation 200, format UID hex.

## LIVRABLES
- Code compilé : `./gradlew testDebugUnitTest --rerun-tasks` vert (compter les tests, 0 failures), `assembleDebug` OK.
- Bump : versionCode 29, versionName "1.9.0".
- Commit local (pas de push). Rapporter : fichiers créés/modifiés, nombre de tests, taille APK.

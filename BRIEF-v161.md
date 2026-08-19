# BRIEF v1.6.1 — network-scanner (auto-update + UI)

À appliquer APRÈS la v1.6.0 (déjà committée). Base : versionCode 25 / versionName "1.6.0". Cible : versionCode 26 / versionName "1.6.1".

## RÈGLES ABSOLUES
- NE PAS casser les signatures/features de la v1.6.0 (GatewayWatcher, BoxStore, SnmpScanner, Device.snmp*).
- Pas de NOUVELLE dépendance Gradle (org.json est déjà utilisé).
- `./gradlew testDebugUnitTest --rerun-tasks` (0 failure) puis `./gradlew assembleDebug` (le CI signera en release).
- Commit final : `git add -A && git commit -m "v1.6.1: auto-update GitHub, version affichée, barre de recherche compacte, scan en haut"` — NE PAS push.

## FEATURE 1 — AUTO-UPDATE via GitHub Releases (pattern Vigie, skill android-app-autoupdate-github-releases)

### build.gradle.kts
- Ajouter `signingConfigs.release` : décode le keystore depuis `NETWORK_SCANNER_KEYSTORE_B64` (env) vers `RUNNER_TEMP/network-scanner-release.keystore` (base64), password/alias depuis `NETWORK_SCANNER_KEYSTORE_PASSWORD`/`NETWORK_SCANNER_KEY_ALIAS`/`NETWORK_SCANNER_KEY_PASSWORD`. Fallback local : si `/root/.secrets/keystores-android/network-scanner-release.keystore` existe (build local), l'utiliser avec les mêmes passwords (lire depuis un fichier env ou env vars).
- `buildTypes.release.signingConfig = signingConfigs.release` UNIQUEMENT si la config est disponible (condititon : présence de la var env du keystore OU fichier local) — sinon pas de signingConfig (le CI a toujours les secrets).
- Imports explicites en tête : `java.io.File`, `java.util.Base64`.
- ⚠️ PKCS12 : storePassword == keyPassword (le keystore existant est en PKCS12).

### CI (.github/workflows/build.yml)
- Passer les 4 secrets `NETWORK_SCANNER_*` en `env` au niveau du job.
- Remplacer `assembleDebug` par `./gradlew testDebugUnitTest assembleRelease --no-daemon` (signé).
- Renommer `app-release.apk` → `network-scanner-v<version>.apk` (idem debug actuel).
- Publier `latest` + release versionnée comme actuellement (garder la logique).

### Côté app : UpdateChecker.kt (nouveau, package com.fabrice.network.scanner)
- `UpdateChecker.check(): UpdateInfo?` — API `https://api.github.com/repos/ClawFabriceH92/network-scanner/releases?per_page=5`, parsing org.json, retenir la version la PLUS HAUTE avec asset `.apk`, ignorer drafts. Comparer à `BuildConfig.VERSION_NAME` (comparaison segment par segment Int, PAS lexicale).
- `UpdateInfo(version: String, url: String)` — url = asset `.apk` browser_download_url.
- try/catch → null si erreur (robuste réseau).
- `shouldUpdate(current: String, remote: String): Boolean` — pur, testable (0.10.0 > 0.9.0).
- Tests JUnit : shouldUpdate (0.9.0 < 1.0.0, 1.6.0 < 1.6.1, 1.10.0 > 1.9.0), parse JSON valide/invalide (org.json testImplementation déjà présent).

### DownloadUpdate.kt (nouveau)
- `DownloadUpdate.start(context, url)`: DownloadManager → destination `getExternalFilesDir(DOWNLOADS)/network-scanner-update.apk` → enregistrer le downloadId dans SharedPreferences `update_prefs`.
- `DownloadUpdate.receiver(context, downloadId)`: BroadcastReceiver (manifest, exported=false, action DOWNLOAD_COMPLETE) → si id match → vérifier `canRequestPackageInstalls()` → installer via FileProvider (autorité `${applicationId}.fileprovider` déjà en place — ajouter `<external-files-path>` au file_paths.xml si nécessaire) + `Intent.ACTION_VIEW` + `FLAG_GRANT_READ_URI_PERMISSION` + `FLAG_ACTIVITY_NEW_TASK`. Sinon → notification canal dédié `updates` avec action vers `Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES` (package:).
- Permission `REQUEST_INSTALL_PACKAGES` au manifest.
- UI : dans l'écran À propos (HelpAboutScreens), ajouter une section « Mise à jour » : bouton « Vérifier les mises à jour » + ligne de statut (⚠️ erreur API / ✅ à jour / ⬇️ téléchargement) + bouton « Installer » si dispo. Le check doit tourner dans une coroutine (Dispatchers.IO) — JAMAIS sur le thread UI (pitfall NetworkOnMainThreadException). Au lancement de l'app, check auto silencieux (optionnel : ne pas polluer l'UI).

## FEATURE 2 — Numéro de version affiché
- Dans l'écran principal Scanner (ScannerScreen.kt), en bas de la liste (ou sous le résumé), ajouter un petit texte discret : `v1.6.1` (BuildConfig.VERSION_NAME), couleur grise, typo petite.
- Garder la version dans À propos (déjà existant).

## FEATURE 3 — Barre de recherche réduite
- La barre de recherche actuelle (TextField) prend trop de place. La rendre COMPACTE : réduire la hauteur (padding vertical ~4-6 dp), marges réduites, icône seule si vide (ou placeholder court), typo bodySmall. Garder la fonctionnalité (filtre IP/nom/fabricant/modèle/MAC).
- But : la liste des périphériques visible le plus vite possible.

## FEATURE 4 — Bouton scan en haut
- Actuellement le scan est un ExtendedFloatingActionButton en bas à droite. Le DÉPLACER en haut :
  - Ajouter une action dans la TopAppBar (icône ⚡ ou « Scanner ») OU un bouton compact en haut de l'écran au-dessus de la liste (préféré : bouton visible avec libellé « Scanner », largeur pleine ou aligné à droite, sous la barre de recherche).
  - Conserver l'état « Scan en cours… » (progress + compteur done/total) comme actuellement.
  - Supprimer le FAB en bas (une seule action primaire visible — règle v1.3.1 : ONE primary action button per state).
- Vérifier qu'aucun test/écran ne référence l'ancien FAB de manière à casser le build.

## LIVRABLES
- Code compilé : `./gradlew testDebugUnitTest --rerun-tasks` vert (compter les tests, 0 failures), `assembleDebug` OK.
- Bump : versionCode 26, versionName "1.6.1".
- Commit local (pas de push). Rapporter : fichiers créés/modifiés, nombre de tests, taille APK.

# NetworkScanner — Scan du réseau local (type Fing)

Application Android qui scanne le réseau Wi-Fi local et liste les périphériques
connectés : IP, MAC, fabricant (base OUI embarquée ~40 000), hostname.

## Fonctionnalités
- Détection automatique du sous-réseau (IP + masque)
- Ping sweep parallèle (64 threads)
- Fusion avec la table ARP (appareils qui ne répondent pas à l'ICMP)
- Reverse DNS pour le nom réseau
- Fabricant via la base OUI IEEE (assets/oui.txt, 39 933 entrées)
- Détail de chaque appareil (IP/MAC/fabricant/hostname/statut)

## Tests
`./gradlew testDebugUnitTest` — 8 tests : parsing ARP, calcul de sous-réseau,
normalisation MAC, chargement de la base OUI complète.

La logique a été validée sur le réseau réel (scan 192.168.0.0/24, appareils
détectés : box Freebox, PC, appareils Xiaomi/HP, Synology…).

## Build
`./gradlew assembleDebug` → `app/build/outputs/apk/debug/app-debug.apk`

## Changelog

### v1.9.25 — correctif compteur imprimante (SNMP Counter32)
- **Bug corrigé** : les compteurs SNMP de type `Counter32`/`Gauge32`/`Counter64`
  (dont `prtMarkerLifeCount`, le compteur de pages) étaient ignorés — le
  décodeur ne gérait que `INTEGER`/`TimeTicks`. Le nombre de pages remonte
  désormais dès que l'imprimante expose le SNMP (ce que confirmait un script
  Python).

### v1.9.24 — compteur imprimante : lecture SNMP plus robuste
- **Compteur de pages SNMP** : si l'index usuel (`prtMarkerLifeCount.1.1`) est
  vide, l'app parcourt (walk) toute la colonne `prtMarkerLifeCount` et prend la
  plus grande valeur — robuste aux index variables (imprimantes couleur, MFP).

### v1.9.23 — MAC sous l'IP + bouton « Compteur » imprimante
- **Adresse MAC affichée sous l'IP** sur chaque carte de l'onglet Périphériques.
- **Bouton « 🖨️ Compteur »** sur les cartes d'imprimante : affiche pages
  imprimées / numérisations / copies (lecture live IPP+SNMP si non déjà en
  cache) dans une boîte de dialogue.

### v1.9.22 — écran « Ma box » : connexion, système, Wi-Fi, redémarrage
- **Écran « 📡 Ma box »** (menu ⋮) désormais accessible : connexion WAN, débit
  temps réel, Wi-Fi box, système, baux DHCP.
- **Connexion / WAN** : IP publique, type d'accès, état de ligne, uptime, et
  **diagnostic xDSL** (marge de bruit SNR, atténuation) sur ADSL/VDSL.
- **Système box** : modèle, firmware, n° de série, uptime, température.
- **Wi-Fi box** : SSID, sécurité, canal + clients Wi-Fi avec signal (RSSI).
- **Redémarrer la box** : bouton avec confirmation (Freebox : réel ; autres :
  selon authentification disponible).
- Endpoints implémentés : SFR (`wan/dsl/system/wlan.getInfo`), Bbox
  (`/api/v1/wan|xdsl|device`), Freebox (reboot authentifié). Best-effort selon
  firmware.

### v1.9.21 — MAC via box : Bbox (corrigé) + Livebox (sysbus)
- **Bbox (Bouygues)** : client réécrit sur la vraie API publique
  `GET /api/v1/hosts` (l'ancien code visait à tort l'API sysbus). Récupère
  MAC/IP/nom/type de connexion **sans authentification**.
- **Livebox (Orange)** : ajout de l'API **sysbus** moderne (Livebox 4+) —
  `createContext` + `Devices:get` avec le mot de passe admin, saisi via un
  dialogue (bouton « Autoriser » de la section box). Repli TR-064 pour les
  Livebox 2/3. Récupère MAC/IP/nom/type de connexion.

### v1.9.20 — MAC via box : Freebox (corrigé) + SFR (nouveau)
- **Box SFR / RED / Neufbox** : nouveau client via l'API locale publique
  `http://<box>/api/1.0/?method=lan.getHostsList` (Sagemcom NB4/5/6). Récupère
  MAC + IP + nom + type de connexion de tout le réseau, **sans autorisation**.
  Détection active (sonde de l'API) pour distinguer SFR d'une Livebox sur
  192.168.1.1.
- **Autorisation Freebox réparée** : l'app poll désormais le statut après la
  demande — c'est cette étape qui valide réellement le jeton. Sans elle, la box
  n'était jamais autorisée, donc aucune MAC n'était récupérée. Après validation
  sur l'écran de la box, un nouveau scan est lancé automatiquement.
- **Version d'API Freebox dynamique** : découverte via `/api_version` au lieu de
  « v9 » figé (l'API échouait si la box était en v8/v10/v13…).
- Rappel : sur Android 10+ la table ARP système est vide ; l'API de la box est
  la source fiable des MAC de tout le réseau.

### v1.9.19 — navigateur DLNA + test Wake-on-LAN
- **Navigateur DLNA** : menu ⋮ → « 🎬 Médias DLNA » découvre les serveurs
  multimédia (UPnP ContentDirectory) et parcourt dossiers/fichiers ; un fichier
  s'ouvre dans le lecteur externe (VLC…).
- **Test Wake-on-LAN** : bouton « Tester le WoL » sur la fiche — envoie le magic
  packet, attend, re-ping, puis mémorise « ✅ WoL confirmé ». Le WoL ne peut pas
  se détecter passivement (appareil éteint = invisible) ; seul le test fait foi.
  La fiche indique aussi « WoL possible (non testé) » quand la MAC est connue.

### v1.9.18 — enrichissement : Web, TLS, RTSP, UPnP-IGD, SNMP+, traceroute, latence
- **Fingerprint web** : titre de la page (`<title>`) + empreinte MD5 du favicon.
- **Certificat TLS** (443/8443/9443) : nom (CN), émetteur, expiration, alertes
  auto-signé/expiré.
- **RTSP/ONVIF** (caméras, port 554) : serveur + URL de flux à ouvrir dans VLC.
- **UPnP-IGD** (passerelle) : IP publique **et liste des redirections de ports**
  (port forwarding) — repère les services exposés sur Internet.
- **SNMP approfondi** : n° de série, contact système, nombre d'interfaces.
- **Traceroute** vers Internet (onglet Réseau) et **historique de latence**
  par appareil (min/moyenne/max + gigue) sur la fiche.
- **Type de connexion** (Wi-Fi/Ethernet) affiché quand la box l'expose.

### v1.9.17 — MAC via la table ARP du routeur (SNMP, agnostique marque)
- **Table ARP de la passerelle en SNMP** (`ipNetToMediaPhysAddress`) : si le
  routeur expose SNMP, l'app lit IP→MAC pour **tout** le réseau, quelle que soit
  la marque (pas besoin d'API propriétaire de box). Complète /proc/net/arp (vide
  sur Android 10+) et la fusion box. Ajout d'un walk SNMP (GetNext).

### v1.9.16 — adresses MAC (box + SNMP)
- **MAC via la box** : sur Android 10+ la table ARP système est vidée, donc l'app
  ne pouvait pas lire les MAC des autres appareils. Les MAC connues de la box
  (baux DHCP Freebox/Livebox/Bbox) sont désormais **fusionnées par IP** dans les
  fiches — MAC + fabricant pour la plupart des appareils du réseau.
- **MAC via SNMP** : pour les appareils exposant SNMP (imprimante, NAS, routeurs
  pro…), la MAC est lue via `ifPhysAddress` quand elle manque.

### v1.9.15 — compteurs imprimante : scans & copies
- **Nombre de numérisations et de copies** en plus des impressions, via la page
  d'usage EWS HP `/DevMgmt/ProductUsageDyn.xml` (impressions / scans ADF+vitre /
  copies). Affichés et historisés sur la fiche (« Numérisations », « Copies »)
  avec évolution depuis le dernier scan. HTTP puis HTTPS (certificat auto-signé
  accepté pour cette lecture locale). Repli SNMP pour les impressions.

### v1.9.14 — imprimantes (IPP), statistiques & profils de lieux
- **Modèle d'imprimante exact via IPP** : requête `Get-Printer-Attributes` sur
  le port 631 → `printer-make-and-model` (ex. « HP Color LaserJet MFP E57540 »),
  état, emplacement, consommables. Repli SNMP si l'IPP est muet.
- **Statistiques imprimante historisées** : compteur de pages (SNMP
  `prtMarkerLifeCount`), niveaux de toner/encre et état sont enregistrés à
  chaque scan (PrinterStatsStore) et affichés dans une section « 🖨️ Imprimante »
  sur la fiche (barres de niveau + évolution du nombre de pages).
- **Profils de lieux de connexion** : chaque réseau (SSID/passerelle) est
  mémorisé avec un instantané des appareils, consultable plus tard via le menu
  ⋮ → « 📍 Profils / Lieux » (même hors de ce réseau).

### v1.9.13 — 🌐 sur les ports web (liste) + libellé nav corrigé
- **Repère site web dans la liste** : les pastilles de ports web affichent 🌐
  directement sur la carte de l'appareil (plus besoin d'ouvrir la fiche).
- **Libellé « Appareils »** : correction du léger rognage du dernier caractère
  dans la barre de navigation.

### v1.9.12 — sites web, pop-up MAJ, lien APK copiable, barre de scan
- **Sites web identifiés** : dans « Services ouverts », les ports servant une
  interface web sont marqués « 🌐 site web » et sont **cliquables** (ouvre
  `http(s)://ip:port` dans le navigateur).
- **Pop-up de mise à jour** : une nouvelle version détectée au lancement
  s'affiche dans une boîte de dialogue (Télécharger / Copier le lien / Plus tard).
- **Lien APK copiable** : dans Réglages, le lien direct de l'APK est affiché et
  copiable — utile quand le téléchargement automatique ne démarre pas.
- **Barre de progression** : reflète désormais les 3 phases (ping, sonde de
  vivacité TCP, scan de ports) au lieu de rester bloquée à 100 % pendant le
  scan de ports.

### v1.9.11 — serveurs web conteneurisés enfin détectés
- **Ports web/conteneurs toujours scannés** : les ports web et self-hosted
  courants (5000, 5001, 8096, 8123, 9443, 3000, 8000, 81, 8081, 32400, API
  Docker 2375…) sont désormais testés sur **tous** les hôtes vivants, même en
  mode Standard. Avant, un serveur web conteneurisé sur un port non standard
  (ex. `192.168.0.180:5000`) n'apparaissait pas.
- **Sonde de vivacité TCP élargie** : ces mêmes ports servent à découvrir les
  hôtes qui filtrent le ping (un conteneur web sur 8096/8123/9443… n'était pas
  détecté du tout car la sonde ne testait que 12 ports).

### v1.9.10 — services Docker en mode bridge (ports)
- **Conteneurs Docker en bridge** : en mode bridge (défaut), un conteneur n'a
  pas d'IP propre — il est derrière l'IP de l'hôte, seuls ses **ports publiés**
  sont visibles. Le mode « Élargi » inclut désormais les ports typiques des
  apps conteneurisées (Portainer 9443, Jellyfin 8096, Home Assistant 8123,
  Grafana 3000, Sonarr/Radarr/Prowlarr, Docker API 2375…).
- **Scan complet des ports (1–65535)** : nouveau bouton sur la fiche d'un
  appareil. Sonde les 65535 ports de l'hôte pour révéler les services sur des
  ports arbitraires. Les ports trouvés sont ajoutés à « Services ouverts »
  (marqués « scan complet »).

### v1.9.9 — détection des conteneurs Docker
- **Sonde de vivacité TCP** : les hôtes qui filtrent l'ICMP (conteneurs Docker,
  serveurs/VM derrière un pare-feu, IoT) sont désormais découverts via une
  connexion TCP sur les ports courants (dont 3000/5000/8000/9000, typiques des
  apps conteneurisées). Avant, un conteneur sans ping ni service multicast
  n'apparaissait jamais dans la liste. La sonde peuple aussi la table ARP, donc
  la MAC de ces hôtes est récupérée. Reporté en mode économie d'énergie.
- **Reconnaissance Docker** : les MAC du préfixe `02:42` sont étiquetées
  « Docker » (au lieu d'« Adresse privée ») et classées **Serveur / Conteneur** 🐳.

### v1.9.8 — nouvelle icône
- **Icône de l'app redessinée** : fond bleu nuit en dégradé radial, balayage
  radar doré en fondu angulaire, aiguille or, anneaux fins et nœuds détectés.
  Variante monochrome (icône thématisée Android 13+) alignée sur le même
  drawable.

### v1.9.7 — bouton de téléchargement direct
- Réglages → un bouton **« Télécharger la dernière version (APK) »** télécharge
  directement l'APK le plus récent (lien stable `network-scanner-latest.apk` de
  la release `latest`), indépendamment de la vérification de version. La CI
  publie désormais aussi l'APK sous ce nom fixe.

### v1.9.6 — correctif détection des mises à jour
- **Auto-update** : l'app lit désormais le numéro de version dans le **nom de
  l'APK** (`network-scanner-vX.Y.Z.apk`) quand le tag de la release n'est pas un
  numéro. La release rolling `latest` (mise à jour à chaque build) est enfin
  détectée — avant, son tag `latest` était interprété comme version 0, donc
  l'app affichait toujours « à jour ».

### v1.9.5 — finitions interface
- **Barre de navigation** : les libellés « Bluetooth »/« Réglages » ne passent
  plus à la ligne. Le libellé n'est affiché que sur l'onglet actif (icône seule
  pour les autres), sur une seule ligne, avec description d'accessibilité sur
  chaque icône.
- **Icônes cohérentes** : les emojis d'action (confiance, blocage box, renommer)
  sont remplacés par des icônes Material vectorielles (rendu homogène).
- **Fondu** léger à la bascule d'onglet.

### v1.9.4 — corrections de bugs & améliorations UI
Passe de qualité (audit + corrections). L'ancienne version est conservée sous
le tag git `backup/v1.9.3-pre-improvements`.

**Corrections de bugs**
- Wake-on-LAN : `SO_BROADCAST` activé (l'envoi du magic packet échouait toujours).
- Progression du scan : la barre reflète les adresses sondées (et non le nombre
  d'appareils trouvés) — elle atteint réellement 100 %.
- Scan Wi-Fi : un résultat vide est livré au timeout (le spinner ne reste plus
  bloqué à l'infini) ; le récepteur n'est plus désenregistré par un scan périmé.
- Permissions Bluetooth : chaque permission est évaluée sur son propre résultat.
- NBNS : lecture de la vraie MAC de l'adaptateur (6 premiers octets du bloc de
  stats, pas les 6 derniers).
- Livebox (TR-064) : énumération des hôtes en index 1-based (le dernier appareil
  n'était plus manquant).
- Freebox : parsing JSON défensif (plus de crash sur réponse inattendue).
- Rapport PDF : pagination multi-pages (la section vulnérabilités n'est plus
  perdue sur les grands réseaux), largeurs de colonnes corrigées, en-tête réseau
  corrigé, échec d'écriture signalé.
- Détection de credentials par défaut testée en HTTPS pour les ports 443/8443.
- Bouton « Retour » système : revient à l'écran précédent au lieu de quitter l'app.
- Carte réseau : les nœuds sont désormais cliquables.
- Graphe RSSI : lignes de repère à nouveau visibles.
- Divers : timeouts, fermeture de sockets/connexions, écritures disque atomiques
  et synchronisées, MdnsResolver/WsdResolver durcis.

**Améliorations UI/UX**
- Barre de navigation avec libellés (Appareils / Réseau / Bluetooth / WiFi /
  NFC / Réglages).
- Pastilles de ports qui passent à la ligne (plus de débordement).
- Champ de recherche non tronqué ; claviers numériques et champs mot de passe
  masqués ; spinner de mise à jour visible ; descriptions d'accessibilité.

**Performances**
- Chargements (base OUI/CVE, assets) et écritures disque déplacés hors du thread
  UI (moins de jank/ANR) ; sondage RSSI unifié ; test de débit sans buffer inutile.

**Sécurité**
- PIN de verrouillage : hachage salé PBKDF2 (migration transparente des anciens
  PIN) + exclusion des sauvegardes.
- Export CSV : neutralisation de l'injection de formules.

**Nettoyage**
- Système de mise à jour unifié : les deux piles d'auto-update concurrentes
  (double appel à l'API GitHub au lancement, deux BroadcastReceiver, deux canaux
  de notification) sont fusionnées en une seule ; suppression de la boucle de
  sondage quotidienne (réveil process toutes les 30 s) au profit d'une simple
  vérification au lancement.

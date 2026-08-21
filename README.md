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

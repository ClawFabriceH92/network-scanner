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

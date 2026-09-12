#!/usr/bin/env python3
"""Génère assets/trackers.json pour NetworkScanner (capture réseau : classification
des connexions « tracker / publicité »).

Source : liste Disconnect Tracking Protection (licence GPLv3 / CC BY-NC-SA pour
la liste) — https://github.com/disconnectme/disconnect-tracking-protection

Sortie : JSON compact {generated, source, count, domains:{"domaine": "Catégorie|Société"}}
La correspondance dans l'app est par SUFFIXE (« ads.doubleclick.net » ⊂ « doubleclick.net »).
"""
import json
import sys
import time
import urllib.request

SRC_URL = "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json"
OUT = "app/src/main/assets/trackers.json"

# Catégories Disconnect → libellé français. Les catégories absentes sont ignorées
# (« Content » = CDN/contenu tiers non pisteur, « ConsentManagers », « Anti-fraud »).
CATEGORIES = {
    "Advertising": "Publicité",
    "Analytics": "Analytique",
    "Social": "Réseau social",
    "FingerprintingInvasive": "Empreinte navigateur",
    "FingerprintingGeneral": "Empreinte navigateur",
    "Cryptomining": "Cryptominage",
    "Email": "Pistage e-mail",
    "EmailAggressive": "Pistage e-mail",
}


def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "NetworkScanner-Trackers/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def main():
    data = http_get(SRC_URL)
    cats = data.get("categories") or {}
    domains = {}
    # Ordre de priorité = ordre de CATEGORIES (Publicité > Analytique > … > e-mail)
    for cat, label in CATEGORIES.items():
        entries = cats.get(cat) or []
        for ent in entries:
            for org, urls in ent.items():
                for _url, doms in urls.items():
                    if not isinstance(doms, list):
                        continue
                    for d in doms:
                        d = d.strip().lower().rstrip(".")
                        if not d or " " in d or "." not in d:
                            continue
                        # Première catégorie gagnante (Advertising avant Analytics…)
                        domains.setdefault(d, f"{label}|{org}")
    if len(domains) < 500:
        print(f"Liste suspecte ({len(domains)} domaines) — abandon", file=sys.stderr)
        sys.exit(1)
    out = {
        "generated": time.strftime("%Y-%m-%d"),
        "source": "disconnect-tracking-protection",
        "count": len(domains),
        "domains": dict(sorted(domains.items())),
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, separators=(",", ":"))
    print(f"{OUT} : {len(domains)} domaines ({out['generated']})")


if __name__ == "__main__":
    main()

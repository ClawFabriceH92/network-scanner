#!/usr/bin/env python3
"""Génère assets/cve_db.json pour NetworkScanner (scan vulnérabilités v0.3.0).

Sources :
1. CISA KEV — vulnérabilités activement exploitées (produit-level, flag kev)
2. NVD API 2.0 — CVE par produit avec ranges de versions (matching précis)

Sortie : JSON compact {generated, sources, products, cves:[...]}
Chaque CVE : {id, product, sev, cvss, desc, kev, ransomware, ranges:[{s,e,si,ei}]}
  ranges = bornes de versions vulnérables (NVD CPE match criteria)
  s=versionStartIncluding, e=versionEndExcluding, si=versionStartExcluding, ei=versionEndIncluding
  rangs vides = alerte produit-level uniquement (KEV)
"""
import json
import sys
import time
import urllib.request
import urllib.parse

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Produits détectables par banner grabbing dans l'app → CPE NVD + mot-clé
PRODUCTS = {
    "openssh":  ("cpe:2.3:a:openbsd:openssh",        "OpenSSH",  "OpenSSH"),
    "apache":   ("cpe:2.3:a:apache:http_server",     "Apache httpd", "httpd"),
    "nginx":    ("cpe:2.3:a:f5:nginx",               "nginx",    "nginx"),
    "iis":      ("cpe:2.3:a:microsoft:internet_information_services", "Microsoft IIS", "iis"),
    "lighttpd": ("cpe:2.3:a:lighttpd:lighttpd",      "lighttpd", "lighttpd"),
    "thttpd":   ("cpe:2.3:a:acme:thttpd",            "thttpd",   "thttpd"),
    "proftpd":  ("cpe:2.3:a:proftpd:proftpd",        "ProFTPD",  "ProFTPD"),
    "vsftpd":   ("cpe:2.3:a:vsftpd:vsftpd",          "vsftpd",   "vsftpd"),
    "pureftpd": ("cpe:2.3:a:pureftpd:pure-ftpd",     "Pure-FTPd", "pure-ftpd"),
    "postfix":  ("cpe:2.3:a:postfix:postfix",        "Postfix",  "postfix"),
    "exim":     ("cpe:2.3:a:exim:exim",              "Exim",     "exim"),
    "sendmail": ("cpe:2.3:a:sendmail:sendmail",      "Sendmail", "sendmail"),
    "dovecot":  ("cpe:2.3:a:dovecot:dovecot",        "Dovecot",  "dovecot"),
}

def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "NetworkScanner-CVEDB/0.3"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))

def sev_from_cvss(score):
    if score is None: return "UNKNOWN"
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"

def extract_metrics(cve):
    """Meilleur score CVSS v3 (sinon v2)."""
    m = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for item in m.get(key, []):
            cvss = item.get("cvssData") or {}
            return cvss.get("baseScore"), cvss.get("baseSeverity")
    for item in m.get("cvssMetricV2", []):
        cvss = item.get("cvssData") or {}
        return cvss.get("baseScore"), None
    return None, None

def extract_ranges(cve, cpe_prefix):
    """Ranges de versions vulnérables du CPE cible dans les configurations."""
    ranges = []
    for conf in (cve.get("configurations") or []):
        for node in conf.get("nodes") or []:
            for cpe in node.get("cpeMatch") or []:
                crit = (cpe.get("criteria") or "").lower()
                if not crit.startswith(cpe_prefix):
                    continue
                r = {}
                if cpe.get("versionStartIncluding"): r["s"] = cpe["versionStartIncluding"]
                if cpe.get("versionEndExcluding"):   r["e"] = cpe["versionEndExcluding"]
                if cpe.get("versionStartExcluding"): r["si"] = cpe["versionStartExcluding"]
                if cpe.get("versionEndIncluding"):   r["ei"] = cpe["versionEndIncluding"]
                if r: ranges.append(r)
    return ranges

def fetch_nvd_product(product, cpe_prefix, label, keyword):
    """Toutes les CVE du produit via keywordSearch (le endpoint cpeName est
    bloqué 404 par Cloudflare). Filtre CPE strict fait par extract_ranges() :
    les CVE sans range du produit ne sont conservées que si KEV (elles le
    seront via la fusion KEV en fin de script)."""
    out, start = [], 0
    total = None
    while True:
        url = f"{NVD_BASE}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=2000&startIndex={start}"
        d = None
        for attempt in range(4):
            try:
                d = http_get(url)
                break
            except Exception as e:
                if attempt == 3:
                    print(f"  ⚠ {label}: échec après 4 essais ({e}) — {len(out)} récupérées")
                    return out
                time.sleep(8)
        if d is None:
            return out
        total = d.get("totalResults", 0)
        out.extend(d.get("vulnerabilities", []))
        start += len(d.get("vulnerabilities", []))
        if start >= total:
            break
        time.sleep(7)  # rate limit NVD sans clé
    print(f"  ✓ {label}: {len(out)} CVE (total NVD {total})")
    return out

def main():
    print("=== Génération cve_db.json ===")
    print("[1/2] CISA KEV…")
    kev = http_get(KEV_URL).get("vulnerabilities", [])
    kev_by_id = {v["cveID"]: v for v in kev}
    print(f"  ✓ KEV: {len(kev)} entrées")

    print("[2/2] NVD par produit…")
    cves = []
    seen = set()
    for product, (cpe, label, keyword) in PRODUCTS.items():
        for cve in fetch_nvd_product(product, cpe, label, keyword):
            cve_id = cve["cve"]["id"]
            if cve_id in seen:
                continue
            seen.add(cve_id)
            k = kev_by_id.get(cve_id)
            score, sev = extract_metrics(cve["cve"])
            if sev is None: sev = sev_from_cvss(score)
            desc = ""
            for d in cve["cve"].get("descriptions") or []:
                if d.get("lang") == "en":
                    desc = d["value"][:180]
                    break
            ranges = extract_ranges(cve["cve"], cpe)
            # Filtre strict : keywordSearch ramène du bruit (ex: "httpd" →
            # Apache Tomcat). On ne garde que les CVE avec un vrai range CPE
            # du produit — les KEV produit-level sont ajoutées plus bas.
            if not ranges:
                continue
            cves.append({
                "id": cve_id,
                "product": product,
                "sev": sev,
                "cvss": score,
                "desc": desc,
                "kev": k is not None,
                "ransomware": bool(k and k.get("knownRansomwareCampaignUse")),
                "ranges": ranges,
            })
        time.sleep(7)

    # KEV : CVE produits non couvertes par NVD-range → alerte produit-level,
    # MAIS uniquement pour les produits réellement détectables par banner
    # (sinon poids mort : un product KEV type « microsoft_windows » ne matche
    # jamais nos clés produit).
    kev_extra = []
    for v in kev:
        if v["cveID"] in seen:
            continue
        product_key = (v.get("product") or "").lower().replace(" ", "_")
        if product_key not in PRODUCTS:
            continue
        kev_extra.append({
            "id": v["cveID"],
            "product": product_key,
            "sev": "UNKNOWN",
            "cvss": None,
            "desc": (v.get("shortDescription") or "")[:180],
            "kev": True,
            "ransomware": bool(v.get("knownRansomwareCampaignUse")),
            "ranges": [],
        })
    cves.extend(kev_extra)

    db = {
        "generated": time.strftime("%Y-%m-%d"),
        "sources": ["CISA KEV", "NVD API 2.0"],
        "product_labels": {k: v[1] for k, v in PRODUCTS.items()},
        "count": len(cves),
        "kev_count": sum(1 for c in cves if c["kev"]),
        "cves": cves,
    }
    out = "app/src/main/assets/cve_db.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, separators=(",", ":"))
    import os
    print(f"\n=== OK: {out} ({os.path.getsize(out)/1024:.0f} Ko, {len(cves)} CVE, {db['kev_count']} KEV) ===")

if __name__ == "__main__":
    sys.exit(main())

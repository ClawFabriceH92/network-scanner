#!/usr/bin/env python3
"""
Génère l'asset compact `assets/nmap_signatures.json` pour network-scanner v1.7.0.

Le fichier source est `nmap-service-probes` (https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes),
mais les bannières réellement grabées par l'app (BannerGrab.kt) sont déjà pré-extraites
(« Server: Apache/2.4.41 », « SSH-2.0-OpenSSH_8.2p1 … », « 220 ProFTPD 1.3.5e … »).
On maintient donc un répertoire CURATED de règles (service, produit, regex, version, flags)
qui matchent ces formats. L'option --download tente de télécharger le fichier Nmap et de
convertir ses regex (`\\xNN` → `\\u00NN`) en règles supplémentaires, en plus du curated.

Format JSON produit (compatible NmapSignatures.kt) :
  [{"service":"http","product":"Apache httpd","version":"{1}","regex":"Server:\\s*Apache/([\\d.]+)","flags":"i"}, ...]

  - `regex`   : regex Java/Kotlin (groupes de capture pour la version).
  - `version` : gabarit de version, « {N} » remplacé par le groupe N, ou littéral.
  - `flags`   : « i » (case-insensitive) — toujours « i » ici.

Usage :
  python3 tools/build_nmap_signatures.py [--download] [--out app/src/main/assets/nmap_signatures.json]
"""
import json
import os
import re
import sys
import urllib.request

# ---------------------------------------------------------------------------
# Répertoire curated : (service, produit, version, regex, flags)
# La version est un gabarit (« {1} » = premier groupe de capture).
# Les règles sont ordonnées : les plus spécifiques en premier (ex: les variantes
# de produits précèdent les règles génériques « Server: »).
# ---------------------------------------------------------------------------
CURATED = [
    # --- HTTP Server (bannière = « Server: <value> ») ---
    ("http", "Apache httpd", "{1}", r"Server:\s*Apache/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "nginx", "{1}", r"Server:\s*nginx/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "OpenResty", "{1}", r"Server:\s*openresty/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "Microsoft IIS", "{1}", r"Server:\s*Microsoft-IIS/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "Microsoft HTTPAPI", "{1}", r"Server:\s*Microsoft-HTTPAPI/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "lighttpd", "{1}", r"Server:\s*lighttpd/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "thttpd", "{1}", r"Server:\s*thttpd/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "Caddy", "{1}", r"Server:\s*Caddy(?:/([0-9][0-9a-zA-Z.\-_]*))?", "i"),
    ("http", "LiteSpeed", "{1}", r"Server:\s*LiteSpeed(?:/([0-9][0-9a-zA-Z.\-_]*))?", "i"),
    ("http", "gunicorn", "{1}", r"Server:\s*gunicorn/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "Jetty", "{1}", r"Server:\s*Jetty(?:\(([0-9][0-9a-zA-Z.\-_]*)\))?", "i"),
    ("http", "Apache Tomcat (Coyote)", "{1}", r"Server:\s*Apache-Coyote/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "Werkzeug", "{1}", r"Server:\s*Werkzeug/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "Node.js", "{1}", r"Server:\s*Node\.js(?:/([0-9][0-9a-zA-Z.\-_]*))?", "i"),
    ("http", "Express", "{1}", r"Server:\s*Express(?:/([0-9][0-9a-zA-Z.\-_]*))?", "i"),
    ("http", "Boa", "{1}", r"Server:\s*Boa/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "GoAhead-Webs", "{1}", r"Server:\s*GoAhead-Webs/([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("http", "Synology DSM", "{1}", r"Server:\s*nginx/([0-9][0-9a-zA-Z.\-_]*).*Synology", "i"),
    ("http", "HP HTTP Server", "", r"Server:\s*HP[^\r\n]*HTTP", "i"),
    ("http", "Epson", "", r"Server:\s*EPSON[^\r\n]*", "i"),
    ("http", "Canon", "", r"Server:\s*Canon[^\r\n]*", "i"),

    # --- SSH (bannière = « SSH-2.0-... ») ---
    ("ssh", "OpenSSH", "{1}", r"OpenSSH[_-]([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("ssh", "Dropbear", "{1}", r"dropbear[_-]([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("ssh", "libssh", "{1}", r"libssh[_-]([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("ssh", "Cisco", "", r"SSH-2\.0-Cisco", "i"),
    ("ssh", "MikroTik", "", r"SSH-2\.0-ROS", "i"),

    # --- FTP (bannière texte) ---
    ("ftp", "ProFTPD", "{1}", r"ProFTPD\s+([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("ftp", "vsftpd", "{1}", r"vsFTPd\s+([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("ftp", "Pure-FTPd", "", r"Pure-FTPd", "i"),
    ("ftp", "FileZilla Server", "{1}", r"FileZilla Server[^\r\n]*?([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("ftp", "Microsoft FTP Service", "", r"Microsoft FTP Service", "i"),
    ("ftp", "IIS FTP", "{1}", r"Microsoft[^\r\n]*FTP[^\r\n]*", "i"),
    ("ftp", "wu-ftpd", "{1}", r"wu-ftpd[^\r\n]*?([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("ftp", "Serv-U", "{1}", r"Serv-U FTP Server v([0-9][0-9a-zA-Z.\-_]*)", "i"),

    # --- SMTP ---
    ("smtp", "Postfix", "", r"ESMTP Postfix", "i"),
    ("smtp", "Exim", "{1}", r"Exim\s+([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("smtp", "Sendmail", "{1}", r"Sendmail\s+([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("smtp", "Microsoft ESMTP", "", r"Microsoft ESMTP", "i"),
    ("smtp", "qmail", "", r"qmail", "i"),
    ("smtp", "Haraka", "", r"Haraka", "i"),

    # --- POP3 ---
    ("pop3", "Dovecot", "", r"Dovecot", "i"),
    ("pop3", "Courier", "", r"Courier", "i"),
    ("pop3", "Qpopper", "{1}", r"Qpopper[^\r\n]*?([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("pop3", "Cyrus POP3", "", r"Cyrus POP3", "i"),

    # --- IMAP ---
    ("imap", "Dovecot", "", r"Dovecot", "i"),
    ("imap", "Courier-IMAP", "", r"Courier-IMAP", "i"),
    ("imap", "Cyrus IMAP", "", r"Cyrus IMAP", "i"),
    ("imap", "Microsoft Exchange IMAP", "", r"Microsoft Exchange", "i"),

    # --- Telnet ---
    ("telnet", "Telnet (login)", "", r"(?:login:|Username:|Password:)", "i"),

    # --- RTSP ---
    ("rtsp", "RTSP Server", "", r"RTSP/[0-9]", "i"),
    ("rtsp", "RealServer", "{1}", r"RealServer[^\r\n]*?([0-9][0-9a-zA-Z.\-_]*)", "i"),

    # --- SIP ---
    ("sip", "Asterisk", "", r"Asterisk", "i"),
    ("sip", "SIP/2.0", "", r"SIP/2\.0", "i"),

    # --- Bases de données / services (si bannière texte) ---
    ("mysql", "MySQL", "{1}", r"mysql[^\r\n]*?([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("mysql", "MariaDB", "{1}", r"MariaDB[^\r\n]*?([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("postgresql", "PostgreSQL", "", r"PostgreSQL", "i"),
    ("mongodb", "MongoDB", "", r"MongoDB", "i"),
    ("redis", "Redis", "{1}", r"redis_version:([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("elasticsearch", "Elasticsearch", "{1}", r"Elasticsearch[^\r\n]*?([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("vnc", "RealVNC", "", r"RFB", "i"),
    ("vnc", "TightVNC", "", r"TightVNC", "i"),
    ("smb", "Samba", "{1}", r"Samba[^\r\n]*?([0-9][0-9a-zA-Z.\-_]*)", "i"),
    ("smb", "Microsoft Windows (SMB)", "", r"(?:SMB|NetBIOS|MICROSOFT NETWORKS)", "i"),
]


def curated_rules():
    out = []
    for service, product, version, regex, flags in CURATED:
        out.append({
            "service": service,
            "product": product,
            "version": version,
            "regex": regex,
            "flags": flags,
        })
    return out


def nmap_hex_to_java(s: str) -> str:
    """Convertit les échappements hexadécimaux Nmap (\\x00) en \\u0000 (Java)."""
    def repl(m):
        return "\\u%04x" % int(m.group(1), 16)
    return re.sub(r"\\x([0-9a-fA-F]{2})", repl, s)


def parse_nmap_probes(text: str, limit: int = 400):
    """Parse `nmap-service-probes` et retourne des règles (best effort).

    Format Nmap : `match <service> m|<regex>|s|i <product> <version-info>`.
    On convertit la regex en Java-compatible et on la borne à [limit] règles.
    """
    rules = []
    count = 0
    for line in text.splitlines():
        if count >= limit:
            break
        m = re.match(r"^(?:soft)?match\s+(\S+)\s+m\|(.*)\|(?:s|i)?p?(?:\|.*)?\s+(.+)$", line)
        if not m:
            continue
        service, regex, rest = m.group(1), m.group(2), m.group(3).strip()
        if len(regex) > 256:
            continue
        try:
            regex_java = nmap_hex_to_java(regex)
            # Validation légère : le regex doit pouvoir être compilé par Python
            re.compile(regex_java)
        except re.error:
            continue
        # extrait produit + version grossièrement (avant le premier « | » ou fin)
        parts = rest.split("|", 1)[0].strip()
        rules.append({
            "service": service,
            "product": parts or service,
            "version": "{1}",
            "regex": regex_java,
            "flags": "i",
        })
        count += 1
    return rules


def download_nmap():
    url = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes"
    req = urllib.request.Request(url, headers={"User-Agent": "network-scanner-build/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main():
    out_path = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else "app/src/main/assets/nmap_signatures.json"
    rules = curated_rules()
    if "--download" in sys.argv:
        try:
            extra = parse_nmap_probes(download_nmap())
            # déduplique par (service, regex) : le curated prime
            seen = {(r["service"], r["regex"]) for r in rules}
            for r in extra:
                if (r["service"], r["regex"]) not in seen:
                    seen.add((r["service"], r["regex"]))
                    rules.append(r)
            print(f"download ok: +{len(extra)} règles Nmap")
        except Exception as e:  # noqa: BLE001
            print(f"download KO ({e}) — curated only")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False)
    print(f"écrit {len(rules)} règles → {out_path}")


if __name__ == "__main__":
    main()

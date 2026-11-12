#!/usr/bin/env python3
"""
zunabo-advisor — Pont « constat → orientation » (Zunabo).

Lit un rapport de scan Zunabo (rapport.json) et, pour chaque constat VALIDÉ,
indique le **module Metasploit / la technique de référence** qu'un opérateur
consulterait pour la phase suivante — ET la remédiation correspondante.

⚠️  C'est un INDEX DE RÉFÉRENCE consultable (équivalent de `msfconsole
search cve:…`), PAS un outil d'exploitation :
  • il ne génère aucun payload, ne configure aucun script (IP/port),
  • il n'exécute rien, ne lance aucun module,
  • l'exploitation reste MANUELLE, décidée par l'opérateur, sous RoE signé.

Objectif : faire gagner du temps d'orientation après l'analyse, et produire un
livrable branché Zunabo reliant chaque faiblesse à sa piste de validation
manuelle et à sa correction.

Réutilise les modules partagés (brand/auth/report/log). stdlib + python-docx (option).
"""

import argparse
import html as _html
import json
import os
import re
import sys
from datetime import datetime

VERSION = "1.0"

try:
    import zunabo_brand as brand
    _HAS_BRAND = True
except Exception:
    brand = None; _HAS_BRAND = False
try:
    import zunabo_auth as auth
    _HAS_AUTH = True
except Exception:
    auth = None; _HAS_AUTH = False
try:
    import zunabo_log as zlog
    _HAS_LOG = True
except Exception:
    zlog = None; _HAS_LOG = False

_LOG = None
_MSF = "https://docs.metasploit.com/"

# ─────────────────────────────────────────────────────────────────────────────
#  Base de connaissances (publique, de référence) — CVE → module connu
#  Chaque entrée : CVE -> (référence module OU None, intitulé, remédiation)
# ─────────────────────────────────────────────────────────────────────────────
CVE_KB = {
    "CVE-2017-0144": ("exploit/windows/smb/ms17_010_eternalblue",
                      "SMBv1 RCE (EternalBlue / MS17-010)",
                      "Désactiver SMBv1, appliquer MS17-010, segmenter."),
    "CVE-2017-0143": ("auxiliary/scanner/smb/smb_ms17_010",
                      "Détection MS17-010", "Appliquer MS17-010, désactiver SMBv1."),
    "CVE-2019-0708": ("auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
                      "BlueKeep RDP (détection)", "Patch RDP, activer NLA, restreindre l'accès."),
    "CVE-2014-6271": ("exploit/multi/http/apache_mod_cgi_bash_env_exec",
                      "Shellshock (CGI/bash)", "Mettre bash à jour, désactiver les CGI inutiles."),
    "CVE-2021-44228": ("exploit/multi/http/log4shell_header_injection",
                       "Log4Shell (JNDI/Log4j)", "Mettre Log4j à jour (≥2.17), bloquer JNDI sortant."),
    "CVE-2017-5638": ("exploit/multi/http/struts2_content_type_ognl",
                      "Apache Struts2 OGNL RCE", "Mettre Struts à jour."),
    "CVE-2018-7600": ("exploit/unix/webapp/drupal_drupalgeddon2",
                      "Drupalgeddon2 (Drupal RCE)", "Mettre Drupal à jour."),
    "CVE-2014-3704": ("exploit/multi/http/drupal_drupageddon",
                      "Drupalgeddon (SQLi)", "Mettre Drupal à jour."),
    "CVE-2012-1823": ("exploit/multi/http/php_cgi_arg_injection",
                      "PHP-CGI argument injection", "Mettre PHP à jour, éviter PHP en CGI."),
    "CVE-2021-26855": ("exploit/windows/http/exchange_proxylogon_rce",
                       "Exchange ProxyLogon", "Appliquer les correctifs Exchange."),
    "CVE-2019-19781": ("exploit/linux/http/citrix_dir_traversal_rce",
                       "Citrix ADC/Gateway RCE", "Appliquer les mitigations/patch Citrix."),
    "CVE-2023-44487": (None, "HTTP/2 « Rapid Reset » (déni de service)",
                       "Mettre à jour le serveur/proxy ; limiter les flux HTTP/2. Pas de RCE."),
    "CVE-2025-23419": (None, "nginx — reprise de session TLS / client-cert",
                       "Revue de la config client-cert + SNI ; mettre nginx à jour. Pas de module public."),
}

# Service/produit (mot-clé) → modules auxiliaires d'énumération / test d'identifiants
SERVICE_KB = {
    "ssh": [("auxiliary/scanner/ssh/ssh_version", "Bannière/version SSH"),
            ("auxiliary/scanner/ssh/ssh_login", "Test d'identifiants SSH (dictionnaire)")],
    "ftp": [("auxiliary/scanner/ftp/anonymous", "Accès FTP anonyme"),
            ("auxiliary/scanner/ftp/ftp_login", "Test d'identifiants FTP")],
    "smb": [("auxiliary/scanner/smb/smb_version", "Version SMB / OS"),
            ("auxiliary/scanner/smb/smb_ms17_010", "Détection MS17-010")],
    "microsoft-ds": [("auxiliary/scanner/smb/smb_version", "Version SMB / OS")],
    "smtp": [("auxiliary/scanner/smtp/smtp_version", "Bannière SMTP"),
             ("auxiliary/scanner/smtp/smtp_enum", "Énumération d'utilisateurs (VRFY/EXPN)")],
    "mysql": [("auxiliary/scanner/mysql/mysql_version", "Version MySQL"),
              ("auxiliary/scanner/mysql/mysql_login", "Test d'identifiants MySQL")],
    "postgresql": [("auxiliary/scanner/postgres/postgres_login", "Test d'identifiants PostgreSQL")],
    "ms-sql-s": [("auxiliary/scanner/mssql/mssql_login", "Test d'identifiants MS-SQL")],
    "rdp": [("auxiliary/scanner/rdp/rdp_scanner", "Détection RDP"),
            ("auxiliary/scanner/rdp/cve_2019_0708_bluekeep", "BlueKeep")],
    "ms-wbt-server": [("auxiliary/scanner/rdp/rdp_scanner", "Détection RDP")],
    "vnc": [("auxiliary/scanner/vnc/vnc_none_auth", "VNC sans authentification")],
    "telnet": [("auxiliary/scanner/telnet/telnet_version", "Bannière Telnet"),
               ("auxiliary/scanner/telnet/telnet_login", "Test d'identifiants Telnet")],
    "snmp": [("auxiliary/scanner/snmp/snmp_login", "Communautés SNMP par défaut")],
    "redis": [("auxiliary/scanner/redis/redis_server", "Redis non authentifié")],
    "mongodb": [("auxiliary/scanner/mongodb/mongodb_login", "MongoDB sans auth / identifiants")],
    "http": [("auxiliary/scanner/http/dir_scanner", "Découverte de répertoires"),
             ("— nuclei —", "Détection applicative déjà couverte par zunabo-scan")],
    "https": [("auxiliary/scanner/http/dir_scanner", "Découverte de répertoires (HTTPS)")],
    "sip": [("auxiliary/scanner/sip/options", "Énumération SIP (OPTIONS)")],
}

# Constats de config (par mot-clé dans le nom/tags) → technique de référence manuelle
CONFIG_KB = [
    (("dépôt git", "git exposé", ".git"), "git-dumper (récupération) puis revue du code/secrets",
     "Bloquer l'accès à .git ; retirer le dossier du webroot."),
    ((".env", "environnement"), "Lecture manuelle du fichier exposé (secrets)",
     "Retirer .env du webroot ; révoquer tout secret exposé."),
    (("ouvert", "open"), "Capture/observation du trafic sur réseau non chiffré",
     "Activer WPA2/WPA3 ou le chiffrement applicatif."),
    (("wep",), "aircrack-ng (récupération de clé WEP)",
     "Migrer vers WPA2-AES/WPA3 immédiatement."),
    (("wps",), "reaver / bully (PIN WPS — Pixie-Dust)", "Désactiver le WPS."),
    (("mot de passe par défaut", "default password", "identifiant"),
     "Test manuel des identifiants par défaut (doc constructeur)",
     "Changer tous les identifiants par défaut ; politique de mots de passe forts."),
    (("sqli", "injection sql"), "sqlmap (validation/extraction) — manuel, sous RoE",
     "Requêtes paramétrées ; WAF en complément."),
    (("xss",), "Validation manuelle en navigateur (contexte d'injection)",
     "Encodage de sortie contextuel + CSP."),
]


def _slug(s):
    return re.sub(r"[^\w.-]", "_", s or "advisor")


# ─────────────────────────────────────────────────────────────────────────────
#  Affichage
# ─────────────────────────────────────────────────────────────────────────────
_C = {"g": "\033[38;5;108m", "am": "\033[38;5;179m", "rd": "\033[38;5;174m", "b": "\033[1m", "x": "\033[0m"}


def _c(t, k):
    return f"{_C.get(k,'')}{t}{_C['x']}"


def section(t):
    print(f"\n{_c('▸ ' + t, 'g')}")


def info(t):
    print(f"  {t}")


def ok(t):
    print(f"  {_c('✓','g')} {t}")


def warn(t):
    print(f"  {_c('!','am')} {t}")


def err(t):
    print(f"  {_c('✗','rd')} {t}")


# ─────────────────────────────────────────────────────────────────────────────
#  Moteur : constats → suggestions d'orientation
# ─────────────────────────────────────────────────────────────────────────────
def advise(data):
    """Renvoie (suggestions, stats). Une suggestion = dict d'orientation (jamais exécutable)."""
    findings = data.get("vulnerabilites", []) or []
    services = (data.get("surface", {}) or {}).get("services", []) or []
    suggestions, seen = [], set()

    def add(target, weakness, ref, note, remediation, source, confidence="potentiel", kind="module"):
        key = (target, ref, weakness)
        if key in seen:
            return
        seen.add(key)
        suggestions.append({
            "target": target, "weakness": weakness, "reference": ref,
            "note": note, "remediation": remediation, "source": source,
            "confidence": confidence, "kind": kind,
        })

    # 1) Par CVE présente dans les constats
    for f in findings:
        for cve in (f.get("cve") or []):
            cve = cve.upper().strip()
            if cve in CVE_KB:
                ref, label, rem = CVE_KB[cve]
                add(f.get("target", "—"), f"{cve} — {label}",
                    ref or "— pas de module public —", f"{label}", rem,
                    source=f.get("source", "scan"),
                    confidence=f.get("confidence", "potentiel"),
                    kind="module" if ref else "info")

    # 2) Par constat de configuration (mots-clés)
    for f in findings:
        hay = (f.get("name", "") + " " + " ".join(f.get("tags", []))).lower()
        for keys, technique, rem in CONFIG_KB:
            if any(k in hay for k in keys):
                add(f.get("target", "—"), f.get("name", "Constat de configuration"),
                    technique, "Technique de référence (manuelle)", rem,
                    source=f.get("source", "scan"),
                    confidence=f.get("confidence", "potentiel"), kind="technique")
                break

    # 3) Par service/produit découvert
    for s in services:
        svc = (s.get("service") or "").lower()
        tgt = f"{s.get('ip') or s.get('host')}:{s.get('port')}"
        prod = (s.get("product", "") + " " + s.get("version", "")).strip()
        for key, mods in SERVICE_KB.items():
            if key and (key == svc or key in svc):
                for ref, label in mods:
                    add(tgt, f"Service {svc or key}" + (f" ({prod})" if prod else ""),
                        ref, label, "Durcir/mettre à jour le service ; limiter l'exposition.",
                        source="service", confidence="potentiel",
                        kind="module" if ref.startswith("auxiliary") or ref.startswith("exploit") else "info")
                break

    stats = {
        "total": len(suggestions),
        "modules": sum(1 for s in suggestions if s["kind"] == "module"),
        "techniques": sum(1 for s in suggestions if s["kind"] == "technique"),
        "info": sum(1 for s in suggestions if s["kind"] == "info"),
    }
    return suggestions, stats


# ─────────────────────────────────────────────────────────────────────────────
#  Rapports (JSON / Markdown / HTML branché)
# ─────────────────────────────────────────────────────────────────────────────
_BANNER = ("⚠ Orientation uniquement — index de référence (type « msfconsole search »). "
           "Aucun payload n'est généré, rien n'est exécuté. L'exploitation est MANUELLE, "
           "décidée par l'opérateur, strictement dans le périmètre autorisé (RoE signé).")


def build_json(suggestions, stats, meta, outdir):
    data = {
        "tool": "zunabo-advisor", "version": VERSION, "kind": "advisory",
        "avertissement": _BANNER,
        "engagement": meta,
        "stats": stats,
        "orientations": suggestions,
    }
    path = os.path.join(outdir, "orientation.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


def build_markdown(suggestions, stats, meta, outdir):
    L = [f"# Plan d'intervention — orientation opérateur", "",
         f"> {_BANNER}", "",
         f"- **Source** : {meta.get('source_report','—')}",
         f"- **Cible** : {meta.get('target','—')}",
         f"- **Client** : {meta.get('client') or '—'}",
         f"- **Opérateur** : {meta.get('operator') or 'D4N'}",
         f"- **Date** : {meta.get('date')}", "",
         f"**Orientations** : {stats['total']} "
         f"({stats['modules']} module(s) de référence · {stats['techniques']} technique(s) · {stats['info']} info)",
         "",
         "| Actif | Faiblesse | Référence | Ce que ça vérifie | Remédiation |",
         "|---|---|---|---|---|"]
    for s in suggestions:
        L.append(f"| {s['target']} | {s['weakness']} | `{s['reference']}` | {s['note']} | {s['remediation']} |")
    L += ["", "— L'exploitation éventuelle relève d'une phase manuelle et délibérée, sous RoE."]
    path = os.path.join(outdir, "orientation.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return path


def build_html(suggestions, stats, meta, outdir):
    path = os.path.join(outdir, "orientation.html")

    def esc(x):
        return _html.escape(str(x))

    rows = ""
    for s in suggestions:
        kcls = {"module": "k-mod", "technique": "k-tech", "info": "k-info"}.get(s["kind"], "")
        rows += (f"<tr class='{kcls}'><td>{esc(s['target'])}</td>"
                 f"<td>{esc(s['weakness'])}</td>"
                 f"<td><code>{esc(s['reference'])}</code></td>"
                 f"<td>{esc(s['note'])}</td>"
                 f"<td>{esc(s['remediation'])}</td></tr>")
    if not suggestions:
        rows = "<tr><td colspan=5 class='z-empty'>Aucune orientation pour ces constats.</td></tr>"
    cards = (f"<div class='z-cards'>"
             f"<div class='z-card high'><div class='num'>{stats['modules']}</div><div class='lbl'>MODULES RÉF.</div></div>"
             f"<div class='z-card medium'><div class='num'>{stats['techniques']}</div><div class='lbl'>TECHNIQUES</div></div>"
             f"<div class='z-card info'><div class='num'>{stats['info']}</div><div class='lbl'>INFO</div></div>"
             f"</div>")
    style = """<style>
      .adv-banner{background:#fff6e5;border:1px solid #e8c37a;border-left:5px solid #c19a3e;
        border-radius:10px;padding:.8rem 1rem;margin:1rem 0;color:#6b5418;font-size:.95em}
      .adv-tbl{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.93em}
      .adv-tbl th{background:#405B39;color:#fff;text-align:left;padding:.5rem .6rem}
      .adv-tbl td{border:1px solid #e0dcc9;padding:.45rem .6rem;vertical-align:top}
      .adv-tbl code{background:#f6f4ec;border:1px solid #e0dcc9;border-radius:4px;padding:.03rem .3rem;font-size:.92em}
      .adv-tbl tr.k-mod td:first-child{border-left:3px solid #b4832a}
      .adv-tbl tr.k-tech td:first-child{border-left:3px solid #5f8257}
    </style>"""
    inner = f"""
  {style}
  <h1>Plan d'intervention — orientation opérateur</h1>
  <div class="adv-banner">{esc(_BANNER)}</div>
  <div class="z-meta">
    <div><b>Source :</b> {esc(meta.get('source_report','—'))}</div>
    <div><b>Cible :</b> {esc(meta.get('target','—'))}</div>
    <div><b>Client :</b> {esc(meta.get('client') or '—')}</div>
    <div><b>Date :</b> {esc(meta.get('date'))}</div>
    <div><b>Opérateur :</b> {esc(meta.get('operator') or 'D4N')}</div>
    <div><b>Orientations :</b> {stats['total']}</div>
  </div>
  {cards}
  <h2>Orientations <span class="z-accent">({stats['total']})</span></h2>
  <table class="adv-tbl"><thead><tr><th>Actif</th><th>Faiblesse</th>
  <th>Référence (module / technique)</th><th>Ce que ça vérifie</th><th>Remédiation</th></tr></thead>
  <tbody>{rows}</tbody></table>
  <p style="color:#6c775f;font-size:.9em;margin-top:1rem">L'exploitation éventuelle relève
  d'une phase manuelle et délibérée, menée par l'opérateur dans le périmètre autorisé.</p>"""
    footer = f"zunabo-advisor v{VERSION} · orientation de référence · exploitation manuelle sous RoE"
    if _HAS_BRAND:
        doc = brand.document("Plan d'intervention", inner, footer_note=footer)
    else:
        doc = (f"<!DOCTYPE html><html lang='fr'><head><meta charset='utf-8'>"
               f"<title>zunabo-advisor</title></head><body><div style='max-width:1000px;"
               f"margin:auto;padding:24px'>{inner}</div></body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path


def write_manifest(outdir, meta, stats):
    L = ["ZUNABO — Plan d'intervention (orientation opérateur)", "=" * 50, "",
         _BANNER, "",
         f"Source    : {meta.get('source_report','—')}",
         f"Cible     : {meta.get('target','—')}",
         f"Client    : {meta.get('client') or '—'}",
         f"Opérateur : {meta.get('operator') or 'D4N'}",
         f"Date      : {meta.get('date')}",
         f"Outil     : zunabo-advisor v{VERSION}", "",
         f"Orientations : {stats['total']} "
         f"({stats['modules']} modules réf. · {stats['techniques']} techniques · {stats['info']} info)", "",
         "Fichiers : orientation.html · orientation.json · orientation.md",
         "",
         "Index de référence uniquement. Aucune exploitation automatisée. Toute action",
         "offensive est manuelle, décidée par l'opérateur, dans le périmètre autorisé (RoE)."]
    path = os.path.join(outdir, "LISEZ-MOI.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return path


# ─────────────────────────────────────────────────────────────────────────────
#  Orchestration
# ─────────────────────────────────────────────────────────────────────────────
def _find_latest_report(base):
    cands = []
    for root, _, files in os.walk(base):
        if "rapport.json" in files:
            p = os.path.join(root, "rapport.json")
            cands.append((os.path.getmtime(p), p))
    cands.sort(reverse=True)
    return cands[0][1] if cands else None


def main():
    p = argparse.ArgumentParser(
        prog="zunabo-advisor",
        description="Pont constat→orientation : index de référence (pas d'exploitation).")
    p.add_argument("report", nargs="?",
                   help="Chemin d'un rapport.json de scan (défaut : le plus récent sous --scans-dir)")
    p.add_argument("--scans-dir", default=".", help="Dossier où chercher le rapport le plus récent")
    p.add_argument("-o", "--out", default="./advisories", help="Dossier de sortie racine")
    p.add_argument("--client", default=None)
    p.add_argument("--operator", default="D4N")
    p.add_argument("--no-lock", action="store_true")
    args = p.parse_args()

    if _HAS_AUTH and not args.no_lock:
        try:
            if not auth.require_unlock(app="Zunabo advisor", interactive=True):
                err("Déverrouillage refusé."); sys.exit(2)
        except SystemExit:
            raise
        except Exception as e:
            err(f"Verrou indisponible : {e}"); sys.exit(2)
    elif not _HAS_AUTH:
        warn("Module de verrou absent — exécution sans verrou.")

    report = args.report or _find_latest_report(args.scans_dir)
    if not report or not os.path.exists(report):
        err("Aucun rapport.json trouvé (fournir un chemin ou --scans-dir).")
        sys.exit(1)

    section(f"Lecture du rapport — {report}")
    try:
        data = json.load(open(report, encoding="utf-8"))
    except Exception as e:
        err(f"Rapport illisible : {e}"); sys.exit(1)

    eng = data.get("engagement", {}) or {}
    now = datetime.now()
    meta = {
        "source_report": os.path.basename(os.path.dirname(report)) or report,
        "target": eng.get("target", ""),
        "client": args.client or eng.get("client"),
        "operator": args.operator or eng.get("operator") or "D4N",
        "date": now.strftime("%Y-%m-%d %H:%M"),
    }

    suggestions, stats = advise(data)

    outdir = os.path.join(args.out, f"{_slug(meta['target'] or 'cible')}_{now.strftime('%Y-%m-%d_%Hh%M')}")
    os.makedirs(outdir, exist_ok=True)
    build_json(suggestions, stats, meta, outdir)
    build_markdown(suggestions, stats, meta, outdir)
    build_html(suggestions, stats, meta, outdir)
    write_manifest(outdir, meta, stats)

    print()
    ok(f"Orientation générée — {stats['total']} entrée(s)")
    print(f"  {stats['modules']} module(s) de référence · {stats['techniques']} technique(s) · {stats['info']} info")
    info(_BANNER)
    info(f"Dossier : {outdir}")


if __name__ == "__main__":
    main()

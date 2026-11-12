#!/usr/bin/env python3
"""
zunabo-scan v2 — Orchestrateur d'audit de vulnérabilités
Marque : Zunabo  |  Auteur : Dan Ibiliabo (D4N)

Pipeline moderne (style ProjectDiscovery) avec repli nmap :

    [domaine]  subfinder → dnsx ─┐
                                 ├→ naabu ──→ httpx ──→ nuclei ──→ rapport
    [IP / CIDR] ─────────────────┘   (ports)  (web/tech) (vulns)

Repli automatique : naabu→nmap, httpx→nmap -sV si les binaires PD manquent.

Sorties : rapport.html · rapport.json · rapport.md · nuclei.sarif
          + sorties brutes de chaque moteur.

⚠️  Outil professionnel. Périmètre d'audit sous la responsabilité de l'opérateur.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# Charte graphique partagée Zunabo (source unique du thème).
try:
    import zunabo_brand as brand
    _HAS_BRAND = True
except ImportError:
    _HAS_BRAND = False

# Verrou d'accès partagé Zunabo (requis pour démarrer — fail closed).
try:
    import zunabo_auth as auth
    _HAS_AUTH = True
except ImportError:
    _HAS_AUTH = False

# Générateur de rapport .docx (livrable client — optionnel).
try:
    import zunabo_report as zreport
    _HAS_REPORT = True
except ImportError:
    _HAS_REPORT = False

# Analyse de surface / détection de takeover (optionnel).
try:
    import zunabo_surface as surface
    _HAS_SURFACE = True
except ImportError:
    _HAS_SURFACE = False

# Journal complet (optionnel).
try:
    import zunabo_log as zlog
    _HAS_LOG = True
except ImportError:
    _HAS_LOG = False

VERSION = "2.0"

# ─────────────────────────────────────────────────────────────────────────────
#  Sortie terminal
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
    RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, GREY = (
        "\033[31m", "\033[32m", "\033[33m", "\033[34m",
        "\033[35m", "\033[36m", "\033[90m",
    )


def _c(txt, color):
    return txt if not sys.stdout.isatty() else f"{color}{txt}{C.RESET}"


# Journal (défini au démarrage dans main) — toutes les sorties y sont copiées.
_LOG = None


def section(t):
    print(f"\n{_c('══ ' + t, C.BOLD + C.CYAN)}")
    if _LOG: _LOG.line(t, level="stage", stage="section")
def info(m):
    print(f"{_c('[*]', C.BLUE)} {m}")
    if _LOG: _LOG.line(m, level="info")
def ok(m):
    print(f"{_c('[+]', C.GREEN)} {m}")
    if _LOG: _LOG.line(m, level="ok")
def warn(m):
    print(f"{_c('[!]', C.YELLOW)} {m}")
    if _LOG: _LOG.line(m, level="warn")
def err(m):
    print(f"{_c('[x]', C.RED)} {m}", file=sys.stderr)
    if _LOG: _LOG.line(m, level="error")


# ─────────────────────────────────────────────────────────────────────────────
#  Sévérité
# ─────────────────────────────────────────────────────────────────────────────
SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
SEV_COLOR = {
    "critical": C.MAGENTA, "high": C.RED, "medium": C.YELLOW,
    "low": C.BLUE, "info": C.GREY, "unknown": C.GREY,
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def sev_norm(s):
    s = (s or "unknown").strip().lower()
    return s if s in SEV_RANK else "unknown"


# ─────────────────────────────────────────────────────────────────────────────
#  Boîte à outils : détecte ce qui est installé, choisit le meilleur moteur
# ─────────────────────────────────────────────────────────────────────────────
class ToolBox:
    KNOWN = ["subfinder", "dnsx", "naabu", "httpx", "nuclei", "nmap"]

    def __init__(self):
        self.available = {t: shutil.which(t) is not None for t in self.KNOWN}

    def has(self, t):
        return self.available.get(t, False)

    def report(self):
        section("Détection des moteurs")
        for t in self.KNOWN:
            mark = _c("✓", C.GREEN) if self.has(t) else _c("✗", C.RED)
            print(f"    {mark} {t}")
        if not self.has("nuclei"):
            warn("nuclei absent : la détection de vulnérabilités sera désactivée.")
        if not self.has("naabu") and not self.has("nmap"):
            err("Ni naabu ni nmap : impossible de découvrir des ports. Arrêt.")
            sys.exit(2)


def run(cmd, timeout=3600, capture=True, stage="-"):
    info(f"{_c('$ ' + ' '.join(cmd), C.DIM)}")
    try:
        p = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
        if _LOG: _LOG.cmd(stage, cmd, p.returncode, p.stderr or "")
        return p.returncode, (p.stdout or ""), (p.stderr or "")
    except subprocess.TimeoutExpired:
        warn(f"Timeout ({timeout}s) : {cmd[0]}")
        if _LOG: _LOG.cmd(stage, cmd, 124, "timeout")
        return 124, "", "timeout"
    except FileNotFoundError:
        err(f"Binaire introuvable : {cmd[0]}")
        if _LOG: _LOG.cmd(stage, cmd, 127, "not found")
        return 127, "", "not found"


# ─────────────────────────────────────────────────────────────────────────────
#  Classification de la cible
# ─────────────────────────────────────────────────────────────────────────────
def classify_target(target):
    """Renvoie 'ip', 'cidr' ou 'domain'."""
    try:
        ipaddress.ip_network(target, strict=False)
        return "cidr" if "/" in target else "ip"
    except ValueError:
        return "domain"


# ─────────────────────────────────────────────────────────────────────────────
#  Étape 1 — Énumération sous-domaines (domaines uniquement, optionnel)
# ─────────────────────────────────────────────────────────────────────────────
def enum_subdomains(domain, tb, outdir):
    section("Étape 1 — Énumération de sous-domaines")
    hosts = {domain}
    if not tb.has("subfinder"):
        warn("subfinder absent : on garde le domaine seul.")
        return sorted(hosts)
    _, out, _ = run(["subfinder", "-d", domain, "-silent"], timeout=600)
    for line in out.splitlines():
        line = line.strip()
        if line:
            hosts.add(line)
    # Résolution DNS (dnsx) pour ne garder que le vivant
    if tb.has("dnsx") and len(hosts) > 1:
        infile = os.path.join(outdir, "subdomains_raw.txt")
        with open(infile, "w") as f:
            f.write("\n".join(sorted(hosts)) + "\n")
        _, out2, _ = run(["dnsx", "-l", infile, "-silent"], timeout=600)
        resolved = {l.strip() for l in out2.splitlines() if l.strip()}
        if resolved:
            hosts = resolved | {domain}
    ok(f"{len(hosts)} hôte(s) retenu(s).")
    return sorted(hosts)


# ─────────────────────────────────────────────────────────────────────────────
#  Étape 2 — Découverte de ports
# ─────────────────────────────────────────────────────────────────────────────
def discover_ports(targets, tb, outdir, full_ports, rate, ports="", proxy=""):
    section("Étape 2 — Découverte de ports")
    tgt_file = os.path.join(outdir, "hosts.txt")
    with open(tgt_file, "w") as f:
        f.write("\n".join(targets) + "\n")

    if tb.has("naabu"):
        out_path = os.path.join(outdir, "ports.json")
        cmd = ["naabu", "-list", tgt_file, "-json", "-o", out_path, "-silent"]
        if ports:
            cmd += ["-p", ports]
        else:
            cmd += ["-p", "-"] if full_ports else ["-top-ports", "1000"]
        if proxy:
            cmd += ["-proxy", proxy]
        if rate:
            cmd += ["-rate", str(rate)]
        run(cmd, timeout=3600, stage="ports")
        return _parse_naabu(out_path)

    warn("naabu absent : repli sur nmap.")
    services = []
    for t in targets:
        xmlp = os.path.join(outdir, f"nmap_{_slug(t)}.xml")
        cmd = ["nmap", "-sV", "-oX", xmlp, "-Pn"]
        if ports:
            cmd += ["-p", ports]
        else:
            cmd += ["-p-"] if full_ports else ["--top-ports", "1000"]
        cmd.append(t)
        run(cmd, timeout=3600, stage="ports")
        services += _parse_nmap_xml(xmlp)
    return services


def _parse_naabu(path):
    services = []
    if not os.path.exists(path):
        return services
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        services.append({
            "ip": d.get("ip", d.get("host", "")),
            "host": d.get("host", d.get("ip", "")),
            "port": str(d.get("port", "")),
            "proto": d.get("protocol", "tcp"),
            "service": "", "product": "", "version": "",
        })
    return services


def _parse_nmap_xml(path):
    import xml.etree.ElementTree as ET
    services = []
    if not os.path.exists(path):
        return services
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return services
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "?"
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port.find("service")
            services.append({
                "ip": ip, "host": ip,
                "port": port.get("portid"), "proto": port.get("protocol"),
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
    return services


def enrich_versions(services, tb, outdir, proxy=""):
    """
    Détection de version ciblée : naabu ne donne que les ports ouverts (versions vides).
    On lance `nmap -sV` UNIQUEMENT sur les ports déjà découverts (rapide) et on
    réinjecte service/produit/version dans la liste des services.
    """
    if not services or not tb.has("nmap"):
        return services
    section("Étape 2bis — Détection de version (nmap -sV ciblé)")
    # ports ouverts groupés par hôte
    by_host = {}
    for s in services:
        ip = s.get("ip") or s.get("host")
        if ip and s.get("port"):
            by_host.setdefault(ip, set()).add(str(s["port"]))

    versioned = {}  # (ip, port) -> {service, product, version}
    for ip, ports in by_host.items():
        plist = ",".join(sorted(ports, key=lambda x: int(x) if x.isdigit() else 0))
        xmlp = os.path.join(outdir, f"sv_{_slug(ip)}.xml")
        cmd = ["nmap", "-sV", "--version-light", "-Pn", "-p", plist, "-oX", xmlp, ip]
        run(cmd, timeout=900, stage="version")
        for svc in _parse_nmap_xml(xmlp):
            versioned[(svc["ip"], str(svc["port"]))] = svc

    filled = 0
    for s in services:
        key = (s.get("ip") or s.get("host"), str(s.get("port")))
        v = versioned.get(key)
        if v:
            if v.get("service") and not s.get("service"):
                s["service"] = v["service"]
            if v.get("product"):
                s["product"] = v["product"]
            if v.get("version"):
                s["version"] = v["version"]
            if s.get("product") or s.get("version"):
                filled += 1
    ok(f"{filled}/{len(services)} service(s) enrichis d'une version.")
    return services


def _slug(s):
    return re.sub(r"[^\w.-]", "_", s)


# ─────────────────────────────────────────────────────────────────────────────
#  Étape 3 — Sonde HTTP + fingerprint tech (httpx)
# ─────────────────────────────────────────────────────────────────────────────
def probe_http(services, tb, outdir, headers=None, proxy=""):
    section("Étape 3 — Sonde web & fingerprint technologique")
    endpoints = sorted({f"{s['ip'] or s['host']}:{s['port']}" for s in services if s.get("port")})
    if not endpoints:
        warn("Aucun endpoint à sonder.")
        return [], []

    if not tb.has("httpx"):
        warn("httpx absent : construction naïve des URLs web.")
        web = _naive_web_targets(services)
        return web, []

    infile = os.path.join(outdir, "endpoints.txt")
    with open(infile, "w") as f:
        f.write("\n".join(endpoints) + "\n")
    out_path = os.path.join(outdir, "httpx.json")
    cmd = [
        "httpx", "-list", infile, "-json", "-o", out_path, "-silent",
        "-title", "-status-code", "-tech-detect", "-web-server",
        "-follow-redirects",
    ]
    for h in (headers or []):
        cmd += ["-H", h]
    if proxy:
        cmd += ["-http-proxy", proxy]
    run(cmd, timeout=1800, stage="httpx")
    web_meta = _parse_httpx(out_path)
    urls = [w["url"] for w in web_meta]
    ok(f"{len(urls)} service(s) web vivant(s).")
    return urls, web_meta


def _parse_httpx(path):
    meta = []
    if not os.path.exists(path):
        return meta
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta.append({
            "url": d.get("url", ""),
            "status": d.get("status_code") or d.get("status-code") or "",
            "title": d.get("title", ""),
            "webserver": d.get("webserver", d.get("web_server", "")),
            "tech": d.get("tech", d.get("technologies", [])) or [],
        })
    return meta


def _naive_web_targets(services):
    urls = set()
    https_ports = {"443", "8443", "9443"}
    for s in services:
        p = s.get("port", "")
        host = s.get("ip") or s.get("host")
        name = (s.get("service") or "").lower()
        is_web = p in ("80", "443", "8080", "8443", "8000") or "http" in name
        if is_web:
            scheme = "https" if (p in https_ports or "ssl" in name or "https" in name) else "http"
            urls.add(f"{scheme}://{host}:{p}")
    return sorted(urls)


# ─────────────────────────────────────────────────────────────────────────────
#  Étape 4 — nuclei (mode automatique basé sur la tech détectée)
# ─────────────────────────────────────────────────────────────────────────────
def run_nuclei(web_urls, all_targets, tb, outdir, severity, exclude_sev,
               rate, auto, extra_tags, headers=None, proxy="", templates=""):
    section("Étape 4 — Détection de vulnérabilités (nuclei)")
    if not tb.has("nuclei"):
        warn("nuclei absent : étape sautée.")
        return []

    targets = sorted(set(web_urls) | set(all_targets))
    if not targets:
        warn("Aucune cible pour nuclei.")
        return []

    tgt_file = os.path.join(outdir, "nuclei_targets.txt")
    with open(tgt_file, "w") as f:
        f.write("\n".join(targets) + "\n")
    info(f"{len(targets)} cible(s) transmise(s) à nuclei.")

    jsonl = os.path.join(outdir, "nuclei.jsonl")
    sarif = os.path.join(outdir, "nuclei.sarif")
    md_dir = os.path.join(outdir, "nuclei_markdown")
    cmd = [
        "nuclei", "-list", tgt_file,
        "-jsonl", "-o", jsonl,
        "-sarif-export", sarif,
        "-markdown-export", md_dir,
        "-severity", severity,
        "-stats", "-silent", "-no-color",
    ]
    if exclude_sev:
        cmd += ["-exclude-severity", exclude_sev]
    if rate:
        cmd += ["-rate-limit", str(rate)]
    if auto:
        # -as : sélection automatique des templates selon la tech (Wappalyzer)
        cmd.append("-as")
    if extra_tags:
        cmd += ["-tags", extra_tags]
    if templates:
        cmd += ["-t", templates]
    for h in (headers or []):
        cmd += ["-H", h]
    if proxy:
        cmd += ["-proxy", proxy]
    run(cmd, timeout=5400, capture=False, stage="nuclei")
    findings = _parse_nuclei(jsonl)
    ok(f"{len(findings)} résultat(s) nuclei.")
    return findings


def _parse_nuclei(path):
    findings = []
    if not os.path.exists(path):
        return findings
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info_d = d.get("info", {}) or {}
        cls = info_d.get("classification", {}) or {}
        # Preuve non destructive capturée par nuclei (validation, pas exploitation)
        extracted = d.get("extracted-results", []) or []
        resp = d.get("response", "") or ""
        evidence = resp.strip()[:600] if resp else ""
        findings.append({
            "source": "nuclei",
            "target": d.get("host") or d.get("matched-at", ""),
            "name": info_d.get("name", d.get("template-id", "?")),
            "severity": sev_norm(info_d.get("severity")),
            "description": info_d.get("description", ""),
            "references": info_d.get("reference", []) or [],
            "cve": cls.get("cve-id", []) or [],
            "cvss": cls.get("cvss-score"),
            "tags": info_d.get("tags", []) or [],
            "matched_at": d.get("matched-at", ""),
            "template": d.get("template-id", ""),
            # Couche preuve
            "confidence": "confirmé",  # nuclei n'émet un finding que si le matcher a déclenché
            "matcher": d.get("matcher-name", ""),
            "extracted": extracted,
            "evidence": evidence,
        })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  Étape 5 (option --deep) — nmap -sV + scripts NSE 'vuln'
# ─────────────────────────────────────────────────────────────────────────────
# Scripts NSE notoirement bruyants (émettent une sortie sans confirmer l'exploitabilité).
NOISY_NSE = {
    "http-csrf", "http-dombased-xss", "http-stored-xss", "http-xssed",
    "http-phpself-xss", "http-litespeed-sourcecode-download", "http-errors",
    "http-comments-displayer",
}
# Scripts propres à un produit : un mot-clé dans l'id → techno requise dans le fingerprint.
NSE_APP_GATE = {
    "drupal": "drupal", "cve2014-3704": "drupal", "wordpress": "wordpress",
    "wp-": "wordpress", "joomla": "joomla", "magento": "magento",
    "phpmyadmin": "phpmyadmin", "django": "django", "jira": "jira",
    "tomcat": "tomcat", "weblogic": "weblogic", "citrix": "citrix",
    "aspnet": "asp.net", "asp-net": "asp.net", "iis": "iis",
}


def deep_nmap(targets, tb, outdir, tech=None, nse_all=False):
    section("Étape 5 (deep) — nmap -sV + NSE vuln")
    if not tb.has("nmap"):
        warn("nmap absent : deep-scan sauté.")
        return []
    findings = []
    for t in targets:
        xmlp = os.path.join(outdir, f"nse_{_slug(t)}.xml")
        run(["nmap", "-sV", "--script", "vuln", "-Pn", "-oX", xmlp, t], timeout=3600)
        findings += _parse_nse(xmlp, tech=tech, nse_all=nse_all)
    kept = len(findings)
    ok(f"{kept} résultat(s) NSE retenu(s) après filtrage anti-bruit.")
    return findings


def _parse_nse(path, tech=None, nse_all=False):
    """
    Parse la sortie NSE en filtrant le bruit :
      • scripts bruyants (NOISY_NSE) écartés sauf --nse-all ;
      • scripts propres à un produit écartés si la techno n'est pas dans le fingerprint ;
      • sévérité « confirmé/élevé » seulement sur un état VULNERABLE explicite ;
      • vulners (version-based) rétrogradé en intel « potentiel ».
    """
    import xml.etree.ElementTree as ET
    findings = []
    tech_hay = " ".join(t.lower() for t in (tech or []))
    if not os.path.exists(path):
        return findings
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return findings
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "?"
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            portid = port.get("portid")
            for script in port.findall("script"):
                sid = (script.get("id") or "").lower()
                out = (script.get("output") or "").strip()
                up = out.upper()
                if not out or "COULD NOT" in up:
                    continue

                # 1) Scripts bruyants → écartés par défaut
                if not nse_all and sid in NOISY_NSE:
                    continue

                # 2) Filtrage par techno : script propre à un produit absent du fingerprint
                gated = False
                for kw, needed in NSE_APP_GATE.items():
                    if kw in sid and needed not in tech_hay:
                        gated = True
                        break
                if gated and not nse_all:
                    continue

                # 3) Sévérité : état VULNERABLE explicite requis pour « confirmé »
                #    (sortie structurée de la lib « vuln » : "State: VULNERABLE")
                has_state = "STATE: VULNERABLE" in up or 'KEY="STATE">VULNERABLE' in up
                sev, conf = "info", "potentiel"
                if "LIKELY VULNERABLE" in up:
                    sev, conf = "medium", "potentiel"
                elif has_state and "NOT VULNERABLE" not in up:
                    sev, conf = "high", "confirmé"
                elif "VULNERABLE" in up and "NOT VULNERABLE" not in up:
                    # mot présent sans état structuré → prudence : moyen/potentiel
                    sev, conf = "medium", "potentiel"

                # 4) vulners : intel par version, jamais « confirmé »
                is_vulners = sid == "vulners"
                if is_vulners:
                    sev = "low" if sev in ("high", "medium") else sev
                    conf = "potentiel"

                cves = sorted({
                    w.strip(".,;:()[]")
                    for w in out.replace("\n", " ").split()
                    if w.upper().startswith("CVE-")
                })
                tags = ["nse"]
                if is_vulners:
                    tags += ["intel", "version-based"]
                if conf == "potentiel":
                    tags += ["à-valider"]

                findings.append({
                    "source": "nse",
                    "target": f"{ip}:{portid}",
                    "name": script.get("id", ""),
                    "severity": sev,
                    "description": (("[Intel version — à confirmer] " if is_vulners else "")
                                    + out[:1200]),
                    "references": [], "cve": cves, "cvss": None,
                    "tags": tags, "matched_at": f"{ip}:{portid}",
                    "template": script.get("id", ""),
                    "confidence": conf, "matcher": ("State: VULNERABLE" if has_state else ""),
                    "extracted": [], "evidence": out[:600],
                })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  Agrégation
# ─────────────────────────────────────────────────────────────────────────────
def merge(*lists):
    seen, out = set(), []
    for lst in lists:
        for f in lst:
            key = (f["source"], f["target"], f["name"])
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
    out.sort(key=lambda x: SEV_RANK[x["severity"]], reverse=True)
    return out


def counts(findings):
    c = {k: 0 for k in SEV_ORDER}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


# ─────────────────────────────────────────────────────────────────────────────
#  Rapports
# ─────────────────────────────────────────────────────────────────────────────
def report_json(findings, services, web_meta, meta, outdir, observations=None):
    path = os.path.join(outdir, "rapport.json")
    payload = {
        "outil": "zunabo-scan", "version": VERSION,
        "engagement": meta,
        "date": datetime.now(timezone.utc).isoformat(),
        "surface": {"services": services, "web": web_meta},
        "resume": counts(findings),
        "observations": observations or [],
        "vulnerabilites": findings,
    }
    json.dump(payload, open(path, "w"), indent=2, ensure_ascii=False)
    return path


def report_markdown(findings, services, web_meta, meta, outdir):
    path = os.path.join(outdir, "rapport.md")
    c = counts(findings)
    lines = [
        f"# Rapport d'audit — zunabo-scan v{VERSION}", "",
        f"**Cible :** {meta['target']}  ",
        f"**Client :** {meta.get('client') or '—'}  ",
        f"**Périmètre :** {meta.get('scope') or '—'}  ",
        f"**Date :** {meta['date']}  ", "",
        "## Synthèse", "",
        "| Sévérité | Nombre |", "|---|---|",
    ]
    for s in SEV_ORDER:
        lines.append(f"| {s.capitalize()} | {c[s]} |")
    lines += ["", f"**Total : {len(findings)} résultat(s)** sur "
              f"{len(services)} service(s) exposé(s).", "", "## Vulnérabilités", ""]
    if not findings:
        lines.append("_Aucune vulnérabilité détectée avec ces paramètres._")
    for f in findings:
        cve = f" — {', '.join(f['cve'])}" if f["cve"] else ""
        lines.append(f"### [{f['severity'].upper()}] {f['name']}{cve}")
        lines.append(f"- **Cible :** `{f['target']}`")
        if f.get("confidence") and f["confidence"] != "info":
            lines.append(f"- **Confiance :** {f['confidence']}")
        if f.get("cvss"):
            lines.append(f"- **CVSS :** {f['cvss']}")
        if f["description"]:
            lines.append(f"- {f['description']}")
        if f.get("extracted"):
            lines.append(f"- **Preuve (extrait) :** {', '.join(str(x) for x in f['extracted'][:8])}")
        for r in f["references"][:5]:
            lines.append(f"- {r}")
        lines.append("")
    open(path, "w").write("\n".join(lines))
    return path


def report_html(findings, services, web_meta, meta, outdir):
    import html
    path = os.path.join(outdir, "rapport.html")
    c = counts(findings)

    def esc(x):
        return html.escape(str(x))

    cards = "".join(
        f'<div class="z-card {s}"><div class="num">{c[s]}</div>'
        f'<div class="lbl">{s.upper()}</div></div>'
        for s in SEV_ORDER
    )

    # Surface : web (httpx) prioritaire, sinon services bruts
    if web_meta:
        rows = "".join(
            f"<tr><td>{esc(w['url'])}</td><td>{esc(w['status'])}</td>"
            f"<td>{esc(w['title'])}</td><td>{esc(w['webserver'])}</td>"
            f"<td>{esc(', '.join(w['tech']))}</td></tr>"
            for w in web_meta
        )
        surface = (
            '<table class="z-table"><thead><tr><th>URL</th><th>Statut</th>'
            "<th>Titre</th><th>Serveur</th><th>Technologies</th></tr></thead><tbody>"
            + (rows or '<tr><td colspan=5 class="z-empty">Aucun</td></tr>')
            + "</tbody></table>"
        )
        surface_n = len(web_meta)
    else:
        rows = "".join(
            f"<tr><td>{esc(s['ip'] or s['host'])}</td>"
            f"<td>{esc(s['port'])}/{esc(s['proto'])}</td>"
            f"<td>{esc(s['service'])}</td>"
            f"<td>{esc((s['product'] + ' ' + s['version']).strip())}</td></tr>"
            for s in services
        )
        surface = (
            '<table class="z-table"><thead><tr><th>Hôte</th><th>Port</th>'
            "<th>Service</th><th>Version</th></tr></thead><tbody>"
            + (rows or '<tr><td colspan=4 class="z-empty">Aucun</td></tr>')
            + "</tbody></table>"
        )
        surface_n = len(services)

    vuln_html = ""
    for f in findings:
        refs = "".join(
            f'<a href="{esc(r)}" target="_blank" rel="noopener">{esc(r)}</a>'
            for r in f["references"][:6]
        )
        cves = " ".join(f'<span class="z-cve">{esc(x)}</span>' for x in f["cve"])
        cvss = f'<span class="z-cvss">CVSS {esc(f["cvss"])}</span>' if f.get("cvss") else ""
        tags = " ".join(f'<span class="z-tag">{esc(t)}</span>' for t in f.get("tags", [])[:6])
        # Couche preuve : confiance + évidence non destructive
        conf = f.get("confidence", "")
        conf_slug = {"confirmé": "confirme", "potentiel": "potentiel"}.get(conf, "")
        conf_html = f'<span class="z-conf {conf_slug}">{esc(conf.upper())}</span>' if conf_slug else ""
        ev_parts = []
        if f.get("matcher"):
            ev_parts.append(f'<div class="z-evrow"><b>Matcher :</b> {esc(f["matcher"])}</div>')
        if f.get("extracted"):
            vals = " · ".join(esc(x) for x in f["extracted"][:8])
            ev_parts.append(f'<div class="z-evrow"><b>Extrait :</b> {vals}</div>')
        if f.get("evidence"):
            ev_parts.append(f'<pre class="z-evich">{esc(f["evidence"])}</pre>')
        evidence_html = ('<details class="z-evbox"><summary>Preuve</summary>'
                         + "".join(ev_parts) + '</details>') if ev_parts else ""
        vuln_html += f"""
        <div class="z-vuln {f['severity']}">
          <div class="z-vhead">
            <span class="badge {f['severity']}">{f['severity'].upper()}</span>
            <span class="z-vname">{esc(f['name'])}</span>
            {conf_html}{cvss}<span class="z-src">{esc(f['source'])}</span>
          </div>
          <div class="z-target">{esc(f['target'])}</div>
          {'<div class="z-desc">' + esc(f['description']) + '</div>' if f['description'] else ''}
          {'<div class="z-cves">' + cves + '</div>' if cves else ''}
          {'<div class="z-tags">' + tags + '</div>' if tags else ''}
          {evidence_html}
          {'<div class="z-refs">' + refs + '</div>' if refs else ''}
        </div>"""
    if not findings:
        vuln_html = '<p class="z-empty">Aucune vulnérabilité détectée avec ces paramètres.</p>'

    inner = f"""
  <h1>Rapport de scan de vulnérabilités</h1>
  <div class="z-meta">
    <div><b>Cible :</b> {esc(meta['target'])}</div>
    <div><b>Client :</b> {esc(meta.get('client') or '—')}</div>
    <div><b>Périmètre :</b> {esc(meta.get('scope') or '—')}</div>
    <div><b>Date :</b> {esc(meta['date'])}</div>
    <div><b>Opérateur :</b> {esc(meta.get('operator') or 'D4N')}</div>
    <div><b>Résultats :</b> {len(findings)}</div>
  </div>
  <div class="z-cards">{cards}</div>
  <h2>Surface d'attaque <span class="z-accent">({surface_n})</span></h2>
  {surface}
  <h2>Vulnérabilités <span class="z-accent">({len(findings)})</span></h2>
  {vuln_html}"""

    footer_note = f"zunabo-scan v{VERSION} · résultats à valider manuellement"
    if _HAS_BRAND:
        doc = brand.document("Rapport de scan", inner, footer_note=footer_note)
    else:
        # Repli minimal si la charte n'est pas présente à côté du script
        doc = (f'<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">'
               f'<title>Rapport zunabo-scan</title></head>'
               f'<body style="background:#0a1512;color:#e9f5ee;font-family:sans-serif">'
               f'<div style="max-width:980px;margin:auto;padding:24px">{inner}</div></body></html>')
    open(path, "w").write(doc)
    return path


# ─────────────────────────────────────────────────────────────────────────────
#  Synthèse terminal
# ─────────────────────────────────────────────────────────────────────────────
def summary(findings):
    section("Synthèse")
    c = counts(findings)
    for s in SEV_ORDER:
        if c[s]:
            print(f"  {_c(s.upper().ljust(9), SEV_COLOR[s])} {c[s]}")
    if not findings:
        ok("Aucune vulnérabilité détectée.")


# ─────────────────────────────────────────────────────────────────────────────
#  Manifeste du dossier de scan
# ─────────────────────────────────────────────────────────────────────────────
_FILE_DESC = {
    "rapport.html":   "Rapport lisible (charte Zunabo) — à ouvrir dans un navigateur",
    "rapport.docx":   "Rapport de pentest Word (livrable client)",
    "rapport.json":   "Données structurées complètes (surface, constats, observations)",
    "rapport.md":     "Rapport Markdown (à coller dans un document plus large)",
    "scan.log":       "Journal lisible horodaté — TOUT ce que le scan a rencontré",
    "events.jsonl":   "Journal structuré (1 événement JSON/ligne) — pour grep/jq/analyse fine",
    "nuclei.sarif":   "Résultats nuclei au format SARIF (GitHub Security / SAST)",
    "nuclei.jsonl":   "Sortie brute nuclei (1 finding JSON/ligne)",
    "nuclei_markdown": "Rapports nuclei détaillés par finding (Markdown)",
    "httpx.json":     "Sortie brute httpx (services web, tech, titres, statuts)",
    "ports.json":     "Sortie brute naabu (ports ouverts)",
    "hosts.txt":      "Liste des hôtes / sous-domaines scannés",
    "endpoints.txt":  "Endpoints transmis à httpx",
    "nuclei_targets.txt": "Cibles transmises à nuclei",
    "subdomains_raw.txt": "Sous-domaines bruts (subfinder, avant résolution)",
}


def write_manifest(outdir, meta, findings, services):
    lines = [
        "═══════════════════════════════════════════════════════════",
        "  ZUNABO-SCAN — Dossier de résultats",
        "═══════════════════════════════════════════════════════════",
        "",
        f"  Cible     : {meta.get('target')}",
        f"  Client    : {meta.get('client') or '—'}",
        f"  Périmètre : {meta.get('scope') or '—'}",
        f"  Opérateur : {meta.get('operator') or 'D4N'}",
        f"  Date/heure: {meta.get('date')}",
        f"  Résultats : {len(findings)} constat(s) · {len(services)} service(s)",
        "",
        "  ── Contenu du dossier ──",
        "",
    ]
    present = sorted(os.listdir(outdir))
    for name in present:
        if name == "LISEZ-MOI.txt":
            continue
        desc = _FILE_DESC.get(name, "")
        lines.append(f"  • {name:22} {desc}")
    lines += [
        "",
        "  Pour approfondir : ouvre scan.log (lisible) ou filtre events.jsonl,",
        "  ex.  jq 'select(.level==\"finding\")' events.jsonl",
        "       grep '\"web_service\"' events.jsonl",
        "",
        "  Zunabo · La technologie, en toute confiance.",
        "",
    ]
    with open(os.path.join(outdir, "LISEZ-MOI.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ─────────────────────────────────────────────────────────────────────────────
#  main
# ─────────────────────────────────────────────────────────────────────────────
def enrich_shodan(hosts, services, timeout=8):
    """
    Enrichissement passif via Shodan InternetDB (gratuit, sans clé API).
    Croise la découverte active avec la vue de Shodan :
      • ports exposés vus par Shodan mais manqués par le scan actif ;
      • CVE connues associées à l'hôte ;
      • tags (ex. eol-product), hostnames, CPE en observations.
    Best-effort : silencieux en cas d'échec réseau.
    """
    import socket
    import urllib.request

    section("Enrichissement passif — Shodan InternetDB")
    findings, observations = [], []

    # Ports découverts activement, par IP
    discovered = {}
    for s in services:
        ip = s.get("ip") or s.get("host")
        if ip and s.get("port"):
            discovered.setdefault(ip, set()).add(str(s["port"]))

    # Résout les hôtes en IP (InternetDB indexe par IP)
    ips = {}
    for h in hosts:
        try:
            socket.inet_aton(h)
            ips[h] = h
        except OSError:
            try:
                ips[h] = socket.gethostbyname(h)
            except Exception:
                continue

    seen = set()
    for host, ip in ips.items():
        if ip in seen:
            continue
        seen.add(ip)
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "zunabo-scan"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.load(r)
        except Exception as e:
            warn(f"Shodan indisponible pour {ip} ({e}).")
            continue

        sh_ports = {str(p) for p in (data.get("ports") or [])}
        found = discovered.get(ip, set()) or discovered.get(host, set())
        missed = sorted(sh_ports - found, key=lambda x: int(x))
        vulns = data.get("vulns") or []
        tags = data.get("tags") or []
        cpes = data.get("cpes") or []
        hostnames = data.get("hostnames") or []

        info(f"{ip} — Shodan : {len(sh_ports)} port(s), {len(vulns)} CVE, tags={tags or '—'}")

        # 1) Ports vus par Shodan et manqués par le scan actif
        if missed:
            findings.append({
                "source": "shodan", "target": ip,
                "name": f"Ports exposés vus par Shodan mais non détectés par le scan actif ({len(missed)})",
                "severity": "medium",
                "description": ("Shodan expose des ports ouverts que le scan actif n'a pas relevés : "
                                + ", ".join(missed) + ". Le balayage a probablement été limité "
                                "(top-ports) ou bridé par la cible. Recommandé : relancer avec "
                                "--full-ports (débit adapté) pour couvrir toute la surface."),
                "references": [f"https://www.shodan.io/host/{ip}"],
                "cve": [], "cvss": None, "tags": ["shodan", "surface", "coverage"],
                "confidence": "potentiel", "matcher": "diff ports Shodan/scan",
                "extracted": missed, "evidence": "Shodan: " + ", ".join(sorted(sh_ports, key=lambda x: int(x))),
            })

        # 2) CVE connues (intel passive à confirmer)
        for cve in vulns:
            findings.append({
                "source": "shodan", "target": ip,
                "name": f"CVE signalée par Shodan — {cve}",
                "severity": "medium",
                "description": ("Shodan associe cette vulnérabilité à un service exposé de l'hôte "
                                "(déduite des bannières/versions). À confirmer contre la version réelle "
                                "du service avant conclusion."),
                "references": [f"https://nvd.nist.gov/vuln/detail/{cve}",
                               f"https://www.shodan.io/host/{ip}"],
                "cve": [cve], "cvss": None, "tags": ["shodan", "cve", "intel"],
                "confidence": "potentiel", "matcher": cve, "extracted": [], "evidence": "",
            })

        # 3) Tags / contexte
        if "eol-product" in tags:
            findings.append({
                "source": "shodan", "target": ip,
                "name": "Composant en fin de vie (eol-product)",
                "severity": "low",
                "description": ("Shodan signale un produit en fin de vie (plus de correctifs de "
                                "sécurité). Identifier et mettre à jour/remplacer le composant concerné."),
                "references": [f"https://www.shodan.io/host/{ip}"],
                "cve": [], "cvss": None, "tags": ["shodan", "eol"],
                "confidence": "potentiel", "matcher": "tag eol-product", "extracted": [], "evidence": "",
            })
        for t in tags:
            if t != "eol-product":
                observations.append({"tag": "shodan", "text": f"{ip} — tag Shodan : {t}"})
        if cpes:
            observations.append({"tag": "shodan", "text": f"{ip} — CPE (Shodan) : " + ", ".join(cpes[:6])})
        for hn in hostnames:
            observations.append({"tag": "shodan", "text": f"{ip} — nom d'hôte (Shodan) : {hn}"})

    ok(f"{len(findings)} constat(s) Shodan, {len(observations)} observation(s).")
    return findings, observations


def main():
    ap = argparse.ArgumentParser(
        prog="zunabo-scan",
        description=f"Orchestrateur d'audit de vulnérabilités (Zunabo) v{VERSION}.",
    )
    ap.add_argument("target", help="IP, CIDR ou domaine")
    ap.add_argument("-o", "--output-dir", default=None)
    ap.add_argument("-s", "--severity", default="low,medium,high,critical",
                    help="Sévérités nuclei (défaut : low,medium,high,critical)")
    ap.add_argument("--exclude-severity", default="", help="Sévérités à exclure")
    ap.add_argument("--full-ports", action="store_true", help="Tous les ports (65535)")
    ap.add_argument("--deep", action="store_true", help="Ajoute nmap -sV + NSE vuln")
    ap.add_argument("--no-auto", action="store_true",
                    help="Désactive nuclei -as (sélection auto par tech)")
    ap.add_argument("--tags", default="", help="Tags nuclei additionnels (ex: cve,rce)")
    ap.add_argument("--rate-limit", type=int, default=0, help="Limite req/s")
    ap.add_argument("--skip-nuclei", action="store_true")
    # Analyse de surface / takeover
    ap.add_argument("--expected-platform", default="",
                    help="Plateforme d'hébergement attendue (ex: cloudflare) ; tout hôte sur "
                         "une autre plateforme est remonté en constat Moyen")
    ap.add_argument("--no-shodan", action="store_true",
                    help="Désactive l'enrichissement passif Shodan InternetDB")
    ap.add_argument("--nse-all", action="store_true",
                    help="Garde les scripts NSE bruyants/hors-techno (désactive l'anti-faux-positifs)")
    ap.add_argument("--no-version", action="store_true",
                    help="Désactive la détection de version nmap -sV ciblée (plus rapide)")
    ap.add_argument("--no-takeover", action="store_true",
                    help="Désactive l'analyse de surface / détection de takeover")
    # Métadonnées d'engagement (optionnelles, imprimées dans le rapport)
    ap.add_argument("--client", default="", help="Nom du client (rapport)")
    ap.add_argument("--scope", default="", help="Réf. de périmètre / autorisation (rapport)")
    ap.add_argument("--operator", default="D4N", help="Opérateur (rapport)")
    # Intégration CI
    ap.add_argument("--ci", action="store_true",
                    help="Code de sortie non nul si findings ≥ seuil")
    ap.add_argument("--fail-on", default="high",
                    help="Seuil --ci : critical|high|medium|low (défaut high)")
    # Enrichissement
    ap.add_argument("--passive", action="store_true",
                    help="Recon sans scan agressif : sous-domaines + httpx + surface "
                         "(pas de naabu/nuclei/nmap). Idéal pour cibles derrière un CDN")
    ap.add_argument("--ports", default="",
                    help="Ports sur mesure (ex: 80,443,8080 ou 1-1000) au lieu du top-1000")
    ap.add_argument("--header", "-H", action="append", default=[], dest="headers",
                    help="En-tête HTTP custom (répétable) : scan authentifié / host override")
    ap.add_argument("--proxy", default="",
                    help="Proxy HTTP pour httpx/nuclei/naabu (ex: http://127.0.0.1:8080)")
    ap.add_argument("--exclude-host", action="append", default=[], dest="exclude_hosts",
                    help="Hôte à exclure du périmètre (répétable)")
    ap.add_argument("--templates", "-t", default="",
                    help="Templates nuclei personnalisés (dossier ou fichier)")
    args = ap.parse_args()

    # ── Verrou d'accès Zunabo (avant toute action) ──
    if not _HAS_AUTH:
        print("[verrou] zunabo_auth.py introuvable — outil verrouillé, "
              "démarrage refusé. Place le fichier à côté du script.", file=sys.stderr)
        sys.exit(3)
    auth.require_unlock(f"zunabo-scan v{VERSION}")

    print(_c(f"┌─ zunabo-scan v{VERSION} · D4N ─────────────────┐", C.BOLD + C.CYAN))
    print(_c("└─ pipeline: naabu → httpx → nuclei ───────┘", C.CYAN))

    tb = ToolBox()
    tb.report()

    kind = classify_target(args.target)
    info(f"Cible classée : {_c(kind, C.BOLD)}")

    # Dossier de sortie : nom de la cible + date/heure du pentest
    now = datetime.now()
    outdir = args.output_dir or f"{_slug(args.target)}_{now.strftime('%Y-%m-%d_%Hh%M')}"
    os.makedirs(outdir, exist_ok=True)
    info(f"Sorties → {outdir}/")

    # ── Journal complet (scan.log + events.jsonl) ──
    global _LOG
    if _HAS_LOG:
        _LOG = zlog.RunLogger(outdir)
        _LOG.event("session", "-", "start", target=args.target, kind=kind,
                   version=VERSION, params=" ".join(sys.argv[1:]),
                   engines=[t for t in tb.KNOWN if tb.has(t)])

    meta = {
        "target": args.target, "kind": kind,
        "client": args.client, "scope": args.scope, "operator": args.operator,
        "date": now.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                + f"  (local {now.strftime('%d/%m/%Y %H:%M')})",
    }

    # Pipeline
    if kind == "domain":
        hosts = enum_subdomains(args.target, tb, outdir)
    else:
        hosts = [args.target]
    if args.exclude_hosts:
        hosts = [h for h in hosts if h not in set(args.exclude_hosts)]
    for h in hosts:
        if _LOG: _LOG.data("hosts", "host", h)

    # Mode passif : pas de scan de ports, on sonde directement 80/443
    if args.passive:
        info("Mode passif : pas de scan de ports (naabu/nuclei/nmap sautés).")
        services = [{"ip": h, "host": h, "port": p, "proto": "tcp",
                     "service": "", "product": "", "version": ""}
                    for h in hosts for p in ("80", "443")]
    else:
        services = discover_ports(hosts, tb, outdir, args.full_ports, args.rate_limit,
                                  ports=args.ports, proxy=args.proxy)
        # Détection de version ciblée (naabu ne renvoie pas les versions)
        if not args.no_version:
            services = enrich_versions(services, tb, outdir, proxy=args.proxy)
    ok(f"{len(services)} service(s)/port(s) ouvert(s).")
    for s in services:
        if _LOG: _LOG.data("ports", "service_open", s)

    web_urls, web_meta = probe_http(services, tb, outdir,
                                    headers=args.headers, proxy=args.proxy)
    for w in web_meta:
        if _LOG: _LOG.data("httpx", "web_service", w)

    all_targets = sorted({s["ip"] or s["host"] for s in services if (s.get("ip") or s.get("host"))})

    nuclei_findings = []
    if not args.skip_nuclei and not args.passive:
        nuclei_findings = run_nuclei(
            web_urls, all_targets, tb, outdir,
            args.severity, args.exclude_severity, args.rate_limit,
            auto=not args.no_auto, extra_tags=args.tags,
            headers=args.headers, proxy=args.proxy, templates=args.templates,
        )

    # Fingerprint techno (issu de httpx) pour filtrer les scripts NSE propres à un produit
    tech_fp = sorted({t for w in web_meta for t in (w.get("tech") or [])}
                     | {w.get("webserver", "") for w in web_meta})
    deep_findings = (deep_nmap(hosts, tb, outdir, tech=tech_fp, nse_all=args.nse_all)
                     if (args.deep and not args.passive) else [])

    # Analyse de surface / détection de takeover
    surface_findings, observations = [], []
    if _HAS_SURFACE and web_meta and not args.no_takeover:
        section("Analyse de surface & takeover")
        surface_findings, observations = surface.analyze(web_meta, args.expected_platform)
        ok(f"{len(surface_findings)} constat(s) de surface, {len(observations)} observation(s).")

    # Enrichissement passif Shodan (croise la découverte active avec la vue Shodan)
    shodan_findings, shodan_obs = [], []
    if not args.no_shodan and not args.passive:
        try:
            shodan_findings, shodan_obs = enrich_shodan(hosts, services)
        except Exception as e:
            warn(f"Enrichissement Shodan ignoré : {e}")
    observations = (observations or []) + shodan_obs

    findings = merge(nuclei_findings, deep_findings, surface_findings, shodan_findings)
    for f in findings:
        if _LOG: _LOG.finding(f)
    for o in observations:
        if _LOG: _LOG.event("observation", "surface", "note",
                            text=o.get("text", "") if isinstance(o, dict) else str(o))

    section("Rapports")
    jp = report_json(findings, services, web_meta, meta, outdir, observations)
    md = report_markdown(findings, services, web_meta, meta, outdir)
    hp = report_html(findings, services, web_meta, meta, outdir)
    ok(f"JSON     : {jp}")
    ok(f"Markdown : {md}")
    ok(f"HTML     : {hp}")
    dp = None
    if _HAS_REPORT:
        try:
            dp = zreport.build(jp, os.path.join(outdir, "rapport.docx"))
            ok(f"Word     : {dp}")
        except Exception as e:
            warn(f"Rapport .docx non généré ({e}).")
    else:
        info("Rapport .docx : module zunabo_report/python-docx absent (optionnel).")

    write_manifest(outdir, meta, findings, services)
    summary(findings)
    print(f"\n{_c('Terminé.', C.BOLD + C.GREEN)} → {_c(outdir + '/', C.CYAN)}\n")

    if _LOG:
        _LOG.close(summary={"findings": len(findings), "services": len(services),
                            "resume": counts(findings), "outdir": outdir})

    # Code de sortie CI
    if args.ci:
        threshold = SEV_RANK.get(args.fail_on, 4)
        hit = [f for f in findings if SEV_RANK[f["severity"]] >= threshold]
        if hit:
            err(f"CI : {len(hit)} finding(s) ≥ {args.fail_on}. Sortie code 1.")
            sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        err("Interrompu.")
        sys.exit(130)

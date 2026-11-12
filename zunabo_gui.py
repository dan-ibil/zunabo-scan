#!/usr/bin/env python3
"""
zunabo_gui.py — Interface web locale pour zunabo-scan.

Un formulaire aux couleurs Zunabo pour lancer des scans avec les modules
choisis (cases à cocher), suivre la sortie en direct, et parcourir
l'historique des scans groupé par client.

Sécurité :
  • N'écoute que sur 127.0.0.1 (jamais exposée au réseau).
  • Protégée par le même verrou que la CLI (code demandé au démarrage).
  • Aucune dépendance externe (bibliothèque standard Python).

Usage :
    cd ~/Desktop/zunabo-scan
    python3 zunabo_gui.py            # ouvre http://127.0.0.1:8770
"""

import base64
import html
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    import zunabo_auth as auth
    _HAS_AUTH = True
except ImportError:
    _HAS_AUTH = False

try:
    import zunabo_brand as brand
    P = brand.PALETTE
    LOGO = brand.LOGO_B64
except Exception:
    P = {"green_deep": "33492e", "sage": "7ba073", "gold": "c19a3e",
         "paper": "f6f4ec", "card": "fffdf8", "ink": "20291b", "muted": "5c6a51",
         "line": "e2ddcf", "critical": "b3282d", "high": "d9642a",
         "medium": "c19a3e", "low": "3f7d8c", "info": "8a9a80"}
    LOGO = ""

PORT = 8770
BASE = os.getcwd()               # les dossiers de scan y sont créés
SCAN_SCRIPT = os.path.join(BASE, "zunabo_scan.py")
_UNLOCK = None                   # code (mémoire uniquement) pour les sous-process
JOBS = {}                        # job_id → {output, done, outdir, rc}


# ─────────────────────────────────────────────────────────────────────────────
#  Construction de la commande depuis les cases cochées
# ─────────────────────────────────────────────────────────────────────────────
def build_command(d):
    target = (d.get("target") or "").strip()
    if not target:
        raise ValueError("Cible manquante.")
    argv = [sys.executable, SCAN_SCRIPT, target]
    # champs texte simples
    for key, flag in [("client", "--client"), ("scope", "--scope"),
                      ("operator", "--operator"), ("expected_platform", "--expected-platform"),
                      ("tags", "--tags"), ("ports", "--ports"), ("proxy", "--proxy"),
                      ("templates", "--templates"), ("exclude_severity", "--exclude-severity")]:
        v = (d.get(key) or "").strip()
        if v:
            argv += [flag, v]
    if d.get("severity"):
        sev = ",".join(d["severity"]) if isinstance(d["severity"], list) else str(d["severity"]).strip()
        if sev:
            argv += ["--severity", sev]
    if d.get("rate_limit"):
        argv += ["--rate-limit", str(int(d["rate_limit"]))]
    # en-têtes (multi-lignes ou liste)
    hs = d.get("headers") or []
    if isinstance(hs, str):
        hs = hs.splitlines()
    for h in hs:
        if h.strip():
            argv += ["--header", h.strip()]
    # hôtes exclus (virgules ou lignes)
    ex = d.get("exclude_hosts") or []
    if isinstance(ex, str):
        ex = ex.replace(",", "\n").splitlines()
    for x in ex:
        if x.strip():
            argv += ["--exclude-host", x.strip()]
    # modules (cases)
    mods = set(d.get("modules", []))
    if "passive" in mods:
        argv += ["--passive"]
    else:
        if "full_ports" in mods:   argv += ["--full-ports"]
        if "nuclei" not in mods:   argv += ["--skip-nuclei"]
        if "deep" in mods:         argv += ["--deep"]
    if "surface" not in mods:      argv += ["--no-takeover"]
    if "shodan" not in mods:       argv += ["--no-shodan"]
    if d.get("no_auto"):           argv += ["--no-auto"]
    return argv


# ─────────────────────────────────────────────────────────────────────────────
#  Lancement d'un scan en tâche de fond
# ─────────────────────────────────────────────────────────────────────────────
def _run_job(job_id, argv):
    job = JOBS[job_id]
    env = dict(os.environ)
    if _UNLOCK is not None:
        env["ZUNABO_UNLOCK"] = _UNLOCK
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1, env=env, cwd=BASE)
        job["proc"] = p
        for line in p.stdout:
            job["output"] += line
            if "Sorties →" in line:
                job["outdir"] = line.split("Sorties →")[-1].strip().rstrip("/")
        p.wait()
        job["rc"] = p.returncode
    except Exception as e:
        job["output"] += f"\n[erreur] {e}\n"
        job["rc"] = 1
    job["done"] = True


# ─────────────────────────────────────────────────────────────────────────────
#  Historique des scans (dossiers dans BASE)
# ─────────────────────────────────────────────────────────────────────────────
def _scan_ts(name, path):
    """Horodatage triable d'un dossier de scan : suffixe _AAAA-MM-JJ_HHhMM, sinon mtime."""
    m = re.search(r"_(\d{4})-(\d{2})-(\d{2})_(\d{2})h(\d{2})", name)
    if m:
        return "".join(m.groups())  # ex. 202609300201, trié lexicographiquement = chronologiquement
    try:
        return str(int(os.path.getmtime(path)))
    except Exception:
        return "0"


def list_scans():
    out = []
    for name in os.listdir(BASE):
        d = os.path.join(BASE, name)
        rj = os.path.join(d, "rapport.json")
        if os.path.isdir(d) and os.path.exists(rj):
            info = {"name": name, "resume": {}, "target": "", "date": "", "client": "",
                    "_ts": _scan_ts(name, d)}
            try:
                data = json.load(open(rj))
                eng = data.get("engagement", {})
                info["resume"] = data.get("resume", {})
                info["target"] = eng.get("target", "")
                info["date"] = eng.get("date", "")
                info["client"] = (eng.get("client") or "").strip()
            except Exception:
                pass
            out.append(info)
    # Tri du plus récent au plus ancien (par horodatage réel, pas par nom)
    out.sort(key=lambda x: x.get("_ts", "0"), reverse=True)
    return out[:80]


def _safe_report(dirname, filename):
    """Renvoie le chemin d'un fichier de rapport, borné à BASE (anti-traversal)."""
    dirname = os.path.basename(dirname)
    filename = os.path.basename(filename)
    path = os.path.join(BASE, dirname, filename)
    if os.path.commonpath([os.path.abspath(path), BASE]) != BASE:
        return None
    return path if os.path.exists(path) else None


# ─────────────────────────────────────────────────────────────────────────────
#  Page HTML (charte Zunabo)
# ─────────────────────────────────────────────────────────────────────────────
def page():
    logo = (f'<img class="logo" alt="Zunabo" src="data:image/png;base64,{LOGO}">'
            if LOGO else '<span class="word">zunabo</span>')
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zunabo Scan — Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fredoka:wght@400;500;600;700&family=Manrope:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
 :root{{
   --paper:#efeadd;--surface:#fbf9f2;--surface-2:#f5f1e6;--ink:#253019;--muted:#6c775f;
   --line:#e0dcc9;--grid-c:rgba(64,91,57,.20);
   --green:#5f8257;--green-deep:#405b39;--green-soft:#7ba073;--green-tint:rgba(95,130,87,.12);
   --amber:#b4832a;--glow-b:rgba(169,194,160,.55);--glow-c:rgba(123,160,115,.35);
   --shadow:0 1px 2px rgba(37,48,25,.05),0 16px 40px -22px rgba(37,48,25,.30);--radius:20px;
   --critical:#b3282d;--high:#c25a2b;--medium:#b4832a;--low:#3f7d8c;--info:#8a9a80;
 }}
 *{{box-sizing:border-box;}}
 body{{margin:0;background:var(--paper);color:var(--ink);min-height:100vh;position:relative;
   font:15px/1.55 "Manrope",system-ui,-apple-system,Segoe UI,sans-serif;-webkit-font-smoothing:antialiased;}}
 body::before{{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.55;
   background:radial-gradient(52vw 42vh at 84% -8%,var(--glow-b),transparent 60%),
     radial-gradient(46vw 40vh at -6% 3%,var(--glow-c),transparent 58%);}}
 body::after{{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.035;
   background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='2'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");}}
 h1,h2,h3,.word,.num,.preset,.btn,.cname,.sec-title,.tag2{{font-family:"Fredoka",sans-serif;}}
 a{{color:inherit;}}
 /* HEADER glass (comme header.bar du site) */
 header.bar{{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:12px;
   padding:12px 22px;background:color-mix(in srgb,var(--paper) 82%,transparent);
   backdrop-filter:blur(14px) saturate(150%);-webkit-backdrop-filter:blur(14px) saturate(150%);
   border-bottom:1px solid var(--line);}}
 header.bar .logo{{height:30px;display:block;}} header.bar .word{{font-size:22px;font-weight:700;color:var(--green);}}
 header.bar .ttl{{font-weight:600;color:var(--green-deep);font-size:14px;}}
 header.bar .tag{{font-size:12px;color:var(--muted);}}
 header.bar .live{{margin-left:auto;display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted);
   background:var(--green-tint);border:1px solid var(--line);padding:5px 12px;border-radius:20px;}}
 header.bar .live .d{{width:8px;height:8px;border-radius:50%;background:var(--green-soft);}}
 .wrap{{max-width:1000px;margin:0 auto;padding:22px 18px 70px;position:relative;z-index:2;}}
 /* KPIs */
 .kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px;}}
 @media(max-width:640px){{.kpis{{grid-template-columns:repeat(2,1fr);}}}}
 .kpi{{position:relative;background:color-mix(in srgb,var(--surface) 88%,transparent);
   backdrop-filter:blur(10px) saturate(140%);-webkit-backdrop-filter:blur(10px) saturate(140%);
   border:1px solid var(--line);border-radius:16px;padding:15px 16px;box-shadow:var(--shadow);overflow:hidden;}}
 .kpi::before{{content:"";position:absolute;left:0;right:0;top:0;height:3px;background:var(--green-soft);}}
 .kpi.high::before{{background:var(--high);}} .kpi.medium::before{{background:var(--amber);}}
 .kpi.clean::before{{background:var(--green-soft);}}
 .kpi.tot::before{{background:linear-gradient(90deg,var(--green),var(--green-soft));}}
 .kpi .num{{font-size:26px;font-weight:700;line-height:1;color:var(--green-deep);}}
 .kpi.high .num{{color:var(--high);}} .kpi.medium .num{{color:var(--amber);}} .kpi.clean .num{{color:var(--green);}}
 .kpi .kpi-l{{font-size:11px;color:var(--muted);margin-top:5px;letter-spacing:.4px;text-transform:uppercase;font-weight:600;}}
 /* CARTES verre + liseré vert (signature du site) */
 .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;align-items:start;}}
 @media(max-width:720px){{.grid{{grid-template-columns:1fr;}}}}
 .card{{position:relative;background:color-mix(in srgb,var(--surface) 88%,transparent);
   backdrop-filter:blur(10px) saturate(140%);-webkit-backdrop-filter:blur(10px) saturate(140%);
   border:1px solid var(--line);border-radius:var(--radius);padding:22px;box-shadow:var(--shadow);overflow:hidden;}}
 .card::before{{content:"";position:absolute;left:0;right:0;top:0;height:3px;
   background:linear-gradient(90deg,var(--green),var(--green-soft));opacity:.9;}}
 h2{{font-size:14px;color:var(--green-deep);margin:0 0 14px;padding-bottom:7px;
   border-bottom:2px solid var(--amber);display:inline-block;letter-spacing:.2px;}}
 label{{display:block;font-size:11px;color:var(--muted);margin:12px 0 4px;font-weight:600;
   text-transform:uppercase;letter-spacing:.4px;}}
 input[type=text],input[type=number]{{width:100%;padding:10px 12px;border:1px solid var(--line);
   border-radius:11px;font-size:14px;font-family:inherit;background:#fff;color:var(--ink);transition:.15s;}}
 input::placeholder{{color:#b3ad9a;}}
 input:focus{{outline:none;border-color:var(--green-soft);box-shadow:0 0 0 3px var(--green-tint);}}
 textarea{{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:11px;font-size:13px;
   font-family:ui-monospace,monospace;background:#fff;color:var(--ink);resize:vertical;transition:.15s;}}
 textarea:focus{{outline:none;border-color:var(--green-soft);box-shadow:0 0 0 3px var(--green-tint);}}
 .adv{{display:flex;flex-direction:column;gap:14px;}}
 .advgrid{{display:grid;grid-template-columns:1fr 1fr;gap:10px 14px;}}
 @media(max-width:600px){{.advgrid{{grid-template-columns:1fr;}}}}
 .sevs{{display:flex;flex-wrap:wrap;gap:6px;}}
 .sev{{display:flex;align-items:center;gap:6px;font-size:12.5px;background:#fff;border:1px solid var(--line);
   border-radius:9px;padding:6px 11px;cursor:pointer;}}
 .sev input{{width:15px;height:15px;accent-color:var(--green);}}
 .presets{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px;}}
 .preset{{background:#fff;border:1.5px solid var(--green-soft);color:var(--green-deep);
   border-radius:20px;padding:6px 14px;font-size:12px;font-weight:600;cursor:pointer;transition:.15s;}}
 .preset:hover{{background:var(--green-soft);color:#fff;transform:translateY(-1px);}}
 .chk{{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:12px;font-size:14px;cursor:pointer;transition:.12s;}}
 .chk:hover{{background:var(--green-tint);}}
 .chk input{{width:18px;height:18px;accent-color:var(--green);cursor:pointer;}}
 .chk b{{font-weight:600;}} .chk small{{color:var(--muted);font-size:12px;}}
 .hint{{font-size:12px;color:var(--muted);margin:10px 2px 0;}}
 .eta{{font-size:12.5px;color:var(--muted);margin-top:12px;background:var(--green-tint);
   border:1px solid var(--line);border-radius:11px;padding:9px 13px;transition:.15s;}}
 .eta.warn{{background:rgba(180,131,42,.14);border-color:var(--amber);color:#7a5a12;}}
 .eta b{{color:var(--green-deep);}} .eta.warn b{{color:#7a5a12;}}
 .row{{display:flex;gap:10px;margin-top:16px;}}
 .btn{{flex:1;background:linear-gradient(135deg,var(--green),var(--green-deep));color:#fff;border:none;
   border-radius:12px;padding:13px;font-size:15px;font-weight:600;cursor:pointer;
   box-shadow:0 3px 12px rgba(64,91,57,.28);transition:.15s;}}
 .btn:hover:not(:disabled){{transform:translateY(-1px);box-shadow:0 5px 16px rgba(64,91,57,.34);}}
 .btn:disabled{{opacity:.45;cursor:not-allowed;box-shadow:none;}}
 .btn.stop{{background:var(--critical);flex:0 0 auto;padding:13px 18px;display:none;box-shadow:0 3px 12px rgba(179,40,45,.25);}}
 .console-head{{display:flex;align-items:center;gap:9px;margin-bottom:9px;font-size:12px;color:var(--muted);}}
 .console-head .d{{width:9px;height:9px;border-radius:50%;background:#c9c2b0;}}
 .console-head .d.run{{background:var(--amber);animation:pulse 1s infinite;}}
 .console-head .d.ok{{background:var(--green-soft);}}
 @keyframes pulse{{50%{{opacity:.25;}}}}
 .clr{{margin-left:auto;font-size:11px;border:1px solid var(--line);background:#fff;color:var(--muted);
   border-radius:8px;padding:4px 10px;cursor:pointer;font-family:inherit;}}
 .clr:hover{{border-color:var(--green-soft);color:var(--green-deep);}}
 pre{{background:#141f16;color:#d8e6da;border-radius:14px;padding:16px;font-size:12.5px;
   font-family:ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;max-height:360px;overflow:auto;
   min-height:96px;box-shadow:inset 0 2px 14px rgba(0,0,0,.30);border:1px solid #26331f;}}
 /* HISTORIQUE — panneaux verre par client */
 .cpanel{{position:relative;border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;
   box-shadow:var(--shadow);margin-bottom:14px;
   background:color-mix(in srgb,var(--surface) 88%,transparent);
   backdrop-filter:blur(10px) saturate(140%);-webkit-backdrop-filter:blur(10px) saturate(140%);}}
 .cpanel .head{{background:linear-gradient(135deg,var(--green),var(--green-deep));color:#fff;
   padding:11px 16px;display:flex;align-items:center;gap:10px;}}
 .cpanel .head .cname{{font-weight:600;font-size:14px;letter-spacing:.3px;}}
 .cpanel .head .badge{{font-size:9px;font-weight:700;background:var(--amber);color:#20291b;
   padding:2px 8px;border-radius:20px;letter-spacing:.5px;}}
 .cpanel .head .agg{{margin-left:auto;display:flex;gap:6px;align-items:center;font-size:12px;color:rgba(255,255,255,.78);}}
 .srow{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:12px 16px;border-top:1px solid var(--line);transition:.12s;}}
 .srow:hover{{background:var(--green-tint);}}
 .srow .tgt{{font-family:ui-monospace,monospace;font-weight:600;color:var(--green-deep);font-size:13.5px;}}
 .srow .dt{{font-size:11px;color:var(--muted);}}
 .acts{{display:flex;gap:6px;margin-left:auto;}}
 .act{{font-size:11px;border:1px solid var(--line);border-radius:8px;padding:4px 9px;color:var(--muted);
   text-decoration:none;cursor:pointer;background:#fff;font-weight:600;transition:.12s;}}
 .act:hover{{border-color:var(--green-soft);color:var(--green-deep);background:var(--green-tint);}}
 .act.rr{{border-style:dashed;}}
 .pill{{font-size:11px;font-weight:700;padding:2px 9px;border-radius:20px;color:#fff;white-space:nowrap;}}
 .pill.critical{{background:var(--critical);}} .pill.high{{background:var(--high);}}
 .pill.medium{{background:var(--amber);color:#2b2008;}} .pill.low{{background:var(--low);}}
 .pill.clean{{background:var(--green-soft);}}
 .empty{{color:var(--muted);text-align:center;padding:26px;font-size:13px;}}
 .sec-title{{font-size:15px;color:var(--green-deep);margin:24px 2px 12px;display:flex;align-items:center;gap:10px;}}
 .sec-title::after{{content:"";flex:1;height:1px;background:var(--line);}}
 footer{{text-align:center;color:var(--muted);font-size:12px;margin-top:30px;}}
</style></head><body>
 <header class="bar">
   {logo}<span class="tag">La technologie, en toute confiance.</span>
   <span class="live"><span class="d"></span>Console locale · :{PORT}</span>
 </header>
 <div class="wrap">

   <div class="kpis">
     <div class="kpi tot"><div class="num" id="k_scans">0</div><div class="kpi-l">Scans</div></div>
     <div class="kpi high"><div class="num" id="k_high">0</div><div class="kpi-l">Élevés</div></div>
     <div class="kpi medium"><div class="num" id="k_medium">0</div><div class="kpi-l">Moyens</div></div>
     <div class="kpi clean"><div class="num" id="k_clean">0</div><div class="kpi-l">Propres</div></div>
   </div>

   <div class="grid">
     <div class="card">
       <h2>Cible &amp; engagement</h2>
       <label>Cible — IP, CIDR ou domaine</label>
       <input type="text" id="target" placeholder="ex: 192.168.1.10 ou zunabo.com">
       <label>Client (rapport)</label>
       <input type="text" id="client" placeholder="optionnel — regroupe les scans">
       <label>Référence d'autorisation / périmètre</label>
       <input type="text" id="scope" placeholder="optionnel">
       <label>Opérateur</label>
       <input type="text" id="operator" placeholder="D4N">
     </div>
     <div class="card">
       <h2>Modules à exécuter</h2>
       <div class="presets">
         <button class="preset" onclick="preset('rapide')">⚡ Rapide</button>
         <button class="preset" onclick="preset('full')">🛠 Complet</button>
         <button class="preset" onclick="preset('deep')">🔬 Profond</button>
         <button class="preset" onclick="preset('web')">🌐 Web seul</button>
         <button class="preset" onclick="preset('passive')">🛰 Passif</button>
       </div>
       <label class="chk"><input type="checkbox" id="m_nuclei" checked>
         <span><b>Vulnérabilités (nuclei)</b><br><small>failles connues / CVE</small></span></label>
       <label class="chk"><input type="checkbox" id="m_surface" checked>
         <span><b>Surface &amp; takeover</b><br><small>hébergement tiers, DNS fantôme</small></span></label>
       <label class="chk"><input type="checkbox" id="m_deep">
         <span><b>Scan profond (nmap NSE)</b><br><small>failles réseau par port</small></span></label>
       <label class="chk"><input type="checkbox" id="m_full_ports">
         <span><b>Tous les ports</b><br><small>65535 au lieu du top-1000</small></span></label>
       <label class="chk"><input type="checkbox" id="m_passive">
         <span><b>Mode passif</b><br><small>sans scan de ports (idéal CDN)</small></span></label>
       <label class="chk"><input type="checkbox" id="m_shodan" checked>
         <span><b>Enrichissement Shodan</b><br><small>ports manqués, CVE, eol (gratuit, sans clé)</small></span></label>
       <p class="hint">Découverte de ports + sonde web tournent toujours (sauf en mode passif).</p>
       <div class="eta" id="eta"></div>
       <div class="row">
         <button class="btn" id="go" onclick="launch()">▶  Lancer le scan</button>
         <button class="btn stop" id="stop" onclick="stopScan()">■ Stop</button>
       </div>
     </div>
   </div>

   <div class="card" style="margin-top:16px">
     <h2>Options avancées</h2>
     <div class="adv">
       <div>
         <label>Sévérités remontées (nuclei)</label>
         <div class="sevs">
           <label class="sev"><input type="checkbox" id="s_critical" checked> Critique</label>
           <label class="sev"><input type="checkbox" id="s_high" checked> Élevée</label>
           <label class="sev"><input type="checkbox" id="s_medium" checked> Moyenne</label>
           <label class="sev"><input type="checkbox" id="s_low" checked> Faible</label>
           <label class="sev"><input type="checkbox" id="s_info"> Info</label>
         </div>
       </div>
       <div class="advgrid">
         <div><label>Plateforme attendue</label><input type="text" id="expected_platform" placeholder="ex: cloudflare"></div>
         <div><label>Débit (req/s)</label><input type="number" id="rate_limit" placeholder="illimité" min="0"></div>
         <div><label>Ports personnalisés</label><input type="text" id="ports" placeholder="ex: 80,443,8080"></div>
         <div><label>Tags nuclei</label><input type="text" id="tags" placeholder="ex: cve,rce"></div>
         <div><label>Proxy HTTP</label><input type="text" id="proxy" placeholder="http://127.0.0.1:8080"></div>
         <div><label>Templates nuclei</label><input type="text" id="templates" placeholder="dossier ou fichier"></div>
         <div><label>Exclure des hôtes</label><input type="text" id="exclude_hosts" placeholder="hôte1, hôte2"></div>
         <div><label>Exclure sévérités</label><input type="text" id="exclude_severity" placeholder="ex: info"></div>
       </div>
       <div>
         <label>En-têtes HTTP custom (un par ligne)</label>
         <textarea id="headers" rows="2" placeholder="Authorization: Bearer …&#10;X-Forwarded-For: 127.0.0.1"></textarea>
       </div>
       <label class="chk" style="padding-left:0"><input type="checkbox" id="no_auto">
         <span><b>Désactiver la sélection auto de templates (-as)</b><br><small>lance un balayage large au lieu de cibler selon la tech détectée</small></span></label>
     </div>
   </div>

   <div class="card" style="margin-top:16px">
     <h2>Sortie en direct</h2>
     <div class="console-head"><span class="d" id="dot"></span><span id="stxt">En attente</span>
       <button class="clr" onclick="clearOut()">Effacer</button></div>
     <pre id="out">En attente d'un scan…</pre>
   </div>

   <div class="sec-title">Historique par client</div>
   <div id="scans"><div class="empty">Chargement…</div></div>

   <footer>zunabo-scan · console locale · 127.0.0.1:{PORT} · jamais exposée au réseau</footer>
 </div>
<script>
let JOB=null;
const $=id=>document.getElementById(id);
function preset(p){{
  const s=(id,v)=>$(id).checked=v;
  const M={{rapide:[1,1,0,0,0,1],full:[1,1,1,1,0,1],deep:[1,1,1,0,0,1],web:[1,1,0,0,0,1],passive:[0,1,0,0,1,1]}}[p];
  ['m_nuclei','m_surface','m_deep','m_full_ports','m_passive','m_shodan'].forEach((id,i)=>s(id,!!M[i]));
  if(p==='rapide'||p==='web') $('rate_limit').value='';   // vitesse max
  updateEta();
}}
function updateEta(){{
  const on=id=>$(id).checked; const rate=parseInt($('rate_limit').value)||0;
  let sec=30;
  if(on('m_passive')) sec=45;
  else {{
    if(on('m_full_ports')) sec+= rate>0 ? Math.round(65535/rate) : 90;
    if(on('m_nuclei')) sec+=120;
    if(on('m_deep')) sec+=1500;
  }}
  let txt,warn=false;
  if(sec<90) txt="quelques instants (&lt; 2 min)";
  else {{ txt="~ "+Math.round(sec/60)+" min"; warn=sec>600; }}
  const e=$('eta');
  e.innerHTML="⏱ Durée estimée : <b>"+txt+"</b>"+(warn?" — long ; envisage sans « Tous les ports »":"");
  e.className="eta"+(warn?" warn":"");
}}
function setDot(k,t){{$('dot').className='d'+(k?' '+k:'');$('stxt').textContent=t;}}
function collectSeverities(){{
  const out=[];
  for(const [id,k] of [["s_critical","critical"],["s_high","high"],["s_medium","medium"],["s_low","low"],["s_info","info"]])
    if($(id).checked) out.push(k);
  return out;
}}
async function launch(){{
  const modules=[];
  for(const [id,key] of [["m_nuclei","nuclei"],["m_surface","surface"],["m_deep","deep"],
      ["m_full_ports","full_ports"],["m_passive","passive"],["m_shodan","shodan"]])
    if($(id).checked) modules.push(key);
  const body={{
    target:$('target').value,client:$('client').value,scope:$('scope').value,operator:$('operator').value,
    expected_platform:$('expected_platform').value,rate_limit:$('rate_limit').value,
    severity:collectSeverities(),tags:$('tags').value,ports:$('ports').value,proxy:$('proxy').value,
    templates:$('templates').value,exclude_severity:$('exclude_severity').value,
    exclude_hosts:$('exclude_hosts').value,headers:$('headers').value,no_auto:$('no_auto').checked,
    modules}};
  if(!body.target){{alert("Renseigne une cible.");return;}}
  $('go').disabled=true; $('stop').style.display='inline-block';
  setDot('run','Scan en cours…'); $('out').textContent="Démarrage…";
  const r=await fetch("/api/scan",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify(body)}});
  const j=await r.json();
  if(j.error){{$('out').textContent="Erreur : "+j.error;done();return;}}
  JOB=j.job; poll();
}}
async function poll(){{
  const r=await fetch("/api/status?job="+JOB); const j=await r.json();
  $('out').textContent=j.output||"…"; $('out').scrollTop=$('out').scrollHeight;
  if(j.done){{done();setDot('ok','Terminé');loadScans();}} else setTimeout(poll,1400);
}}
function done(){{$('go').disabled=false;$('stop').style.display='none';}}
async function stopScan(){{ if(JOB) await fetch("/api/stop?job="+JOB); }}
function clearOut(){{$('out').textContent="En attente d'un scan…";setDot('','En attente');}}
function pills(c){{
  const n=(c.critical||0)+(c.high||0)+(c.medium||0)+(c.low||0);
  if(!n) return '<span class="pill clean">propre</span>';
  return (c.critical?'<span class="pill critical">'+c.critical+' crit</span>':'')
    +(c.high?'<span class="pill high">'+c.high+' élevé</span>':'')
    +(c.medium?'<span class="pill medium">'+c.medium+' moyen</span>':'')
    +(c.low?'<span class="pill low">'+c.low+' faible</span>':'');
}}
async function loadScans(){{
  const r=await fetch("/api/scans"); const list=await r.json();
  // KPIs
  let hi=0,me=0,cl=0;
  list.forEach(s=>{{const c=s.resume||{{}};hi+=c.high||0;me+=c.medium||0;
    if(!((c.critical||0)+(c.high||0)+(c.medium||0)+(c.low||0)))cl++;}});
  $('k_scans').textContent=list.length;$('k_high').textContent=hi;
  $('k_medium').textContent=me;$('k_clean').textContent=cl;
  // groupes
  const box=$('scans');
  if(!list.length){{box.innerHTML='<div class="empty">Aucun scan pour l\\'instant — lance ton premier audit ci-dessus.</div>';return;}}
  // list arrive déjà triée du plus récent au plus ancien (côté serveur).
  const groups={{}}; const keys=[]; const seen={{}};
  list.forEach(s=>{{const k=s.client||"— Sans client —";
    if(!seen[k]){{seen[k]=1;keys.push(k);}}          // groupes ordonnés par scan le plus récent
    (groups[k]=groups[k]||[]).push(s);}});           // lignes déjà récentes→anciennes
  const rep=(d,f,l,cls)=>'<a class="act '+(cls||'')+'" href="/report?dir='+encodeURIComponent(d)+'&file='+f+'" target="_blank">'+l+'</a>';
  box.innerHTML=keys.map(k=>{{
    const g=groups[k]; const isC=!k.startsWith('—');
    let agg={{}};g.forEach(s=>{{const c=s.resume||{{}};for(const kk in c)agg[kk]=(agg[kk]||0)+c[kk];}});
    const rows=g.map(s=>
      '<div class="srow"><span class="tgt">'+(s.target||s.name)+'</span>'
      +'<span class="dt">'+(s.date||'')+'</span> '+pills(s.resume||{{}})
      +'<span class="acts">'+rep(s.name,'rapport.html','HTML')+rep(s.name,'rapport.docx','Word')
      +rep(s.name,'rapport.json','JSON')+rep(s.name,'scan.log','Journal')
      +'<button class="act rr" onclick="rerun(\\''+s.target+'\\')">↻</button></span></div>').join("");
    return '<div class="cpanel"><div class="head">'
      +(isC?'<span class="badge">CLIENT</span>':'')
      +'<span class="cname">'+k+'</span>'
      +'<span class="agg">'+g.length+' scan(s) &nbsp; '+pills(agg)+'</span></div>'+rows+'</div>';
  }}).join("");
}}
function rerun(t){{$('target').value=t;window.scrollTo({{top:0,behavior:'smooth'}});$('target').focus();}}
['m_nuclei','m_surface','m_deep','m_full_ports','m_passive'].forEach(id=>$(id).addEventListener('change',updateEta));
$('rate_limit').addEventListener('input',updateEta);
updateEta();
loadScans();
</script></body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  Serveur HTTP
# ─────────────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # silence

    def _send(self, code, body, ctype="application/json"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self._send(200, page(), "text/html; charset=utf-8")
        if u.path == "/api/scans":
            return self._send(200, json.dumps(list_scans()))
        if u.path == "/api/status":
            job = parse_qs(u.query).get("job", [""])[0]
            j = JOBS.get(job)
            if not j:
                return self._send(404, json.dumps({"error": "job inconnu"}))
            return self._send(200, json.dumps(
                {"output": j["output"], "done": j["done"], "outdir": j.get("outdir")}))
        if u.path == "/api/stop":
            job = parse_qs(u.query).get("job", [""])[0]
            j = JOBS.get(job)
            if j and j.get("proc") and not j["done"]:
                try:
                    j["proc"].terminate()
                    j["output"] += "\n[arrêté par l'opérateur]\n"
                except Exception:
                    pass
            return self._send(200, json.dumps({"ok": True}))
        if u.path == "/report":
            q = parse_qs(u.query)
            path = _safe_report(q.get("dir", [""])[0], q.get("file", ["rapport.html"])[0])
            if not path:
                return self._send(404, "introuvable", "text/plain")
            ext = os.path.splitext(path)[1].lower()
            ctype = {
                ".html": "text/html; charset=utf-8",
                ".json": "application/json",
                ".md": "text/markdown; charset=utf-8",
                ".log": "text/plain; charset=utf-8",
                ".jsonl": "text/plain; charset=utf-8",
                ".txt": "text/plain; charset=utf-8",
                ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            }.get(ext, "application/octet-stream")
            with open(path, "rb") as f:
                return self._send(200, f.read(), ctype)
        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/api/scan":
            return self._send(404, json.dumps({"error": "not found"}))
        n = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(n) or "{}")
            argv = build_command(data)
        except Exception as e:
            return self._send(200, json.dumps({"error": str(e)}))
        job_id = uuid.uuid4().hex[:12]
        JOBS[job_id] = {"output": "$ " + " ".join(argv) + "\n", "done": False,
                        "outdir": None, "rc": None, "proc": None}
        threading.Thread(target=_run_job, args=(job_id, argv), daemon=True).start()
        return self._send(200, json.dumps({"job": job_id}))


def _unlock_at_start():
    """Demande le code une fois, le garde en mémoire pour les sous-process."""
    global _UNLOCK
    if not _HAS_AUTH:
        print("[verrou] zunabo_auth.py introuvable — arrêt.", file=sys.stderr)
        sys.exit(3)
    if not auth.is_configured():
        print("Aucun code défini. Lance d'abord un scan en CLI pour le créer.", file=sys.stderr)
        sys.exit(3)
    import getpass
    for _ in range(3):
        code = getpass.getpass("🔒 Code secret Zunabo : ")
        if auth.verify(code):
            _UNLOCK = code
            return
        print("   Code incorrect.")
    sys.exit(3)


def main():
    if not os.path.exists(SCAN_SCRIPT):
        print(f"[erreur] {SCAN_SCRIPT} introuvable. Lance la console depuis "
              "le dossier du toolkit.", file=sys.stderr)
        sys.exit(2)
    _unlock_at_start()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"\n  Console Zunabo prête → http://127.0.0.1:{PORT}\n"
          f"  (Ctrl+C pour arrêter)\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
zunabo_report.py — Générateur de rapport de pentest .docx (charte Zunabo).

Transforme le rapport.json d'un scan zunabo-scan en un livrable Word branché
(logo officiel + couleurs Zunabo), calé sur le formulaire d'autorisation.

Le contenu s'adapte : rapport « propre » si aucune faille, rempli de constats
Critique/Élevé s'il y a de la matière.

Usage :
    import zunabo_report as report
    report.build(scan_json_path, out_docx_path)

    # ou en autonome sur un dossier de scan :
    python3 zunabo_report.py scan_<cible>_<date>/rapport.json

Dépendance : python-docx  (pip install python-docx)
"""

import base64
import json
import os
import sys
import tempfile
from datetime import datetime

try:
    from docx import Document
    from docx.shared import Pt, RGBColor, Cm
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    _HAS_DOCX = True
except ImportError:
    _HAS_DOCX = False

try:
    import zunabo_brand as brand
    P = brand.PALETTE
    _LOGO_B64 = brand.LOGO_B64
except Exception:
    # Repli si la charte n'est pas importable : palette admin en dur
    P = {"green_deep": "33492e", "sage": "7ba073", "gold": "c19a3e",
         "paper": "f6f4ec", "ink": "20291b", "muted": "5c6a51", "line": "e2ddcf",
         "critical": "b3282d", "high": "d9642a", "medium": "c19a3e",
         "low": "3f7d8c", "info": "8a9a80"}
    _LOGO_B64 = ""

# Couleurs (le formulaire d'autorisation utilise 405B39 pour les titres)
GREEN = "405B39"
GREEN2 = P.get("green_deep", "33492e").lstrip("#")
GOLD = P.get("gold", "c19a3e").lstrip("#")
CREAM = "F6F4EC"
LINE = "E0DCC9"
INK = P.get("ink", "20291b").lstrip("#")
MUTED = P.get("muted", "5c6a51").lstrip("#")
SEV_HEX = {k: P.get(k, "8a9a80").lstrip("#") for k in ("critical", "high", "medium", "low", "info")}
SEV_FR = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne",
          "low": "Faible", "info": "Informative"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
FONT = "Calibri"
TAGLINE = "La technologie, en toute confiance."


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers bas niveau
# ─────────────────────────────────────────────────────────────────────────────
def _rgb(hexs):
    return RGBColor.from_string(hexs.lstrip("#").upper())


def _run(p, text, size=10.5, bold=False, italic=False, color=INK):
    r = p.add_run(text)
    r.font.name = FONT
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.italic = italic
    r.font.color.rgb = _rgb(color)
    return r


def _bottom_border(p, color=GOLD, sz=12, space=1):
    pPr = p._p.get_or_add_pPr()
    pbdr = OxmlElement("w:pBdr")
    b = OxmlElement("w:bottom")
    b.set(qn("w:val"), "single"); b.set(qn("w:sz"), str(sz))
    b.set(qn("w:space"), str(space)); b.set(qn("w:color"), color)
    pbdr.append(b); pPr.append(pbdr)


def _shade(cell, fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear"); shd.set(qn("w:fill"), fill); shd.set(qn("w:color"), "auto")
    tcPr.append(shd)


def _table_borders(table, color=LINE, sz=4):
    tblPr = table._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        e = OxmlElement(f"w:{edge}")
        e.set(qn("w:val"), "single"); e.set(qn("w:sz"), str(sz))
        e.set(qn("w:space"), "0"); e.set(qn("w:color"), color)
        borders.append(e)
    tblPr.append(borders)


def _cell(cell, text, size=10, bold=False, color=INK, align=None, fill=None):
    if fill:
        _shade(cell, fill)
    cell.paragraphs[0].clear()
    p = cell.paragraphs[0]
    if align:
        p.alignment = align
    _run(p, text, size=size, bold=bold, color=color)


def _heading(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(16)
    p.paragraph_format.space_after = Pt(7)
    _run(p, text, size=13, bold=True, color=GREEN)
    _bottom_border(p, color=LINE, sz=6, space=4)
    return p


def _para(doc, text, justify=True, size=10.5, color=INK, before=0, after=6):
    p = doc.add_paragraph()
    if justify:
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_before = Pt(before)
    p.paragraph_format.space_after = Pt(after)
    _run(p, text, size=size, color=color)
    return p


def _bullet(doc, text, num=False):
    p = doc.add_paragraph(style="List Number" if num else "List Bullet")
    p.paragraph_format.space_after = Pt(4)
    _run(p, text, size=10.5, color=INK)
    return p


def _subhead(doc, text, size=11, color=GREEN):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(3)
    _run(p, text, size=size, bold=True, color=color)
    return p


def _page_number_footer(section):
    p = section.footer.paragraphs[0]
    p.clear()
    _run(p, "Zunabo  ·  contact@zunabo.com  ·  zunabo.com        ", size=8, color=MUTED)
    _run(p, "Page ", size=8, color=MUTED)
    _add_field(p, "PAGE")
    _run(p, " / ", size=8, color=MUTED)
    _add_field(p, "NUMPAGES")


def _add_field(paragraph, field):
    r = paragraph.add_run()
    fldc = OxmlElement("w:fldChar"); fldc.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText"); instr.set(qn("xml:space"), "preserve"); instr.text = f" {field} "
    fld2 = OxmlElement("w:fldChar"); fld2.set(qn("w:fldCharType"), "end")
    r._r.append(fldc); r._r.append(instr); r._r.append(fld2)
    r.font.size = Pt(8); r.font.color.rgb = _rgb(MUTED); r.font.name = FONT


# ─────────────────────────────────────────────────────────────────────────────
#  Construction
# ─────────────────────────────────────────────────────────────────────────────
def build(scan_json_path, out_path=None):
    if not _HAS_DOCX:
        raise RuntimeError("python-docx absent (pip install python-docx).")

    with open(scan_json_path) as f:
        data = json.load(f)

    eng = data.get("engagement", {}) or {}
    resume = data.get("resume", {}) or {}
    findings = data.get("vulnerabilites", []) or []
    services = (data.get("surface", {}) or {}).get("services", []) or []
    observations = data.get("observations", []) or []
    kind = (data.get("kind") or "network").lower()
    is_mobile = kind == "mobile"
    is_web = kind == "web"
    is_wifi = kind == "wifi"
    app = data.get("application", {}) or {}
    web = data.get("web", {}) or {}
    wifi = data.get("wifi", {}) or {}

    if out_path is None:
        out_path = os.path.join(os.path.dirname(scan_json_path), "rapport.docx")

    doc = Document()
    # marges + police par défaut
    for s in doc.sections:
        s.top_margin = s.bottom_margin = Cm(2.5)
        s.left_margin = s.right_margin = Cm(2.5)
    style = doc.styles["Normal"]
    style.font.name = FONT
    style.font.size = Pt(10.5)
    style.font.color.rgb = _rgb(INK)

    # ── En-tête de marque : logo officiel ──
    if _LOGO_B64:
        logo_bytes = base64.b64decode(_LOGO_B64)
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        tmp.write(logo_bytes); tmp.close()
        pic_p = doc.add_paragraph()
        pic_p.paragraph_format.space_after = Pt(3)
        pic_p.add_run().add_picture(tmp.name, width=Cm(5.4))
        os.unlink(tmp.name)
    else:
        p = doc.add_paragraph(); _run(p, "zunabo", size=22, bold=True, color=GREEN)

    p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(10)
    _run(p, TAGLINE, size=9, italic=True, color=MUTED)

    p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(2)
    _title = ("Rapport d'analyse de sécurité mobile" if is_mobile
              else "Rapport de test d'intrusion web" if is_web
              else "Rapport d'audit Wi-Fi" if is_wifi
              else "Rapport de test d'intrusion")
    _sub = ("Analyse statique d'application Android (OWASP MASVS/MASTG)" if is_mobile
            else "Application web (OWASP Top 10 / WSTG)" if is_web
            else "Audit de réseau sans fil (suite aircrack-ng)" if is_wifi
            else "Évaluation de la surface réseau")
    _run(p, _title, size=20, bold=True, color=GREEN2)
    p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(3)
    _run(p, _sub, size=12, color=MUTED)
    rule = doc.add_paragraph(); rule.paragraph_format.space_after = Pt(10)
    _bottom_border(rule, color=GOLD, sz=16)

    # ── Bloc d'engagement (mappé sur le formulaire) ──
    ref = eng.get("ref") or f"ZNB-PT-{datetime.now():%Y}-001"
    rows = [
        ("Référence de dossier", ref),
        ("Prestataire", "Zunabo — Dan Ibiliabo (D4N), Fondateur & CEO"),
        ("Client", eng.get("client") or "—"),
        ("Application" if is_mobile else "Périmètre autorisé", eng.get("target", "—")),
        ("Fenêtre d'engagement", eng.get("date", "—")),
        ("Référence d'autorisation", eng.get("scope") or "—"),
        ("Outil", f"zunabo-mobile v{data.get('version', '1.0')} (androguard, OWASP MASVS/MASTG)"
                  if is_mobile else
                  f"zunabo-web v{data.get('version', '1.0')} (OWASP Top 10 / WSTG)" if is_web else
                  f"zunabo-wifi v{data.get('version', '1.0')} (suite aircrack-ng)" if is_wifi else
                  f"zunabo-scan v{data.get('version', '2.0')} (naabu, httpx, nuclei, nmap NSE)"),
        ("Date du rapport", datetime.now().strftime("%d/%m/%Y")),
        ("Classification", "Confidentiel"),
    ]
    t = doc.add_table(rows=len(rows), cols=2)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    _table_borders(t)
    t.columns[0].width = Cm(4.7); t.columns[1].width = Cm(11.3)
    for i, (k, v) in enumerate(rows):
        t.rows[i].cells[0].width = Cm(4.7); t.rows[i].cells[1].width = Cm(11.3)
        _cell(t.rows[i].cells[0], k, bold=True, color=GREEN, fill=CREAM)
        _cell(t.rows[i].cells[1], v)
    note = doc.add_paragraph(); note.paragraph_format.space_before = Pt(4); note.paragraph_format.space_after = Pt(6)
    _run(note, "Ce rapport constitue le livrable prévu à la section 8 du formulaire d'autorisation "
               "Zunabo. Pour une mission client, le bloc ci-dessus reprend les informations du "
               "formulaire signé (sections 2, 4 et 5).", size=9, italic=True, color=MUTED)

    # ── 1. Résumé exécutif (dynamique) ──
    crit, high, med = resume.get("critical", 0), resume.get("high", 0), resume.get("medium", 0)
    low, info = resume.get("low", 0), resume.get("info", 0)
    total = crit + high + med + low + info
    nserv = len(services)

    _heading(doc, "1.  Résumé exécutif")
    if is_mobile:
        _para(doc, "Une analyse statique de sécurité a été menée sur l'application mobile identifiée "
                   "ci-dessus, sans l'exécuter ni l'installer. L'objectif était d'évaluer sa "
                   "configuration (manifeste, permissions, composants exposés, signature) et de "
                   "repérer les faiblesses de codage (secrets en dur, communications en clair), "
                   "selon le référentiel OWASP MASVS/MASTG.")
    elif is_web:
        _para(doc, "Un test d'intrusion a été mené sur l'application web identifiée ci-dessus. "
                   "L'objectif était d'évaluer sa surface exposée (pages, formulaires, paramètres), "
                   "sa configuration de sécurité (en-têtes, cookies, TLS) et sa résistance aux "
                   "attaques classiques (injection, XSS, redirection ouverte, CORS), selon le "
                   "référentiel OWASP Top 10 / WSTG. Les tests ont été non destructifs.")
    elif is_wifi:
        _para(doc, "Un audit de sécurité des réseaux sans fil a été mené sur la zone autorisée. "
                   "L'objectif était de cartographier les points d'accès et clients, d'évaluer leur "
                   "configuration de chiffrement (WEP/WPA/WPA2/WPA3, WPS), de détecter d'éventuels "
                   "points d'accès pirates, et, sur la cible autorisée, d'éprouver la robustesse de "
                   "la passphrase par un test de crack hors-ligne.")
    else:
        _para(doc, "Un test d'intrusion de la surface réseau a été mené sur le périmètre défini "
                   "ci-dessus. L'objectif était d'évaluer l'exposition des services et de valider, "
                   "par la preuve, toute vulnérabilité détectée.")
    if crit + high == 0 and med == 0:
        verdict = ("Résultat global : la posture de sécurité est solide. Aucune vulnérabilité "
                   "exploitable n'a été identifiée dans le périmètre. "
                   + (f"Le balayage a relevé {nserv} service(s) exposé(s). " if nserv else
                      "Aucun service exposé n'a été détecté. ")
                   + ("Une observation de niveau informatif est relevée." if info else
                      "Aucun constat n'est à signaler."))
        urgence = ("Aucune action corrective urgente n'est requise. Les recommandations "
                   "formulées relèvent de l'hygiène de sécurité et du maintien en condition.")
    else:
        verdict = (f"Résultat global : {total} constat(s) ont été identifiés, dont "
                   f"{crit} critique(s), {high} élevé(s) et {med} moyen(s). "
                   "Des vulnérabilités exploitables sont présentes dans le périmètre.")
        urgence = ("Une action corrective est requise. Les constats de gravité critique et élevée "
                   "doivent être traités en priorité, avant toute mise en production ou exposition.")
    _para(doc, verdict)
    _para(doc, urgence)

    # ── 2. Périmètre et autorisation ──
    _heading(doc, "2.  Périmètre et autorisation")
    if is_mobile:
        _para(doc, "L'analyse a porté strictement sur l'artefact applicatif autorisé :", justify=False, after=3)
        _bullet(doc, f"Application : {eng.get('target', '—')}"
                + (f" (v{app.get('version_name')})" if app.get("version_name") else ""))
        _bullet(doc, f"Fichier analysé : {app.get('file', '—')}")
        _bullet(doc, f"SDK minimal / cible : {app.get('min_sdk', '—')} / {app.get('target_sdk', '—')}")
        _para(doc, "Aucune infrastructure tierce n'a été sollicitée. L'application n'a été ni "
                   "installée, ni exécutée, ni contactée sur le réseau : l'analyse est purement "
                   "statique et non destructive.")
    elif is_web:
        _para(doc, "Le test a porté strictement sur la cible autorisée :", justify=False, after=3)
        _bullet(doc, f"Cible : {eng.get('target', '—')}")
        _bullet(doc, f"Surface explorée : {web.get('pages', 0)} page(s), "
                f"{web.get('forms', 0)} formulaire(s), {web.get('params', 0)} paramètre(s)")
        _para(doc, "Aucun système tiers n'a été ciblé. Les tests actifs ont utilisé des marqueurs "
                   "inoffensifs, sans écriture destructive ni déni de service.")
    elif is_wifi:
        _para(doc, "L'audit a porté strictement sur la zone autorisée :", justify=False, after=3)
        _bullet(doc, f"Zone / cible : {eng.get('target', '—')}")
        _bullet(doc, f"Surface observée : {wifi.get('aps', 0)} point(s) d'accès, "
                f"{wifi.get('stations', 0)} client(s)")
        _para(doc, "Les étapes actives (capture de handshake, crack) ont été limitées à la cible "
                   "explicitement déclarée. Aucune désauthentification large ni déni de service n'a "
                   "été réalisé.")
    else:
        _para(doc, "Le test a porté strictement sur le périmètre autorisé :", justify=False, after=3)
        _bullet(doc, f"Cible : {eng.get('target', '—')}")
        if services:
            svc_line = ", ".join(sorted({f"{s.get('port')}/{s.get('proto')}" for s in services if s.get('port')}))
            _bullet(doc, f"Services découverts : {svc_line}")
        _para(doc, "Aucun système tiers n'a été ciblé. Aucune exploitation active ni attaque par déni "
                   "de service n'a été menée, conformément à une approche de validation non destructive "
                   "(section 7 du formulaire).")

    # ── 3. Méthodologie ──
    _heading(doc, "3.  Méthodologie")
    if is_mobile:
        _para(doc, "L'évaluation a suivi une chaîne d'analyse statique automatisée :", justify=False, after=3)
        _bullet(doc, "Décompression de l'APK et lecture du manifeste (composants, drapeaux, SDK).", num=True)
        _bullet(doc, "Inventaire des permissions et des composants exportés (surface IPC).", num=True)
        _bullet(doc, "Contrôle du certificat de signature (algorithme, schéma v1/v2/v3).", num=True)
        _bullet(doc, "Balayage du bytecode (DEX) : secrets en dur, URL en clair.", num=True)
        _para(doc, "Chaque constat porte un niveau de confiance (Confirmé / Potentiel). Les constats "
                   "« Potentiel » doivent être confirmés par une analyse dynamique ou une revue de code. "
                   "Aucune exploitation active n'a été réalisée.")
    elif is_web:
        _para(doc, "L'évaluation a suivi une méthodologie de test applicatif automatisée :", justify=False, after=3)
        _bullet(doc, "Reconnaissance — crawl du périmètre (pages, formulaires, paramètres, endpoints JS).", num=True)
        _bullet(doc, "Analyse passive — en-têtes de sécurité, cookies, TLS, fingerprint, fuites d'info.", num=True)
        _bullet(doc, "Tests actifs non destructifs — XSS réfléchi, injection SQL, redirection ouverte, CORS.", num=True)
        _para(doc, "Chaque constat porte un niveau de confiance (Confirmé / Potentiel). Les constats "
                   "« Potentiel » sont à confirmer manuellement. L'exploitation approfondie relève d'une "
                   "phase ultérieure, manuelle et délibérée.")
    elif is_wifi:
        _para(doc, "L'audit a suivi une méthodologie sans fil standard (suite aircrack-ng) :", justify=False, after=3)
        _bullet(doc, "Reconnaissance — scan des points d'accès et clients (airodump-ng).", num=True)
        _bullet(doc, "Audit de configuration — chiffrement (WEP/WPA/WPA2/WPA3), WPS, réseaux ouverts, rogue AP.", num=True)
        _bullet(doc, "Capture ciblée — handshake WPA / PMKID sur la cible autorisée (déauth ciblé).", num=True)
        _bullet(doc, "Crack hors-ligne — test de robustesse de la passphrase par dictionnaire.", num=True)
        _para(doc, "Chaque constat porte un niveau de confiance (Confirmé / Potentiel). Les étapes "
                   "actives ont été strictement limitées à la cible autorisée, sans déni de service.")
    else:
        _para(doc, "L'évaluation a suivi un pipeline de reconnaissance et de détection automatisé :", justify=False, after=3)
        _bullet(doc, "Découverte de ports — balayage (naabu), avec repli nmap.", num=True)
        _bullet(doc, "Sonde applicative — services web et empreinte technologique (httpx).", num=True)
        _bullet(doc, "Détection de vulnérabilités — nuclei (sélection automatique par technologie) "
                     "puis scripts NSE « vuln » de nmap.", num=True)
    if not is_mobile and not is_web and not is_wifi:
        if any("dns" in (o.get("tag", "") or "") for o in observations) or \
           any(s.get("port") == "53" for s in services):
            _bullet(doc, "Vérification ciblée — test du résolveur DNS (récursion, version).", num=True)
        _para(doc, "Chaque constat est accompagné d'un niveau de confiance (Confirmé / Potentiel) et de "
                   "la preuve technique non destructive associée. Aucune exploitation active n'a été "
                   "réalisée : celle-ci relève d'une phase ultérieure, manuelle et délibérée.")

    # ── 4. Synthèse ──
    _heading(doc, "4.  Synthèse des résultats")
    st = doc.add_table(rows=1 + len(SEV_ORDER), cols=2)
    st.alignment = WD_TABLE_ALIGNMENT.CENTER
    _table_borders(st)
    st.columns[0].width = Cm(8); st.columns[1].width = Cm(8)
    _cell(st.rows[0].cells[0], "Gravité", bold=True, color="FFFFFF", fill=GREEN2)
    _cell(st.rows[0].cells[1], "Nombre de constats", bold=True, color="FFFFFF",
          fill=GREEN2, align=WD_ALIGN_PARAGRAPH.CENTER)
    for i, sev in enumerate(SEV_ORDER, start=1):
        st.rows[i].cells[0].width = Cm(8); st.rows[i].cells[1].width = Cm(8)
        _cell(st.rows[i].cells[0], SEV_FR[sev], bold=True, color=SEV_HEX[sev])
        _cell(st.rows[i].cells[1], str(resume.get(sev, 0)), align=WD_ALIGN_PARAGRAPH.CENTER)
    p = doc.add_paragraph(); p.paragraph_format.space_before = Pt(6); p.paragraph_format.space_after = Pt(6)
    exploit = crit + high + med
    _run(p, f"Total : {total} constat(s)"
            + (f", dont {exploit} exploitable(s)." if exploit else " (aucun exploitable)."),
         size=10.5, bold=True, color=GREEN)

    # ── 5. Constats détaillés ──
    _heading(doc, "5.  Constats détaillés")
    if not findings:
        _para(doc, "Aucun constat n'a été relevé sur le périmètre testé.")
    for idx, f in enumerate(findings, start=1):
        sev = f.get("severity", "info")
        code = f"{SEV_FR.get(sev, 'INFO')[:4].upper()}-{idx:02d}"
        _subhead(doc, f"{code} — {f.get('name', '?')}", size=11.5, color=GREEN2)
        ft = doc.add_table(rows=4, cols=2)
        _table_borders(ft)
        ft.columns[0].width = Cm(4.7); ft.columns[1].width = Cm(11.3)
        meta_rows = [
            ("Gravité", SEV_FR.get(sev, "Informative")),
            ("Confiance", (f.get("confidence") or "—").capitalize()
             + (f" · CVSS {f['cvss']}" if f.get("cvss") else "")),
            ("Actif concerné", f.get("target", "—")),
            ("Preuve", _evidence_line(f)),
        ]
        for r, (k, v) in enumerate(meta_rows):
            ft.rows[r].cells[0].width = Cm(4.7); ft.rows[r].cells[1].width = Cm(11.3)
            _cell(ft.rows[r].cells[0], k, bold=True, color=GREEN, fill=CREAM)
            _cell(ft.rows[r].cells[1], v)
        if f.get("description"):
            _subhead(doc, "Description")
            _para(doc, f["description"])
        if f.get("cve"):
            _subhead(doc, "Références")
            _para(doc, ", ".join(f["cve"]) + (
                " — " + "; ".join(f.get("references", [])[:3]) if f.get("references") else ""))

    # ── 6. Points forts / observations ──
    strengths = []
    if crit + high + med == 0:
        strengths.append("Aucune vulnérabilité exploitable détectée sur le périmètre.")
    if nserv == 0:
        strengths.append("Aucun service exposé sur la cible au moment du test.")
    for o in observations:
        strengths.append(o.get("text", "") if isinstance(o, dict) else str(o))
    if strengths:
        _heading(doc, "6.  Points forts et observations")
        for s in strengths:
            if s:
                _bullet(doc, s)

    # ── 7. Recommandations ──
    _heading(doc, "7.  Recommandations")
    recs = []
    if crit + high > 0:
        recs.append("Corriger en priorité les vulnérabilités critiques et élevées avant toute publication.")
    if is_mobile:
        recs += [
            "Désactiver android:debuggable et android:allowBackup dans les builds de production.",
            "Ne jamais embarquer de secret (clé, mot de passe, jeton) dans l'APK ; recourir à un "
            "coffre côté serveur et à l'Android Keystore.",
            "Restreindre les composants exportés : android:exported=\"false\" par défaut, sinon "
            "protéger par une permission de signature.",
            "Interdire le trafic en clair via une Network Security Config (cleartextTrafficPermitted=false).",
            "Signer en schéma v2/v3 (SHA-256) et relever le minSdkVersion à une version maintenue.",
            "Compléter par une analyse dynamique (exécution instrumentée) pour confirmer les constats « Potentiel ».",
        ]
    elif is_web:
        recs += [
            "Utiliser des requêtes préparées (paramétrées) pour toute interaction avec la base (anti-SQLi).",
            "Encoder toute sortie selon son contexte et déployer une Content-Security-Policy stricte (anti-XSS).",
            "Positionner les en-têtes de sécurité (HSTS, X-Frame-Options/frame-ancestors, X-Content-Type-Options).",
            "Marquer les cookies de session HttpOnly, Secure et SameSite.",
            "Restreindre les redirections et le CORS à une liste blanche d'origines/destinations de confiance.",
            "Renvoyer des erreurs génériques et retirer les fichiers sensibles exposés (.git, .env, sauvegardes).",
        ]
    elif is_wifi:
        recs += [
            "Abandonner WEP et les réseaux ouverts ; imposer WPA2-CCMP au minimum, viser WPA3 (SAE).",
            "Désactiver le WPS sur tous les points d'accès.",
            "Utiliser des passphrases longues et aléatoires (≥ 16 caractères), non devinables.",
            "Interdire TKIP ; n'autoriser que CCMP (AES).",
            "Surveiller les points d'accès pirates (rogue AP / evil-twin) usurpant les ESSID légitimes.",
            "Isoler les clients (client isolation) et séparer le réseau invité du réseau interne.",
        ]
    else:
        recs += [
            "Maintenir les systèmes et firmwares à jour pour bénéficier des correctifs de sécurité.",
            "Réduire la surface exposée : désactiver les services non nécessaires, fermer les ports inutiles.",
            "Renforcer les identifiants d'administration (remplacer tout mot de passe par défaut).",
            "Re-scanner périodiquement la surface externe depuis un point de vue tiers.",
            "Segmenter le réseau afin d'isoler les équipements sensibles.",
        ]
    for r in recs:
        _bullet(doc, r, num=True)

    # ── 8. Conclusion ──
    _heading(doc, "8.  Conclusion")
    if crit + high + med == 0:
        _para(doc, "Au moment du test, le périmètre évalué présente une posture de sécurité solide : "
                   "aucune vulnérabilité confirmée exploitable. Les recommandations ci-dessus visent "
                   "le maintien de ce niveau de sécurité dans la durée.")
    else:
        _para(doc, "Le périmètre évalué présente des vulnérabilités exploitables nécessitant une "
                   "remédiation. Un nouveau test de validation est recommandé après application des "
                   "correctifs afin de confirmer leur efficacité.")

    # ── Annexe ──
    _heading(doc, "Annexe — Portée et avertissement")
    _para(doc, f"Ce rapport reflète l'état du périmètre au moment du test ({eng.get('date', '')}). "
               "Il repose sur un scan automatisé complété, le cas échéant, de vérifications ciblées ; "
               "il ne constitue pas un test manuel applicatif approfondi. L'absence de constat "
               "exploitable ne garantit pas l'absence de toute vulnérabilité en toute circonstance.")
    _para(doc, "Conformément à la section 8 du formulaire d'autorisation, les preuves techniques "
               "collectées sont conservées de façon sécurisée le temps de la rédaction, puis détruites "
               "dans un délai de 30 jours après remise du rapport, sauf demande écrite contraire. "
               "Le présent document est confidentiel.")

    _page_number_footer(doc.sections[0])
    doc.save(out_path)
    return out_path


def _evidence_line(f):
    parts = []
    if f.get("matcher"):
        parts.append(f"matcher={f['matcher']}")
    if f.get("extracted"):
        parts.append("extrait: " + " · ".join(str(x) for x in f["extracted"][:5]))
    if not parts and f.get("evidence"):
        parts.append(f["evidence"][:200].replace("\n", " "))
    return " ; ".join(parts) if parts else "—"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage : python3 zunabo_report.py <rapport.json> [sortie.docx]")
        sys.exit(1)
    out = build(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    print("Rapport .docx généré :", out)

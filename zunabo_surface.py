#!/usr/bin/env python3
"""
zunabo_surface.py — Analyse de surface & détection de subdomain takeover.

Transforme les données httpx (déjà collectées par zunabo-scan) en constats :
  • Signatures de takeover connues (S3 « NoSuchBucket », GitHub Pages, Heroku,
    Vercel, Netlify, Fastly, Azure…) → constat de gravité élevée.
  • Hébergement sur une plateforme tierce inattendue (différente de la plateforme
    « attendue » du domaine) → constat Moyen à vérifier (DNS potentiellement
    fantôme).
  • Sinon, chaque plateforme détectée est journalisée en observation.

Non destructif : au plus une requête GET (lecture) par service web candidat.
Référence des signatures : projet public can-i-take-over-xyz.
"""

import ssl
import urllib.request

# Détection de plateforme à partir de serveur / techno / titre
PLATFORM_SIGNS = {
    "Cloudflare":      ["cloudflare"],
    "Vercel":          ["vercel"],
    "AWS CloudFront":  ["cloudfront"],
    "Amazon S3":       ["amazons3", "amazon s3", "s3-website"],
    "GitHub Pages":    ["github.io", "github pages", "githubusercontent"],
    "Netlify":         ["netlify"],
    "Heroku":          ["heroku"],
    "Fastly":          ["fastly"],
    "Azure":           ["azurewebsites", "windows-azure", "azureedge"],
    "Shopify":         ["shopify"],
    "Firebase":        ["firebaseapp", "firebase"],
    "Pantheon":        ["pantheon"],
}

# Signatures de takeover (plateforme, aiguille en minuscules, gravité)
TAKEOVER_SIGNS = [
    ("Amazon S3",      "the specified bucket does not exist", "high"),
    ("Amazon S3",      "nosuchbucket",                         "high"),
    ("GitHub Pages",   "there isn't a github pages site here", "high"),
    ("Heroku",         "no such app",                          "high"),
    ("Heroku",         "no-such-app",                          "high"),
    ("Vercel",         "deployment_not_found",                 "high"),
    ("Vercel",         "the deployment could not be found",    "high"),
    ("Netlify",        "not found - request id",               "medium"),
    ("Fastly",         "fastly error: unknown domain",         "high"),
    ("Shopify",        "sorry, this shop is currently unavailable", "medium"),
    ("Azure",          "404 web site not found",               "high"),
    ("Firebase",       "site not found",                       "medium"),
    ("Pantheon",       "the gods are wise",                    "high"),
]

_REF = "https://github.com/EdOverflow/can-i-take-over-xyz"


def _platform(meta):
    hay = " ".join([
        meta.get("webserver", ""),
        " ".join(meta.get("tech", []) or []),
        meta.get("title", ""),
    ]).lower()
    for name, keys in PLATFORM_SIGNS.items():
        if any(k in hay for k in keys):
            return name
    return None


def _fetch_body(url, timeout=6, maxbytes=20000):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "zunabo-scan/surface"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(maxbytes).decode("utf-8", "replace")
    except Exception:
        return ""


def _finding(w, plat, sev, desc, evidence, confidence):
    return {
        "source": "surface",
        "target": w.get("url", ""),
        "name": f"Hébergement tiers — {plat}",
        "severity": sev,
        "description": desc,
        "references": [_REF],
        "cve": [], "cvss": None,
        "tags": ["dns", "takeover", plat.lower().replace(" ", "-")],
        "confidence": confidence,
        "matcher": plat,
        "extracted": [],
        "evidence": (evidence or "")[:300],
    }


def analyze(web_meta, expected_platform=None, fetch=True):
    """
    Renvoie (findings, observations).
      expected_platform : nom (ex. 'cloudflare') ; tout hôte sur une AUTRE
        plateforme est alors remonté en constat Moyen.
    """
    findings, observations, seen = [], [], set()
    exp = (expected_platform or "").strip().lower()

    for w in web_meta:
        plat = _platform(w)
        if not plat:
            continue

        body = _fetch_body(w["url"]) if fetch else (w.get("_body", "") or "")
        hay = " ".join([body, w.get("title", ""), w.get("webserver", "")]).lower()

        # 1) Signature de takeover confirmée ?
        hit = next((t for t in TAKEOVER_SIGNS if t[0] == plat and t[1] in hay), None)
        if hit:
            findings.append(_finding(
                w, plat, hit[2],
                f"Signature de subdomain takeover détectée sur {plat}. La ressource "
                "pointée par le DNS semble non réclamée : un tiers pourrait la revendiquer "
                "et servir son contenu sous votre domaine (phishing, vol de session).",
                evidence=hit[1], confidence="confirmé"))
            continue

        # 2) Plateforme tierce différente de l'attendue ?
        if exp and exp not in plat.lower():
            findings.append(_finding(
                w, plat, "medium",
                f"Ce service est hébergé sur {plat}, différent de la plateforme attendue "
                f"({expected_platform}). À vérifier : enregistrement DNS potentiellement "
                "fantôme pointant vers une ressource tierce (risque de subdomain takeover).",
                evidence=f"HTTP {w.get('status','')} · {w.get('title','')} · srv={w.get('webserver','')}",
                confidence="potentiel"))
            continue

        # 3) Sinon : simple observation (contexte)
        key = (plat, w.get("url", "").split("//")[-1].split(":")[0])
        if key not in seen:
            seen.add(key)
            observations.append({"tag": "surface",
                                 "text": f"{w.get('url','')} hébergé sur {plat}."})

    return findings, observations

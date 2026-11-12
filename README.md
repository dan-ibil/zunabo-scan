# zunabo-scan v2

Orchestrateur d'audit de vulnérabilités — **collection Zunabo**.
Pipeline moderne façon ProjectDiscovery, avec repli automatique sur nmap.

```
[domaine]  subfinder → dnsx ─┐
                             ├→ naabu ──→ httpx ──→ nuclei ──→ rapport
[IP / CIDR] ─────────────────┘  (ports)  (web+tech) (vulns)
```

> Outil professionnel destiné aux audits Zunabo. Le périmètre relève de
> l'opérateur — renseigne `--client` / `--scope` pour le tracer dans le rapport.

---

## Nouveautés v2

| Domaine | v1 | v2 |
|---------|----|----|
| Découverte ports | nmap | **naabu** (rapide) + repli nmap |
| Sonde web | URLs devinées | **httpx** : titre, statut, serveur, **fingerprint tech** |
| Vulns | nuclei severity | **nuclei `-as`** (templates auto selon la tech), CVSS, tags |
| Cibles | IP / CIDR | + **domaines** (énum. sous-domaines) |
| Rapports | JSON + HTML | + **Markdown** + **SARIF** (natif nuclei) |
| Automation | — | **`--ci`** avec code de sortie par seuil de sévérité |
| Engagement | prompt bloquant | **métadonnées optionnelles** dans le rapport |
| Preuve | — | **Confirmé / Potentiel** + section *Preuve* par finding |

Le prompt d'autorisation bloquant a été retiré : l'outil tourne directement,
comme n'importe quel outil pro. À la place, `--client` et `--scope` documentent
le périmètre dans l'en-tête du rapport (utile pour tes livrables clients).

**Couche preuve** : chaque finding porte un niveau de confiance (**Confirmé** si
le matcher a déclenché / **Potentiel** pour les indices) et une section *Preuve*
dépliable (matcher, donnée extraite, extrait de réponse). C'est l'évidence non
destructive qui montre que la faille est réelle — sans l'exploiter.

> **Pas d'exploitation active dans l'outil, volontairement.** `zunabo-scan`
> détecte et *valide par preuve* ; il n'exécute aucun exploit. L'exploitation
> reste une étape **manuelle et délibérée** (Metasploit, PoC ciblé), sous ton
> RoE — jamais tirée en automatique sur une simple IP.

---

## Prérequis (sur thebeast)

Tout est **optionnel sauf un** moteur de découverte (naabu **ou** nmap) et,
pour les vulns, nuclei. L'outil détecte ce qui est présent et s'adapte.

```bash
# Suite ProjectDiscovery (recommandée) — nécessite Go
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Repli / deep-scan
sudo apt install -y nmap

# naabu a besoin de libpcap
sudo apt install -y libpcap-dev
```

Python 3.8+, **stdlib uniquement** (zéro dépendance pip).

> **Charte graphique** : le fichier `zunabo_brand.py` doit rester **à côté** de
> `zunabo_scan.py`. C'est la source unique du thème Zunabo (logo, couleurs, police)
> — tous les futurs outils l'importeront pour un rendu cohérent. Sans lui, le
> rapport HTML retombe sur un style minimal mais reste fonctionnel.

---

## Verrou d'accès 🔒

Les outils sont protégés par un **code secret** (`zunabo_auth.py`, module partagé).

- **1er lancement** : l'outil te demande de définir un code (≥ 6 caractères).
- **Ensuite** : le code est exigé avant toute action.
- Le code n'est jamais stocké en clair — seul un **hash PBKDF2 salé** (200 000
  itérations) est écrit dans `~/.zunabo/auth.json` (permissions `0600`).
- **Anti-force-brute** : blocage 5 min après 5 échecs.
- **Fail-closed** : si `zunabo_auth.py` est absent, l'outil refuse de démarrer.

```bash
python3 zunabo_auth.py --status    # état du verrou
python3 zunabo_auth.py --change    # changer le code (exige l'ancien)
```

**Automatisation** (scans planifiés / CI) : définir `ZUNABO_UNLOCK=<code>` permet
une exécution non interactive.

```bash
ZUNABO_UNLOCK="ton-code" python3 zunabo_scan.py cible.com --ci
```

> ⚠️ **Portée honnête** : ce verrou dissuade un usage occasionnel par un tiers
> ayant accès à ta machine. Ce n'est **pas** un coffre-fort : qui peut éditer le
> `.py` peut retirer le verrou. Pour un vrai « inexécutable sans le code », il
> faut chiffrer le code de l'outil (payload chiffré) — mécanisme séparé.

---

## Utilisation

```bash
# Audit standard d'une IP
python3 zunabo_scan.py 192.168.1.10

# Un domaine (avec énum. sous-domaines)
python3 zunabo_scan.py exemple-client.com

# Livrable client tracé + scan profond
python3 zunabo_scan.py 10.0.0.0/24 \
  --client "ACME Corp" --scope "RoE #2026-014" --deep

# Intégration CI : échoue si une vuln ≥ high
python3 zunabo_scan.py app.client.com --ci --fail-on high

# Tous ports, débit limité (discret)
python3 zunabo_scan.py 192.168.1.10 --full-ports --rate-limit 150
```

### Options clés

| Flag | Effet |
|------|-------|
| `--full-ports` | 65535 ports au lieu du top-1000 |
| `--deep` | Ajoute `nmap -sV` + scripts NSE `vuln` |
| `--no-auto` | Désactive `nuclei -as` (sélection auto par tech) |
| `--tags cve,rce` | Tags nuclei additionnels |
| `--rate-limit N` | Limite req/s (discrétion / cibles fragiles) |
| `--client` / `--scope` | Métadonnées d'engagement (rapport) |
| `--ci` / `--fail-on` | Code de sortie non nul par seuil de sévérité |
| `-s / --exclude-severity` | Filtre les sévérités nuclei |

---

## Sorties

Dans le dossier horodaté :

- `rapport.html` — livrable lisible (surface d'attaque + vulns + tech)
- `rapport.md` — version Markdown (à coller dans un rapport plus large)
- `rapport.json` — données structurées
- `nuclei.sarif` — pour GitHub Security / outils SAST
- `httpx.json`, `ports.json`, `nuclei.jsonl`, `nuclei_markdown/` — brut par moteur

---

## Notes de terrain

- **naabu** en `-p -` (full) veut souvent les privilèges root pour le SYN scan.
- **`nuclei -as`** ne teste que ce qui correspond à la tech détectée par httpx —
  plus rapide et moins bruyant, mais lance `--no-auto` pour un balayage exhaustif.
- Les CVE remontées par nuclei sont **taggées à la source** (classification) ;
  elles reflètent l'état courant des templates communautaires.
- Aucun résultat automatisé n'est un verdict : c'est un accélérateur de recon.

---

*zunabo-scan v2 · D4N · boîte à outils Zunabo.*

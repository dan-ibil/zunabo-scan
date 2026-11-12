#!/usr/bin/env python3
"""
zunabo_auth.py — Verrou d'accès partagé pour les outils Zunabo.

Chaque outil appelle `require_unlock("nom")` au démarrage :
  • Première utilisation  → définition du code secret (saisi deux fois).
  • Utilisations suivantes → saisie du code exigée avant toute action.

Le code n'est JAMAIS stocké en clair : seul un hash PBKDF2-HMAC-SHA256 salé
(200 000 itérations) est écrit dans ~/.zunabo/auth.json (permissions 0600).
Protection anti-force-brute : blocage temporaire après plusieurs échecs.

⚠️  PORTÉE (à lire) :
    C'est un dissuasif contre un usage occasionnel par un tiers ayant accès
    à la machine. Ce n'est PAS un coffre-fort : quiconque peut éditer le .py
    peut retirer l'appel au verrou. Pour un vrai « inexécutable sans le code »,
    il faut chiffrer le code de l'outil (payload chiffré) — autre mécanisme.

Automatisation (scans planifiés / CI) :
    Définir la variable d'environnement ZUNABO_UNLOCK avec le code permet une
    exécution non interactive. Pratique, mais moins sûr (le code transite en
    variable d'env) — à réserver aux tâches de fond maîtrisées.

Utilitaire en ligne de commande :
    python3 zunabo_auth.py --change   # changer le code (exige l'ancien)
    python3 zunabo_auth.py --status   # état du verrou
"""

import getpass
import hashlib
import hmac
import json
import os
import stat
import sys
import time

CONFIG_DIR = os.path.expanduser("~/.zunabo")
AUTH_FILE = os.path.join(CONFIG_DIR, "auth.json")

ITERATIONS = 200_000
MIN_LEN = 6
MAX_ATTEMPTS = 5           # échecs avant blocage
LOCKOUT_SECONDS = 300      # durée du blocage (5 min)
ENV_OVERRIDE = "ZUNABO_UNLOCK"

_GREEN = "\033[32m"; _RED = "\033[31m"; _YEL = "\033[33m"; _DIM = "\033[2m"; _RST = "\033[0m"


def _c(t, c):
    return t if not sys.stdout.isatty() else f"{c}{t}{_RST}"


# ─────────────────────────────────────────────────────────────────────────────
#  Stockage
# ─────────────────────────────────────────────────────────────────────────────
def _ensure_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, stat.S_IRWXU)  # 0700
    except OSError:
        pass


def _load():
    if not os.path.exists(AUTH_FILE):
        return {}
    try:
        with open(AUTH_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data):
    _ensure_dir()
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, AUTH_FILE)
    try:
        os.chmod(AUTH_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  Cryptographie du code
# ─────────────────────────────────────────────────────────────────────────────
def _derive(code, salt, iterations=ITERATIONS):
    return hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt, iterations)


def is_configured():
    return bool(_load().get("hash"))


def set_code(code):
    """Définit (ou remplace) le code. Renvoie (ok, message)."""
    if len(code) < MIN_LEN:
        return False, f"Le code doit faire au moins {MIN_LEN} caractères."
    salt = os.urandom(16)
    digest = _derive(code, salt)
    data = _load()
    data.update({
        "salt": salt.hex(),
        "hash": digest.hex(),
        "iterations": ITERATIONS,
        "algo": "pbkdf2_sha256",
        "updated": int(time.time()),
        "fails": 0,
        "lock_until": 0,
    })
    _save(data)
    return True, "Code enregistré."


def verify(code):
    """Compare en temps constant. Renvoie True/False."""
    data = _load()
    if not data.get("hash"):
        return False
    salt = bytes.fromhex(data["salt"])
    iterations = data.get("iterations", ITERATIONS)
    expected = bytes.fromhex(data["hash"])
    candidate = _derive(code, salt, iterations)
    return hmac.compare_digest(candidate, expected)


# ─────────────────────────────────────────────────────────────────────────────
#  État de blocage (anti-force-brute)
# ─────────────────────────────────────────────────────────────────────────────
def _now():
    return int(time.time())


def _locked_remaining():
    return max(0, _load().get("lock_until", 0) - _now())


def _register_fail():
    data = _load()
    data["fails"] = data.get("fails", 0) + 1
    if data["fails"] >= MAX_ATTEMPTS:
        data["lock_until"] = _now() + LOCKOUT_SECONDS
        data["fails"] = 0
    _save(data)


def _register_success():
    data = _load()
    data["fails"] = 0
    data["lock_until"] = 0
    _save(data)


# ─────────────────────────────────────────────────────────────────────────────
#  Flux interactifs
# ─────────────────────────────────────────────────────────────────────────────
def _first_run_setup(app):
    print(_c("╭─ Premier lancement — verrouillage Zunabo", _GREEN))
    print(f"│ Aucun code n'est encore défini pour les outils Zunabo.")
    print(f"│ Choisis un code secret (≥ {MIN_LEN} caractères). Il protégera « {app} »")
    print(f"│ et tout autre outil Zunabo sur cette machine.")
    for _ in range(3):
        c1 = getpass.getpass("╰─ Nouveau code : ")
        if len(c1) < MIN_LEN:
            print(_c(f"   Trop court (min {MIN_LEN}).", _YEL)); continue
        c2 = getpass.getpass("   Confirme le code : ")
        if c1 != c2:
            print(_c("   Les deux saisies diffèrent.", _YEL)); continue
        ok, msg = set_code(c1)
        if ok:
            print(_c("   ✓ " + msg + " Verrou actif.", _GREEN))
            return True
        print(_c("   " + msg, _YEL))
    print(_c("   Échec de la définition du code. Arrêt.", _RED))
    return False


def require_unlock(app="Zunabo", interactive=True):
    """
    Point d'entrée à appeler au démarrage de chaque outil.
    Sort le programme (sys.exit) si l'accès est refusé.
    """
    # 1) Override par variable d'environnement (automatisation)
    env_code = os.environ.get(ENV_OVERRIDE)
    if env_code is not None:
        if is_configured() and verify(env_code):
            _register_success()
            return True
        print(_c(f"[verrou] Code {ENV_OVERRIDE} invalide.", _RED), file=sys.stderr)
        sys.exit(3)

    # 2) Non interactif sans override → refus (fail closed)
    if not interactive or not sys.stdin.isatty():
        print(_c(f"[verrou] Session non interactive : définis {ENV_OVERRIDE}.", _RED),
              file=sys.stderr)
        sys.exit(3)

    # 3) Blocage en cours ?
    rem = _locked_remaining()
    if rem > 0:
        print(_c(f"[verrou] Trop d'échecs. Réessaie dans {rem // 60}m{rem % 60:02d}s.", _RED),
              file=sys.stderr)
        sys.exit(3)

    # 4) Première utilisation → définition
    if not is_configured():
        if _first_run_setup(app):
            return True
        sys.exit(3)

    # 5) Saisie normale
    data = _load()
    remaining = MAX_ATTEMPTS - data.get("fails", 0)
    print(_c(f"🔒 {app} — accès protégé Zunabo", _GREEN))
    while remaining > 0:
        code = getpass.getpass("   Code secret : ")
        if verify(code):
            _register_success()
            print(_c("   ✓ Accès autorisé.", _GREEN))
            return True
        _register_fail()
        if _locked_remaining() > 0:
            print(_c(f"   Trop d'échecs. Verrou {LOCKOUT_SECONDS // 60} min.", _RED),
                  file=sys.stderr)
            sys.exit(3)
        remaining -= 1
        print(_c(f"   Code incorrect. {remaining} essai(s) restant(s).", _YEL))
    sys.exit(3)


def change_code():
    """Change le code : exige l'ancien, puis en définit un nouveau."""
    if not is_configured():
        print("Aucun code défini. Lance un outil pour le configurer.")
        return
    old = getpass.getpass("Code actuel : ")
    if not verify(old):
        print(_c("Code actuel incorrect.", _RED)); return
    for _ in range(3):
        n1 = getpass.getpass(f"Nouveau code (≥ {MIN_LEN}) : ")
        n2 = getpass.getpass("Confirme : ")
        if n1 != n2:
            print(_c("Les saisies diffèrent.", _YEL)); continue
        ok, msg = set_code(n1)
        print(_c(("✓ " if ok else "") + msg, _GREEN if ok else _YEL))
        if ok:
            return


def _status():
    data = _load()
    if not data.get("hash"):
        print("Verrou : non configuré (sera défini au 1er lancement).")
        return
    rem = _locked_remaining()
    print("Verrou Zunabo : ACTIF")
    print(f"  Fichier   : {AUTH_FILE}")
    print(f"  Algo      : {data.get('algo')} × {data.get('iterations')}")
    print(f"  Échecs    : {data.get('fails', 0)}/{MAX_ATTEMPTS}")
    print(f"  Blocage   : {'oui, ' + str(rem) + 's restantes' if rem else 'non'}")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "--status"
    if arg == "--change":
        change_code()
    elif arg == "--status":
        _status()
    else:
        print("Usage : python3 zunabo_auth.py [--change|--status]")

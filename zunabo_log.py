#!/usr/bin/env python3
"""
zunabo_log.py — Journalisation complète pour zunabo-scan.

Écrit TOUT ce que l'outil rencontre dans le dossier de scan :
  • scan.log      — journal lisible, horodaté (narratif + données + commandes).
  • events.jsonl  — un événement JSON par ligne, pour analyse fine
                    (grep / jq / ré-import) : hôtes, ports, services web,
                    commandes exécutées, constats, observations, erreurs.

Rien n'est perdu : chaque hôte découvert, chaque port ouvert, chaque service
web (avec tous ses champs httpx), chaque commande (avec code retour et stderr),
chaque constat et chaque erreur est journalisé, pour approfondir après coup.
"""

import json
import os
from datetime import datetime, timezone


def _short(v, n=200):
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + "…"


class RunLogger:
    def __init__(self, outdir):
        self.dir = outdir
        self._txt = open(os.path.join(outdir, "scan.log"), "a", encoding="utf-8")
        self._jsonl = open(os.path.join(outdir, "events.jsonl"), "a", encoding="utf-8")
        self.counts = {}

    @staticmethod
    def _ts():
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def event(self, level, stage, event, **data):
        """Événement structuré → events.jsonl + ligne lisible → scan.log."""
        ts = self._ts()
        rec = {"ts": ts, "level": level, "stage": stage, "event": event, "data": data}
        self._jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self._jsonl.flush()
        line = f"[{ts}] {level.upper():7} {stage:10} {event}"
        if data:
            line += " | " + "  ".join(f"{k}={_short(str(v), 120)}" for k, v in data.items())
        self._txt.write(line + "\n")
        self._txt.flush()
        self.counts[level] = self.counts.get(level, 0) + 1

    def line(self, text, level="log", stage="-"):
        """Ligne narrative simple (reprend ce que le terminal affiche)."""
        ts = self._ts()
        self._txt.write(f"[{ts}] {level.upper():7} {stage:10} {text}\n")
        self._txt.flush()

    def cmd(self, stage, argv, rc, stderr=""):
        self.event("cmd", stage, "exec", cmdline=" ".join(argv), rc=rc,
                   stderr=(stderr or "").strip()[:300])

    def data(self, stage, event, item):
        """Journalise un élément rencontré (hôte, port, service web…)."""
        self.event("data", stage, event, **(item if isinstance(item, dict) else {"value": item}))

    def finding(self, f):
        self.event("finding", f.get("source", "-"), "finding",
                   severity=f.get("severity"), name=f.get("name"),
                   target=f.get("target"), confidence=f.get("confidence"),
                   cve=",".join(f.get("cve", []) or []))

    def close(self, summary=None):
        if summary:
            self.event("session", "-", "end", **summary)
        for h in (self._txt, self._jsonl):
            try:
                h.close()
            except Exception:
                pass

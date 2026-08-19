"""
templates.py — validated firmware templates with per-model release history.

A "template" is a known-good device (curef + friendly name + the FOTA mode it
uses) plus a *history* of the firmware releases we've seen for it. Each release
records tv / fw_id and the date it first showed up, so:

  * a model can carry several firmware versions over time (they don't collapse
    to one — TCL ships new builds and we keep the trail),
  * `refresh()` re-checks the live server and appends anything new, stamped with
    today's date, and
  * listings can flag a recently-dropped build as NEW.

Downloads still resolve live (see fota.resolve) — the history is a record, never
a stale substitute for the current target.

Storage: tcl_fw/data/templates.json (schema 1).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Optional

from . import fota

_DATA_FILE = Path(__file__).resolve().parent / "data" / "templates.json"

# A release counts as "new" for this many days after we first see it.
NEW_WINDOW_DAYS = 21


@dataclass
class Release:
    tv: str
    fw_id: str
    first_seen: str            # YYYY-MM-DD — when this build first appeared here
    last_seen: str             # YYYY-MM-DD — last refresh that still saw it live

    def is_new(self, today: Optional[str] = None) -> bool:
        """True if first_seen is within NEW_WINDOW_DAYS of `today`."""
        try:
            seen = date.fromisoformat(self.first_seen)
            now = date.fromisoformat(today) if today else date.today()
        except ValueError:
            return False
        return 0 <= (now - seen).days <= NEW_WINDOW_DAYS


@dataclass
class Template:
    curef: str
    name: str = ""
    mode: int = 4              # the FOTA mode this device actually serves
    releases: list[Release] = field(default_factory=list)

    def latest(self) -> Optional[Release]:
        """Most recently first-seen release (the current build we know of)."""
        return max(self.releases, key=lambda r: r.first_seen) if self.releases else None

    def find(self, tv: str, fw_id: str) -> Optional[Release]:
        for r in self.releases:
            if r.tv == tv and r.fw_id == fw_id:
                return r
        return None


def _today() -> str:
    return date.today().isoformat()


def load() -> list[Template]:
    """Read templates.json. Returns [] if it's missing or unreadable."""
    try:
        raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []
    out: list[Template] = []
    for d in raw.get("devices", []):
        cu = d.get("curef")
        if not cu:
            continue
        rels = [
            Release(r["tv"], r["fw_id"],
                    r.get("first_seen", _today()), r.get("last_seen", r.get("first_seen", _today())))
            for r in d.get("releases", [])
            if r.get("tv") and r.get("fw_id")
        ]
        out.append(Template(cu, d.get("name", ""), int(d.get("mode", 4)), rels))
    return out


def save(templates: list[Template]) -> None:
    """Write templates.json (sorted by name for stable diffs)."""
    payload = {
        "schema": 1,
        "devices": [
            {
                "curef": t.curef,
                "name": t.name,
                "mode": t.mode,
                "releases": [
                    {"tv": r.tv, "fw_id": r.fw_id,
                     "first_seen": r.first_seen, "last_seen": r.last_seen}
                    for r in sorted(t.releases, key=lambda r: r.first_seen)
                ],
            }
            for t in sorted(templates, key=lambda t: (t.name or t.curef).lower())
        ],
    }
    _DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    _DATA_FILE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def refresh(
    templates: Optional[list[Template]] = None,
    today: Optional[str] = None,
    discover: Callable[[str, int], tuple[Optional[str], Optional[str]]] | None = None,
) -> list[tuple[str, str, str]]:
    """Re-check every template against the live server. Append any release we
    haven't recorded (stamped `today`) and bump last_seen on ones we still see.

    `discover(curef, mode) -> (tv, fw_id)` is injectable for testing; it defaults
    to a live fota.resolve. Returns the list of newly-added (curef, tv, fw_id).
    Does not save — the caller decides (so a dry run is possible).
    """
    today = today or _today()
    tpls = templates if templates is not None else load()

    def _live(curef: str, mode: int) -> tuple[Optional[str], Optional[str]]:
        _, tv, fw = fota.resolve(curef, mode=mode)
        return tv, fw

    disc = discover or _live
    added: list[tuple[str, str, str]] = []
    for t in tpls:
        tv, fw = disc(t.curef, t.mode)
        if not (tv and fw):
            continue
        rel = t.find(tv, fw)
        if rel:
            rel.last_seen = today
        else:
            t.releases.append(Release(tv, fw, first_seen=today, last_seen=today))
            added.append((t.curef, tv, fw))
    return added

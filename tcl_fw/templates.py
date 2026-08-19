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
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable, Optional

from . import fota, sharing

AUTOSYNC_INTERVAL = 86400  # seconds — pull the community list at most once a day

# Bundled, curated templates (committed to the repo).
_DATA_FILE = Path(__file__).resolve().parent / "data" / "templates.json"


def _local_file() -> Path:
    """User-writable overlay where auto-grown (server-sourced) devices land."""
    return sharing.config_dir() / "templates.local.json"

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


def _read_file(path: Path) -> list[Template]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
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


def _merge(into: dict[str, Template], extra: list[Template]) -> None:
    """Merge `extra` templates into a curef-keyed dict, combining releases and
    keeping the earliest first_seen for any shared build."""
    for t in extra:
        cur = into.get(t.curef)
        if not cur:
            into[t.curef] = Template(t.curef, t.name, t.mode, list(t.releases))
            continue
        if t.name and not cur.name:
            cur.name = t.name
        for r in t.releases:
            ex = cur.find(r.tv, r.fw_id)
            if ex:
                if r.first_seen and r.first_seen < ex.first_seen:
                    ex.first_seen = r.first_seen
                if r.last_seen and r.last_seen > ex.last_seen:
                    ex.last_seen = r.last_seen
            else:
                cur.releases.append(Release(r.tv, r.fw_id, r.first_seen, r.last_seen))


def load() -> list[Template]:
    """All templates: the bundled curated set overlaid with the user-local,
    auto-grown set pulled from the community server."""
    merged: dict[str, Template] = {}
    _merge(merged, _read_file(_DATA_FILE))
    _merge(merged, _read_file(_local_file()))
    return list(merged.values())


def load_bundled() -> list[Template]:
    """Only the curated, committed templates (used by the maintainer `refresh`)."""
    return _read_file(_DATA_FILE)


def _write(path: Path, templates: list[Template]) -> None:
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def save(templates: list[Template]) -> None:
    """Write the bundled curated templates.json (sorted for stable diffs)."""
    _write(_DATA_FILE, templates)


def save_local(templates: list[Template]) -> None:
    """Write the user-local, auto-grown overlay."""
    _write(_local_file(), templates)


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


def _fetch_feed(url: str) -> Optional[dict]:
    try:
        req = urllib.request.Request(url + "/api/templates",
                                     headers={"User-Agent": f"tcl-fw/{sharing.__version__}"})
        with urllib.request.urlopen(req, timeout=6) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def pull_from_server(
    url: Optional[str] = None,
    fetch: Optional[Callable[[str], Optional[dict]]] = None,
) -> list[tuple[str, str, str]]:
    """Pull the community template feed and merge any device/release we don't
    already have (bundled or local) into the user-local overlay — this is how a
    combination recorded by one user 'writes itself into' everyone's tool.

    Returns the newly-added (curef, tv, fw_id). Network-safe: on any failure it
    returns [] and changes nothing. `fetch` is injectable for tests.
    """
    url = (url or sharing.server_url()).rstrip("/")
    if not url:
        return []
    data = (fetch or _fetch_feed)(url)
    if not data:
        return []

    bundled = {t.curef: t for t in load_bundled()}
    localset = {t.curef: t for t in _read_file(_local_file())}
    added: list[tuple[str, str, str]] = []

    for d in data.get("devices", []):
        curef = d.get("curef")
        if not curef:
            continue
        mode = int(d.get("mode", 4))
        name = d.get("name", "")
        for r in d.get("releases", []):
            tv, fw = r.get("tv"), r.get("fw_id")
            if not (tv and fw):
                continue
            if curef in bundled and bundled[curef].find(tv, fw):
                continue  # already shipped in the curated set
            if curef in localset and localset[curef].find(tv, fw):
                continue  # already pulled previously
            first = r.get("first_seen", _today())
            _merge(localset, [Template(curef, name, mode, [Release(tv, fw, first, first)])])
            added.append((curef, tv, fw))

    if added:
        save_local(list(localset.values()))
    return added


def autosync_if_due() -> None:
    """Background, throttled, opt-out-gated pull of the community device list.
    Non-blocking and failure-proof — call it freely at startup (CLI + GUI)."""
    try:
        if not sharing.is_enabled():
            return
        if time.time() - sharing.last_sync() < AUTOSYNC_INTERVAL:
            return
        sharing.mark_sync()
        threading.Thread(target=pull_from_server, daemon=True).start()
    except Exception:
        pass

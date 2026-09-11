"""
devices.py — the curef database and resolution helpers.

A curef (e.g. "T704SP-EAUHUS12-V") is TCL's product/build identifier. Given a
curef we can pull firmware; the trick is helping a user find theirs. Three ways,
in order of least effort:

  1. auto-detect from a plugged-in phone (see adb.py),
  2. pick a device by friendly name from this bundled table (+ a community
     data/devices.json overlay), or
  3. type the curef directly (adb shell getprop ro.tct.curef).

The built-in table carries live-confirmed tv/fw_id so those models resolve
without a network round-trip; unknown curefs fall back to fota.discover().
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import fota


@dataclass
class KnownDevice:
    curef: str
    tv: Optional[str] = None
    fw_id: Optional[str] = None
    name: str = ""
    source: str = "builtin"     # builtin | bundled | community


# Live-confirmed models (curef -> tv, fw_id, marketing name).
_BUILTIN: dict[str, tuple[str, str, str]] = {
    "T704SP-EAUHUS12-V": ("6CEVPPV0", "969459", "Verizon / Ruby_VZW / 50 XL NXTPAPER"),
    "T513Z-2ARXUS12-V":  ("9GCAZDA0", "975861", "Dish / Beryl_Dish"),
    "T702W-2ATBUS12":    ("6AASWTS0", "964377", "T-Mobile / Goldfinch_TMO"),
    "T702Z-EARXUS12-V":  ("ARATZDT0", "965341", "Dish-Boost / Goldfinch"),
    "T704SP-2AUHUS12-V": ("6CEVPPV0", "969453", "Verizon (2A variant)"),
    "T513Z-EARXUS12-V":  ("9GCAZDA0", "975713", "Dish (EA variant)"),
}

_DATA_FILE = Path(__file__).resolve().parent / "data" / "devices.json"


def _load_overlay() -> dict[str, KnownDevice]:
    """Community additions from data/devices.json, if present. Each entry:
    {"curef": ..., "tv": ..., "fw_id": ..., "name": ...} (tv/fw_id optional)."""
    out: dict[str, KnownDevice] = {}
    try:
        raw = json.loads(_DATA_FILE.read_text())
    except Exception:
        return out
    for e in raw if isinstance(raw, list) else raw.get("devices", []):
        cu = e.get("curef")
        if cu:
            out[cu] = KnownDevice(cu, e.get("tv"), e.get("fw_id"), e.get("name", ""))
    return out


def model_of(curef: str) -> str:
    """The model code a curef starts with: T807D1-2CLCA112 -> T807D1."""
    return (curef or "").split("-")[0].strip().upper()


def _name_index() -> dict[str, str]:
    """model code -> marketing name, learned from every named entry we ship.

    Community curefs arrive from the server with no name (the client never
    submits one), but a sibling variant of the same model usually is named —
    so T807W-2ATBUS12 can borrow T807W-EATBUS12-V's "TCL 50 XL 5G"."""
    idx: dict[str, str] = {}
    for cu, (_tv, _fw, nm) in _BUILTIN.items():
        if nm:
            idx.setdefault(model_of(cu), nm)
    for d in _load_overlay().values():
        if d.name:
            idx.setdefault(model_of(d.curef), d.name)
    try:
        from . import templates as _tpl
        for t in _tpl.load_bundled():
            if t.name:
                idx.setdefault(model_of(t.curef), t.name)
    except Exception:
        pass
    return idx


def friendly_name(curef: str, name: str = "") -> str:
    """Best display name, never blank: an explicit name, else a named sibling
    variant of the same model, else the bare model code."""
    if name:
        return name
    return _name_index().get(model_of(curef)) or model_of(curef)


def _community() -> dict[str, KnownDevice]:
    """Devices known only through the template store — the bundled set plus
    whatever `tcl-fw sync` has pulled from the community server."""
    out: dict[str, KnownDevice] = {}
    try:
        from . import templates as _tpl
        shipped = {t.curef for t in _tpl.load_bundled()}
        for t in _tpl.load():
            r = t.latest()
            out[t.curef] = KnownDevice(
                t.curef, r.tv if r else None, r.fw_id if r else None, t.name,
                "bundled" if t.curef in shipped else "community")
    except Exception:
        pass
    return out


def catalog(include_community: bool = True) -> dict[str, KnownDevice]:
    """Every device we can name. Built-ins, the bundled data/devices.json
    overlay, and — unless told otherwise — the template store that `tcl-fw sync`
    grows, so the CLI lists the same set the GUI does instead of drifting."""
    out = {
        cu: KnownDevice(cu, tv, fw, name, "builtin")
        for cu, (tv, fw, name) in _BUILTIN.items()
    }
    for cu, d in _load_overlay().items():
        out[cu] = KnownDevice(d.curef, d.tv, d.fw_id, d.name, "bundled")
    if include_community:
        for cu, d in _community().items():
            out.setdefault(cu, d)          # never downgrade a curated entry
    for cu, d in out.items():
        d.name = friendly_name(cu, d.name)
    return out


def lookup(curef: str) -> Optional[KnownDevice]:
    """Resolution-time lookup. Deliberately excludes community entries: those
    record builds we have *seen*, not a promise they are current, so a download
    must discover the live build rather than pin a stale tv/fw_id."""
    return catalog(include_community=False).get(curef)


def search(query: str) -> list[KnownDevice]:
    """Fuzzy find by curef or friendly name (case-insensitive substring)."""
    q = query.lower()
    return [d for d in catalog().values()
            if q in d.curef.lower() or q in (d.name or "").lower()]


def resolve(curef: str, tv: Optional[str] = None, fw_id: Optional[str] = None,
            mode: int = 4, fv: str = "000000") -> tuple[str, Optional[str], Optional[str]]:
    """Resolve a curef to (curef, tv, fw_id): explicit args win, then the
    built-in/overlay table, then a live check_new.php discovery.

    fv is only consulted by discovery and only matters for OTA (mode 2) — see
    fota.resolve. The built-in table holds FULL-image targets, so it's only
    trusted to short-circuit a FULL (mode 4) resolve; OTA always discovers live
    against the device's current fv."""
    if tv and fw_id:
        return curef, tv, fw_id
    if mode == 4:
        known = lookup(curef)
        if known and known.tv and known.fw_id:
            return curef, tv or known.tv, fw_id or known.fw_id
    return fota.resolve(curef, tv, fw_id, mode=mode, fv=fv)

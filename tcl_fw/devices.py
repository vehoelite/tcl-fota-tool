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


def catalog() -> dict[str, KnownDevice]:
    """All known devices: built-ins overlaid with community data/devices.json."""
    out = {
        cu: KnownDevice(cu, tv, fw, name)
        for cu, (tv, fw, name) in _BUILTIN.items()
    }
    out.update(_load_overlay())
    return out


def lookup(curef: str) -> Optional[KnownDevice]:
    return catalog().get(curef)


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

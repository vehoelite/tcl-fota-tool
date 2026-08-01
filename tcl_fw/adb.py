"""
adb.py — read a plugged-in TCL phone's identity so the user types nothing.

The whole point of "auto-CUREF": if a phone is connected with USB debugging on,
we can read its curef (and firmware version) directly, then let fota.discover()
turn that into a tv/fw_id. No manual lookup, no dongle.

Finds adb from (in order): the TCL_FW_ADB env var, a bundled platform-tools/
next to the package, or the system PATH.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class Device:
    serial: str
    curef: Optional[str] = None
    fv: Optional[str] = None          # ro.build.version.incremental
    model: Optional[str] = None
    name: Optional[str] = None        # marketing name, if any


def adb_path() -> Optional[str]:
    """Locate an adb binary, or None if unavailable."""
    env = os.environ.get("TCL_FW_ADB")
    if env and Path(env).exists():
        return env
    bundled = Path(__file__).resolve().parent.parent / "platform-tools" / (
        "adb.exe" if os.name == "nt" else "adb"
    )
    if bundled.exists():
        return str(bundled)
    return shutil.which("adb")


def _adb(args: list[str], serial: Optional[str] = None, timeout: int = 10) -> str:
    exe = adb_path()
    if not exe:
        raise RuntimeError("adb not found (set TCL_FW_ADB, add adb to PATH, "
                           "or drop platform-tools/ next to tcl-fw)")
    cmd = [exe]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0:
        raise RuntimeError((out.stderr or out.stdout or "adb error").strip())
    return out.stdout.strip()


def available() -> bool:
    return adb_path() is not None


def list_serials() -> list[str]:
    """Authorized, online device serials (skips 'unauthorized' / 'offline')."""
    try:
        out = _adb(["devices"])
    except Exception:
        return []
    serials = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


def _getprop(serial: str, prop: str) -> Optional[str]:
    try:
        v = _adb(["shell", "getprop", prop], serial=serial).strip()
        return v or None
    except Exception:
        return None


def read_device(serial: str) -> Device:
    """Read curef / firmware-version / model from one device."""
    curef = _getprop(serial, "ro.tct.curef") or _getprop(serial, "ro.vendor.tct.curef")
    fv = _getprop(serial, "ro.build.version.incremental")
    model = _getprop(serial, "ro.product.model")
    name = _getprop(serial, "ro.tct.setupwizard.marketname") or model
    return Device(serial=serial, curef=curef, fv=fv, model=model, name=name)


def detect() -> Optional[Device]:
    """Return the first connected device's identity, or None if nothing usable."""
    serials = list_serials()
    if not serials:
        return None
    return read_device(serials[0])

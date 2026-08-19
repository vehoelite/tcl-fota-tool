"""
sharing.py — optional, opt-out reporting of the (curef, fv) identifiers this
tool looks up, so the community device list grows by itself.

Design principles:
  * Transparent: a plain-language notice is printed on first run (never hidden).
  * Opt-out: on by default, one command turns it off (`tcl-fw sharing --off`).
  * Minimal: only device identifiers leave the machine — curef, fv, mode, the
    resolved tv/fw_id, and the tool version. No IMEI (the FOTA protocol uses a
    fixed placeholder), no IP, no account, nothing personal.
  * Harmless: submission is fire-and-forget on a daemon thread with a short
    timeout; if the server is down or slow it never affects the tool.

Config lives in a small JSON file in the user config dir. The server URL and
whether sharing is enabled can also be overridden by environment variables
(handy for testing): TCL_FW_SHARE_URL, TCL_FW_SHARE (0/1).
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
from pathlib import Path
from typing import Optional

from . import __version__

# The community registry endpoint (behind a Cloudflare Zero Trust tunnel).
# Overridable via TCL_FW_SHARE_URL. Empty string = sharing can't submit (no-op).
DEFAULT_SERVER = "https://tcl.tunnel-me.online"

# Anti-spam key for the write endpoint. This ships in the open-source client, so
# it is NOT a secret — it only deters casual junk; the server also validates and
# rate-limits. Kept configurable so the server key can rotate independently.
API_KEY = "us4zI1xHemiIo499wgrfX_6q_7Okky5o"

_TIMEOUT = 4  # seconds; submission must never hang the tool

NOTICE = """\
=====================================================================
  tcl-fw can share the device IDs it looks up (curef + firmware
  version) with a community registry, so the built-in device list
  grows automatically for everyone.

  Shared:   curef, firmware version, mode, resolved build, tool version
  NOT shared: no IMEI, no IP, no account - nothing that identifies you.

  This is ON by default. Turn it off any time:   tcl-fw sharing --off
  See exactly what's recorded and why:            tcl-fw sharing
====================================================================="""


def config_dir() -> Path:
    """User-writable config/data dir for tcl-fw (also used for auto-grown data)."""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "tcl-fw"


def _config_dir() -> Path:  # backward-compatible alias
    return config_dir()


def _config_file() -> Path:
    return _config_dir() / "config.json"


def _load() -> dict:
    try:
        return json.loads(_config_file().read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(cfg: dict) -> None:
    try:
        d = _config_dir()
        d.mkdir(parents=True, exist_ok=True)
        _config_file().write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass  # config is best-effort; never crash the tool over it


def is_enabled() -> bool:
    """True unless the user has opted out. Env override wins (for tests)."""
    env = os.environ.get("TCL_FW_SHARE")
    if env is not None:
        return env not in ("0", "false", "no", "off", "")
    return bool(_load().get("sharing", {}).get("enabled", True))


def set_enabled(value: bool) -> None:
    cfg = _load()
    s = cfg.setdefault("sharing", {})
    s["enabled"] = bool(value)
    s["notice_shown"] = True  # choosing is itself acknowledgement
    _save(cfg)


def server_url() -> str:
    return (os.environ.get("TCL_FW_SHARE_URL")
            or _load().get("server")
            or DEFAULT_SERVER).rstrip("/")


def notice_pending() -> bool:
    """True if the first-run notice hasn't been shown yet."""
    return not _load().get("sharing", {}).get("notice_shown", False)


def mark_notice_shown() -> None:
    cfg = _load()
    cfg.setdefault("sharing", {})["notice_shown"] = True
    _save(cfg)


def last_sync() -> float:
    """Unix time of the last auto-sync of the community device list (0 if never)."""
    try:
        return float(_load().get("last_sync", 0))
    except Exception:
        return 0.0


def mark_sync() -> None:
    cfg = _load()
    cfg["last_sync"] = __import__("time").time()
    _save(cfg)


def _post(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url + "/api/curef", data=data, method="POST",
        headers={"Content-Type": "application/json", "x-tcl-key": API_KEY,
                 "User-Agent": f"tcl-fw/{__version__}"},
    )
    try:
        urllib.request.urlopen(req, timeout=_TIMEOUT).read()
    except Exception:
        pass  # offline / server down / anything — silently ignore


def submit(curef: str, fv: Optional[str], mode: int,
           tv: Optional[str] = None, fw_id: Optional[str] = None) -> None:
    """Report a looked-up device, if sharing is enabled. Non-blocking and
    failure-proof: spawns a daemon thread and returns immediately."""
    if not is_enabled():
        return
    url = server_url()
    if not url:
        return
    payload = {
        "curef": curef,
        "fv": fv or "",
        "mode": str(mode),
        "tv": tv or "",
        "fw_id": fw_id or "",
        "tool_version": __version__,
    }
    t = threading.Thread(target=_post, args=(url, payload), daemon=True)
    t.start()


def status_text() -> str:
    """Human-readable status for `tcl-fw sharing`."""
    on = is_enabled()
    return (
        f"Community device sharing is {'ON' if on else 'OFF'}.\n\n"
        "When ON, after a lookup tcl-fw reports the device identifiers it used\n"
        "so the built-in device list grows for everyone:\n"
        "  shared:      curef, firmware version (fv), mode, resolved tv/fw_id,\n"
        "               tcl-fw version\n"
        "  NOT shared:  IMEI (the protocol uses a fixed placeholder), IP address,\n"
        "               account, name, location - nothing that identifies you.\n\n"
        f"  server:      {server_url() or '(none configured)'}\n"
        f"  config:      {_config_file()}\n\n"
        "Read what's recorded (public):  <server>/about  and  <server>/api/curefs\n"
        "Turn it off:  tcl-fw sharing --off      Turn it on:  tcl-fw sharing --on"
    )

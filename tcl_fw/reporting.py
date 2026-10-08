"""
reporting.py — anonymous error reports, so bugs surface while nobody is looking.

Covered by the same community-sharing toggle as device IDs (`tcl-fw sharing
--off` turns both off), disclosed in the first-run notice, the README, and the
server's public /about page. The aggregated reports are public at
<server>/api/errors, so anyone can see what is being fixed and why.

THE PRIVACY CONTRACT
--------------------
Nothing in a report is free text. Exception *messages* are never sent — they
routinely contain file paths, usernames and output folders ("Permission denied:
'C:\\Users\\<you>\\...'"), and scrubbing them can't be audited. A report is
built only from:

  * a code from the fixed vocabulary in CODES below,
  * an exception's *type name* and errno (e.g. PermissionError, 13),
  * stack frames inside tcl-fw itself, reduced to  module:function:line,
  * tool / Python / OS-family versions, the command, and the device IDs the
    tool already shares (curef, tv, fw_id, mode).

tests/test_reporting.py holds this contract: a payload built from an exception
whose message carries a path and a username must contain neither.

Like sharing, sending is fire-and-forget on a daemon thread with a short
timeout, deduplicated per pull, and capped per process.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import threading
import traceback
import urllib.request
from typing import Iterable, Optional

from . import __version__, sharing

#: Every code a report can carry. Anything else is dropped before sending, and
#: the server rejects it too.
CODES = {
    # a pull wrote nothing for a file
    "probe_failed", "cdn_404", "no_name", "empty_header", "header_rejected",
    "footer_missing", "footer_checksum_mismatch", "body_checksum_mismatch",
    "body_short", "unwrap_short", "unwrap_crc", "unwrap_unknown_length",
    "pull_error",
    # a pull wrote a file, but something deserves a look
    "unverified", "name_collision",
    # other commands
    "pack_no_scatter", "pack_low_confidence",
    # anything unexpected
    "exception",
}

COMMANDS = {"pull", "list", "pack", "verify", "gui", "other"}

_MAX_PER_PROCESS = 10
_MAX_FRAMES = 12
_TIMEOUT = 4
_sent = 0
_lock = threading.Lock()
_PKGS = ("tcl_fw", "tcl_fw_gui")


def _env() -> dict:
    sysname = platform.system()
    env = {
        "tool_version": __version__,
        "python": "%d.%d" % sys.version_info[:2],
        "os": sysname if sysname in ("Windows", "Linux", "Darwin") else "Other",
    }
    pyside = sys.modules.get("PySide6")
    ver = getattr(pyside, "__version__", None)
    if ver:
        env["pyside"] = str(ver)[:16]
    return env


def frames(tb) -> list[str]:
    """`module:function:line` for frames inside tcl-fw only — never a path."""
    out = []
    for fs in traceback.extract_tb(tb):
        parts = os.path.normpath(fs.filename).replace("\\", "/").split("/")
        pkg = next((p for p in reversed(parts[:-1]) if p in _PKGS), None)
        if not pkg:
            continue
        mod = os.path.splitext(parts[-1])[0]
        out.append("%s.%s:%s:%d" % (pkg, mod, fs.name, fs.lineno or 0))
    return out[-_MAX_FRAMES:]


def exception_event(exc: BaseException) -> dict:
    """The only things taken from an exception: its type, errno, and tcl-fw
    frames. Never str(exc)."""
    ev = {"code": "exception", "exc_type": type(exc).__name__[:64], "count": 1}
    errno = getattr(exc, "errno", None)
    if isinstance(errno, int):
        ev["errno"] = errno
    st = frames(exc.__traceback__)
    if st:
        ev["stack"] = st
    return ev


def pull_events(results: Iterable) -> list[dict]:
    """Collapse a pull's PartResults into one event per code, with a count."""
    counts: dict[str, int] = {}
    for r in results:
        code = getattr(r, "code", None)
        if r.error and not code:
            code = "pull_error"
        if code:
            counts[code] = counts.get(code, 0) + 1
        if not r.error and r.verified is None:
            counts["unverified"] = counts.get("unverified", 0) + 1
        if getattr(r, "collided", False):
            counts["name_collision"] = counts.get("name_collision", 0) + 1
    return [{"code": c, "count": n} for c, n in sorted(counts.items()) if c in CODES]


def build_payload(command: str, events: list[dict], curef: str = "",
                  tv: Optional[str] = None, fw_id: Optional[str] = None,
                  mode: Optional[int] = None) -> dict:
    p = dict(_env())
    p["command"] = command if command in COMMANDS else "other"
    p["events"] = [e for e in events if e.get("code") in CODES]
    if curef:
        p["curef"] = curef
    if tv:
        p["tv"] = tv
    if fw_id:
        p["fw_id"] = fw_id
    if mode is not None:
        p["mode"] = str(mode)
    return p


def _post(url: str, payload: dict) -> None:
    req = urllib.request.Request(
        url + "/api/error", data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", "x-tcl-key": sharing.API_KEY,
                 "User-Agent": f"tcl-fw/{__version__}"},
    )
    try:
        urllib.request.urlopen(req, timeout=_TIMEOUT).read()
    except Exception:
        pass


def send(payload: dict, block: bool = False) -> bool:
    """Send one report if sharing is on and the per-process cap allows.
    Returns True if a send was started."""
    global _sent
    if not payload.get("events") or not sharing.is_enabled():
        return False
    url = sharing.server_url()
    if not url:
        return False
    with _lock:
        if _sent >= _MAX_PER_PROCESS:
            return False
        _sent += 1
    if block:                      # used from an excepthook, where the process
        _post(url, payload)        # is about to exit and a daemon would die
    else:
        threading.Thread(target=_post, args=(url, payload), daemon=True).start()
    return True


def report_pull(results: list, curef: str = "", tv: Optional[str] = None,
                fw_id: Optional[str] = None, mode: Optional[int] = None,
                command: str = "pull") -> bool:
    """One report per pull, covering every file, if anything went wrong."""
    try:
        events = pull_events(results)
        return send(build_payload(command, events, curef, tv, fw_id, mode))
    except Exception:
        return False


def report_code(code: str, command: str, curef: str = "", count: int = 1) -> bool:
    try:
        return send(build_payload(command, [{"code": code, "count": count}], curef))
    except Exception:
        return False


def report_exception(exc: BaseException, command: str = "other", curef: str = "",
                     block: bool = False) -> bool:
    """Report an unexpected exception (type + tcl-fw frames only)."""
    try:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            return False
        return send(build_payload(command, [exception_event(exc)], curef), block=block)
    except Exception:
        return False


def install_excepthook(command: str = "gui") -> None:
    """Report uncaught exceptions (incl. exceptions raised in Qt slots, which
    PySide routes to sys.excepthook), then defer to the previous hook."""
    prev = sys.excepthook

    def hook(etype, value, tb):
        if value is not None:
            if value.__traceback__ is None:
                value = value.with_traceback(tb)
            report_exception(value, command)
        prev(etype, value, tb)

    sys.excepthook = hook

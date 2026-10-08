"""Anonymous error reports (4.5.0).

The first test is the privacy contract: whatever an exception's message holds
- a Windows path, a username, an output folder - must never appear anywhere in
what is sent. Reports carry codes, type names and tcl-fw frames, nothing else.
"""

import json

import pytest

from tcl_fw import reporting, sharing
from tcl_fw.puller import PartResult

SECRET_USER = "alicesmith"
SECRET_PATH = r"C:\Users\alicesmith\Documents\pkg_T702Z-EARXUS12-V\boot.img"


@pytest.fixture
def sent(monkeypatch, tmp_path):
    """Capture posts instead of sending; sharing ON; fresh per-process cap."""
    monkeypatch.setenv("TCL_FW_SHARE", "1")
    monkeypatch.setenv("TCL_FW_SHARE_URL", "http://registry.test")
    monkeypatch.setattr(reporting, "_sent", 0)
    out = []
    capture = lambda url, payload: out.append((url, payload))  # noqa: E731
    monkeypatch.setattr(reporting, "_post", capture)
    # Send inline instead of on a daemon thread. Patch reporting's own seam -
    # never threading.Thread, which is global and would affect other tests.
    monkeypatch.setattr(reporting, "_spawn", capture)
    return out


def _raise_with_secrets():
    def inner():
        raise PermissionError(13, "Permission denied", SECRET_PATH)
    try:
        inner()
    except PermissionError as e:
        return e


# ── the privacy contract ─────────────────────────────────────────────────────

def test_exception_message_never_leaves_the_machine(sent):
    exc = _raise_with_secrets()
    assert SECRET_USER in str(exc) and "Documents" in str(exc)  # it does hold them
    reporting.report_exception(exc, "pull", curef="T702Z-EARXUS12-V")
    assert len(sent) == 1
    wire = json.dumps(sent[0][1])
    assert SECRET_USER not in wire
    assert "Users" not in wire and "Documents" not in wire
    assert "\\\\" not in wire and "pkg_" not in wire  # no path fragments at all
    ev = sent[0][1]["events"][0]
    assert ev["exc_type"] == "PermissionError" and ev["errno"] == 13
    for frame in ev.get("stack", []):               # module:function:line only
        mod, fn, line = frame.split(":")
        assert mod.startswith(("tcl_fw.", "tcl_fw_gui.")) and line.isdigit()


def test_frames_keep_only_tcl_fw_and_drop_paths():
    try:
        reporting.frames(None)
        from tcl_fw import crypto
        crypto.decrypt_header(b"short")
    except ValueError as e:
        st = reporting.frames(e.__traceback__)
    assert st and all(f.startswith("tcl_fw.") for f in st)
    assert any(f.startswith("tcl_fw.crypto:decrypt_header:") for f in st)
    assert not any("/" in f or "\\" in f or "test_reporting" in f for f in st)


def test_payload_has_no_free_text_fields(sent):
    reporting.report_exception(_raise_with_secrets(), "gui")
    p = sent[0][1]
    allowed = {"tool_version", "python", "os", "pyside", "command", "events",
               "curef", "tv", "fw_id", "mode"}
    assert set(p) <= allowed
    assert p["os"] in ("Windows", "Linux", "Darwin", "Other")
    for ev in p["events"]:
        assert set(ev) <= {"code", "count", "exc_type", "errno", "stack"}
        assert ev["code"] in reporting.CODES


# ── what gets reported, and how often ────────────────────────────────────────

def _r(fid, error=None, code=None, verified=True, collided=False):
    return PartResult(fid, "x.img", "body", error=error, code=code,
                      verified=verified, collided=collided)


def test_a_clean_pull_sends_nothing(sent):
    assert not reporting.report_pull([_r("1"), _r("2")], "X-1")
    assert sent == []


def test_one_report_per_pull_with_counts(sent):
    results = [_r(str(i), error="x", code="cdn_404", verified=False) for i in range(30)]
    results += [_r("a", verified=None), _r("b", collided=True),
                _r("c", error="boom", code=None, verified=False)]
    reporting.report_pull(results, "X-1", "TV", "FW", 4)
    assert len(sent) == 1                           # 33 files, one post
    events = {e["code"]: e["count"] for e in sent[0][1]["events"]}
    assert events == {"cdn_404": 30, "unverified": 1, "name_collision": 1,
                      "pull_error": 1}
    assert sent[0][1]["curef"] == "X-1" and sent[0][1]["mode"] == "4"


def test_unknown_codes_are_dropped(sent):
    reporting.report_code("rm -rf /", "pull")
    assert sent == []


def test_capped_per_process(sent):
    for _ in range(50):
        reporting.report_code("probe_failed", "pull")
    assert len(sent) == reporting._MAX_PER_PROCESS


def test_sharing_off_sends_nothing(sent, monkeypatch):
    monkeypatch.setenv("TCL_FW_SHARE", "0")
    reporting.report_exception(_raise_with_secrets(), "pull")
    reporting.report_code("cdn_404", "pull")
    assert sent == []


def test_keyboard_interrupt_is_not_an_error(sent):
    assert not reporting.report_exception(KeyboardInterrupt(), "pull")
    assert sent == []


# ── the disclosure fires again for existing users ────────────────────────────

def test_notice_reappears_for_users_who_saw_the_old_one(monkeypatch, tmp_path):
    monkeypatch.setattr(sharing, "_config_dir", lambda: tmp_path)
    (tmp_path / "config.json").write_text(
        json.dumps({"sharing": {"enabled": True, "notice_shown": True}}))
    assert sharing.notice_pending()                 # saw v1, must see v2
    sharing.mark_notice_shown()
    assert not sharing.notice_pending()
    assert "error reports" in sharing.NOTICE
    assert "error reports" in sharing.status_text()


def test_fresh_install_sees_the_notice(monkeypatch, tmp_path):
    monkeypatch.setattr(sharing, "_config_dir", lambda: tmp_path)
    assert sharing.notice_pending()

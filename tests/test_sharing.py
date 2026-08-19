"""Tests for opt-out community sharing: config, consent, and fail-safe submit."""

import time

import pytest

from tcl_fw import sharing


@pytest.fixture(autouse=True)
def isolate_config(tmp_path, monkeypatch):
    # Point the config dir at a temp location on every platform, and clear the
    # env overrides so we exercise the real file-backed logic.
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("TCL_FW_SHARE", raising=False)
    monkeypatch.delenv("TCL_FW_SHARE_URL", raising=False)
    yield


def test_default_enabled_and_notice_pending():
    assert sharing.is_enabled() is True
    assert sharing.notice_pending() is True


def test_opt_out_persists_and_clears_notice():
    sharing.set_enabled(False)
    assert sharing.is_enabled() is False
    assert sharing.notice_pending() is False   # choosing counts as acknowledgement
    sharing.set_enabled(True)
    assert sharing.is_enabled() is True


def test_env_override_wins(monkeypatch):
    sharing.set_enabled(True)
    monkeypatch.setenv("TCL_FW_SHARE", "0")
    assert sharing.is_enabled() is False
    monkeypatch.setenv("TCL_FW_SHARE", "1")
    assert sharing.is_enabled() is True


def test_server_url_override(monkeypatch):
    assert sharing.server_url() == sharing.DEFAULT_SERVER
    monkeypatch.setenv("TCL_FW_SHARE_URL", "http://example.test:9/")
    assert sharing.server_url() == "http://example.test:9"


def test_submit_noop_when_disabled(monkeypatch):
    sharing.set_enabled(False)
    called = []
    monkeypatch.setattr(sharing, "_post", lambda *a, **k: called.append(a))
    sharing.submit("T1-A-V", "AA00", 4)
    time.sleep(0.05)
    assert called == []


def test_submit_is_fast_and_safe_when_server_dead(monkeypatch):
    # Unreachable server: submit must return immediately and never raise; the
    # tool keeps going and the record is simply skipped.
    sharing.set_enabled(True)
    monkeypatch.setenv("TCL_FW_SHARE_URL", "http://127.0.0.1:1")
    start = time.monotonic()
    sharing.submit("T807W-EATBUS12-V", "AXAMWTM0", 4, tv="AXAMWTM0", fw_id="983299")
    assert time.monotonic() - start < 0.5   # did not block on the network


def test_submit_builds_expected_payload(monkeypatch):
    sharing.set_enabled(True)
    seen = {}
    monkeypatch.setattr(sharing, "_post", lambda url, payload: seen.update(payload))
    sharing.submit("T608DL-2ALGUS12-V", "9LBHZDH0", 2, tv="X", fw_id="9")
    time.sleep(0.1)
    assert seen["curef"] == "T608DL-2ALGUS12-V"
    assert seen["fv"] == "9LBHZDH0"
    assert seen["mode"] == "2"
    assert seen["tv"] == "X" and seen["fw_id"] == "9"
    assert "tool_version" in seen

"""The shared device model name must be best-effort: if adb is missing, no phone
matches, or adb blows up, the lookup degrades to no name and the submission (and
the download around it) still goes through untouched."""

import time

import pytest

from tcl_fw import adb, sharing


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("TCL_FW_SHARE", raising=False)
    monkeypatch.setenv("TCL_FW_SHARE_URL", "http://example.test:9")


def _capture(monkeypatch):
    seen = {}
    monkeypatch.setattr(sharing, "_post", lambda url, payload: seen.update(payload))
    return seen


# ── adb.match degrades instead of raising ────────────────────────────────────

def test_match_returns_none_when_adb_missing(monkeypatch):
    monkeypatch.setattr(adb, "available", lambda: False)
    assert adb.match("T807W-EATBUS12-V") is None


def test_match_returns_none_when_nothing_matches(monkeypatch):
    monkeypatch.setattr(adb, "available", lambda: True)
    monkeypatch.setattr(adb, "list_serials", lambda: ["abc"])
    monkeypatch.setattr(adb, "read_device",
                        lambda s: adb.Device(serial=s, curef="OTHER-1-V", name="Other"))
    assert adb.match("T807W-EATBUS12-V") is None


def test_match_swallows_adb_errors(monkeypatch):
    """A broken/hung adb must not propagate into the download path."""
    monkeypatch.setattr(adb, "available", lambda: True)
    monkeypatch.setattr(adb, "list_serials", lambda: ["abc"])

    def boom(_serial):
        raise OSError("adb exploded")

    monkeypatch.setattr(adb, "read_device", boom)
    assert adb.match("T807W-EATBUS12-V") is None


def test_match_ignores_trailing_v_suffix(monkeypatch):
    monkeypatch.setattr(adb, "available", lambda: True)
    monkeypatch.setattr(adb, "list_serials", lambda: ["abc"])
    monkeypatch.setattr(adb, "read_device",
                        lambda s: adb.Device(serial=s, curef="T807W-EATBUS12",
                                             fv="AXAM", name="TCL 50 XL 5G"))
    got = adb.match("T807W-EATBUS12-V")
    assert got is not None and got.name == "TCL 50 XL 5G"


def test_match_handles_empty_curef():
    assert adb.match("") is None


# ── submission still happens without a name ──────────────────────────────────

def test_submit_without_name_still_posts(monkeypatch):
    seen = _capture(monkeypatch)
    sharing.submit("T807W-EATBUS12-V", "AXAM", 4, "TV", "123", name=None)
    time.sleep(0.3)
    assert seen["curef"] == "T807W-EATBUS12-V"
    assert "name" not in seen, "an absent name must be omitted, not sent empty"


def test_submit_includes_cleaned_name(monkeypatch):
    seen = _capture(monkeypatch)
    sharing.submit("T807W-EATBUS12-V", "AXAM", 4, "TV", "123",
                   name="  TCL 50   XL 5G  ")
    time.sleep(0.3)
    assert seen["name"] == "TCL 50 XL 5G"


def test_submit_survives_a_garbage_name(monkeypatch):
    seen = _capture(monkeypatch)
    sharing.submit("T807W-EATBUS12-V", "AXAM", 4, "TV", "123", name="x" * 500)
    time.sleep(0.3)
    assert len(seen["name"]) == 64


# ── clean_name edges ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,want", [
    (None, ""), ("", ""), ("   ", ""),
    ("TCL 50 XL 5G", "TCL 50 XL 5G"),
    ("TCL\t50\nXL", "TCL 50 XL"),
    ("TCL\x00\x07 50", "TCL 50"),
])
def test_clean_name(raw, want):
    assert sharing.clean_name(raw) == want

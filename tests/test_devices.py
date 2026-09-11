"""Device catalog: community merge, name resolution, and the resolution boundary.

`tcl-fw sync` grows the template store, so the device list has to read it or the
CLI silently drifts from the GUI (it did — `tcl-fw devices` was frozen at the
built-ins). But community entries must NOT leak into resolution: they record
builds we have seen, not a promise they are current.
"""

import pytest

from tcl_fw import devices
from tcl_fw.templates import Release, Template


@pytest.fixture
def fake_store(monkeypatch):
    """A bundled template plus a community-only one."""
    shipped = [Template("T807W-EATBUS12-V", "TCL NxtPaper 70 Pro", 4,
                        [Release("AXAMWTM0", "983299", "2026-08-19", "2026-08-19")])]
    community = shipped + [
        Template("5033E-2HOFBRA", "", 4,
                 [Release("OLDTV", "111111", "2026-09-01", "2026-09-01")]),
    ]
    monkeypatch.setattr(devices, "_community", lambda: {
        t.curef: devices.KnownDevice(
            t.curef, t.latest().tv, t.latest().fw_id, t.name,
            "bundled" if any(s.curef == t.curef for s in shipped) else "community")
        for t in community
    })
    return community


def test_model_of_takes_the_first_curef_segment():
    assert devices.model_of("T807D1-2CLCA112") == "T807D1"
    assert devices.model_of("5033E-2HOFBRA") == "5033E"
    assert devices.model_of("t614sp-2auhus12") == "T614SP"
    assert devices.model_of("") == ""


def test_friendly_name_prefers_an_explicit_name():
    assert devices.friendly_name("T704SP-EAUHUS12-V", "Custom") == "Custom"


def test_friendly_name_borrows_from_a_named_sibling_variant():
    # A community T807W-* arrives nameless; a shipped T807W-* is named.
    got = devices.friendly_name("T807W-2ATBUS12")
    assert got == devices.friendly_name("T807W-EATBUS12-V")
    assert got and got != "T807W"


def test_friendly_name_falls_back_to_the_model_code_never_blank():
    assert devices.friendly_name("T999X-9ZZZUS12-V") == "T999X"


def test_catalog_includes_community_entries(fake_store):
    cat = devices.catalog()
    assert "5033E-2HOFBRA" in cat
    assert cat["5033E-2HOFBRA"].source == "community"


def test_catalog_can_exclude_community(fake_store):
    assert "5033E-2HOFBRA" not in devices.catalog(include_community=False)


def test_no_catalog_entry_is_ever_blank_named(fake_store):
    assert all(d.name for d in devices.catalog().values())


def test_curated_entries_are_not_downgraded_by_community(fake_store):
    # A built-in keeps its own name/provenance even though the store lists it.
    d = devices.catalog()["T704SP-EAUHUS12-V"]
    assert d.source == "builtin"
    assert d.name == "Verizon / Ruby_VZW / 50 XL NXTPAPER"


def test_lookup_ignores_community_so_downloads_resolve_live(fake_store):
    """The regression guard: if a community tv/fw_id reached lookup(), a mode-4
    resolve would short-circuit to a recorded build instead of the current one."""
    assert devices.lookup("5033E-2HOFBRA") is None


def test_resolve_does_not_pin_a_community_build(fake_store, monkeypatch):
    called = {}

    def fake_fota_resolve(curef, tv, fw_id, mode=4, fv="000000"):
        called["hit"] = True
        return curef, "LIVETV", "999999"

    monkeypatch.setattr(devices.fota, "resolve", fake_fota_resolve)
    out = devices.resolve("5033E-2HOFBRA", None, None, mode=4)
    assert called.get("hit"), "resolve must go live for a community-only device"
    assert out == ("5033E-2HOFBRA", "LIVETV", "999999")

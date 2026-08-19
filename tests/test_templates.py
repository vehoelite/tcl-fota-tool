"""Tests for firmware-template release history, tagging, and refresh."""

from tcl_fw import templates as T
from tcl_fw.templates import Release, Template


def test_is_new_within_and_outside_window():
    r = Release("AXAMWTM0", "983299", first_seen="2026-08-10", last_seen="2026-08-10")
    assert r.is_new(today="2026-08-19") is True          # 9 days
    assert r.is_new(today="2026-09-30") is False         # well past NEW_WINDOW_DAYS
    # A future first_seen (clock skew) is not "new".
    assert Release("X", "1", "2026-08-20", "2026-08-20").is_new(today="2026-08-19") is False


def test_latest_picks_most_recent_first_seen():
    t = Template("T807W-EATBUS12-V", "NxtPaper", 4, [
        Release("OLD1", "100", "2026-01-01", "2026-01-01"),
        Release("NEW9", "200", "2026-08-01", "2026-08-01"),
        Release("MID5", "150", "2026-05-01", "2026-05-01"),
    ])
    assert t.latest().tv == "NEW9"


def test_refresh_appends_new_bumps_seen_ignores_missing():
    tpls = [
        Template("A-CUREF", "A", 4, [Release("TVOLD", "1", "2026-01-01", "2026-01-01")]),
        Template("B-CUREF", "B", 4, [Release("TVB", "2", "2026-08-01", "2026-08-01")]),
        Template("C-CUREF", "C", 2, []),
    ]
    # A gets a brand-new build; B still serves the same one; C serves nothing.
    fake = {
        "A-CUREF": ("TVNEW", "9"),
        "B-CUREF": ("TVB", "2"),
        "C-CUREF": (None, None),
    }
    added = T.refresh(tpls, today="2026-08-19", discover=lambda cu, mode: fake[cu])

    assert added == [("A-CUREF", "TVNEW", "9")]
    a = tpls[0]
    assert {r.tv for r in a.releases} == {"TVOLD", "TVNEW"}
    assert a.find("TVNEW", "9").first_seen == "2026-08-19"
    # B: no new release, but last_seen advanced to today.
    assert tpls[1].find("TVB", "2").last_seen == "2026-08-19"
    # C: nothing discovered, still empty.
    assert tpls[2].releases == []


def test_save_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(T, "_DATA_FILE", tmp_path / "templates.json")
    tpls = [Template("Z-CUREF", "Zed", 4,
                     [Release("TV1", "11", "2026-08-19", "2026-08-19")])]
    T.save(tpls)
    back = T.load()
    assert len(back) == 1
    assert back[0].curef == "Z-CUREF" and back[0].mode == 4
    assert back[0].latest().fw_id == "11"

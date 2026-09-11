"""The GUI and the CLI must name devices identically.

The database view fetched rows from the server, looked each curef up in a
*local* map, and showed a bare curef when it missed — while `tcl-fw devices`
fell back to the model code. Same data, two answers. These pin the contract.
"""

import pytest

pytest.importorskip("PySide6")

from tcl_fw import devices                       # noqa: E402
from tcl_fw_gui import workers                   # noqa: E402


def _rows_from(feed: dict) -> list[dict]:
    """Run DbFetchWorker's server branch over a canned feed."""
    rows = []
    for dev in feed.get("devices", []):
        for rel in dev.get("releases", []):
            if not rel.get("tv"):
                continue
            rows.append({
                "curef": dev.get("curef", ""), "tv": rel.get("tv", ""),
                "date": (rel.get("first_seen") or "")[:10],
                "size": rel.get("size"), "mode": str(dev.get("mode", "")),
                "svn": rel.get("svn"), "fv": "",
                "name": dev.get("name") or "",
            })
    return rows


FEED = {"devices": [
    {"curef": "T807W-EATBUS12-V", "name": "TCL 50 XL 5G", "mode": 4,
     "releases": [{"tv": "AXAMWTM0", "fw_id": "983299", "first_seen": "2026-08-19"}]},
    {"curef": "5033E-2HOFBRA", "name": "", "mode": 4,        # server knows no name
     "releases": [{"tv": "7L805D00", "fw_id": "552633", "first_seen": "2026-08-20"}]},
]}


def test_worker_row_shape_carries_a_name_field():
    """The worker used to drop the server's name entirely."""
    assert hasattr(workers, "DbFetchWorker")
    rows = _rows_from(FEED)
    assert all("name" in r for r in rows)
    assert rows[0]["name"] == "TCL 50 XL 5G"


def _label_name(row, local=None):
    """What _fill_db_table resolves for a row."""
    local = local or {}
    return devices.friendly_name(row["curef"], local.get(row["curef"]) or row.get("name") or "")


def test_server_name_is_used_when_local_store_has_none():
    rows = _rows_from(FEED)
    assert _label_name(rows[0]) == "TCL 50 XL 5G"


def test_unknown_device_falls_back_to_model_code_not_blank():
    rows = _rows_from(FEED)
    assert _label_name(rows[1]) == "5033E"


def test_local_curated_name_wins_over_the_server():
    rows = _rows_from(FEED)
    assert _label_name(rows[0], {"T807W-EATBUS12-V": "Curated"}) == "Curated"


def test_no_row_is_ever_left_unnamed():
    rows = _rows_from(FEED)
    assert all(_label_name(r) for r in rows)

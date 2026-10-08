"""Drive the real main window through Load with every kind of partition row.

Two GUI crashes reached this suite only by luck: a missing `fota` import in the
table fill, and `_apply_filter` handing PySide6 a str for a bool (which aborted
Load before the background name probe started). Both live in code that runs on
every Load, so a single headless Load catches the whole class.
"""

import os

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication                    # noqa: E402

from tcl_fw import fota                                        # noqa: E402
from tcl_fw.fota import DownloadInfo, FileEntry                # noqa: E402
from tcl_fw.puller import PullPlan                             # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app, monkeypatch):
    from tcl_fw_gui import main_window
    started = []
    monkeypatch.setattr(main_window.NameProbeWorker, "start",
                        lambda self: started.append(self))
    w = main_window.MainWindow()
    w._probes_started = started
    yield w
    w.close()


def _plan():
    files = [FileEntry("1", "/a"), FileEntry("2", "/b"), FileEntry("3", "/c"),
             FileEntry("4", "/d"), FileEntry("5", "/e")]
    info = DownloadInfo("X-1", "tv", "fw", "slave", "enc", files)
    return info, PullPlan(info=info,
                          sizes={"1": 0, "2": 5000, "3": -1,
                                 "4": fota.BODY_GONE, "5": 9000},
                          names={"2": "boot.img"})


def _rows(w):
    return {w.table.item(r, 2).text(): (w.table.item(r, 1).text(),
                                        w.table.item(r, 4).text())
            for r in range(w.table.rowCount())}


def test_load_shows_every_row_state(window):
    info, plan = _plan()
    window._on_loaded("X-1", info, plan)
    rows = _rows(window)
    assert rows["2"] == ("boot.img", "body")
    assert rows["1"][1].startswith("header")
    assert rows["3"] == ("«probe failed»", "?")
    assert "CDN" in rows["4"][0]


def test_load_reaches_the_background_name_probe(window):
    """The unnamed body part (FILE_ID 5) must get a name probe; the filter
    crash used to abort Load before this point."""
    info, plan = _plan()
    window._on_loaded("X-1", info, plan)
    assert len(window._probes_started) == 1


def test_filter_hides_and_shows_rows(window):
    info, plan = _plan()
    window._on_loaded("X-1", info, plan)
    window.filter_edit.setText("boot")
    visible = [r for r in range(window.table.rowCount())
               if not window.table.isRowHidden(r)]
    assert [window.table.item(r, 2).text() for r in visible] == ["2"]
    window.filter_edit.setText("")
    assert not any(window.table.isRowHidden(r) for r in range(window.table.rowCount()))

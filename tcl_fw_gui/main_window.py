"""
main_window.py — the tcl-fw desktop window.

Flow: pick / detect a curef -> Load (populates the partition table) -> tick the
parts you want -> Pull. All backend work is delegated to workers.py; this file
is only widgets, layout, and signal wiring.
"""

from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from tcl_fw import __version__, devices, sharing, templates
from tcl_fw.crypto import key_hex
from tcl_fw.fota import DownloadInfo, FileEntry
from tcl_fw.puller import PartResult, PullPlan

from .workers import (DetectWorker, LoadWorker, NameProbeWorker, PackWorker,
                      PullWorker)

CREDIT = "Mode-4 header decryption by Littlenine Ennea · github.com/LittlenineEnnea"

# Column indices for the partition table.
C_SEL, C_NAME, C_ID, C_SIZE, C_SRC, C_PROG = range(6)


def human_size(n: int) -> str:
    if n <= 0:
        return "—"
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.0f} B"


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"tcl-fw {__version__} — TCL FOTA firmware")
        self.resize(940, 680)

        self._info: Optional[DownloadInfo] = None
        self._plan: Optional[PullPlan] = None
        self._row_of: dict[str, int] = {}     # file_id -> table row
        self._entry_of: dict[str, FileEntry] = {}
        self._load_worker: Optional[LoadWorker] = None
        # fv (firmware version) from the last auto-detect, kept with its curef so
        # OTA (mode 2) can use the device's real current version. Only trusted
        # when the curef in the box still matches what we detected.
        self._detected_curef: Optional[str] = None
        self._detected_fv: Optional[str] = None
        self._detect_worker: Optional[DetectWorker] = None
        self._pull_worker: Optional[PullWorker] = None
        self._name_worker: Optional[NameProbeWorker] = None
        self._pack_worker: Optional[PackWorker] = None

        self._build_ui()

    # ── UI construction ───────────────────────────────────────────────────
    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(10)

        # Title + credit
        title = QLabel("tcl-fw")
        tf = QFont()
        tf.setPointSize(18)
        tf.setBold(True)
        title.setFont(tf)
        credit = QLabel(CREDIT)
        credit.setObjectName("credit")
        head = QVBoxLayout()
        head.setSpacing(0)
        head.addWidget(title)
        head.addWidget(credit)
        outer.addLayout(head)

        # Device row
        drow = QHBoxLayout()
        drow.addWidget(QLabel("Device:"))
        self.curef_box = QComboBox()
        self.curef_box.setEditable(True)
        self.curef_box.setMinimumWidth(320)
        self.curef_box.setInsertPolicy(QComboBox.NoInsert)
        # Validated templates first (with a NEW tag on recent builds), then any
        # remaining catalog devices. _tpl_mode lets us preselect the right FOTA
        # mode when the user picks one.
        self._tpl_mode: dict[str, int] = {}
        seen: set[str] = set()
        for t in sorted(templates.load(), key=lambda t: (t.name or t.curef).lower()):
            r = t.latest()
            tag = "   ·   NEW" if (r and r.is_new()) else ""
            label = f"{t.curef}   ·   {t.name}{tag}" if t.name else f"{t.curef}{tag}"
            self.curef_box.addItem(label, t.curef)
            self._tpl_mode[t.curef] = t.mode
            seen.add(t.curef)
        for d in devices.catalog().values():
            if d.curef in seen:
                continue
            label = f"{d.curef}   ·   {d.name}" if d.name else d.curef
            self.curef_box.addItem(label, d.curef)
        self.curef_box.setCurrentIndex(-1)
        self.curef_box.currentIndexChanged.connect(self._on_curef_picked)
        self.curef_box.setEditText("")
        self.curef_box.lineEdit().setPlaceholderText(
            "curef (e.g. T704SP-EAUHUS12-V) or pick a known device")
        drow.addWidget(self.curef_box, 1)

        self.mode_box = QComboBox()
        self.mode_box.addItem("mode 4", 4)
        self.mode_box.addItem("mode 2", 2)
        self.mode_box.setToolTip("FOTA mode. 4 = full image (default); "
                                 "try 2 if a device serves nothing on 4.")
        drow.addWidget(self.mode_box)

        self.fv_edit = QLineEdit()
        self.fv_edit.setPlaceholderText("FV (OTA only)")
        self.fv_edit.setToolTip(
            "Current firmware version. Only needed for OTA (mode 2). Auto-filled "
            "by Detect when a phone is plugged in; otherwise type it "
            "(getprop ro.tct.sys.ver, rearranged — the phone's About screen shows it).")
        self.fv_edit.setMaximumWidth(150)
        drow.addWidget(self.fv_edit)

        self.detect_btn = QPushButton("Detect phone")
        self.detect_btn.clicked.connect(self.on_detect)
        drow.addWidget(self.detect_btn)

        self.load_btn = QPushButton("Load ▸")
        self.load_btn.setObjectName("primary")
        self.load_btn.clicked.connect(self.on_load)
        drow.addWidget(self.load_btn)
        outer.addLayout(drow)

        self.info_lbl = QLabel("")
        self.info_lbl.setObjectName("info")
        outer.addWidget(self.info_lbl)

        # Table toolbar
        trow = QHBoxLayout()
        self.small_only = QCheckBox("Small parts only (lk / preloader / …)")
        self.small_only.stateChanged.connect(self._apply_filter)
        trow.addWidget(self.small_only)
        trow.addStretch(1)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("filter by name…")
        self.filter_edit.setMaximumWidth(200)
        self.filter_edit.textChanged.connect(self._apply_filter)
        trow.addWidget(self.filter_edit)
        self.all_btn = QPushButton("Select all")
        self.all_btn.clicked.connect(lambda: self._check_visible(True))
        self.none_btn = QPushButton("None")
        self.none_btn.clicked.connect(lambda: self._check_visible(False))
        trow.addWidget(self.all_btn)
        trow.addWidget(self.none_btn)
        outer.addLayout(trow)

        # Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["", "Partition", "FILE_ID", "Size", "Source", "Progress"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setAlternatingRowColors(True)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(C_SEL, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(C_NAME, QHeaderView.Stretch)
        hh.setSectionResizeMode(C_ID, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(C_SIZE, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(C_SRC, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(C_PROG, QHeaderView.Fixed)
        self.table.setColumnWidth(C_PROG, 170)
        outer.addWidget(self.table, 1)

        # Output row
        orow = QHBoxLayout()
        orow.addWidget(QLabel("Output:"))
        self.out_edit = QLineEdit()
        self.out_edit.setPlaceholderText("pkg_<curef>  (chosen automatically)")
        orow.addWidget(self.out_edit, 1)
        self.browse_btn = QPushButton("Browse…")
        self.browse_btn.clicked.connect(self.on_browse)
        orow.addWidget(self.browse_btn)
        orow.addWidget(QLabel("Parallel:"))
        self.parallel_spin = QSpinBox()
        self.parallel_spin.setRange(1, 8)
        self.parallel_spin.setValue(3)
        self.parallel_spin.setToolTip("How many partitions to download at once.")
        orow.addWidget(self.parallel_spin)
        self.verify_chk = QCheckBox("Verify SHA-1")
        self.verify_chk.setChecked(True)
        orow.addWidget(self.verify_chk)
        outer.addLayout(orow)

        # Action row
        arow = QHBoxLayout()
        self.pull_btn = QPushButton("Pull selected ▾")
        self.pull_btn.setObjectName("primary")
        self.pull_btn.clicked.connect(self.on_pull)
        self.pull_btn.setEnabled(False)
        arow.addWidget(self.pull_btn)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.on_cancel)
        self.cancel_btn.setEnabled(False)
        arow.addWidget(self.cancel_btn)
        self.pack_btn = QPushButton("⚡ Make flashable")
        self.pack_btn.setToolTip("Rename to real partition names + write an "
                                 "SP Flash Tool scatter.txt.")
        self.pack_btn.clicked.connect(self.on_pack)
        self.pack_btn.setEnabled(False)
        arow.addWidget(self.pack_btn)
        self.open_btn = QPushButton("Open folder")
        self.open_btn.clicked.connect(self.on_open_folder)
        self.open_btn.setEnabled(False)
        arow.addWidget(self.open_btn)
        arow.addStretch(1)
        self.overall = QProgressBar()
        self.overall.setMaximumWidth(240)
        self.overall.setTextVisible(True)
        self.overall.setFormat("%v / %m")
        arow.addWidget(self.overall)
        outer.addLayout(arow)

        # Status + log
        self.status_lbl = QLabel("Ready.")
        self.status_lbl.setObjectName("status")
        outer.addWidget(self.status_lbl)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(150)
        self.log.setObjectName("log")
        outer.addWidget(self.log)

        # Community sharing (opt-out) footer
        frow = QHBoxLayout()
        self.share_chk = QCheckBox("Share anonymous device IDs (curef + fv) to grow the device list")
        self.share_chk.setChecked(sharing.is_enabled())
        self.share_chk.setToolTip("Opt-out. Shares only device/firmware identifiers — "
                                  "no IMEI, no IP, no account.")
        self.share_chk.toggled.connect(self._on_share_toggled)
        frow.addWidget(self.share_chk)
        about = QLabel('<a href="#">what\'s shared?</a>')
        about.linkActivated.connect(
            lambda: QDesktopServices.openUrl(QUrl(sharing.server_url() + "/about")))
        frow.addWidget(about)
        frow.addStretch()
        outer.addLayout(frow)

        self._log(f"tcl-fw {__version__} · universal header key {key_hex()}")
        self._log(CREDIT)

        # First-run disclosure, shown once after the window is up.
        QTimer.singleShot(0, self._maybe_show_sharing_notice)

    # ── helpers ───────────────────────────────────────────────────────────
    def _log(self, msg: str) -> None:
        self.log.appendPlainText(msg)

    def _status(self, msg: str) -> None:
        self.status_lbl.setText(msg)

    def _on_share_toggled(self, checked: bool) -> None:
        sharing.set_enabled(checked)
        self._log(f"Community device sharing turned {'ON' if checked else 'OFF'}.")

    def _maybe_show_sharing_notice(self) -> None:
        """Show the opt-out disclosure once, letting the user turn it off here."""
        if not sharing.notice_pending():
            return
        box = QMessageBox(self)
        box.setWindowTitle("Community device sharing")
        box.setTextFormat(Qt.RichText)
        box.setText(
            "<b>tcl-fw can share the device IDs it looks up</b> (curef + firmware "
            "version) with a community registry, so the built-in device list grows "
            "automatically for everyone.<br><br>"
            "<b>Shared:</b> curef, firmware version, mode, resolved build, tool version.<br>"
            "<b>Not shared:</b> no IMEI, no IP, no account — nothing that identifies you."
            "<br><br>It's on by default. You can turn it off now or any time from the "
            "checkbox at the bottom of the window."
        )
        keep = box.addButton("Keep sharing on", QMessageBox.AcceptRole)
        off = box.addButton("Turn it off", QMessageBox.RejectRole)
        box.setDefaultButton(keep)
        box.exec()
        if box.clickedButton() is off:
            self.share_chk.setChecked(False)   # triggers _on_share_toggled -> saves OFF
        else:
            sharing.set_enabled(True)
        sharing.mark_notice_shown()

    def _on_curef_picked(self, index: int) -> None:
        """When a validated template is chosen, preselect the mode it serves."""
        mode = self._tpl_mode.get(self.curef_box.itemData(index))
        if mode is not None:
            i = self.mode_box.findData(mode)
            if i >= 0:
                self.mode_box.setCurrentIndex(i)

    def _current_curef(self) -> str:
        idx = self.curef_box.currentIndex()
        text = self.curef_box.currentText().strip()
        # If the user picked a catalog entry, its data holds the bare curef.
        if idx >= 0 and self.curef_box.itemText(idx) == text:
            return self.curef_box.itemData(idx) or text
        # Editable text may be "CUREF   ·   Name"; keep the leading token.
        return text.split("·")[0].strip().split()[0] if text else ""

    def _set_busy(self, busy: bool) -> None:
        self.load_btn.setEnabled(not busy)
        self.detect_btn.setEnabled(not busy)
        self.pull_btn.setEnabled(not busy and self._plan is not None)

    # ── detect ────────────────────────────────────────────────────────────
    def on_detect(self) -> None:
        self._status("Probing for a connected phone…")
        self._set_busy(True)
        self._detect_worker = DetectWorker()
        self._detect_worker.found.connect(self._on_detected)
        self._detect_worker.failed.connect(self._on_detect_failed)
        self._detect_worker.finished.connect(lambda: self._set_busy(False))
        self._detect_worker.start()

    def _on_detected(self, dev) -> None:
        self.curef_box.setEditText(dev.curef)
        self._detected_curef = dev.curef
        self._detected_fv = dev.fv
        if dev.fv:
            self.fv_edit.setText(dev.fv)
        fv_note = f", fv {dev.fv}" if dev.fv else ""
        self._log(f"Detected {dev.name or dev.model or dev.serial} → curef {dev.curef}{fv_note}")
        self._status(f"Detected {dev.curef} — click Load.")

    def _on_detect_failed(self, msg: str) -> None:
        self._log(f"detect: {msg}")
        self._status("No phone detected.")

    # ── load ──────────────────────────────────────────────────────────────
    def on_load(self) -> None:
        curef = self._current_curef()
        if not curef:
            QMessageBox.warning(self, "No device", "Enter or pick a curef first.")
            return
        if self._name_worker:
            self._name_worker.cancel()
        self.table.setRowCount(0)
        self._row_of.clear()
        self._entry_of.clear()
        self._info = self._plan = None
        self.pull_btn.setEnabled(False)
        self.open_btn.setEnabled(False)
        self._set_busy(True)
        self._status("Loading…")
        self._log(f"Loading {curef} …")

        # fv for OTA (mode 2): a value typed into the FV box wins; otherwise the
        # auto-detected fv, but only if it still belongs to the curef shown.
        typed_fv = self.fv_edit.text().strip()
        if typed_fv:
            fv = typed_fv
        elif curef == self._detected_curef and self._detected_fv:
            fv = self._detected_fv
        else:
            fv = "000000"
        self._load_worker = LoadWorker(curef, mode=self.mode_box.currentData(), fv=fv)
        self._load_worker.status.connect(self._status)
        self._load_worker.loaded.connect(self._on_loaded)
        self._load_worker.failed.connect(self._on_load_failed)
        self._load_worker.finished.connect(lambda: self._set_busy(False))
        self._load_worker.start()

    def _on_load_failed(self, msg: str) -> None:
        self._log(f"load failed: {msg}")
        self._status("Load failed.")
        QMessageBox.critical(self, "Load failed", msg)

    def _on_loaded(self, curef: str, info: DownloadInfo, plan: PullPlan) -> None:
        self._info = info
        self._plan = plan
        known = devices.lookup(curef)
        small = sum(1 for f in info.files if plan.sizes.get(f.file_id, -1) <= 0)
        self.info_lbl.setText(
            f"{curef}   tv={info.tv}  fw_id={info.fw_id}   ·   "
            f"{len(info.files)} parts ({small} small / {len(info.files)-small} body)"
            + (f"   ·   {known.name}" if known and known.name else ""))
        if not self.out_edit.text().strip():
            self.out_edit.setText(f"pkg_{curef.replace('/', '_')}")

        # Populate, largest body first (small parts sink to the bottom).
        ordered = sorted(info.files, key=lambda x: -(plan.sizes.get(x.file_id, -1)))
        self.table.setRowCount(len(ordered))
        for row, f in enumerate(ordered):
            bs = plan.sizes.get(f.file_id, -1)
            is_small = bs <= 0
            name = plan.names.get(f.file_id) or (
                "«in encrypted header»" if is_small else f"‹{f.file_id}›")

            sel = QTableWidgetItem()
            sel.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            sel.setCheckState(Qt.Checked)
            self.table.setItem(row, C_SEL, sel)

            self.table.setItem(row, C_NAME, QTableWidgetItem(name))
            self.table.setItem(row, C_ID, QTableWidgetItem(f.file_id))
            size_item = QTableWidgetItem(human_size(bs))
            size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, C_SIZE, size_item)
            src = QTableWidgetItem("header ⭑" if is_small else "body")
            self.table.setItem(row, C_SRC, src)

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setTextVisible(True)
            bar.setFormat("")
            self.table.setCellWidget(row, C_PROG, bar)

            self._row_of[f.file_id] = row
            self._entry_of[f.file_id] = f

        self.pull_btn.setEnabled(True)
        self._status(f"Loaded {len(ordered)} parts. Tick what you want, then Pull.")
        self._log(f"Loaded {len(ordered)} parts for {curef} (tv={info.tv} fw_id={info.fw_id}).")
        self._apply_filter()

        # Fill real names for unnamed body parts in the background (non-blocking).
        unnamed = [f for f in ordered
                   if plan.sizes.get(f.file_id, -1) > 0 and not plan.names.get(f.file_id)]
        if unnamed:
            self._name_worker = NameProbeWorker(plan, unnamed)
            self._name_worker.name_resolved.connect(self._on_name_resolved)
            self._name_worker.start()

    def _on_name_resolved(self, file_id: str, name: str) -> None:
        # Cache on the plan so pull_one reuses it (no second probe), and show it.
        if self._plan:
            self._plan.names[file_id] = name
        row = self._row_of.get(file_id)
        if row is not None:
            self.table.item(row, C_NAME).setText(name)

    # ── table filtering / selection ───────────────────────────────────────
    def _apply_filter(self, *_: object) -> None:
        needle = self.filter_edit.text().strip().lower()
        small_only = self.small_only.isChecked()
        for fid, row in self._row_of.items():
            is_small = self._plan.sizes.get(fid, -1) <= 0 if self._plan else False
            name = self.table.item(row, C_NAME).text().lower()
            hide = (small_only and not is_small) or (needle and needle not in name)
            self.table.setRowHidden(row, hide)

    def _check_visible(self, checked: bool) -> None:
        state = Qt.Checked if checked else Qt.Unchecked
        for row in self._row_of.values():
            if not self.table.isRowHidden(row):
                self.table.item(row, C_SEL).setCheckState(state)

    def _selected_entries(self) -> list[FileEntry]:
        out = []
        for fid, row in self._row_of.items():
            if self.table.isRowHidden(row):
                continue
            if self.table.item(row, C_SEL).checkState() == Qt.Checked:
                out.append(self._entry_of[fid])
        return out

    # ── pull ──────────────────────────────────────────────────────────────
    def on_pull(self) -> None:
        if not self._plan:
            return
        files = self._selected_entries()
        if not files:
            QMessageBox.information(self, "Nothing selected",
                                    "Tick at least one partition to pull.")
            return
        outdir = self.out_edit.text().strip() or f"pkg_{self._info.curef.replace('/', '_')}"
        self.out_edit.setText(outdir)
        self._last_outdir = os.path.abspath(outdir)

        self.overall.setRange(0, len(files))
        self.overall.setValue(0)
        self._done_count = 0
        for f in files:                       # reset visible bars
            bar = self.table.cellWidget(self._row_of[f.file_id], C_PROG)
            if bar:
                bar.setValue(0)
                bar.setFormat("")
        self._set_busy(True)
        self.pull_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.open_btn.setEnabled(False)
        conc = self.parallel_spin.value()
        self._status(f"Pulling {len(files)} parts → {outdir}/  ({conc} at a time)…")
        self._log(f"Pull started: {len(files)} parts → {outdir}/  (parallel={conc})")

        self._pull_worker = PullWorker(
            self._plan, files, outdir, verify=self.verify_chk.isChecked(),
            concurrency=conc)
        self._pull_worker.file_started.connect(self._on_file_started)
        self._pull_worker.file_progress.connect(self._on_file_progress)
        self._pull_worker.file_done.connect(self._on_file_done)
        self._pull_worker.finished_all.connect(self._on_pull_finished)
        self._pull_worker.failed.connect(self._on_pull_failed)
        self._pull_worker.start()

    def _on_file_started(self, fid: str, name: str, total: int) -> None:
        row = self._row_of.get(fid)
        if row is None:
            return
        self.table.item(row, C_NAME).setText(name)
        bar = self.table.cellWidget(row, C_PROG)
        if bar:
            if total > 0:
                bar.setRange(0, 100)
                bar.setFormat("%p%")
            else:
                bar.setRange(0, 0)           # busy/indeterminate for headers
                bar.setFormat("decrypt…")

    def _on_file_progress(self, fid: str, got: int, total: int) -> None:
        row = self._row_of.get(fid)
        if row is None or total <= 0:
            return
        bar = self.table.cellWidget(row, C_PROG)
        if bar:
            if bar.maximum() == 0:
                bar.setRange(0, 100)
            bar.setValue(int(got * 100 / total))

    def _on_file_done(self, res: PartResult) -> None:
        row = self._row_of.get(res.file_id)
        self._done_count += 1
        self.overall.setValue(self._done_count)
        if row is not None:
            self.table.item(row, C_NAME).setText(res.name)
            self.table.item(row, C_SIZE).setText(human_size(res.size))
            bar = self.table.cellWidget(row, C_PROG)
            if bar:
                bar.setRange(0, 100)
                if res.error:
                    bar.setValue(0)
                    bar.setFormat("error")
                elif res.verified is False:
                    bar.setValue(100)
                    bar.setFormat("✓ (bad SHA)")
                else:
                    bar.setValue(100)
                    bar.setFormat("done ✓" if res.verified else "done")
        tag = "DEC " if res.kind == "header" else "BODY"
        if res.error:
            self._log(f"  ✗ {res.name}: {res.error}")
        else:
            v = "" if res.verified is None else (" ✓" if res.verified else " ✗SHA")
            self._log(f"  {tag} {res.name}  {res.size:,} B{v}")

    def _on_pull_finished(self, results: list, mpath: str) -> None:
        self._set_busy(False)
        self.cancel_btn.setEnabled(False)
        self.pull_btn.setEnabled(True)
        self.open_btn.setEnabled(True)
        self.pack_btn.setEnabled(True)
        ok = sum(1 for r in results if not r.error)
        dec = sum(1 for r in results if r.kind == "header" and not r.error)
        self._status(f"Done — {ok}/{len(results)} parts written ({dec} decrypted). "
                     f"manifest.json saved.")
        self._log(f"Finished: {ok}/{len(results)} OK, {dec} decrypted. Manifest: {mpath}")

    def _on_pull_failed(self, msg: str) -> None:
        self._set_busy(False)
        self.cancel_btn.setEnabled(False)
        self.pull_btn.setEnabled(True)
        self._log(f"pull failed: {msg}")
        self._status("Pull failed.")
        QMessageBox.critical(self, "Pull failed", msg)

    def on_cancel(self) -> None:
        if self._pull_worker:
            self._pull_worker.cancel()
            self._status("Cancelling after the current part…")
            self._log("Cancel requested.")

    # ── misc actions ──────────────────────────────────────────────────────
    def on_browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose output folder")
        if d:
            self.out_edit.setText(d)

    def on_pack(self) -> None:
        outdir = getattr(self, "_last_outdir", None) or self.out_edit.text().strip()
        if not outdir or not os.path.isdir(outdir):
            QMessageBox.information(self, "No folder",
                                    "Pull a package first (or set the output folder).")
            return
        self.pack_btn.setEnabled(False)
        self._status("Making flashable — mapping partitions + writing scatter…")
        self._log(f"Pack: {outdir}")
        self._pack_worker = PackWorker(outdir)
        self._pack_worker.done.connect(self._on_packed)
        self._pack_worker.failed.connect(self._on_pack_failed)
        self._pack_worker.finished.connect(lambda: self.pack_btn.setEnabled(True))
        self._pack_worker.start()

    def _on_packed(self, result) -> None:
        conf = [m for m in result.matches if m.part and m.confidence >= 0.7]
        low = [m for m in result.matches if m.part and m.confidence < 0.7]
        for m in sorted(conf, key=lambda x: -x.probe.size):
            self._log(f"  {m.probe.fname}  →  {m.new_name}  [{m.confidence:.2f} {m.how}]")
        if low:
            self._log(f"  {len(low)} low-confidence left as-is (verify): "
                      + ", ".join(f"{m.probe.fname}~{m.part.file_name}" for m in low))
        scat = os.path.basename(result.scatter_path or "scatter.txt")
        self._status(f"Flashable: renamed {len(conf)} partitions, wrote {scat}. "
                     f"Load it in SP Flash Tool / mtkclient.")
        self._log(f"  scatter → {scat}")

    def _on_pack_failed(self, msg: str) -> None:
        self._log(f"pack: {msg}")
        self._status("Make flashable failed.")
        QMessageBox.warning(self, "Make flashable", msg)

    def on_open_folder(self) -> None:
        path = getattr(self, "_last_outdir", None) or self.out_edit.text().strip()
        if path and os.path.isdir(path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))

    def closeEvent(self, event) -> None:
        """Cancel and let running workers unwind so Qt doesn't kill live threads."""
        for w in (self._name_worker, self._pull_worker, self._pack_worker):
            if w and w.isRunning():
                if hasattr(w, "cancel"):
                    w.cancel()
                w.wait(3000)
        super().closeEvent(event)

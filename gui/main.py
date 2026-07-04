#!/usr/bin/env python3
"""
tcl-fota GUI — a friendly front-end for tcl-fota.js aimed at people who
aren't comfortable with a command line.

This does not reimplement the TCL protocol. It shells out to the Node.js
tool (`node tcl-fota.js devices-json|check-json|download-json`) and parses
its JSON output. tcl-fota.js stays the single source of truth for the
CUREF/VK/download protocol; this file is presentation only.

OTA updates only (the common case for ~80% of devices). FULL image mode
has its own multi-file/encrypted-header workflow that's CLI-only for now.

Requires: PySide6, and Node.js reachable as `node` on PATH (or see
NODE_PATH_OVERRIDE below).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TCL_FOTA_JS = REPO_ROOT / "tcl-fota.js"

# If `node` isn't on PATH, set this to a full path (e.g. r"C:\Program Files\nodejs\node.exe").
NODE_PATH_OVERRIDE = None


def find_node() -> str:
    return NODE_PATH_OVERRIDE or "node"


def format_bytes(n: int) -> str:
    if not n:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    i = 0
    size = float(n)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    return f"{size:.1f} {units[i]}"


class JsonLineProcess(QThread):
    """Runs `node tcl-fota.js <args>` and emits each parsed JSON line."""

    line = Signal(dict)
    finished_ok = Signal()
    failed = Signal(str)

    def __init__(self, args, parent=None):
        super().__init__(parent)
        self.args = args
        self._proc = None
        self._stop_requested = False

    def run(self):
        try:
            self._proc = subprocess.Popen(
                [find_node(), str(TCL_FOTA_JS), *self.args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=str(REPO_ROOT),
            )
        except FileNotFoundError:
            self.failed.emit(
                "This app needs Node.js, which isn't installed on this computer.\n\n"
                "Go to nodejs.org, download the installer (choose the \"LTS\" version), "
                "run it with the default options, then close and reopen this app."
            )
            return
        except Exception as e:
            self.failed.emit(str(e))
            return

        assert self._proc.stdout is not None
        for raw_line in self._proc.stdout:
            if self._stop_requested:
                break
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                obj = json.loads(raw_line)
            except json.JSONDecodeError:
                continue  # ignore any stray non-JSON output
            self.line.emit(obj)

        self._proc.wait()
        stderr = self._proc.stderr.read() if self._proc.stderr else ""
        if self._proc.returncode not in (0, None) and stderr.strip():
            self.failed.emit(stderr.strip())
        else:
            self.finished_ok.emit()

    def stop(self):
        self._stop_requested = True
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()


class DeviceDetectPage(QWidget):
    """Step 1: find a phone over USB, or let the user pick manually."""

    device_chosen = Signal(str, str)  # curef, fv ("" if unknown)

    KNOWN_DEVICES = {
        "TCL 30 XE 5G": "T776B-2ALGUS12-V",
        "TCL 30 V 5G": "T781S-2ALGUS12-V",
        "TCL 40 XE": "T609DL-2ALGUS12-V",
        "TCL 30 XL (Tracfone)": "T601DL-2AKFUS11-N",
        "TCL REVVL V+ 5G": "T618DL-2ALGUS12-V",
        "TCL REVVL 6 5G": "T608DL-2ALGUS12-V",
        "TCL REVVL 6 5G (Tracfone)": "T608DL-2AKFUS11-N",
        "TCL REVVL 6 Pro 5G": "T609DL-2ALGUS12-V",
        "TCL REVVL 7 5G": "T701DL-2ALGUS12-V",
        "TCL REVVL 7 Pro 5G": "T702DL-2ALGUS12-V",
        "TCL T702Z (Dish/Boost)": "T702Z-EARXUS12-V",
        "TCL NxtPaper 70 Pro (T-Mobile/Metro)": "T807W-EATBUS12-V",
        "Alcatel Joy Tab 2": "9032Z-2ALGUS12-V",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(12)

        title = QLabel("Find your phone")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")
        layout.addWidget(title)

        subtitle = QLabel(
            "Plug your TCL / REVVL / Alcatel phone into this computer with a USB "
            "cable. If a popup appears on the phone, tap “Allow USB debugging.”"
        )
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        self.detect_btn = QPushButton("Detect my phone")
        self.detect_btn.clicked.connect(self.detect)
        layout.addWidget(self.detect_btn)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        layout.addWidget(sep)

        manual_label = QLabel("Or pick your model manually:")
        layout.addWidget(manual_label)

        self.device_combo = QComboBox()
        self.device_combo.addItem("Select a device…")
        for name in self.KNOWN_DEVICES:
            self.device_combo.addItem(name)
        self.device_combo.addItem("Custom CUREF…")
        layout.addWidget(self.device_combo)

        self.custom_curef_edit = QLineEdit()
        self.custom_curef_edit.setPlaceholderText("Enter CUREF (e.g. T702Z-EARXUS12-V)")
        self.custom_curef_edit.hide()
        layout.addWidget(self.custom_curef_edit)
        self.device_combo.currentTextChanged.connect(self._on_combo_changed)

        fv_label = QLabel("Current firmware version (FV) — see Settings → About Phone:")
        layout.addWidget(fv_label)
        self.fv_edit = QLineEdit()
        self.fv_edit.setPlaceholderText("e.g. 9LBHZDH0")
        layout.addWidget(self.fv_edit)

        self.continue_btn = QPushButton("Continue")
        self.continue_btn.clicked.connect(self._on_continue)
        layout.addWidget(self.continue_btn)

        layout.addStretch()

    def _on_combo_changed(self, text):
        self.custom_curef_edit.setVisible(text == "Custom CUREF…")

    def _selected_curef(self):
        text = self.device_combo.currentText()
        if text in self.KNOWN_DEVICES:
            return self.KNOWN_DEVICES[text]
        if text == "Custom CUREF…":
            return self.custom_curef_edit.text().strip()
        return ""

    def _on_continue(self):
        curef = self._selected_curef()
        fv = self.fv_edit.text().strip()
        if not curef:
            QMessageBox.warning(self, "Missing device", "Select or enter a device CUREF first.")
            return
        if not fv:
            QMessageBox.warning(self, "Missing firmware version", "Enter your current firmware version (FV).")
            return
        self.device_chosen.emit(curef, fv)

    def detect(self):
        self.detect_btn.setEnabled(False)
        self.status_label.setText("Looking for a connected phone…")
        self._worker = JsonLineProcess(["devices-json"])
        self._worker.line.connect(self._on_result)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished_ok.connect(lambda: self.detect_btn.setEnabled(True))
        self._worker.start()

    def _on_result(self, obj):
        if not obj.get("adbAvailable"):
            self.status_label.setText(
                "Couldn't run adb (Android's device tool). Auto-detect isn't "
                "available on this computer — pick your device manually below."
            )
            return

        devices = obj.get("devices", [])
        found = [d for d in devices if d.get("curef")]

        if not devices:
            self.status_label.setText(
                "No phone found. Make sure it's plugged in via USB and USB "
                "debugging is turned on (Settings → About Phone → tap "
                "“Build number” 7 times, then Settings → System → "
                "Developer options → USB debugging)."
            )
        elif not found:
            self.status_label.setText(
                f"Found {len(devices)} device(s) connected, but couldn't read a "
                "TCL model number from any of them. It may not be a TCL/REVVL "
                "phone — pick your model manually below."
            )
        else:
            d = found[0]
            self.status_label.setText(
                f"Found it! Model: {d['curef']}\n"
                "Firmware version isn't auto-detectable yet — check "
                "Settings → About Phone and type it in below."
            )
            # Pre-select in the combo if it's a known device, else drop it into
            # the custom field so the user doesn't have to retype it.
            for name, curef in self.KNOWN_DEVICES.items():
                if curef == d["curef"]:
                    self.device_combo.setCurrentText(name)
                    break
            else:
                self.device_combo.setCurrentText("Custom CUREF…")
                self.custom_curef_edit.setText(d["curef"])

    def _on_failed(self, message):
        self.status_label.setText(f"Auto-detect failed: {message}")
        self.detect_btn.setEnabled(True)


class UpdatePage(QWidget):
    """Step 2: check for an update, then download it with progress."""

    back_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.curef = ""
        self.fv = ""
        self.out_dir = str(Path.home() / "Downloads")
        self._worker = None
        self._update_info = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(12)

        self.title = QLabel("Checking for updates…")
        self.title.setStyleSheet("font-size: 20px; font-weight: 600;")
        layout.addWidget(self.title)

        self.info_label = QLabel("")
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        out_row = QHBoxLayout()
        out_row.addWidget(QLabel("Save to:"))
        self.out_edit = QLineEdit(self.out_dir)
        out_row.addWidget(self.out_edit)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse)
        out_row.addWidget(browse_btn)
        layout.addLayout(out_row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.hide()
        layout.addWidget(self.progress)

        self.progress_label = QLabel("")
        layout.addWidget(self.progress_label)

        btn_row = QHBoxLayout()
        self.back_btn = QPushButton("← Back")
        self.back_btn.clicked.connect(self.back_requested.emit)
        btn_row.addWidget(self.back_btn)

        self.download_btn = QPushButton("Download update")
        self.download_btn.clicked.connect(self._start_download)
        self.download_btn.setEnabled(False)
        btn_row.addWidget(self.download_btn)
        layout.addLayout(btn_row)

        layout.addStretch()

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Choose download folder", self.out_edit.text())
        if d:
            self.out_edit.setText(d)

    def start_check(self, curef: str, fv: str):
        self.curef = curef
        self.fv = fv
        self.title.setText("Checking for updates…")
        self.info_label.setText(f"Device: {curef}\nCurrent version: {fv}")
        self.download_btn.setEnabled(False)
        self.progress.hide()
        self.progress_label.setText("")

        self._worker = JsonLineProcess(["check-json", "--curef", curef, "--fv", fv])
        self._worker.line.connect(self._on_check_result)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_check_result(self, obj):
        info = obj.get("info")
        if not info or not info.get("fw_id"):
            self.title.setText("No update available")
            self.info_label.setText(
                "Your firmware may already be the latest version, or the "
                "device/version info entered doesn't match TCL's records."
            )
            return

        self._update_info = info
        size = format_bytes(int(info.get("filesize") or 0))
        self.title.setText("Update available!")
        self.info_label.setText(
            f"New version: {info.get('tv', '?')}\n"
            f"File: {info.get('filename', '?')}\n"
            f"Size: {size}"
        )
        self.download_btn.setEnabled(True)

    def _start_download(self):
        self.download_btn.setEnabled(False)
        self.progress.show()
        self.progress.setValue(0)
        self.progress_label.setText("Starting download…")

        self._worker = JsonLineProcess([
            "download-json",
            "--curef", self.curef,
            "--fv", self.fv,
            "--out", self.out_edit.text().strip() or self.out_dir,
        ])
        self._worker.line.connect(self._on_download_event)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_download_event(self, obj):
        t = obj.get("type")
        if t == "downloading":
            self.progress_label.setText(f"Downloading {obj.get('filename', '')}…")
        elif t == "progress":
            received, total = obj.get("received", 0), obj.get("total", 0)
            if total:
                pct = int(received / total * 100)
                self.progress.setValue(pct)
                self.progress_label.setText(
                    f"{format_bytes(received)} / {format_bytes(total)} ({pct}%)"
                )
            else:
                self.progress_label.setText(f"{format_bytes(received)} downloaded")
        elif t == "verifying":
            self.progress_label.setText("Verifying download…")
        elif t == "done":
            self.progress.setValue(100)
            verified = obj.get("verified")
            note = ""
            if verified is True:
                note = " Checksum verified — the file downloaded correctly."
            elif verified is False:
                note = " WARNING: checksum did not match — try downloading again."
            self.progress_label.setText(f"Done! Saved to {obj.get('dest', '')}.{note}")
            self.download_btn.setText("Download again")
            self.download_btn.setEnabled(True)
        elif t == "error":
            QMessageBox.critical(self, "Download failed", obj.get("message", "Unknown error"))
            self.download_btn.setEnabled(True)

    def _on_failed(self, message):
        QMessageBox.critical(self, "Error", message)
        self.download_btn.setEnabled(True)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("tcl-fota — Firmware Updater")
        self.resize(560, 480)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.detect_page = DeviceDetectPage()
        self.update_page = UpdatePage()

        self.stack.addWidget(self.detect_page)
        self.stack.addWidget(self.update_page)

        self.detect_page.device_chosen.connect(self._go_to_update_page)
        self.update_page.back_requested.connect(lambda: self.stack.setCurrentWidget(self.detect_page))

    def _go_to_update_page(self, curef, fv):
        self.stack.setCurrentWidget(self.update_page)
        self.update_page.start_check(curef, fv)


def main():
    if not TCL_FOTA_JS.exists():
        print(f"Error: {TCL_FOTA_JS} not found.", file=sys.stderr)
        sys.exit(1)

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

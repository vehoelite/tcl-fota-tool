"""
workers.py — QThread workers wrapping the (blocking) tcl_fw backend.

Nothing here touches widgets. Each worker does one backend job on its own thread
and reports back purely through signals, which Qt delivers on the GUI thread:

  * DetectWorker  — adb.detect() for auto-CUREF.
  * LoadWorker    — devices.resolve -> fota.request_download -> puller.build_plan.
  * PullWorker    — puller.pull_one() over the chosen files, with live progress.

Python objects (DownloadInfo, PullPlan, PartResult) ride across signals as
`object`; Qt marshals them to the GUI thread untouched.
"""

from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import QThread, Signal

from tcl_fw import adb, devices, fota, puller
from tcl_fw.fota import DownloadInfo, FileEntry
from tcl_fw.puller import PartResult, PullPlan


class DetectWorker(QThread):
    """Probe for a plugged-in phone and read its curef."""

    found = Signal(object)      # tcl_fw.adb.Device
    failed = Signal(str)

    def run(self) -> None:
        try:
            if not adb.available():
                self.failed.emit(
                    "adb not found — set TCL_FW_ADB, add adb to PATH, "
                    "or drop platform-tools/ next to tcl-fw.")
                return
            dev = adb.detect()
            if not dev or not dev.curef:
                self.failed.emit("No authorized device with a readable curef.")
                return
            self.found.emit(dev)
        except Exception as e:  # noqa: BLE001 — surface anything to the UI
            self.failed.emit(str(e))


class LoadWorker(QThread):
    """Resolve a curef, fetch the fileset, and probe sizes + names."""

    status = Signal(str)
    loaded = Signal(str, object, object)   # curef, DownloadInfo, PullPlan
    failed = Signal(str)

    def __init__(self, curef: str, tv: Optional[str] = None,
                 fw_id: Optional[str] = None) -> None:
        super().__init__()
        self._curef = curef.strip()
        self._tv = tv
        self._fw_id = fw_id

    def run(self) -> None:
        try:
            self.status.emit("Resolving tv / fw_id…")
            curef, tv, fw_id = devices.resolve(self._curef, self._tv, self._fw_id)
            if not (tv and fw_id):
                self.failed.emit(
                    f"Could not resolve tv/fw_id for {curef}. "
                    "Check the curef, or the server has nothing for it.")
                return

            self.status.emit("Requesting fileset…")
            info: DownloadInfo = fota.request_download(curef, tv, fw_id)
            if not info.files:
                self.failed.emit("Server returned an empty fileset.")
                return

            self.status.emit(
                f"Probing {len(info.files)} bodies + resolving names…")
            plan: PullPlan = puller.build_plan(curef, info)
            self.loaded.emit(curef, info, plan)
        except Exception as e:  # noqa: BLE001
            self.failed.emit(str(e))


class PullWorker(QThread):
    """Pull a chosen subset of files, decrypting headers / streaming bodies."""

    file_started = Signal(str, str, int)     # file_id, name, total (0 = unknown)
    file_progress = Signal(str, int, int)    # file_id, got, total
    file_done = Signal(object)               # PartResult
    finished_all = Signal(list, str)         # [PartResult], manifest_path
    failed = Signal(str)

    def __init__(self, plan: PullPlan, files: list[FileEntry], outdir: str,
                 verify: bool = True) -> None:
        super().__init__()
        self._plan = plan
        self._files = files
        self._outdir = outdir
        self._verify = verify
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        try:
            os.makedirs(self._outdir, exist_ok=True)
            results: list[PartResult] = []
            for f in self._files:
                if self._cancel:
                    break
                plan = self._plan
                name = plan.names.get(f.file_id) or f.file_id
                total = plan.sizes.get(f.file_id, -1)
                self.file_started.emit(f.file_id, name, total if total > 0 else 0)

                def cb(got: int, tot: int, _fid=f.file_id) -> None:
                    self.file_progress.emit(_fid, got, tot or 0)

                res = puller.pull_one(
                    plan, f, self._outdir, on_progress=cb, verify=self._verify)
                results.append(res)
                self.file_done.emit(res)

            mpath = puller.write_manifest(
                self._plan.info.curef, self._plan, results, self._outdir)
            self.finished_all.emit(results, mpath)
        except Exception as e:  # noqa: BLE001
            self.failed.emit(str(e))

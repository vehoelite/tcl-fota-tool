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
from concurrent.futures import ThreadPoolExecutor, as_completed
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


class NameProbeWorker(QThread):
    """Fill in real names for body parts the .sca join didn't cover.

    Runs *after* Load so the list shows something immediately; each body's first
    bytes are fetched in parallel and identified by content-magic, and names are
    reported one at a time as they land. Small (header) parts are skipped — their
    name needs a full header fetch + decrypt, which happens at pull time.
    """

    name_resolved = Signal(str, str)         # file_id, name
    done = Signal()

    def __init__(self, plan: PullPlan, files: list[FileEntry],
                 workers: int = 12) -> None:
        super().__init__()
        self._plan = plan
        self._files = files
        self._workers = workers
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        if not self._files:
            self.done.emit()
            return
        try:
            with ThreadPoolExecutor(max_workers=self._workers) as ex:
                futs = {ex.submit(puller._resolve_name, self._plan, f, False): f
                        for f in self._files}
                for fut in as_completed(futs):
                    if self._cancel:
                        break
                    f = futs[fut]
                    try:
                        name = fut.result()
                    except Exception:
                        name = None
                    if name:
                        self.name_resolved.emit(f.file_id, name)
        except Exception:  # noqa: BLE001 — naming is best-effort, never fatal
            pass
        self.done.emit()


class PullWorker(QThread):
    """Pull a chosen subset of files, decrypting headers / streaming bodies."""

    file_started = Signal(str, str, int)     # file_id, name, total (0 = unknown)
    file_progress = Signal(str, int, int)    # file_id, got, total
    file_done = Signal(object)               # PartResult
    finished_all = Signal(list, str)         # [PartResult], manifest_path
    failed = Signal(str)

    def __init__(self, plan: PullPlan, files: list[FileEntry], outdir: str,
                 verify: bool = True, concurrency: int = 3) -> None:
        super().__init__()
        self._plan = plan
        self._files = files
        self._outdir = outdir
        self._verify = verify
        self._concurrency = max(1, concurrency)
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def _pull_one(self, f: FileEntry) -> Optional[PartResult]:
        """Pull a single file (runs on a pool thread). Progress/started/done
        signals are keyed by file_id, so concurrent pulls update independently."""
        if self._cancel:
            return None
        plan = self._plan
        name = plan.names.get(f.file_id) or f.file_id
        total = plan.sizes.get(f.file_id, -1)
        self.file_started.emit(f.file_id, name, total if total > 0 else 0)

        def cb(got: int, tot: int, _fid=f.file_id) -> None:
            self.file_progress.emit(_fid, got, tot or 0)

        res = puller.pull_one(plan, f, self._outdir, on_progress=cb,
                              verify=self._verify)
        self.file_done.emit(res)
        return res

    def run(self) -> None:
        try:
            os.makedirs(self._outdir, exist_ok=True)
            results: list[PartResult] = []
            with ThreadPoolExecutor(max_workers=self._concurrency) as ex:
                futs = [ex.submit(self._pull_one, f) for f in self._files]
                for fut in as_completed(futs):
                    r = fut.result()
                    if r is not None:
                        results.append(r)
            mpath = puller.write_manifest(
                self._plan.info.curef, self._plan, results, self._outdir)
            self.finished_all.emit(results, mpath)
        except Exception as e:  # noqa: BLE001
            self.failed.emit(str(e))

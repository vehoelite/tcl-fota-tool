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

from tcl_fw import adb, devices, flashpack, fota, puller, sharing, templates
from tcl_fw.fota import DownloadInfo, FileEntry
from tcl_fw.puller import PartResult, PullPlan


class DbFetchWorker(QThread):
    """Fetch the community firmware database (server, with a local fallback)."""

    loaded = Signal(list)   # list[dict]: curef, tv, date, size, mode, api, fv

    def run(self) -> None:
        import json
        import urllib.request
        rows: list[dict] = []
        try:
            url = sharing.server_url()
            if url:
                req = urllib.request.Request(
                    url + "/api/curefs?limit=5000",
                    headers={"User-Agent": f"tcl-fw/{sharing.__version__}"})
                data = json.loads(urllib.request.urlopen(req, timeout=8).read())
                for r in data.get("records", []):
                    if not r.get("tv"):
                        continue
                    rows.append({
                        "curef": r.get("curef", ""), "tv": r.get("tv", ""),
                        "date": (r.get("first_seen") or "")[:10],
                        "size": r.get("size"), "mode": r.get("mode", ""),
                        "svn": r.get("svn"), "fv": r.get("fv") or "",
                    })
        except Exception:
            rows = []
        if not rows:  # offline fallback: whatever the local device list knows
            try:
                for t in templates.load():
                    for rel in t.releases:
                        rows.append({
                            "curef": t.curef, "tv": rel.tv,
                            "date": (rel.first_seen or "")[:10],
                            "size": None, "mode": str(t.mode), "svn": None, "fv": "",
                        })
            except Exception:
                pass
        self.loaded.emit(rows)


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
                 fw_id: Optional[str] = None, mode: int = 4,
                 fv: str = "000000") -> None:
        super().__init__()
        self._curef = curef.strip()
        self._tv = tv
        self._fw_id = fw_id
        self._mode = mode
        self._fv = fv or "000000"

    def _autopull_fv(self) -> None:
        """OTA needs a real fv. If none was supplied, read it straight off a
        plugged-in phone whose curef matches — so the value is pulled, never
        typed, whenever the device is actually connected."""
        if self._mode != 4 and self._fv == "000000":
            want = self._curef.lower().removesuffix("-v")
            try:
                for serial in adb.list_serials():
                    dev = adb.read_device(serial)
                    if dev.curef and dev.fv and dev.curef.lower().removesuffix("-v") == want:
                        self._fv = dev.fv
                        self.status.emit(f"Read firmware version {dev.fv} from the phone.")
                        return
            except Exception:
                pass  # no adb / no match — fall through, resolve will report it

    def run(self) -> None:
        try:
            self._autopull_fv()
            self.status.emit("Resolving tv / fw_id…")
            curef, tv, fw_id = devices.resolve(self._curef, self._tv, self._fw_id,
                                               mode=self._mode, fv=self._fv)
            if not (tv and fw_id):
                if self._mode == 4:
                    # No FULL image for this curef — usually means the device
                    # only gets OTA deltas, not a bad curef. Steer to mode 2.
                    self.failed.emit(
                        f"No FULL image is published for {curef}. That's normal — "
                        "many devices only get OTA updates. Switch the mode selector "
                        "to OTA (mode 2) and try again.")
                elif self._fv == "000000":
                    # OTA with no real firmware version — the server can't compute
                    # a delta from a placeholder. This is the usual cause, not a
                    # bad curef.
                    self.failed.emit(
                        f"OTA needs this device's current firmware version, which "
                        f"isn't set for {curef}. Plug the phone in and click Detect "
                        "(it fills FV automatically), or type the FV in the box "
                        "(from ro.tct.sys.ver / the phone's About screen).")
                else:
                    self.failed.emit(
                        f"No OTA update offered for {curef} at firmware {self._fv}. "
                        "The phone may already be on the latest version, or the FV "
                        "may be wrong.")
                return

            self.status.emit("Requesting fileset…")
            info: DownloadInfo = fota.request_download(
                curef, tv, fw_id, mode=self._mode,
                fv=self._fv if self._fv != "000000" else "AAA000")
            fv_used = None if self._fv == "000000" else self._fv
            sharing.submit(curef, fv_used, self._mode, tv, fw_id,
                           size=sum(f.size for f in info.files),
                           svn_fn=lambda: fota.check_svn(curef, self._mode, self._fv))
            if not info.files:
                self.failed.emit("Server returned an empty fileset.")
                return

            self.status.emit(
                f"Probing {len(info.files)} bodies + resolving names…")
            plan: PullPlan = puller.build_plan(curef, info, mode=self._mode)
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


class PackWorker(QThread):
    """Rename a pulled folder's images to real partition names + write scatter.txt."""

    done = Signal(object)                    # flashpack.PackResult
    failed = Signal(str)

    def __init__(self, pkgdir: str, min_conf: float = 0.7) -> None:
        super().__init__()
        self._dir = pkgdir
        self._conf = min_conf

    def run(self) -> None:
        try:
            result = flashpack.build(self._dir)
            if not result:
                self.failed.emit("No MTK scatter in this folder "
                                 "(device may use the GOTU .sca format).")
                return
            flashpack.apply(self._dir, result, min_confidence=self._conf)
            self.done.emit(result)
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

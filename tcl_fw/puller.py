"""
puller.py — orchestrates a full service-package pull.

The per-file model (from Littlenine's tcl-fw.py), decided by body size:
  * empty body (HTTP 416 / size 0)  -> SMALL partition: the real image is the
    decrypted 4 MiB encrypted header.
  * non-empty body                  -> LARGE partition: the plaintext body IS
    the image; stream it.

Naming is server-authoritative when possible (check_new manifest + .sca scatter),
falling back to content-magic identification. Output lands in <outdir>/, and a
manifest.json records what was pulled.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import fota, manifest as manifest_mod, naming
from .crypto import decrypt_header
from .download import fetch_checksums, sha1_file, stream_body
from .fota import DownloadInfo, FileEntry

# How much of a body to fetch for content-naming: enough to un-sparse block 0
# (ext4/f2fs superblock at raw offset 1024) and read a zip's first entry.
NAME_HEAD_BYTES = 1 << 16


@dataclass
class PartResult:
    file_id: str
    name: str
    kind: str                 # "header" | "body"
    size: int = 0
    path: Optional[str] = None
    verified: Optional[bool] = None
    error: Optional[str] = None


@dataclass
class PullPlan:
    info: DownloadInfo
    names: dict[str, str] = field(default_factory=dict)   # FILE_ID -> real name
    sizes: dict[str, int] = field(default_factory=dict)   # FILE_ID -> body size
    manifest: Optional["manifest_mod.Manifest"] = None    # embedded target_files manifest


# ── naming ──────────────────────────────────────────────────────────────────

def authoritative_names(curef: str, info: DownloadInfo,
                        mode: int = 4) -> dict[str, str]:
    """FILE_ID -> real file_name via the check_new manifest + .sca scatter.
    Returns {} if the scatter/manifest is unavailable (caller falls back)."""
    manifest, sca_fid = fota.manifest(curef, mode=mode)
    by_id = info.by_id()
    if not manifest or not sca_fid or sca_fid not in by_id:
        return {}
    rel = by_id[sca_fid]
    # The .sca is itself a small partition — its body may be empty, so decrypt
    # the header if needed.
    from .download import stream_body  # noqa: F401 (kept explicit for clarity)
    data = b""
    if info.slave:
        try:
            import urllib.request
            req = urllib.request.Request("http://%s%s" % (info.slave, rel),
                                         headers={"User-Agent": fota.USER_AGENT})
            data = urllib.request.urlopen(req, timeout=60).read()
        except Exception:
            data = b""
    if not data and info.encslave:
        enc = fota.fetch_header(info.encslave, rel)
        data = decrypt_header(enc) if len(enc) >= 16 else b""
    sca = naming.parse_sca(data.decode("latin1", "replace"))
    if not sca:
        return {}
    return naming.join_names(manifest, sca, by_id)


# ── planning ────────────────────────────────────────────────────────────────

def _fetch_body(slave: str, rel: str, cap: int = 64 << 20) -> bytes:
    """Fetch a whole body into memory (capped). Used only for the small
    target_files zip; returns b'' on any error."""
    try:
        import urllib.request
        req = urllib.request.Request("http://%s%s" % (slave, rel),
                                     headers={"User-Agent": fota.USER_AGENT})
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read(cap)
    except Exception:
        return b""


def load_embedded_manifest(info: DownloadInfo,
                           sizes: dict[str, int]) -> Optional["manifest_mod.Manifest"]:
    """Some devices serve no top-level .sca; instead the partition manifest is
    bundled inside a downloaded ``target_files`` zip. Find that zip (a modest
    body whose first zip entry is target_files_extract/…) and parse it."""
    if not info.slave:
        return None
    for f in info.files:
        bs = sizes.get(f.file_id, -1)
        if bs <= 0 or bs > 64 * 1024 * 1024:          # only a real, modest body
            continue
        head = fota.body_head(info.slave, f.rel_url, n=64)
        if head[:4] != b"PK\x03\x04":
            continue
        inner = naming._zip_first_entry(head) or ""
        if not inner.startswith("target_files"):
            continue
        man = manifest_mod.from_zip_bytes(_fetch_body(info.slave, f.rel_url))
        if man:
            return man
    return None


def build_plan(curef: str, info: DownloadInfo,
               probe_workers: int = 16, mode: int = 4) -> PullPlan:
    """Probe every file's body size (parallel) and resolve authoritative names."""
    names = authoritative_names(curef, info, mode=mode)
    sizes: dict[str, int] = {}

    def probe(f: FileEntry) -> tuple[str, int]:
        return f.file_id, (fota.body_size(info.slave, f.rel_url) if info.slave else -1)

    with ThreadPoolExecutor(max_workers=probe_workers) as ex:
        for fid, sz in ex.map(probe, info.files):
            sizes[fid] = sz

    # No server-authoritative .sca? Fall back to the manifest the pack may embed
    # in its target_files zip — the scatter-first source the OTU engine uses.
    man = None if names else load_embedded_manifest(info, sizes)
    return PullPlan(info=info, names=names, sizes=sizes, manifest=man)


def _resolve_name(plan: PullPlan, f: FileEntry, is_small: bool) -> Optional[str]:
    """Server-authoritative name if known, else identify by content."""
    nm = plan.names.get(f.file_id)
    if nm:
        return nm
    if is_small:
        if not plan.info.encslave:
            return None
        enc = fota.fetch_header(plan.info.encslave, f.rel_url)
        if len(enc) < 16:
            return None
        n, e = naming.magic_name(decrypt_header(enc))
        return "%s_%s.%s" % (n, f.file_id, e)
    # 64 KiB is enough to un-sparse block 0 (the ext4/f2fs superblock sits at raw
    # offset 1024) and to read a zip's first entry name, so sparse partitions get
    # their real label (vendor/cache/userdata) instead of an anonymous "sparse".
    head = fota.body_head(plan.info.slave, f.rel_url, n=NAME_HEAD_BYTES) if plan.info.slave else b""
    n, e = naming.magic_name(head)
    # If the pack embedded a manifest, let it authoritatively name a filesystem
    # partition by its raw size — this catches a blank ext4 label (tctpersist)
    # and confirms the label-read ones.
    if plan.manifest and naming.is_filesystem(head):
        raw = naming.sparse_raw_size(head) or plan.sizes.get(f.file_id, -1)
        mn = plan.manifest.name_for_size(raw) if raw and raw > 0 else None
        if mn:
            n = naming.alias(mn)
    return "%s_%s.%s" % (n, f.file_id, e)


# ── pulling ─────────────────────────────────────────────────────────────────

def pull_one(plan: PullPlan, f: FileEntry, outdir: str,
             on_progress: Optional[Callable[[int, int], None]] = None,
             verify: bool = True) -> PartResult:
    """Pull a single partition to disk (decrypt header, or stream body)."""
    info = plan.info
    bs = plan.sizes.get(f.file_id, -1)
    is_small = bs <= 0
    name = _resolve_name(plan, f, is_small)
    if not name:
        return PartResult(f.file_id, "?", "skip", error="no name / empty")

    dest = os.path.join(outdir, name)
    try:
        if is_small:
            enc = fota.fetch_header(info.encslave, f.rel_url)
            if len(enc) < 16:
                return PartResult(f.file_id, name, "header", error="empty header")
            img = decrypt_header(enc)
            with open(dest, "wb") as fh:
                fh.write(img)
            res = PartResult(f.file_id, name, "header", size=len(img), path=dest)
        else:
            got = stream_body(info.slave, f.rel_url, dest, on_progress)
            res = PartResult(f.file_id, name, "body", size=got, path=dest)
            if verify and info.encslave:
                cs = fetch_checksums(info.encslave, f.rel_url)
                if cs and cs.body:
                    res.verified = (sha1_file(dest) == cs.body.lower())
        return res
    except Exception as e:
        return PartResult(f.file_id, name, "small" if is_small else "body", error=str(e))


def write_manifest(curef: str, plan: PullPlan, results: list[PartResult],
                   outdir: str) -> str:
    info = plan.info
    doc = {
        "curef": curef, "tv": info.tv, "fw_id": info.fw_id,
        "generated_by": "tcl-fw 4.0",
        "credit": "header decryption by Littlenine Ennea (github.com/LittlenineEnnea)",
        "slave": info.slave, "encslave": info.encslave,
        "files": [
            {"file_id": r.file_id, "name": r.name, "kind": r.kind,
             "size": r.size, "verified": r.verified, "error": r.error}
            for r in results
        ],
    }
    # If the pack embedded a partition manifest, record it and drop the raw
    # descriptors next to the images so they're available for flashing/naming.
    if plan.manifest:
        doc["embedded_manifest"] = {
            "partition_sizes": plan.manifest.sizes,
            "fs_types": plan.manifest.fs_types,
            "descriptors": sorted(plan.manifest.files),
        }
        for fname, text in plan.manifest.files.items():
            try:
                with open(os.path.join(outdir, fname), "w", encoding="utf-8") as fh:
                    fh.write(text)
            except Exception:
                pass
    path = os.path.join(outdir, "manifest.json")
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2)
    return path

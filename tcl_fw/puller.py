"""
puller.py — orchestrates a full service-package pull.

The per-file model (from Littlenine's tcl-fw.py), decided by body size:
  * every partition's image is  body || unpad(decrypt(header blob)).
  * empty body (HTTP 416 / size 0)  -> SMALL partition: the image is just the
    decrypted header blob.
  * non-empty body                  -> LARGE partition: stream the body, then
    append the decrypted blob, which is the image's final 4 MiB (#15).

Naming is server-authoritative when possible (check_new manifest + .sca scatter),
falling back to content-magic identification. Output lands in <outdir>/, and a
manifest.json records what was pulled.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import fota, manifest as manifest_mod, naming
from .crypto import decrypt_header
from .download import (crc_trusted, fetch_checksums, sha1_file, stream_body,
                       stream_unwrap)
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
    collided: bool = False    # another file already claimed this name


@dataclass
class PullPlan:
    info: DownloadInfo
    names: dict[str, str] = field(default_factory=dict)   # FILE_ID -> real name
    sizes: dict[str, int] = field(default_factory=dict)   # FILE_ID -> body size
    manifest: Optional["manifest_mod.Manifest"] = None    # embedded target_files manifest
    heads: dict[str, bytes] = field(default_factory=dict)  # FILE_ID -> body head
    # Content-derived names live apart from `names`, which is reserved for
    # server-authoritative ones: once a guess is written into `names` there is
    # no way to tell the two apart again.
    guessed: dict[str, str] = field(default_factory=dict)  # FILE_ID -> guessed name
    # basename -> FILE_ID. The .sca join is not injective (several coded names
    # can map to one file_name), so without this two partitions can resolve to
    # the same destination — and a resumed body append itself onto the other.
    claimed: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def claim(self, name: str, file_id: str) -> tuple[str, bool]:
        """Reserve `name` for `file_id`. Returns (unique_name, collided).

        The first claimant keeps the clean name; a later one is suffixed with
        its FILE_ID so two images can never share a path. Thread-safe: the GUI
        pulls in parallel."""
        with self._lock:
            owner = self.claimed.get(name)
            if owner is None:
                self.claimed[name] = file_id
                return name, False
            if owner == file_id:                  # re-resolved, same file
                return name, False
            stem, dot, ext = name.rpartition(".")
            alt = ("%s_%s.%s" % (stem, file_id, ext) if dot
                   else "%s_%s" % (name, file_id))
            self.claimed[alt] = file_id
            return alt, True


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
        # No body server at all => every image lives in its encrypted header.
        # That is a real answer (0), not a failed probe (-1): keeping them
        # distinct is what lets pull_one refuse to guess after a network error.
        return f.file_id, (fota.body_size(info.slave, f.rel_url) if info.slave else 0)

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
    nm = plan.guessed.get(f.file_id)               # already identified by content
    if nm:
        return nm
    if is_small:
        if not plan.info.encslave:
            return None
        enc = fota.fetch_header(plan.info.encslave, f.rel_url)
        if len(enc) < 16:
            return None
        n, e = naming.magic_name(decrypt_header(enc))
        plan.guessed[f.file_id] = "%s_%s.%s" % (n, f.file_id, e)
        return plan.guessed[f.file_id]
    # 64 KiB is enough to un-sparse block 0 (the ext4/f2fs superblock sits at raw
    # offset 1024) and to read a zip's first entry name, so sparse partitions get
    # their real label (vendor/cache/userdata) instead of an anonymous "sparse".
    head = fota.body_head(plan.info.slave, f.rel_url, n=NAME_HEAD_BYTES) if plan.info.slave else b""
    plan.heads[f.file_id] = head          # reused by pull_one, so we fetch once
    n, e = naming.magic_name(head)
    # Size-matching must look at the *real* image, which for the big partitions
    # sits inside a zip wrapper — the container's size means nothing.
    wrapped = naming.zip_wrapped_image(head)
    probe = (naming.zip_inner_head(head) or head) if wrapped else head
    # If the pack embedded a manifest, let it authoritatively name a filesystem
    # partition by its raw size — this catches a blank ext4 label (tctpersist)
    # and confirms the label-read ones.
    if plan.manifest and naming.is_filesystem(probe):
        raw = naming.sparse_raw_size(probe)
        if raw is None and not wrapped:
            raw = plan.sizes.get(f.file_id, -1)
        mn = plan.manifest.name_for_size(raw) if raw and raw > 0 else None
        if mn:
            n = mn          # a manifest name is already the partition's real
                            # name; alias() is for self-reported MTK strings
    plan.guessed[f.file_id] = "%s_%s.%s" % (n, f.file_id, e)
    return plan.guessed[f.file_id]


# ── pulling ─────────────────────────────────────────────────────────────────

def pull_one(plan: PullPlan, f: FileEntry, outdir: str,
             on_progress: Optional[Callable[[int, int], None]] = None,
             verify: bool = True) -> PartResult:
    """Pull a single partition to disk (decrypt header, or stream body)."""
    info = plan.info
    bs = plan.sizes.get(f.file_id, -1)
    if bs < 0:
        # The probe failed (timeout / DNS / 5xx). It is NOT the same as an empty
        # body, and treating it as one would silently decrypt this partition's
        # encrypted header and write that out as the image. Re-probe once, then
        # give up rather than guess.
        bs = fota.body_size(info.slave, f.rel_url) if info.slave else 0
        plan.sizes[f.file_id] = bs
        if bs == fota.BODY_GONE:
            return PartResult(f.file_id, "?", "skip",
                              error="no longer on TCL's CDN (404) - not pulled. "
                                    "OTA deltas expire; FULL (--mode 4) does not.")
        if bs < 0:
            return PartResult(f.file_id, "?", "skip",
                              error="body size probe failed - not pulled")
    is_small = bs == 0
    name = _resolve_name(plan, f, is_small)
    if not name:
        return PartResult(f.file_id, "?", "skip", error="no name / empty")

    # Reserve the destination so two files can never share one path: the .sca
    # join is not injective, and a shared path means a resumed body appends
    # itself onto the previous image.
    name, collided = plan.claim(name, f.file_id)
    dest = os.path.join(outdir, name)
    # Stage under the FILE_ID so a resume can only ever continue its own bytes,
    # and a half-finished pull never looks like a flashable image.
    part = os.path.join(outdir, ".%s.part" % f.file_id)
    try:
        return _pull_image(plan, f, bs, name, dest, part, collided,
                           on_progress, verify)
    except Exception as e:
        return PartResult(f.file_id, name, "header" if is_small else "body",
                          error=str(e), collided=collided)


def _sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def _discard(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _pull_image(plan: PullPlan, f: FileEntry, bs: int, name: str, dest: str,
                part: str, collided: bool,
                on_progress: Optional[Callable[[int, int], None]],
                verify: bool) -> PartResult:
    """One model for every partition:  image = body || unpad(decrypt(header)).

    A small partition has an empty body, so its image is the decrypted header
    blob. A large one streams its body and the blob supplies the final 4 MiB
    (#15) - without it every large image was exactly 4 MiB short and sparse
    images failed simg2img.

    checksum.php covers every byte: BODY is the SHA-1 of the body, FOOTER of
    the decrypted, unpadded blob. Both are checked whenever the server provides
    them; a mismatch deletes the staged file and returns an error, so nothing
    unverified-and-wrong ever lands under a flashable name.
    """
    info = plan.info
    is_small = bs == 0
    kind = "header" if is_small else "body"

    def fail(msg: str) -> PartResult:
        _discard(part)
        return PartResult(f.file_id, name, kind, error=msg, verified=False,
                          collided=collided)

    cs = fetch_checksums(info.encslave, f.rel_url) if (verify and info.encslave) else None

    # The header blob first: it is at most ~4 MiB, so a bad one is caught before
    # a multi-GB body is downloaded.
    # When checksum.php answered for a large file but lists no FOOTER, the
    # server has said there is no footer: don't fetch one (an error page there
    # would otherwise be refused as bad padding and fail a file that is fine).
    no_footer = cs is not None and not cs.footer and not is_small
    enc = (fota.fetch_header(info.encslave, f.rel_url)
           if info.encslave and not no_footer else b"")
    if len(enc) >= 16:
        try:
            foot = decrypt_header(enc)
        except ValueError as e:
            return fail("header blob rejected: %s" % e)
    else:
        foot = b""
    if is_small and not foot:
        return fail("empty header")
    if cs and cs.footer:
        if not foot:
            return fail("server lists a footer but none was returned")
        if _sha1(foot) != cs.footer:
            return fail("footer/header checksum mismatch")
    elif not is_small and not foot:
        # No checksum to say whether a footer exists, and none was served. The
        # image may be complete or 4 MiB short; there is no way to tell.
        pass
    # Every byte so far proven: the footer matched FOOTER, or the server's
    # checksum record says this file has no footer at all.
    checked = bool(cs and (cs.footer or no_footer))

    if is_small:
        with open(part, "wb") as fh:
            fh.write(foot)
        os.replace(part, dest)
        return PartResult(f.file_id, name, kind, size=len(foot), path=dest,
                          verified=True if checked else None, collided=collided)

    head = plan.heads.get(f.file_id)
    if head is None and info.slave:
        head = fota.body_head(info.slave, f.rel_url, n=NAME_HEAD_BYTES)
    wrapped = naming.zip_wrapped_image(head) if head else None

    if wrapped:
        # zip -> .mbn -> image: inflate in-flight, the footer fed through the
        # same inflater, so the container never lands on disk.
        want = int(wrapped[2].get("size") or 0)
        if 0 < want < 0xFFFFFFFF and os.path.exists(dest) \
                and os.path.getsize(dest) == want:
            # Complete from an earlier run. The served bytes are gone, so the
            # body cannot be re-proven without re-downloading: say so.
            return PartResult(f.file_id, name, kind, size=want, path=dest,
                              verified=None, collided=collided)
        got, body_sha, _raw = stream_unwrap(info.slave, f.rel_url, part,
                                            wrapped[2], on_progress, tail=foot)
        if cs and cs.body and body_sha != cs.body:
            return fail("body checksum mismatch")
        os.replace(part, dest)
        # Proven when the footer matched FOOTER and the body is covered either
        # by BODY or by the zip's own CRC-32 over the whole inflated image
        # (stream_unwrap raises on a CRC mismatch).
        ok = checked and bool((cs and cs.body) or crc_trusted(wrapped[2]))
        return PartResult(f.file_id, name, kind, size=got, path=dest,
                          verified=True if ok else None, collided=collided)

    full = bs + len(foot)
    # Already complete from an earlier run? Size alone is not enough: every
    # short image 4.x wrote is exactly `bs` bytes, so match the full length and,
    # when we can, re-prove both halves before trusting it.
    if os.path.exists(dest) and os.path.getsize(dest) == full:
        if not cs:
            return PartResult(f.file_id, name, kind, size=full, path=dest,
                              verified=None, collided=collided)
        body_ok = not cs.body or sha1_file(dest, limit=bs) == cs.body
        if body_ok:
            with open(dest, "rb") as fh:
                fh.seek(bs)
                tail_ok = not foot or fh.read() == foot
            if tail_ok:
                return PartResult(f.file_id, name, kind, size=full, path=dest,
                                  verified=True if (cs.body and checked) else None,
                                  collided=collided)
        # Present but wrong (e.g. a short 4.x image): pull it again.

    got = stream_body(info.slave, f.rel_url, part, on_progress)
    if got != bs:
        return fail("body is %d bytes, expected %d (download incomplete)" % (got, bs))
    if cs and cs.body and sha1_file(part) != cs.body:
        return fail("body checksum mismatch")
    with open(part, "ab") as fh:
        fh.write(foot)
    os.replace(part, dest)
    ok = checked and bool(cs and cs.body)
    return PartResult(f.file_id, name, kind, size=got + len(foot), path=dest,
                      verified=True if ok else None, collided=collided)


def write_manifest(curef: str, plan: PullPlan, results: list[PartResult],
                   outdir: str) -> str:
    info = plan.info
    doc = {
        "curef": curef, "tv": info.tv, "fw_id": info.fw_id,
        "generated_by": "tcl-fw 4.4.0",
        "credit": "header decryption by Littlenine Ennea (github.com/LittlenineEnnea)",
        "slave": info.slave, "encslave": info.encslave,
        "files": [
            {"file_id": r.file_id, "name": r.name, "kind": r.kind,
             "size": r.size, "verified": r.verified, "error": r.error,
             # True == another file claimed this name first, so this one was
             # suffixed with its FILE_ID. At most one of the pair is genuine.
             "collided": r.collided}
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

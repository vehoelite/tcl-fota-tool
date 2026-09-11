"""
download.py — low-level transfer helpers: streaming body download (with resume),
SHA-1 verification, and the per-part checksum lookup (checksum.php).

Higher-level orchestration (which files are headers vs bodies, parallelism,
progress UI) lives in puller.py; this module is just the I/O primitives.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import http.client
import zlib
from dataclasses import dataclass
from typing import Callable, Optional

from .crypto import ENC_ACCOUNT, ENC_PASSWORD
from .fota import USER_AGENT

ProgressCb = Optional[Callable[[int, int], None]]  # (received_total, total)


@dataclass
class PartChecksums:
    body: Optional[str] = None
    footer: Optional[str] = None
    encrypt_footer: Optional[str] = None


def sha1_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def _content_range_total(cr: Optional[str]) -> Optional[int]:
    """Parse the total size out of a 'Content-Range: bytes */12345' header."""
    if cr and "/" in cr:
        tail = cr.rsplit("/", 1)[-1].strip()
        if tail.isdigit():
            return int(tail)
    return None


def stream_unwrap(slave: str, rel: str, dest: str, entry: dict,
                  on_progress: ProgressCb = None, timeout: int = 120
                  ) -> tuple[int, str, int]:
    """Stream a zip-wrapped payload, inflating its first entry straight to dest.

    TCL wraps the big partitions as zip -> .mbn -> sparse, so the container has
    no value of its own. Decompressing in-flight means the 720 MB archive never
    touches the disk — only the image inside it does.

    The raw (still-compressed) bytes are hashed as they pass through, so the
    server's body checksum can still be verified even though what we write is
    the decompressed image. Returns (bytes_written, raw_sha1, raw_bytes).

    No resume: an inflate stream can't restart mid-way, so a retry starts over.
    """
    req = urllib.request.Request("http://%s%s" % (slave, rel),
                                 headers={"User-Agent": USER_AGENT})
    h = hashlib.sha1()
    dec = zlib.decompressobj(-15) if entry.get("method") == 8 else None
    skip = entry.get("data_offset", 0)          # bytes of zip header to drop
    # comp_size is 0 when the entry uses a trailing data descriptor; then we
    # just feed everything and let the decompressor stop at the stream end.
    remaining = entry.get("comp_size") or None
    raw = written = 0

    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length", 0)) or None
        if on_progress:
            on_progress(0, total)
        while True:
            buf = r.read(1 << 20)
            if not buf:
                break
            h.update(buf)                        # hash the body as served
            raw += len(buf)
            chunk = buf
            if skip:
                if len(chunk) <= skip:
                    skip -= len(chunk)
                    chunk = b""
                else:
                    chunk = chunk[skip:]
                    skip = 0
            if chunk and remaining is not None:
                chunk = chunk[:remaining]
                remaining -= len(chunk)
            if chunk:
                out = dec.decompress(chunk) if dec else chunk
                if out:
                    f.write(out)
                    written += len(out)
            if on_progress:
                on_progress(raw, total)
        if dec:
            out = dec.flush()
            if out:
                f.write(out)
                written += len(out)

    # A short body yields a short image. Silently writing a truncated system.img
    # is the dangerous outcome here — someone could flash it — so fail loudly and
    # delete the partial instead of leaving something that looks complete.
    short = (remaining or 0) > 0 or (dec is not None and not dec.eof)
    if short:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise IOError(
            "wrapped payload ended early: got %d of %d compressed bytes "
            "(the download is incomplete)"
            % (raw, (entry.get("data_offset", 0) + (entry.get("comp_size") or 0))))
    return written, h.hexdigest(), raw


def stream_body(slave: str, rel: str, dest: str,
                on_progress: ProgressCb = None, resume: bool = True,
                timeout: int = 120) -> int:
    """Stream a plaintext body to dest, resuming from a partial file if present.
    Returns the total bytes on disk. Raises on network error."""
    have = os.path.getsize(dest) if (resume and os.path.exists(dest)) else 0
    headers = {"User-Agent": USER_AGENT}
    if have:
        headers["Range"] = "bytes=%d-" % have

    req = urllib.request.Request("http://%s%s" % (slave, rel), headers=headers)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        # 416 = our resume offset is at/past EOF: the file is already complete
        # (or, if the local file is longer than the remote, it's corrupt).
        if e.code == 416 and have:
            total = _content_range_total(e.headers.get("Content-Range"))
            if total is not None and have > total:
                os.remove(dest)                       # over-long → start clean
                return stream_body(slave, rel, dest, on_progress,
                                   resume=False, timeout=timeout)
            if on_progress:
                on_progress(have, total or have)
            return have
        raise

    # If the server ignored our Range (200 not 206), restart from scratch.
    mode = "ab"
    if have and getattr(r, "status", 200) != 206:
        have = 0
        mode = "wb"

    total = have + int(r.headers.get("Content-Length", 0))
    got = have
    with r, open(dest, mode) as f:
        if on_progress:
            on_progress(got, total)
        while True:
            buf = r.read(1 << 20)
            if not buf:
                break
            f.write(buf)
            got += len(buf)
            if on_progress:
                on_progress(got, total)
    return got


def fetch_checksums(encslave: str, rel: str, timeout: int = 30) -> Optional[PartChecksums]:
    """Query checksum.php for a file's authoritative per-part SHA-1s."""
    payload = json.dumps({rel: rel})
    body = urllib.parse.urlencode(
        {"account": ENC_ACCOUNT, "password": ENC_PASSWORD, "address": payload}
    ).encode()
    conn = http.client.HTTPConnection(encslave, timeout=timeout)
    try:
        conn.request(
            "POST", "/checksum.php", body,
            {"Content-Type": "application/x-www-form-urlencoded",
             "User-Agent": USER_AGENT, "Content-Length": str(len(body))},
        )
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None
    finally:
        conn.close()

    # Response is { rel: {"body": sha1, "footer": sha1, "encrypt_footer": sha1} }
    entry = data.get(rel) if isinstance(data, dict) else None
    if not isinstance(entry, dict):
        return None
    return PartChecksums(
        body=entry.get("body"),
        footer=entry.get("footer"),
        encrypt_footer=entry.get("encrypt_footer") or entry.get("encryptFooter"),
    )

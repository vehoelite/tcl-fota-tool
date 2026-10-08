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
import xml.etree.ElementTree as ET
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


def sha1_file(path: str, chunk: int = 1 << 20, limit: Optional[int] = None) -> str:
    """SHA-1 of a file, or of only its first `limit` bytes."""
    h = hashlib.sha1()
    left = limit
    with open(path, "rb") as f:
        while left is None or left > 0:
            block = f.read(chunk if left is None else min(chunk, left))
            if not block:
                break
            h.update(block)
            if left is not None:
                left -= len(block)
    return h.hexdigest()


def _content_range_total(cr: Optional[str]) -> Optional[int]:
    """Parse the total size out of a 'Content-Range: bytes */12345' header."""
    if cr and "/" in cr:
        tail = cr.rsplit("/", 1)[-1].strip()
        if tail.isdigit():
            return int(tail)
    return None


def crc_trusted(entry: dict) -> bool:
    """True when a zip entry's CRC-32 is in its local header (general-purpose
    flag bit 3 clear), so stream_unwrap can check it."""
    return not (entry.get("flags", 0) & 0x08)


def stream_unwrap(slave: str, rel: str, dest: str, entry: dict,
                  on_progress: ProgressCb = None, timeout: int = 120,
                  tail: bytes = b"") -> tuple[int, str, int]:
    """Stream a zip-wrapped payload, inflating its first entry straight to dest.

    TCL wraps the big partitions as zip -> .mbn -> sparse, so the container has
    no value of its own. Decompressing in-flight means the 720 MB archive never
    touches the disk — only the image inside it does.

    The served body is NOT the whole container: its last 4 MiB arrive as the
    decrypted header blob (`tail`). The deflate stream runs straight across that
    seam, so `tail` is fed through the same pipeline after the body. Without it
    every wrapped partition stopped 4 MiB short (#15).

    Only the served body bytes are hashed, so the result can be checked against
    checksum.php's BODY. Returns (bytes_written, body_sha1, body_bytes).

    No resume: an inflate stream can't restart mid-way, so a retry starts over.
    """
    req = urllib.request.Request("http://%s%s" % (slave, rel),
                                 headers={"User-Agent": USER_AGENT})
    h = hashlib.sha1()
    dec = zlib.decompressobj(-15) if entry.get("method") == 8 else None
    skip = entry.get("data_offset", 0)          # bytes of zip header to drop
    # comp_size is 0 with a trailing data descriptor and 0xFFFFFFFF for zip64;
    # either way the real length is unknown, so feed everything and let the
    # decompressor find the end of the stream.
    csz = entry.get("comp_size") or 0
    remaining = csz if 0 < csz < 0xFFFFFFFF else None
    if dec is None and remaining is None:
        raise IOError("stored zip entry of unknown length - cannot unwrap safely")
    state = {"skip": skip, "remaining": remaining, "written": 0, "crc": 0}

    def feed(chunk: bytes, f) -> None:
        if state["skip"]:
            if len(chunk) <= state["skip"]:
                state["skip"] -= len(chunk)
                return
            chunk = chunk[state["skip"]:]
            state["skip"] = 0
        if state["remaining"] is not None:
            chunk = chunk[:state["remaining"]]
            state["remaining"] -= len(chunk)
        if chunk:
            out = dec.decompress(chunk) if dec else chunk
            if out:
                f.write(out)
                state["written"] += len(out)
                state["crc"] = zlib.crc32(out, state["crc"])

    raw = 0
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
            feed(buf, f)
            if on_progress:
                on_progress(raw, total)
        if tail:
            feed(tail, f)
        if dec:
            out = dec.flush()
            if out:
                f.write(out)
                state["written"] += len(out)
                state["crc"] = zlib.crc32(out, state["crc"])

    # A short stream yields a short image. Silently writing a truncated
    # system.img is the dangerous outcome here — someone could flash it — so
    # fail loudly and delete the partial instead.
    short = ((state["remaining"] or 0) > 0
             or (dec is not None and not dec.eof)
             # a stored entry of unknown length has no end marker: we would
             # write the zip's central directory into the image. Refuse.
             or (dec is None and remaining is None))
    if short:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise IOError(
            "wrapped payload ended early after %d body + %d footer bytes "
            "(the download is incomplete)" % (raw, len(tail)))
    # The zip records a CRC-32 of the whole uncompressed image. When it sits in
    # the local header (no data descriptor), it proves every byte we wrote -
    # including for files where checksum.php publishes no BODY hash.
    if crc_trusted(entry) and state["crc"] != entry.get("crc", 0):
        try:
            os.remove(dest)
        except OSError:
            pass
        raise IOError("unwrapped image fails the zip's CRC-32 (corrupt download)")
    return state["written"], h.hexdigest(), raw


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


def parse_checksums(text: str, rel: str) -> Optional[PartChecksums]:
    """Parse a checksum.php response for `rel`.

    The server answers in XML (<GOTU><FILE_CHECKSUM_LIST><FILE>...), with
    BODY = SHA-1 of the plaintext body, FOOTER = SHA-1 of the decrypted,
    PKCS#7-unpadded header blob, and ENCRYPT_FOOTER = SHA-1 of the raw blob.
    Older code parsed this as JSON, failed, and returned None — so through 4.3
    no checksum was ever actually checked. JSON is still accepted in case a
    server variant uses it."""
    text = (text or "").strip()
    if text.startswith("<"):
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return None
        for f in root.iter("FILE"):
            addr = (f.findtext("ADDRESS") or "").strip()
            if addr and addr != rel:
                continue
            got = PartChecksums(
                body=(f.findtext("BODY") or "").strip().lower() or None,
                footer=(f.findtext("FOOTER") or "").strip().lower() or None,
                encrypt_footer=(f.findtext("ENCRYPT_FOOTER") or "").strip().lower() or None,
            )
            return got if (got.body or got.footer) else None
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    entry = data.get(rel) if isinstance(data, dict) else None
    if not isinstance(entry, dict):
        return None
    got = PartChecksums(
        body=(entry.get("body") or "").lower() or None,
        footer=(entry.get("footer") or "").lower() or None,
        encrypt_footer=(entry.get("encrypt_footer")
                        or entry.get("encryptFooter") or "").lower() or None,
    )
    return got if (got.body or got.footer) else None


def fetch_checksums(encslave: str, rel: str, timeout: int = 30) -> Optional[PartChecksums]:
    """Query checksum.php for a file's authoritative per-part SHA-1s. The
    address must be the JSON map form; a bare path returns an empty <GOTU/>."""
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
        return parse_checksums(resp.read().decode("utf-8", "replace"), rel)
    except Exception:
        return None
    finally:
        conn.close()

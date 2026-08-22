"""
naming.py — turn opaque partition blobs into real, flash-ready filenames.

Two layers:
  * content magic (magic_name / identify): name a blob from its own first bytes —
    an MTK GFH header carries its partition name; a sparse ext4 image carries a
    volume label; AVB / ANDROID! / dtbo / scatter are recognised by magic.
  * scatter join (parse_sca / authoritative_names): read the .sca GOTU scatter's
    rename_prefix -> file_name map and join it to the check_new manifest's coded
    names, so partitions get their *server-authoritative* names (lk.img, ...).

Ported from Littlenine Ennea's tcl-fw.py.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass
from typing import Optional

# Alias a few self-reported names to their conventional partition names.
_ALIAS = {
    "md1rom": "md1img", "dpmpm": "dpm", "tinysys-scp": "scp",
    "tinysys-sspm": "sspm", "tinysys-vcp": "vcp", "tinysys-mcupm": "mcupm",
    "atf": "tee", "superheader": "super",
}


def alias(n: Optional[str]) -> str:
    n = (n or "").lower()
    for k, v in _ALIAS.items():
        if n.startswith(k) or k in n:
            return v
    return n


@dataclass
class Identity:
    name: str
    size: int
    family: str
    confidence: float


SPARSE_MAGIC = b"\x3a\xff\x26\xed"


def unsparse_head(d: bytes, want: int = 1 << 16) -> bytes:
    """Materialize up to `want` bytes of the RAW image from an Android sparse
    buffer. Non-sparse input is returned unchanged. Bounded: a don't-care / fill
    chunk that nominally spans gigabytes only contributes up to `want` bytes, so
    this never blows up on a userdata-sized sparse header."""
    if d[:4] != SPARSE_MAGIC:
        return d
    try:
        (magic, vmaj, vmin, fhdr, chdr, blk, tb, tc, crc) = struct.unpack_from(
            "<IHHHHIIII", d, 0)
        pos, out = fhdr, bytearray()
        for _ in range(tc):
            if pos + 12 > len(d) or len(out) >= want:
                break
            ct, _r, csz, tsz = struct.unpack_from("<HHII", d, pos)
            pos += 12
            span = csz * blk                       # raw bytes this chunk expands to
            need = want - len(out)
            if ct == 0xCAC1:                       # raw
                take = min(tsz - chdr, need)
                out += d[pos:pos + take]; pos += tsz - chdr
            elif ct == 0xCAC2:                     # fill
                fill = d[pos:pos + 4] or b"\x00"; pos += 4
                out += (fill * ((min(span, need) // 4) + 1))[:min(span, need)]
            elif ct == 0xCAC3:                     # don't care -> zeros
                out += b"\x00" * min(span, need)
            elif ct == 0xCAC4:                     # crc32
                pos += 4
        return bytes(out[:want])
    except Exception:
        return d


def sparse_raw_size(head: bytes) -> Optional[int]:
    """The un-sparsed (raw) byte size of an Android sparse image, from its
    28-byte header alone (total_blocks * block_size). None if not sparse."""
    if head[:4] != SPARSE_MAGIC or len(head) < 28:
        return None
    try:
        _m, _vj, _vn, _fh, _ch, blk, tblk, _tc, _crc = struct.unpack_from(
            "<IHHHHIIII", head, 0)
        return blk * tblk
    except Exception:
        return None


def is_filesystem(head: bytes) -> bool:
    """True if `head` is (or wraps) a mountable filesystem image — a sparse
    container, or a raw ext4/f2fs/erofs superblock."""
    if head[:4] == SPARSE_MAGIC:
        return True
    raw = head
    if len(raw) >= 0x43a and raw[0x438:0x43a] == b"\x53\xef":
        return True
    if len(raw) >= 0x404 and raw[0x400:0x404] in (b"\x10\x20\xf5\xf2",
                                                  b"\xe2\xe1\xf5\xe0"):
        return True
    return False


def fs_label(raw: bytes) -> Optional[tuple[str, str]]:
    """(name, family) from a RAW (already un-sparsed) filesystem head, or None.
    ext4/erofs self-report a volume label; f2fs has no label but is, on these
    MTK devices, always userdata."""
    if len(raw) >= 0x43a and raw[0x438:0x43a] == b"\x53\xef":            # ext4
        lab = raw[0x478:0x488].split(b"\x00")[0].decode("latin1", "replace")
        lab = lab.rsplit("/", 1)[-1]               # "/mnt/vendor/otap" -> "otap"
        return (lab, "ext4") if lab else ("ext4", "ext4")
    if len(raw) >= 0x404 and raw[0x400:0x404] == b"\x10\x20\xf5\xf2":    # f2fs
        return ("userdata", "f2fs")
    if len(raw) >= 0x450 and raw[0x400:0x404] == b"\xe2\xe1\xf5\xe0":    # erofs
        lab = raw[0x440:0x450].split(b"\x00")[0].decode("latin1", "replace")
        return (lab, "erofs") if lab else ("erofs", "erofs")
    return None


def ext4_label(d: bytes) -> Optional[str]:
    """Volume label from a (possibly sparse) ext4 image. Kept for callers that
    only care about ext4; new code should prefer fs_label(unsparse_head(d))."""
    hit = fs_label(unsparse_head(d))
    if hit and hit[1] == "ext4" and hit[0] != "ext4":
        return hit[0]
    return None


def _zip_first_entry(b: bytes) -> Optional[str]:
    """Name of the first local file inside a ZIP, read from its front (the
    central directory sits at the end, so this works on a truncated head)."""
    if b[:4] != b"PK\x03\x04" or len(b) < 30:
        return None
    try:
        nlen = struct.unpack_from("<H", b, 26)[0]
        return b[30:30 + nlen].decode("latin1", "replace") or None
    except Exception:
        return None


def magic_name(b: bytes) -> tuple[str, str]:
    """(name, ext) from the first bytes of an image — works for a decrypted
    header or a body head. Sparse- and zip-aware: it un-sparses far enough to
    read an ext4/f2fs/erofs identity, and peeks inside a zip-wrapped payload."""
    if b[:4] == b"\x88\x16\x88\x58":
        nm = b[8:24].split(b"\x00")[0].decode("latin1", "replace")
        return (nm or "gfh"), "img"
    if b[:4] == b"AVB0":
        return "vbmeta", "img"
    if b[:4] == b"ANDR" or b[:8] == b"ANDROID!":
        return "boot_or_vendorboot", "img"
    if b[:4] == SPARSE_MAGIC:
        hit = fs_label(unsparse_head(b))
        return (alias(hit[0]) if hit else "sparse"), "img"
    if b[:4] == b"PK\x03\x04":
        inner = _zip_first_entry(b) or ""
        low = inner.lower()
        if low.startswith("target_files") or low.endswith((".p", "updater")):
            return "ota_recovery", "zip"
        if low.endswith(".map"):
            return os.path.splitext(os.path.basename(inner))[0] + "_map", "zip"
        stem = os.path.splitext(os.path.basename(inner))[0]
        return ("zip_" + stem if stem else "zip"), "zip"
    if b[:4] == b"\x4d\x4d\x4d\x01":
        return "mtk_mmm", "img"
    if b[:5] == b"<?xml":
        return "scatter_or_cfg", "xml"
    if b[:2] == b"MZ":
        return "pe", "bin"
    if b[:8] == b"\x00" * 8:
        return "zero", "img"
    return "part_%s" % b[:4].hex(), "bin"


def identify(data: bytes, size: int) -> Identity:
    """Identify an image from its content. `data` is the first ~1 MiB; `size` is
    the full file size. Confidence gates how eagerly the scatter join trusts it."""
    d = data
    if d[:4] == b"\x88\x16\x88\x58":
        return Identity(alias(d[8:24].split(b"\x00")[0].decode("latin1")), size, "gfh", 1.0)
    if d[:8] == b"ANDROID!":
        return Identity("boot", size, "android", 0.5)      # boot | init_boot (by size)
    if d[:4] == b"VNDR":
        return Identity("vendor_boot", size, "vndr", 1.0)
    if d[:4] == b"AVB0":
        return Identity("vbmeta", size, "avb", 0.5)         # vbmeta{,_system,_vendor}
    if d[:4] == b"\xd7\xb7\xab\x1e":
        return Identity("dtbo", size, "dtbo", 1.0)
    if d[:4] == b"\x4d\x4d\x4d\x01":
        return Identity("preloader", size, "mmm", 1.0)
    if d[:4] == SPARSE_MAGIC:
        hit = fs_label(unsparse_head(d))
        if hit:
            name, fam = hit
            named = name not in ("ext4", "erofs")   # a real label, not just the fs
            return Identity(alias(name), size, fam, 0.9 if named else 0.4)
        return Identity("sparse", size, "sparse", 0.3)
    if d[:5] == b"<?xml":
        return Identity("scatter", size, "xml", 1.0)
    if d[:8] == b"\x00" * 8:
        return Identity("zero", size, "zero", 0.1)
    return Identity("part_" + d[:4].hex(), size, "unknown", 0.1)


def parse_sca(text: str) -> dict[str, str]:
    """.sca GOTU scatter -> {rename_prefix: file_name} for is_download partitions."""
    out: dict[str, str] = {}
    for blk in re.split(r"partition_index:", text)[1:]:
        def g(k: str) -> str:
            m = re.search(r"\b%s:\s*([^\n\r]*)" % k, blk)
            return m.group(1).strip() if m else ""
        if g("is_download") == "true" and g("rename_prefix"):
            out.setdefault(g("rename_prefix"), g("file_name"))
    return out


def join_names(manifest: dict[str, str], sca: dict[str, str],
               by_id: dict[str, str]) -> dict[str, str]:
    """FILE_ID -> real file_name. Join the check_new manifest's coded names to
    the .sca rename_prefix map: prefix == coded[0] + coded[-2] (2-char) or coded[0]."""
    names: dict[str, str] = {}
    for fid, coded in manifest.items():
        if fid not in by_id or not coded:
            continue
        base = coded.rsplit(".", 1)[0]
        if coded.endswith((".sca", ".txt", ".xml")):
            names[fid] = coded
        elif len(base) >= 2:
            names[fid] = sca.get(base[0] + base[-2]) or sca.get(base[0]) or coded
        else:
            names[fid] = sca.get(base) or coded
    return names

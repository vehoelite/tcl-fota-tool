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


def magic_name(b: bytes) -> tuple[str, str]:
    """(name, ext) from the first bytes of an image — works for a decrypted
    header or a body head."""
    if b[:4] == b"\x88\x16\x88\x58":
        nm = b[8:24].split(b"\x00")[0].decode("latin1", "replace")
        return (nm or "gfh"), "img"
    if b[:4] == b"AVB0":
        return "vbmeta", "img"
    if b[:4] == b"ANDR" or b[:8] == b"ANDROID!":
        return "boot_or_vendorboot", "img"
    if b[:4] == b"\x3a\xff\x26\xed":
        return "sparse", "img"
    if b[:4] == b"\x4d\x4d\x4d\x01":
        return "mtk_mmm", "img"
    if b[:5] == b"<?xml":
        return "scatter_or_cfg", "xml"
    if b[:2] == b"MZ":
        return "pe", "bin"
    if b[:8] == b"\x00" * 8:
        return "zero", "img"
    return "part_%s" % b[:4].hex(), "bin"


def ext4_label(d: bytes) -> Optional[str]:
    """Volume label from a sparse ext4 image (self-identifies system/vendor/...)."""
    if d[:4] != b"\x3a\xff\x26\xed":
        return None
    try:
        (magic, vmaj, vmin, fhdr, chdr, blk, tb, tc, crc) = struct.unpack_from(
            "<IHHHHIIII", d, 0)
        pos, out = fhdr, b""
        for _ in range(tc):
            if pos + 12 > len(d):
                break
            ct, _r, csz, tsz = struct.unpack_from("<HHII", d, pos)
            pos += 12
            if ct == 0xCAC1:
                out += d[pos:pos + csz * blk]; pos += csz * blk
            elif ct == 0xCAC2:
                pos += 4
            if len(out) >= 0x500:
                break
        if len(out) >= 0x490 and out[0x438:0x43a] == b"\x53\xef":
            lab = out[0x478:0x488].split(b"\x00")[0].decode("latin1", "replace")
            return lab.rsplit("/", 1)[-1] or lab      # "/mnt/vendor/otap" -> "otap"
    except Exception:
        pass
    return None


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
    if d[:4] == b"\x3a\xff\x26\xed":
        lab = ext4_label(d)
        return Identity(alias(lab) if lab else "sparse", size, "ext4", 0.9 if lab else 0.3)
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

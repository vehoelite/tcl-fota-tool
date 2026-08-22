"""
manifest.py — recover the authoritative partition manifest that some TCL/MTK
service packs embed *inside* a downloaded ``target_files`` zip, for devices that
serve no top-level ``.sca`` scatter.

That zip (a ``part_...`` blob whose content is a ZIP containing
``target_files_extract/``) carries three plaintext descriptors:

  * ``misc_info.txt``      — ``<name>_fs_type`` + ``<name>_size`` for the
    filesystem partitions (system, vendor, cache, userdata, tctpersist, …).
  * ``scatter_emmc.txt``   — the ordered ``<name> <hex_offset>`` eMMC layout;
    a partition's size is the delta to the next offset.
  * ``ota_update_list.txt`` — ``<image>.img <slot> [<slot> …]`` for the flat
    (GFH) images.

This is the same scatter-first naming the official OTU engine relies on
(``sugar_otu_r.dll``: ``OtuCheckSca`` / ``OtuStartScaFile`` / ``OtuExtract``):
partitions are named from the scatter, never guessed. When present, it lets us
name a filesystem partition whose ext4 volume label is blank (e.g. tctpersist)
and confirm the ones we already read from their labels.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Optional

_TF_PREFIX = "target_files_extract/"
_WANT = ("misc_info.txt", "scatter_emmc.txt", "ota_update_list.txt")

# Partitions that hold a mountable filesystem — the only ones we'll name by a
# size match, so a size collision with a non-fs partition (e.g. tctpersist vs
# simlock, both 8 MiB) never mis-labels a security/nvram blob as a filesystem.
_FS_PARTITIONS = {
    "system", "system_ext", "system_dlkm", "system_other", "vendor",
    "vendor_dlkm", "product", "odm", "odm_dlkm", "oem", "cust", "preload",
    "cache", "userdata", "metadata", "super", "tctpersist",
}


@dataclass
class Manifest:
    sizes: dict[str, int] = field(default_factory=dict)       # partition -> bytes
    fs_types: dict[str, str] = field(default_factory=dict)    # partition -> "ext4"/…
    scatter: list[tuple[str, int]] = field(default_factory=list)   # (name, offset)
    image_map: dict[str, list[str]] = field(default_factory=dict)  # img stem -> slots
    files: dict[str, str] = field(default_factory=dict)       # descriptor -> raw text

    def name_for_size(self, size: int) -> Optional[str]:
        """The filesystem partition of exactly `size` bytes, if unambiguous.
        Only filesystem partitions are considered, so a non-fs blob sharing a
        size never wins."""
        hits = [n for n, s in self.sizes.items()
                if s == size and n in _FS_PARTITIONS]
        return hits[0] if len(hits) == 1 else None


# ── parsers ───────────────────────────────────────────────────────────────────

def parse_misc_info(text: str) -> tuple[dict[str, int], dict[str, str]]:
    sizes: dict[str, int] = {}
    fs_types: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z0-9_]+)_size\s*=\s*(\d+)\s*$", line)
        if m:
            sizes[m.group(1).lower()] = int(m.group(2))
            continue
        m = re.match(r"\s*([A-Za-z0-9_]+)_fs_type\s*=\s*(\S+)\s*$", line)
        if m:
            fs_types[m.group(1).lower()] = m.group(2).lower()
    return sizes, fs_types


def parse_scatter_emmc(text: str) -> list[tuple[str, int]]:
    """Ordered ``<name> <hex_offset>`` lines. Sentinel offsets (0xFFFF….) and
    the GPT pseudo-partitions are skipped for sizing but kept in order."""
    out: list[tuple[str, int]] = []
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z0-9_]+)\s+(0x[0-9A-Fa-f]+)\s*$", line)
        if m:
            out.append((m.group(1).lower(), int(m.group(2), 16)))
    return out


def scatter_sizes(parts: list[tuple[str, int]]) -> dict[str, int]:
    """Derive each partition's size as the gap to the next real offset."""
    real = [(n, off) for n, off in parts if off < 0xFFFF0000]
    sizes: dict[str, int] = {}
    for i, (name, off) in enumerate(real[:-1]):
        nxt = real[i + 1][1]
        if nxt > off:
            sizes[name] = nxt - off
    return sizes


def parse_ota_update_list(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        toks = line.split()
        if len(toks) >= 2 and toks[0].endswith(".img"):
            out[toks[0][:-4].lower()] = [t.lower() for t in toks[1:]]
    return out


# ── zip loading ─────────────────────────────────────────────────────────────

def from_zip_bytes(blob: bytes) -> Optional[Manifest]:
    """Build a Manifest from the bytes of a ``target_files`` zip, or None if the
    blob isn't such a zip / carries none of the descriptors."""
    if blob[:4] != b"PK\x03\x04":
        return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except Exception:
        return None
    names = zf.namelist()
    if not any(n.startswith(_TF_PREFIX) for n in names):
        return None

    def read(want: str) -> Optional[str]:
        full = _TF_PREFIX + want
        if full in names:
            try:
                return zf.read(full).decode("latin1", "replace")
            except Exception:
                return None
        return None

    man = Manifest()
    misc = read("misc_info.txt")
    if misc:
        man.sizes, man.fs_types = parse_misc_info(misc)
        man.files["misc_info.txt"] = misc
    sca = read("scatter_emmc.txt")
    if sca:
        man.scatter = parse_scatter_emmc(sca)
        for name, sz in scatter_sizes(man.scatter).items():
            man.sizes.setdefault(name, sz)     # misc_info wins on conflict
        man.files["scatter_emmc.txt"] = sca
    oul = read("ota_update_list.txt")
    if oul:
        man.image_map = parse_ota_update_list(oul)
        man.files["ota_update_list.txt"] = oul

    if not (man.sizes or man.scatter or man.image_map):
        return None
    return man

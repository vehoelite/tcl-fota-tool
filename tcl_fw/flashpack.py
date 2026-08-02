"""
flashpack.py — turn a pulled service-pack folder into a flash-ready package.

Given a directory of pulled images plus the MTK scatter XML, this:
  1. reads each image's identity (content magic, ext4/erofs label, size),
  2. maps every image to a scatter partition (strong content match first, then
     boot/vbmeta disambiguation, then greedy size-fit for the filesystem blobs),
  3. renames the images to their true partition filenames, and
  4. writes a classic <platform>_Android_scatter.txt SP Flash Tool can load.

The mapping is reported with a confidence so a human can eyeball the few that
can only be inferred by size. Nothing is renamed in dry-run mode.
"""

from __future__ import annotations

import glob
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from . import naming, scatter
from .scatter import MtkPart, ScatterDoc

_SKIP = {"manifest.json"}
_HEAD = 256 * 1024          # bytes to read for identification (covers sparse sb)


@dataclass
class Probe:
    path: str
    fname: str
    size: int
    family: str
    cname: str              # content-derived name (may be a guess)
    label: Optional[str]


@dataclass
class Match:
    probe: Probe
    part: Optional[MtkPart]
    confidence: float
    how: str                # why this mapping was chosen
    new_name: Optional[str] = None


@dataclass
class PackResult:
    doc: ScatterDoc
    matches: list[Match] = field(default_factory=list)
    scatter_path: Optional[str] = None
    unmapped: list[Probe] = field(default_factory=list)


# ── identification ────────────────────────────────────────────────────────────

def _erofs_label(head: bytes) -> Optional[str]:
    if len(head) >= 1024 + 0x50 and head[1024:1028] == b"\xe2\xe1\xf5\xe0":
        return head[1024 + 0x40:1024 + 0x50].split(b"\x00")[0].decode("latin1", "replace")
    return None


def _avb_partitions(blob: bytes) -> set[str]:
    """Best-effort: which partition names an AVB0 vbmeta blob references (from its
    descriptor ASCII). Lets us tell vbmeta / vbmeta_system / vbmeta_vendor apart."""
    names: set[str] = set()
    for key in (b"vbmeta_system", b"vbmeta_vendor", b"system_ext", b"system",
                b"product", b"vendor_dlkm", b"vendor", b"boot", b"init_boot",
                b"vendor_boot", b"dtbo"):
        if key in blob:
            names.add(key.decode())
    return names


def probe_file(path: str) -> Probe:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(_HEAD)
    ident = naming.identify(head, size)
    label = naming.ext4_label(head) or _erofs_label(head)
    fam = ident.family
    if fam == "erofs" or (fam == "zero" and head[1024:1028] == b"\xe2\xe1\xf5\xe0"):
        fam = "erofs"
    return Probe(path=path, fname=os.path.basename(path), size=size,
                 family=fam, cname=ident.name, label=label or None)


def _probe_dir(pkgdir: str) -> list[Probe]:
    probes = []
    for p in sorted(glob.glob(os.path.join(pkgdir, "*"))):
        b = os.path.basename(p)
        if not os.path.isfile(p) or b in _SKIP:
            continue
        if b.endswith((".txt",)) or b.startswith("scatter_or_cfg") or b.endswith(".xml"):
            continue                                  # config/scatter, not a partition
        probes.append(probe_file(p))
    return probes


# ── partition index ───────────────────────────────────────────────────────────

def _stem(fn: str) -> str:
    return os.path.splitext(fn or "")[0].lower()


def _base(name: str) -> str:
    """partition_name minus an A/B slot suffix: 'boot_a' -> 'boot'."""
    n = name.lower()
    for suf in ("_a", "_b"):
        if n.endswith(suf):
            return n[:-2]
    return n


def _keys_for(p: MtkPart) -> set[str]:
    ks = {_stem(p.file_name), _base(p.name)}
    ks.discard("")
    ks.discard("none")
    return ks


# Partition/image "class": filesystem images must not land on non-filesystem
# partitions (and vice-versa) during blind size-fit.
_FS_NAMES = {
    "system", "system_other", "system_ext", "system_dlkm", "vendor",
    "vendor_dlkm", "product", "odm", "odm_dlkm", "preload", "oem", "super",
    "userdata", "cache", "metadata", "otapkg", "cust",
}


def _part_is_fs(p: MtkPart) -> bool:
    return _base(p.name) in _FS_NAMES or _stem(p.file_name) in _FS_NAMES \
        or "EXT4" in p.ptype.upper() or "EROFS" in p.ptype.upper()


def _probe_is_fs(prb: "Probe") -> bool:
    return prb.family in ("ext4", "erofs") or prb.cname.startswith("sparse")


# Slack for an image that decrypts a few bytes larger than its nominal
# partition size (padding tail): treat it as still fitting.
_FIT_SLACK = 4096


# ── the resolver ──────────────────────────────────────────────────────────────

def resolve(doc: ScatterDoc, probes: list[Probe]) -> tuple[list[Match], list[Probe]]:
    parts = list(doc.download_parts())
    used_parts: set[str] = set()
    matches: list[Match] = []
    remaining = list(probes)

    def take(prb: Probe, part: MtkPart, conf: float, how: str) -> None:
        used_parts.add(part.name)
        matches.append(Match(prb, part, conf, how, new_name=part.file_name))
        remaining.remove(prb)

    def free_parts() -> list[MtkPart]:
        return [p for p in parts if p.name not in used_parts]

    def find_key(key: str) -> Optional[MtkPart]:
        key = naming.alias(key) if key else key
        for p in free_parts():
            if key in _keys_for(p) or naming.alias(_base(p.name)) == key:
                return p
        return None

    # Pass 0 — files already named exactly as a scatter partition's file_name
    # (the pull's .sca naming, or a previous pack run). Lock them so pack is
    # idempotent and doesn't re-compete already-correct names.
    by_fname: dict[str, MtkPart] = {}
    for p in parts:
        by_fname.setdefault(p.file_name.lower(), p)
    for prb in list(remaining):
        p = by_fname.get(prb.fname.lower())
        if p and p.name not in used_parts:
            take(prb, p, 1.0, "already-named")

    # Pass 1 — strong content identity (GFH name, dtbo, vendor_boot, preloader,
    # zip->otapkg, ext4/erofs label).
    for prb in list(remaining):
        cand: Optional[MtkPart] = None
        how = ""
        if prb.family == "gfh":
            cand, how = find_key(naming.alias(prb.cname)), "gfh-name"
        elif prb.family == "dtbo":
            cand, how = find_key("dtbo"), "dtbo-magic"
        elif prb.family == "vndr":
            cand, how = find_key("vendor_boot"), "vndr-magic"
        elif prb.family == "mmm" or prb.cname == "mtk_mmm":
            cand, how = find_key("preloader"), "preloader-magic"
        elif prb.cname.startswith("part_504b0304"):        # PK zip
            cand, how = find_key("otapkg"), "zip->otapkg"
        elif prb.label:
            cand, how = find_key(naming.alias(prb.label)), "fs-label"
        if cand:
            take(prb, cand, 1.0, how)

    # Pass 2 — boot family (ANDROID!): boot vs init_boot by size (larger = boot).
    androids = [p for p in remaining if p.family == "android"]
    if androids:
        androids.sort(key=lambda x: -x.size)
        for prb, key in zip(androids, ("boot", "init_boot")):
            c = find_key(key)
            if c:
                take(prb, c, 0.9, "android-size")

    # Pass 3 — vbmeta (AVB0): split by descriptor contents, else by size.
    avbs = [p for p in remaining if p.family == "avb"]
    if avbs:
        for prb in sorted(avbs, key=lambda x: -x.size):
            with open(prb.path, "rb") as f:
                refs = _avb_partitions(f.read(min(prb.size, 1 << 20)))
            if {"vbmeta_system", "vbmeta_vendor"} & refs:
                key = "vbmeta"
            elif {"vendor", "vendor_dlkm"} & refs and "system" not in refs:
                key = "vbmeta_vendor"
            elif {"system", "product", "system_ext"} & refs:
                key = "vbmeta_system"
            else:
                key = "vbmeta"
            c = find_key(key) or find_key("vbmeta")
            if c:
                take(prb, c, 0.85 if refs else 0.5, "avb-descriptor")

    # Pass 4 — greedy size-fit for the remaining blobs. Largest image first;
    # assign the smallest free partition whose alloc >= image size, preferring a
    # partition of the same class (filesystem vs not). A small over-size slack
    # absorbs the decryption padding tail.
    for prb in sorted(list(remaining), key=lambda x: -x.size):
        want_fs = _probe_is_fs(prb)

        def candidates(same_class: bool) -> list[MtkPart]:
            pool = [p for p in free_parts()
                    if p.size + _FIT_SLACK >= prb.size
                    and (_part_is_fs(p) == want_fs) == same_class]
            return sorted(pool, key=lambda p: p.size)

        fits = candidates(True) or candidates(False)
        if fits:
            same = _part_is_fs(fits[0]) == want_fs
            big = prb.size > 50 * 1024 * 1024
            conf = 0.75 if (big and same) else (0.5 if same else 0.3)
            take(prb, fits[0], conf, "size-fit" if same else "size-fit(x-class)")
        else:
            biggest = sorted(free_parts(), key=lambda p: -p.size)
            if biggest:
                take(prb, biggest[0], 0.2, "size-fit(over)")

    return matches, remaining


# ── orchestration ─────────────────────────────────────────────────────────────

def find_scatter(pkgdir: str) -> Optional[tuple[str, ScatterDoc]]:
    """Locate + parse the MTK scatter XML in a pulled folder."""
    for p in glob.glob(os.path.join(pkgdir, "*")):
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "rb") as f:
                text = f.read(400).decode("latin1", "replace")
            if not text.lstrip().startswith("<?xml"):
                continue
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                full = f.read()
            if scatter.looks_like_mtk(full):
                return p, scatter.parse(full)
        except Exception:
            continue                     # unreadable/unparseable scatter -> skip
    return None


def build(pkgdir: str) -> Optional[PackResult]:
    found = find_scatter(pkgdir)
    if not found:
        return None
    _, doc = found
    probes = _probe_dir(pkgdir)
    matches, unmapped = resolve(doc, probes)
    return PackResult(doc=doc, matches=matches, unmapped=unmapped)


def apply(pkgdir: str, result: PackResult, dry_run: bool = False,
          min_confidence: float = 0.7) -> str:
    """Rename confidently-matched images to canonical names and write the
    scatter.txt. Matches below `min_confidence` are left untouched (reported for
    manual review) so we never confidently mis-name a partition. Returns the
    scatter.txt path. In dry-run, nothing is written."""
    overrides: dict[str, str] = {}
    # Avoid clobbering: if two matches want the same name, keep the confident one.
    taken: dict[str, Match] = {}
    for m in result.matches:
        if not m.part or not m.new_name or m.confidence < min_confidence:
            continue
        prev = taken.get(m.new_name)
        if prev is None or m.confidence > prev.confidence:
            taken[m.new_name] = m

    for name, m in taken.items():
        dest = os.path.join(pkgdir, name)
        overrides[m.part.name] = name
        m.new_name = name
        if dry_run or os.path.abspath(dest) == os.path.abspath(m.probe.path):
            continue
        if os.path.exists(dest) and os.path.abspath(dest) != os.path.abspath(m.probe.path):
            os.replace(m.probe.path, dest)   # overwrite an existing same-named file
        else:
            os.rename(m.probe.path, dest)

    txt = scatter.scatter_txt(result.doc, overrides)
    fname = "%s_Android_scatter.txt" % (result.doc.platform or "MTK")
    path = os.path.join(pkgdir, fname)
    result.scatter_path = path
    if not dry_run:
        with open(path, "w", encoding="utf-8") as f:
            f.write(txt)
    return path

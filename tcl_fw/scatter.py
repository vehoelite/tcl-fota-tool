"""
scatter.py — read MediaTek's MTK_PLATFORM_CFG scatter (the XML that ships as a
partition in the service pack) and re-emit it as a classic SP Flash Tool
`<platform>_Android_scatter.txt`.

TCL's full-image packs name every downloaded file only by a numeric FILE_ID; the
real partition layout lives in this XML (partition_name, file_name, address,
size, region, type). Parsing it lets us (a) rename the blobs to their true
partition filenames and (b) produce a scatter SP Flash Tool / mtkclient accept.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional


@dataclass
class MtkPart:
    index: str            # partition_index, e.g. "SYS0"
    name: str             # partition_name, e.g. "boot_a"
    file_name: str        # scatter file_name, e.g. "boot.img" ("NONE" if none)
    is_download: bool
    ptype: str            # type, e.g. "NORMAL_ROM" / "SV5_BL_BIN"
    linear_addr: int
    phys_addr: int
    size: int             # partition_size (bytes)
    region: str
    storage: str
    operation_type: str
    reserve: str = "0x00"
    boundary_check: str = "true"
    is_reserved: str = "false"

    @property
    def downloadable(self) -> bool:
        return self.is_download and self.file_name.upper() != "NONE"


@dataclass
class ScatterDoc:
    platform: str
    project: str
    config_version: str
    storage: str
    boot_channel: str
    block_size: str
    parts: list[MtkPart]

    def download_parts(self) -> list[MtkPart]:
        return [p for p in self.parts if p.downloadable]


def looks_like_mtk(text: str) -> bool:
    """True if `text` is an MTK_PLATFORM_CFG scatter (not a GOTU .sca)."""
    return "MTK_PLATFORM_CFG" in text and "partition_index" in text


def _int(s: Optional[str]) -> int:
    s = (s or "").strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s or "0")
    except ValueError:
        return 0


def _clean_xml(text: str) -> str:
    """Trim padding after the XML. These scatters ship as a decrypted partition
    whose tail is padded (form-feeds / NULs); anything after the root element
    makes ElementTree choke, so cut at the closing root tag."""
    i = text.rfind("</root>")
    if i != -1:
        return text[:i + len("</root>")]
    return text.rstrip("\x00\x0b\x0c \t\r\n")


def parse(xml_text: str) -> ScatterDoc:
    """Parse the MTK scatter XML into a ScatterDoc. The table is often repeated
    in the file (e.g. a second storage block); partitions are de-duplicated by
    partition_name, first occurrence wins."""
    root = ET.fromstring(_clean_xml(xml_text))

    def find_text(path: str, default: str = "") -> str:
        el = root.find(path)
        return (el.text or default).strip() if el is not None else default

    platform = ""
    project = ""
    config_version = ""
    for cv in root.iter("config_version"):
        config_version = cv.get("name", "")
        platform = (cv.findtext("platform") or "").strip()
        project = (cv.findtext("project") or "").strip()
        break

    storage = boot_channel = block_size = ""
    for st in root.iter("storage"):
        storage = st.get("name", "") or storage
        boot_channel = (st.findtext("boot_channel") or "").strip() or boot_channel
        block_size = (st.findtext("block_size") or "").strip() or block_size
        break
    if not storage:
        for stype in root.iter("storage_type"):
            storage = stype.get("name", "")
            break

    parts: list[MtkPart] = []
    seen: set[str] = set()
    for pi in root.iter("partition_index"):
        g = lambda t: (pi.findtext(t) or "").strip()  # noqa: E731
        name = g("partition_name")
        if not name or name in seen:
            continue
        seen.add(name)
        parts.append(MtkPart(
            index=pi.get("name", ""),
            name=name,
            file_name=g("file_name") or "NONE",
            is_download=g("is_download").lower() == "true",
            ptype=g("type") or "NORMAL_ROM",
            linear_addr=_int(g("linear_start_addr")),
            phys_addr=_int(g("physical_start_addr")),
            size=_int(g("partition_size")),
            region=g("region") or "EMMC_USER",
            storage=g("storage") or "HW_STORAGE_EMMC",
            operation_type=g("operation_type") or "UPDATE",
            reserve=g("reserve") or "0x00",
            boundary_check=g("boundary_check") or "true",
            is_reserved=g("is_reserved") or "false",
        ))
    return ScatterDoc(platform, project, config_version, storage,
                      boot_channel, block_size, parts)


# ── SP Flash Tool scatter.txt emitter ────────────────────────────────────────

def _region_txt(r: str) -> str:
    """Normalise the XML region name to SP Flash Tool's spelling."""
    return {"EMMC_BOOT1": "EMMC_BOOT_1", "EMMC_BOOT2": "EMMC_BOOT_2"}.get(r, r)


_HR = "#" * 106


def scatter_txt(doc: ScatterDoc, overrides: Optional[dict[str, str]] = None) -> str:
    """Render a classic SP Flash Tool scatter.txt.

    `overrides` maps partition_name -> on-disk filename for the files actually
    present; a partition with no override (or "NONE") is written is_download:
    false so SP Flash Tool skips it instead of erroring on a missing file.
    """
    overrides = overrides or {}
    out: list[str] = []
    out.append(_HR)
    out.append("#")
    out.append("#  General Setting")
    out.append("#")
    out.append(_HR)
    out.append("- general: MTK_PLATFORM_CFG")
    out.append("  info:")
    out.append("    - config_version: %s" % (doc.config_version or "V1.1.2"))
    out.append("      platform: %s" % doc.platform)
    out.append("      project: %s" % doc.project)
    out.append("      storage: %s" % (doc.storage or "EMMC"))
    out.append("      boot_channel: %s" % (doc.boot_channel or "MSDC_0"))
    out.append("      block_size: %s" % (doc.block_size or "0x20000"))
    out.append(_HR)
    out.append("#")
    out.append("#  Layout Setting")
    out.append("#")
    out.append(_HR)

    for p in doc.parts:
        fname = overrides.get(p.name)
        if fname:
            is_dl, file_name = "true", fname
        else:
            is_dl, file_name = "false", (p.file_name if p.downloadable else "NONE")
        out.append("- partition_index: %s" % p.index)
        out.append("  partition_name: %s" % p.name)
        out.append("  file_name: %s" % file_name)
        out.append("  is_download: %s" % is_dl)
        out.append("  type: %s" % p.ptype)
        out.append("  linear_start_addr: 0x%x" % p.linear_addr)
        out.append("  physical_start_addr: 0x%x" % p.phys_addr)
        out.append("  partition_size: 0x%x" % p.size)
        out.append("  region: %s" % _region_txt(p.region))
        out.append("  storage: %s" % p.storage)
        out.append("  boundary_check: %s" % p.boundary_check)
        out.append("  is_reserved: %s" % p.is_reserved)
        out.append("  operation_type: %s" % p.operation_type)
        out.append("  reserve: %s" % p.reserve)
        out.append("")
    return "\n".join(out) + "\n"

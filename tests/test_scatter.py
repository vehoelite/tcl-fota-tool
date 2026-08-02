"""Tests for MTK scatter parsing, scatter.txt emission, and the pack resolver."""

from tcl_fw import flashpack, scatter
from tcl_fw.flashpack import Probe

# A minimal MTK_PLATFORM_CFG scatter with the partition table intentionally
# duplicated (as real TCL packs do) to exercise de-duplication.
_XML = """<?xml version="1.0" encoding="utf-8"?>
<root>
 <general name="MTK_PLATFORM_CFG">
  <config_version name="V2.2.0"><platform>MT6835</platform><project>demo</project></config_version>
 </general>
 <storage_type name="EMMC">
  <general name="MTK_STORAGE_CFG"><storage name="EMMC">
    <boot_channel>MSDC_0</boot_channel><block_size>0x20000</block_size></storage></general>
  {P}
  {P}
 </storage_type>
</root>"""

_PARTS = """
 <partition_index name="SYS0"><partition_name>preloader</partition_name>
  <file_name>preloader_demo.bin</file_name><is_download>true</is_download>
  <type>SV5_BL_BIN</type><linear_start_addr>0x0</linear_start_addr>
  <physical_start_addr>0x0</physical_start_addr><partition_size>0x100000</partition_size>
  <region>EMMC_BOOT1</region><operation_type>BOOTLOADERS</operation_type></partition_index>
 <partition_index name="SYS1"><partition_name>boot_a</partition_name>
  <file_name>boot.img</file_name><is_download>true</is_download>
  <type>NORMAL_ROM</type><linear_start_addr>0x100000</linear_start_addr>
  <physical_start_addr>0x0</physical_start_addr><partition_size>0x4000000</partition_size>
  <region>EMMC_USER</region><operation_type>UPDATE</operation_type></partition_index>
 <partition_index name="SYS2"><partition_name>dtbo_a</partition_name>
  <file_name>dtbo.img</file_name><is_download>true</is_download>
  <type>NORMAL_ROM</type><linear_start_addr>0x200000</linear_start_addr>
  <physical_start_addr>0x0</physical_start_addr><partition_size>0x800000</partition_size>
  <region>EMMC_USER</region><operation_type>UPDATE</operation_type></partition_index>
 <partition_index name="SYS3"><partition_name>system_a</partition_name>
  <file_name>system.img</file_name><is_download>true</is_download>
  <type>EXT4_IMG</type><linear_start_addr>0x300000</linear_start_addr>
  <physical_start_addr>0x0</physical_start_addr><partition_size>0x40000000</partition_size>
  <region>EMMC_USER</region><operation_type>UPDATE</operation_type></partition_index>
 <partition_index name="SYS4"><partition_name>nvram</partition_name>
  <file_name>NONE</file_name><is_download>false</is_download>
  <type>NORMAL_ROM</type><linear_start_addr>0x400000</linear_start_addr>
  <physical_start_addr>0x0</physical_start_addr><partition_size>0x4000000</partition_size>
  <region>EMMC_USER</region><operation_type>PROTECTED</operation_type></partition_index>
"""

XML = _XML.replace("{P}", _PARTS)


def _doc():
    return scatter.parse(XML)


def test_looks_like_mtk():
    assert scatter.looks_like_mtk(XML)
    assert not scatter.looks_like_mtk("<?xml version='1.0'?><data><parameter/></data>")


def test_parse_dedups_and_reads_fields():
    doc = _doc()
    assert doc.platform == "MT6835" and doc.project == "demo"
    names = [p.name for p in doc.parts]
    assert names == ["preloader", "boot_a", "dtbo_a", "system_a", "nvram"]  # deduped
    dl = {p.name for p in doc.download_parts()}
    assert dl == {"preloader", "boot_a", "dtbo_a", "system_a"}  # nvram excluded
    boot = next(p for p in doc.parts if p.name == "boot_a")
    assert boot.size == 0x4000000 and boot.file_name == "boot.img"


def test_scatter_txt_has_layout_and_overrides():
    doc = _doc()
    txt = scatter.scatter_txt(doc, overrides={"boot_a": "boot.img"})
    assert "MTK_PLATFORM_CFG" in txt and "platform: MT6835" in txt
    assert "region: EMMC_BOOT_1" in txt          # normalised from EMMC_BOOT1
    # boot has an override -> is_download true; system has none -> false
    boot_blk = txt.split("partition_name: boot_a")[1].split("partition_index")[0]
    assert "is_download: true" in boot_blk
    sys_blk = txt.split("partition_name: system_a")[1].split("partition_index")[0]
    assert "is_download: false" in sys_blk


def test_resolver_maps_by_magic_and_size():
    doc = _doc()
    probes = [
        Probe("x/a", "a", 60 << 20, "android", "boot", None),      # -> boot_a (size)
        Probe("x/b", "b", 0xd00000, "dtbo", "dtbo", None),          # -> dtbo_a (magic)
        Probe("x/c", "c", 0x3f000000, "erofs", "zero", None),      # -> system_a (fs size-fit)
        Probe("x/d", "d", 0x90000, "mmm", "preloader", None),      # -> preloader (magic)
    ]
    matches, unmapped = flashpack.resolve(doc, probes)
    got = {m.probe.fname: (m.part.name if m.part else None) for m in matches}
    assert got["b"] == "dtbo_a"
    assert got["d"] == "preloader"
    assert got["a"] == "boot_a"
    assert got["c"] == "system_a"
    assert not unmapped

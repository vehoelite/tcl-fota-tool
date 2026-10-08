"""#17: `pack` / Make flashable on devices that ship only a GOTU .sca.

The .sca is an MTK scatter in its text form (MTK_PLATFORM_CFG). Pack used to
read only the XML form and told these users their device couldn't be handled.
The sample below is an excerpt of the real T611B-2ALCGB12 .sca.
"""

from tcl_fw import flashpack, scatter

SCA = """\
############################################################################################################
#
#  General Setting
#
############################################################################################################
- general: MTK_PLATFORM_CFG
  info:
    - config_version: V1.1.8
      platform: MT6768
      project: ladybirdpro_k510
      storage: EMMC
      boot_channel: MSDC_0
      block_size: 0x20000
#    FCM_VERSION: 3
############################################################################################################
- partition_index: SYS0
  rename_prefix: P0
  partition_name: preloader
  file_name: preloader_ladybirdpro_k510.bin
  is_download: true
  is_perso: false
  type: SV5_BL_BIN
  linear_start_addr: 0x0
  physical_start_addr: 0x0
  partition_size: 0x80000
  region: EMMC_BOOT1_BOOT2
  storage: HW_STORAGE_EMMC
  boundary_check: true
  is_reserved: false
  operation_type: BOOTLOADERS
  reserve: 0x00

- partition_index: SYS4
  rename_prefix:
  partition_name: persist
  file_name: NONE
  is_download: false
  type: EXT4_IMG
  linear_start_addr: 0x4308000
  physical_start_addr: 0x4308000
  partition_size: 0x3000000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
  operation_type: PROTECTED

- partition_index: SYS20
  rename_prefix: LK
  partition_name: lk_a
  file_name: lk.img
  is_download: true
  type: NORMAL_ROM
  linear_start_addr: 0x23800000
  physical_start_addr: 0x23800000
  partition_size: 0x300000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
  operation_type: UPDATE

- partition_index: SYS30
  rename_prefix: VB
  partition_name: vbmeta_a
  file_name: vbmeta.img
  is_download: true
  type: NORMAL_ROM
  linear_start_addr: 0x2d000000
  physical_start_addr: 0x2d000000
  partition_size: 0x800000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
  operation_type: UPDATE
"""


def test_text_scatter_parses():
    doc = scatter.parse(SCA)
    assert (doc.platform, doc.project, doc.config_version) == (
        "MT6768", "ladybirdpro_k510", "V1.1.8")
    assert (doc.storage, doc.boot_channel, doc.block_size) == ("EMMC", "MSDC_0", "0x20000")
    names = [p.name for p in doc.parts]
    assert names == ["preloader", "persist", "lk_a", "vbmeta_a"]
    pre = doc.parts[0]
    assert pre.file_name == "preloader_ladybirdpro_k510.bin"
    assert pre.ptype == "SV5_BL_BIN" and pre.region == "EMMC_BOOT1_BOOT2"
    assert pre.size == 0x80000 and pre.operation_type == "BOOTLOADERS"
    lk = doc.parts[2]
    assert (lk.linear_addr, lk.size, lk.file_name) == (0x23800000, 0x300000, "lk.img")
    assert [p.name for p in doc.download_parts()] == ["preloader", "lk_a", "vbmeta_a"]


def test_text_scatter_round_trips_through_the_emitter():
    doc = scatter.parse(SCA)
    again = scatter.parse(scatter.scatter_txt(doc, {"lk_a": "lk.img"}))
    lk = [p for p in again.parts if p.name == "lk_a"][0]
    assert (lk.linear_addr, lk.size, lk.file_name, lk.is_download) == (
        0x23800000, 0x300000, "lk.img", True)


def _pack_dir(tmp_path, with_sca=True):
    (tmp_path / "lk.img").write_bytes(b"\x88\x16\x88\x58" + b"\x00" * 4092)
    (tmp_path / "vbmeta.img").write_bytes(b"AVB0" + b"\x00" * 4092)
    (tmp_path / "preloader_ladybirdpro_k510.bin").write_bytes(b"\x4d\x4d\x4d\x01" + b"\x00" * 4092)
    if with_sca:
        (tmp_path / "K3FB8080DS00.sca").write_text(SCA)
    return tmp_path


def test_pack_works_from_a_sca_only_folder(tmp_path):
    """The reporter's case: no XML, only the .sca. Pack must find it."""
    d = _pack_dir(tmp_path)
    found = flashpack.find_scatter(str(d))
    assert found and found[0].endswith(".sca")
    res = flashpack.build(str(d))
    got = {m.probe.fname: (m.part.name, m.confidence) for m in res.matches if m.part}
    assert got == {"lk.img": ("lk_a", 1.0), "vbmeta.img": ("vbmeta_a", 1.0),
                   "preloader_ladybirdpro_k510.bin": ("preloader", 1.0)}


def test_the_scatter_file_is_never_probed_as_a_partition(tmp_path):
    """Seen live: pack size-fitted the .sca itself onto dtbo."""
    d = _pack_dir(tmp_path)
    (d / ".1254815.part").write_bytes(b"\x00" * 100)
    res = flashpack.build(str(d))
    probed = {m.probe.fname for m in res.matches} | {p.fname for p in res.unmapped}
    assert "K3FB8080DS00.sca" not in probed
    assert ".1254815.part" not in probed


def test_xml_scatter_is_preferred_over_sca(tmp_path, monkeypatch):
    d = _pack_dir(tmp_path)
    (d / "K2FA6060EB10.xml").write_text("<?xml version='1.0'?><root/>")
    xml_doc = scatter.parse(SCA)
    xml_doc.project = "from-xml"
    real = scatter.parse
    monkeypatch.setattr(scatter, "looks_like_mtk", lambda t: True)
    monkeypatch.setattr(scatter, "parse",
                        lambda t: xml_doc if t.lstrip().startswith("<") else real(t))
    path, doc = flashpack.find_scatter(str(d))
    assert path.endswith(".xml") and doc.project == "from-xml"


def test_no_scatter_at_all_is_still_reported(tmp_path):
    d = _pack_dir(tmp_path, with_sca=False)
    assert flashpack.build(str(d)) is None

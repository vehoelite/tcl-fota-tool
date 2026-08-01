"""Tests for content-magic identification and scatter name joining."""

from tcl_fw import naming


def test_magic_name_common_formats():
    assert naming.magic_name(b"AVB0" + b"\x00" * 12)[0] == "vbmeta"
    assert naming.magic_name(b"ANDROID!" + b"\x00" * 8)[0] == "boot_or_vendorboot"
    assert naming.magic_name(b"\x3a\xff\x26\xed" + b"\x00" * 12)[0] == "sparse"
    assert naming.magic_name(b"<?xml version")[0] == "scatter_or_cfg"
    assert naming.magic_name(b"\x00" * 16)[0] == "zero"


def test_magic_name_gfh_carries_partition_name():
    # MTK GFH header: 88 16 88 58, then partition name at offset 8.
    blob = b"\x88\x16\x88\x58" + b"\x00\x00\x00\x00" + b"lk\x00\x00" + b"\x00" * 16
    name, ext = naming.magic_name(blob)
    assert name == "lk"
    assert ext == "img"


def test_alias_maps_conventional_names():
    assert naming.alias("md1rom") == "md1img"
    assert naming.alias("atf") == "tee"
    assert naming.alias("superheader") == "super"
    assert naming.alias("lk") == "lk"


def test_parse_sca_extracts_download_partitions():
    sca = (
        "partition_index: SYS0\n"
        "  partition_name: lk\n"
        "  file_name: lk.img\n"
        "  is_download: true\n"
        "  rename_prefix: lk\n"
        "partition_index: SYS1\n"
        "  partition_name: nvram\n"
        "  file_name: NONE\n"
        "  is_download: false\n"
        "  rename_prefix: nv\n"
    )
    out = naming.parse_sca(sca)
    assert out == {"lk": "lk.img"}


def test_join_names_prefix_rules():
    # coded 'ab.img' -> prefix coded[0]+coded[-2] == 'a' + 'g' -> not present;
    # falls back to coded[0] == 'a'.
    manifest = {"1": "boot.img", "2": "lk.sca"}
    by_id = {"1": "/x", "2": "/y"}
    sca = {"bt": "boot.img", "b": "boot.img"}
    names = naming.join_names(manifest, sca, by_id)
    # 'boot' -> base[0]+base[-2] == 'b'+'o' == 'bo' (absent) -> base[0] 'b' -> boot.img
    assert names["1"] == "boot.img"
    # .sca kept as-is
    assert names["2"] == "lk.sca"

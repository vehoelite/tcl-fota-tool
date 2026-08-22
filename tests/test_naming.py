"""Tests for content-magic identification and scatter name joining."""

import struct

from tcl_fw import naming


# ── sparse-image builders (Android sparse: 28-byte header + typed chunks) ──────
def _sparse(*blocks: bytes, blk: int = 4096) -> bytes:
    """Wrap raw 4 KiB blocks as a single-raw-chunk sparse image."""
    body = b"".join(blocks)
    nblk = len(body) // blk
    hdr = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, nblk, 1, 0)
    chunk = struct.pack("<HHII", 0xCAC1, 0, nblk, 12 + len(body))
    return hdr + chunk + body


def _ext4_block(label: bytes = b"") -> bytes:
    b = bytearray(4096)
    b[0x438:0x43A] = b"\x53\xef"                 # ext4 s_magic
    b[0x478:0x478 + len(label)] = label          # s_volume_name
    return bytes(b)


def _f2fs_block() -> bytes:
    b = bytearray(4096)
    b[0x400:0x404] = b"\x10\x20\xf5\xf2"          # f2fs super magic
    return bytes(b)


def _erofs_block(label: bytes = b"") -> bytes:
    b = bytearray(4096)
    b[0x400:0x404] = b"\xe2\xe1\xf5\xe0"          # erofs super magic
    b[0x440:0x440 + len(label)] = label
    return bytes(b)


def test_magic_name_common_formats():
    assert naming.magic_name(b"AVB0" + b"\x00" * 12)[0] == "vbmeta"
    assert naming.magic_name(b"ANDROID!" + b"\x00" * 8)[0] == "boot_or_vendorboot"
    # a sparse image too short to un-sparse still degrades to "sparse".
    assert naming.magic_name(b"\x3a\xff\x26\xed" + b"\x00" * 12)[0] == "sparse"
    assert naming.magic_name(b"<?xml version")[0] == "scatter_or_cfg"
    assert naming.magic_name(b"\x00" * 16)[0] == "zero"


def test_sparse_ext4_named_by_volume_label():
    # The real bug: sparse partitions came out as anonymous "sparse". Now the
    # ext4 volume label inside is read through the sparse container.
    for label in (b"vendor", b"cache", b"system", b"product"):
        img = _sparse(_ext4_block(label))
        assert naming.magic_name(img)[0] == label.decode()
        assert naming.identify(img, len(img)).name == label.decode()


def test_sparse_f2fs_is_userdata():
    img = _sparse(_f2fs_block())
    assert naming.magic_name(img)[0] == "userdata"
    ident = naming.identify(img, len(img))
    assert ident.name == "userdata" and ident.family == "f2fs"


def test_sparse_erofs_named_by_label():
    img = _sparse(_erofs_block(b"product"))
    assert naming.magic_name(img)[0] == "product"


def test_sparse_blank_ext4_label_falls_back_to_family_not_sparse():
    img = _sparse(_ext4_block(b""))            # ext4, no volume label
    assert naming.magic_name(img)[0] == "ext4"


def test_unsparse_head_is_bounded_on_huge_dont_care():
    # A don't-care chunk spanning ~4 GiB must not materialize 4 GiB of zeros.
    hdr = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 4096, 1 << 20, 1, 0)
    dontcare = struct.pack("<HHII", 0xCAC3, 0, 1 << 20, 12)   # 1M blocks, no body
    raw = naming.unsparse_head(hdr + dontcare, want=8192)
    assert len(raw) <= 8192


def test_zip_wrapped_payloads_get_meaningful_names():
    def zip_head(name: bytes) -> bytes:
        return (b"PK\x03\x04" + struct.pack("<HHHHHIIIHH",
                20, 0, 8, 0, 0, 0, 0, 0, len(name), 0) + name)
    assert naming.magic_name(zip_head(b"system.map"))[0] == "system_map"
    assert naming.magic_name(zip_head(b"vendor.map"))[0] == "vendor_map"
    assert naming.magic_name(zip_head(b"target_files_extract/build.prop"))[0] == "ota_recovery"
    assert naming.magic_name(zip_head(b"y7l85d00ct20.mbn"))[0] == "zip_y7l85d00ct20"


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

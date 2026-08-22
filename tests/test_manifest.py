"""Tests for the embedded target_files partition manifest (scatter-first naming
for devices that serve no top-level .sca)."""

import io
import zipfile

from tcl_fw import manifest

# Trimmed from a real 5033E-2HOFBRA pack.
MISC = """\
recovery_api_version=3
blocksize=4096
system_size=1459617792
userdata_fs_type=f2fs
userdata_size=3221225472
tctpersist_size=8388608
simlock_size=8388608
cache_fs_type=ext4
cache_size=117440512
vendor_fs_type=ext4
vendor_size=327155712
"""

SCATTER = """\
tctpersist 0x7688000
simlock 0x7e88000
protect1 0x8688000
vendor 0x13800000
system 0x27000000
cache 0x7e000000
userdata 0x85000000
sgpt 0xFFFF0000
"""

OTA_LIST = """\
tee.img tee1 tee2
lk.img bootloader bootloader2
odmdtbo.img odmdtbo
"""


def test_parse_misc_info():
    sizes, fs = manifest.parse_misc_info(MISC)
    assert sizes["system"] == 1459617792
    assert sizes["tctpersist"] == 8388608
    assert fs["userdata"] == "f2fs"
    assert fs["vendor"] == "ext4"


def test_scatter_sizes_are_offset_deltas():
    parts = manifest.parse_scatter_emmc(SCATTER)
    sizes = manifest.scatter_sizes(parts)
    # vendor -> system gap == 0x27000000 - 0x13800000
    assert sizes["vendor"] == 0x27000000 - 0x13800000 == 327155712
    assert sizes["cache"] == 0x85000000 - 0x7E000000 == 117440512
    assert sizes["tctpersist"] == 8388608
    # userdata is the last real partition (next is the 0xFFFF sentinel) -> no size
    assert "userdata" not in sizes
    assert "sgpt" not in sizes


def test_parse_ota_update_list():
    m = manifest.parse_ota_update_list(OTA_LIST)
    assert m["tee"] == ["tee1", "tee2"]
    assert m["lk"] == ["bootloader", "bootloader2"]


def test_name_for_size_unique_filesystem():
    m = manifest.Manifest()
    m.sizes, m.fs_types = manifest.parse_misc_info(MISC)
    assert m.name_for_size(327155712) == "vendor"
    assert m.name_for_size(3221225472) == "userdata"


def test_name_for_size_prefers_filesystem_over_colliding_nonfs():
    # tctpersist and simlock are both 8 MiB; only tctpersist is a filesystem, so
    # the 8 MiB ext4 image resolves to tctpersist, not the simlock security blob.
    m = manifest.Manifest()
    m.sizes, m.fs_types = manifest.parse_misc_info(MISC)
    assert m.name_for_size(8388608) == "tctpersist"


def test_name_for_size_none_when_no_filesystem_match():
    m = manifest.Manifest()
    m.sizes, m.fs_types = manifest.parse_misc_info(MISC)
    assert m.name_for_size(12345) is None


def _target_files_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("target_files_extract/misc_info.txt", MISC)
        z.writestr("target_files_extract/scatter_emmc.txt", SCATTER)
        z.writestr("target_files_extract/ota_update_list.txt", OTA_LIST)
    return buf.getvalue()


def test_from_zip_bytes_builds_full_manifest():
    m = manifest.from_zip_bytes(_target_files_zip())
    assert m is not None
    assert m.sizes["vendor"] == 327155712
    assert m.name_for_size(8388608) == "tctpersist"
    assert set(m.files) == {"misc_info.txt", "scatter_emmc.txt", "ota_update_list.txt"}
    assert m.image_map["tee"] == ["tee1", "tee2"]


def test_from_zip_bytes_rejects_non_target_files_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("something_else/readme.txt", "hi")
    assert manifest.from_zip_bytes(buf.getvalue()) is None
    assert manifest.from_zip_bytes(b"not a zip") is None

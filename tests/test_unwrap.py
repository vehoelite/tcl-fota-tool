"""Streaming unwrap of zip-wrapped partitions.

TCL ships the big filesystem partitions triple-wrapped (zip -> .mbn -> Android
sparse -> ext4), so the partition a user wants is two layers down. These pin the
detection, the in-flight inflate, and — importantly — that the server's body
checksum is still verifiable even though what lands on disk is the decompressed
image rather than the bytes that came over the wire.
"""

import hashlib
import io
import struct
import zipfile

import pytest

from tcl_fw import download, naming


# ── builders ─────────────────────────────────────────────────────────────────

def _ext4_block(label: bytes) -> bytes:
    b = bytearray(4096)
    b[0x438:0x43A] = b"\x53\xef"
    b[0x478:0x478 + len(label)] = label
    return bytes(b)


def _sparse(payload: bytes, blk: int = 4096) -> bytes:
    nblk = len(payload) // blk
    hdr = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, blk, nblk, 1, 0)
    chunk = struct.pack("<HHII", 0xCAC1, 0, nblk, 12 + len(payload))
    return hdr + chunk + payload


def _zip_of(name: str, data: bytes, method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        z.writestr(name, data)
    return buf.getvalue()


IMAGE = _sparse(_ext4_block(b"system"))
WRAPPED = _zip_of("y7l85d00ct20.mbn", IMAGE)


# ── fake transport so no network/server is needed ────────────────────────────

class _FakeResp:
    def __init__(self, data: bytes):
        self._d, self._i = data, 0
        self.headers = {"Content-Length": str(len(data))}

    def read(self, n=-1):
        if self._i >= len(self._d):
            return b""
        end = len(self._d) if (n is None or n < 0) else self._i + n
        chunk = self._d[self._i:end]
        self._i += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def serve(monkeypatch):
    def _serve(blob):
        monkeypatch.setattr(download.urllib.request, "urlopen",
                            lambda *a, **k: _FakeResp(blob))
    return _serve


# ── detection ────────────────────────────────────────────────────────────────

def test_wrapped_partition_is_detected_and_named_by_inner_image():
    got = naming.zip_wrapped_image(WRAPPED)
    assert got is not None
    name, ext, entry = got
    assert (name, ext) == ("system", "img")
    assert entry["name"] == "y7l85d00ct20.mbn"


def test_magic_name_uses_the_inner_image():
    assert naming.magic_name(WRAPPED)[0] == "system"


def test_metadata_zip_is_left_alone():
    """A zip of ordinary files is not a partition and must stay zipped."""
    meta = _zip_of("system.map", b"/system/app/Foo/Foo.apk 1-2\n")
    assert naming.zip_wrapped_image(meta) is None
    assert naming.magic_name(meta)[0] == "system_map"


def test_target_files_zip_is_not_treated_as_a_partition():
    tf = _zip_of("target_files_extract/build.prop", b"ro.build.id=X\n")
    assert naming.zip_wrapped_image(tf) is None


# ── streaming unwrap ─────────────────────────────────────────────────────────

def test_unwrap_writes_the_inner_image_not_the_container(tmp_path, serve):
    serve(WRAPPED)
    dest = tmp_path / "system.img"
    entry = naming.zip_entry(WRAPPED)
    written, sha, raw = download.stream_unwrap("h", "/r", str(dest), entry)
    assert dest.read_bytes() == IMAGE, "must land as the image, not the zip"
    assert written == len(IMAGE)
    assert raw == len(WRAPPED)


def test_unwrap_hashes_the_body_as_served_so_checksums_still_verify(tmp_path, serve):
    serve(WRAPPED)
    dest = tmp_path / "system.img"
    written, sha, raw = download.stream_unwrap("h", "/r", str(dest), naming.zip_entry(WRAPPED))
    assert sha == hashlib.sha1(WRAPPED).hexdigest()
    assert sha != hashlib.sha1(IMAGE).hexdigest()


def test_unwrap_handles_a_stored_uncompressed_entry(tmp_path, serve):
    blob = _zip_of("plain.mbn", IMAGE, method=zipfile.ZIP_STORED)
    serve(blob)
    dest = tmp_path / "out.img"
    download.stream_unwrap("h", "/r", str(dest), naming.zip_entry(blob))
    assert dest.read_bytes() == IMAGE


def test_unwrap_reports_progress_against_the_download_size(tmp_path, serve):
    serve(WRAPPED)
    seen = []
    download.stream_unwrap("h", "/r", str(tmp_path / "o.img"),
                           naming.zip_entry(WRAPPED),
                           on_progress=lambda got, total: seen.append((got, total)))
    assert seen, "progress must be reported"
    assert seen[-1][0] == len(WRAPPED)          # compressed bytes = what's downloaded
    assert all(t == len(WRAPPED) for _g, t in seen if t)


def test_truncated_download_raises_and_leaves_no_partial_image(tmp_path, serve):
    """A real 5033E pull was short by 4 MiB. A truncated body must not quietly
    become a short system.img that someone then flashes."""
    serve(WRAPPED[:len(WRAPPED) // 2])
    dest = tmp_path / "system.img"
    with pytest.raises(IOError, match="ended early"):
        download.stream_unwrap("h", "/r", str(dest), naming.zip_entry(WRAPPED))
    assert not dest.exists(), "the partial image must be removed, not left behind"


def test_unwrap_ignores_trailing_bytes_after_the_entry(tmp_path, serve):
    """The zip central directory follows the entry; it must not corrupt output."""
    serve(WRAPPED)
    dest = tmp_path / "system.img"
    download.stream_unwrap("h", "/r", str(dest), naming.zip_entry(WRAPPED))
    assert dest.read_bytes() == IMAGE

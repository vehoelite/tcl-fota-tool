"""Byte-exact image assembly: image = body || unpad(decrypt(header blob)).

Regressions for #15 (large partitions saved 4 MiB short), #16 (header images
kept their PKCS#7 pad), and the checksum parser that silently never ran. The
real download code runs against a local Range-capable HTTP server; only the
two encrypt-server calls are faked, using genuinely AES-encrypted blobs.
"""

import hashlib
import http.server
import io
import os
import threading
import zipfile
import zlib

import pytest
from Crypto.Cipher import AES

from tcl_fw import fota, puller
from tcl_fw.crypto import BLOCK, KEY
from tcl_fw.download import parse_checksums
from tcl_fw.fota import DownloadInfo, FileEntry
from tcl_fw.puller import PullPlan

sha1 = lambda b: hashlib.sha1(b).hexdigest()


def _encrypt(plain: bytes) -> bytes:
    n = BLOCK - len(plain) % BLOCK
    return AES.new(KEY, AES.MODE_ECB).encrypt(plain + bytes([n]) * n)


# ── a tiny CDN ────────────────────────────────────────────────────────────────

class _Bodies(http.server.BaseHTTPRequestHandler):
    bodies: dict = {}
    hits: list = []

    def do_GET(self):
        data = self.bodies.get(self.path)
        if data is None:
            self.send_error(404)
            return
        self.hits.append(self.path)
        rng = self.headers.get("Range")
        start = int(rng.split("=")[1].split("-")[0]) if rng else 0
        if start >= len(data) and rng:
            self.send_response(416)
            self.send_header("Content-Range", "bytes */%d" % len(data))
            self.end_headers()
            return
        chunk = data[start:]
        self.send_response(206 if rng else 200)
        if rng:
            self.send_header("Content-Range",
                             "bytes %d-%d/%d" % (start, len(data) - 1, len(data)))
        self.send_header("Content-Length", str(len(chunk)))
        self.end_headers()
        self.wfile.write(chunk)

    def log_message(self, *a):
        pass


@pytest.fixture
def cdn():
    _Bodies.bodies, _Bodies.hits = {}, []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Bodies)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def server(cdn, monkeypatch):
    """Register a partition: body on the CDN, encrypted blob + checksums on the
    (faked) encrypt server. Returns a function that builds a PullPlan."""
    blobs, sums = {}, {}
    monkeypatch.setattr(fota, "fetch_header", lambda enc, rel, **k: blobs.get(rel, b""))
    monkeypatch.setattr(puller, "fetch_checksums", lambda enc, rel, **k: sums.get(rel))

    def add(fid, body, footer, checksums=True, footer_sum=None, body_sum=None,
            no_body_sum=False):
        rel = "/body/x/%s" % fid
        _Bodies.bodies[rel] = body
        blobs[rel] = _encrypt(footer)
        if checksums:
            sums[rel] = parse_checksums(
                "<GOTU><FILE_CHECKSUM_LIST><FILE><ADDRESS>%s</ADDRESS>"
                "<FOOTER>%s</FOOTER><BODY>%s</BODY></FILE></FILE_CHECKSUM_LIST></GOTU>"
                % (rel, footer_sum or sha1(footer),
                   "" if no_body_sum else (body_sum or sha1(body))), rel)
        return FileEntry(fid, rel)

    def plan(files, heads=None):
        info = DownloadInfo("X-1", "tv", "fw", cdn, "enc.invalid", files)
        p = PullPlan(info=info, names={f.file_id: "p%s.img" % f.file_id for f in files},
                     sizes={f.file_id: len(_Bodies.bodies[f.rel_url]) for f in files})
        p.heads.update(heads or {f.file_id: b"\x00" * 64 for f in files})
        return p

    add.plan = plan
    return add


# ── #16: a header image comes out exactly, and is verified ───────────────────

def test_small_partition_is_byte_exact_and_verified(server, tmp_path):
    image = b"AVB0" + b"\x00" * 8188                 # ends in zeros, block aligned
    f = server("1", b"", image)
    r = puller.pull_one(server.plan([f]), f, str(tmp_path))
    assert r.error is None and r.verified is True
    assert (tmp_path / "p1.img").read_bytes() == image   # no trailing pad block


# ── #15: a large partition gets its footer ───────────────────────────────────

def test_large_partition_gets_its_footer(server, tmp_path):
    body, footer = os.urandom(300_000), os.urandom(4096 * 3)
    f = server("2", body, footer)
    r = puller.pull_one(server.plan([f]), f, str(tmp_path))
    assert r.error is None and r.verified is True
    out = (tmp_path / "p2.img").read_bytes()
    assert out == body + footer                       # not body alone
    assert r.size == len(body) + len(footer)


def test_without_checksums_the_image_is_complete_but_reported_unverified(server, tmp_path):
    body, footer = os.urandom(50_000), os.urandom(4096)
    f = server("3", body, footer, checksums=False)
    r = puller.pull_one(server.plan([f]), f, str(tmp_path))
    assert r.error is None
    assert r.verified is None                         # honest: nothing proved it
    assert (tmp_path / "p3.img").read_bytes() == body + footer


def test_footer_checksum_mismatch_writes_nothing(server, tmp_path):
    f = server("4", os.urandom(10_000), os.urandom(4096), footer_sum="0" * 40)
    r = puller.pull_one(server.plan([f]), f, str(tmp_path))
    assert r.error and "checksum" in r.error and r.verified is False
    assert not list(tmp_path.iterdir())               # no image, no .part
    assert _Bodies.hits == []                         # caught before the body


def test_body_checksum_mismatch_writes_nothing(server, tmp_path):
    f = server("5", os.urandom(10_000), os.urandom(4096), body_sum="0" * 40)
    r = puller.pull_one(server.plan([f]), f, str(tmp_path))
    assert r.error and "body checksum" in r.error
    assert not list(tmp_path.iterdir())


def test_a_short_4x_image_on_disk_is_pulled_again(server, tmp_path):
    """4.x left every large image exactly `body` bytes long. Re-running must not
    call that complete just because its size matches the body."""
    body, footer = os.urandom(40_000), os.urandom(4096)
    f = server("6", body, footer)
    (tmp_path / "p6.img").write_bytes(body)           # what 4.3 produced
    r = puller.pull_one(server.plan([f]), f, str(tmp_path))
    assert r.verified is True
    assert (tmp_path / "p6.img").read_bytes() == body + footer


def test_a_complete_image_on_disk_is_reproven_not_redownloaded(server, tmp_path):
    body, footer = os.urandom(40_000), os.urandom(4096)
    f = server("7", body, footer)
    (tmp_path / "p7.img").write_bytes(body + footer)
    r = puller.pull_one(server.plan([f]), f, str(tmp_path))
    assert r.verified is True and _Bodies.hits == []


def test_an_invalid_header_blob_is_refused(server, tmp_path, monkeypatch):
    """An error page or wrong-key blob must not be decrypted and written out."""
    f = server("8", os.urandom(1000), os.urandom(4096), checksums=False)
    monkeypatch.setattr(fota, "fetch_header", lambda *a, **k: os.urandom(64))
    r = puller.pull_one(server.plan([f]), f, str(tmp_path))
    assert r.error and "rejected" in r.error
    assert not list(tmp_path.iterdir())


# ── #15 on the zip-wrapped path: the deflate stream crosses the seam ─────────

def _wrapped(image: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("system.mbn", image)
    return buf.getvalue()


@pytest.mark.parametrize("footer_len", [200, 4000, 30_000])
def test_wrapped_partition_inflates_across_body_and_footer(server, tmp_path, footer_len):
    image = b"\x3a\xff\x26\xed" + os.urandom(60_000) + b"\x00" * 100_000
    container = _wrapped(image)
    assert footer_len < len(container)
    body, footer = container[:-footer_len], container[-footer_len:]
    f = server("9", body, footer)
    p = server.plan([f], heads={"9": body[:65536]})
    r = puller.pull_one(p, f, str(tmp_path))
    assert r.error is None, r.error
    assert r.verified is True
    assert (tmp_path / "p9.img").read_bytes() == image  # the image, not the zip


def test_wrapped_partition_is_proven_by_zip_crc_when_server_has_no_body_hash(
        server, tmp_path):
    """Seen live on 5033E system: checksum.php gives FOOTER but no BODY. The
    zip's CRC-32 over the inflated image still proves every byte."""
    image = b"\x3a\xff\x26\xed" + os.urandom(50_000)
    container = _wrapped(image)
    body, footer = container[:-3000], container[-3000:]
    f = server("11", body, footer, no_body_sum=True)
    p = server.plan([f], heads={"11": body[:65536]})
    r = puller.pull_one(p, f, str(tmp_path))
    assert r.error is None and r.verified is True
    assert (tmp_path / "p11.img").read_bytes() == image


def test_wrapped_partition_failing_zip_crc_is_refused(server, tmp_path):
    image = b"\x3a\xff\x26\xed" + os.urandom(50_000)
    container = bytearray(_wrapped(image))
    container[14:18] = (int.from_bytes(container[14:18], "little") ^ 1).to_bytes(4, "little")
    body, footer = bytes(container[:-3000]), bytes(container[-3000:])
    f = server("12", body, footer, no_body_sum=True)
    p = server.plan([f], heads={"12": body[:65536]})
    r = puller.pull_one(p, f, str(tmp_path))
    assert r.error and "CRC" in r.error
    assert not list(tmp_path.iterdir())


def test_wrapped_partition_without_its_footer_is_refused(server, tmp_path, monkeypatch):
    """The pre-fix behaviour: body alone ends mid-stream. Must fail, not write."""
    image = b"\x3a\xff\x26\xed" + os.urandom(80_000)
    container = _wrapped(image)
    body, footer = container[:-5000], container[-5000:]
    f = server("10", body, footer, checksums=False)
    monkeypatch.setattr(fota, "fetch_header", lambda *a, **k: b"")
    p = server.plan([f], heads={"10": body[:65536]})
    r = puller.pull_one(p, f, str(tmp_path))
    assert r.error and "incomplete" in r.error
    assert not (tmp_path / "p10.img").exists()


# ── the checksum parser that never ran ───────────────────────────────────────

LIVE = ('<?xml version="1.0" encoding="utf-8"?>\n<GOTU><FILE_CHECKSUM_LIST><FILE>'
        '<ADDRESS>/body/b434/25/1209125</ADDRESS>'
        '<ENCRYPT_FOOTER>15339d83eed5f623affb616ae4920ae0964c1605</ENCRYPT_FOOTER>'
        '<FOOTER>8f35a39a850550bb3f5faf87485723fae5418098</FOOTER>'
        '<BODY>8264bf365a4f21b4f8afcee062f4c2427675cb35</BODY>'
        '</FILE></FILE_CHECKSUM_LIST></GOTU>\n')


def test_parses_the_real_xml_response():
    cs = parse_checksums(LIVE, "/body/b434/25/1209125")
    assert cs.body == "8264bf365a4f21b4f8afcee062f4c2427675cb35"
    assert cs.footer == "8f35a39a850550bb3f5faf87485723fae5418098"
    assert cs.encrypt_footer == "15339d83eed5f623affb616ae4920ae0964c1605"


def test_empty_or_foreign_response_is_none():
    assert parse_checksums('<?xml version="1.0"?>\n<GOTU/>\n', "/x") is None
    assert parse_checksums(LIVE, "/body/other") is None
    assert parse_checksums("", "/x") is None
    assert parse_checksums("<html>502</html", "/x") is None


def test_json_form_still_accepted():
    cs = parse_checksums('{"/a": {"body": "AB", "footer": "CD"}}', "/a")
    assert (cs.body, cs.footer) == ("ab", "cd")

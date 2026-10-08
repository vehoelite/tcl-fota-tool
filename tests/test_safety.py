"""Safety regressions for the v4.3.1 patch.

Each test here pins a path that could previously put wrong bytes under a
right-looking filename — the failure mode that ends in a bricked handset. They
are deliberately blunt: if one of these ever goes red, stop and read it.
"""

import struct

import pytest

from tcl_fw import fota, naming, puller
from tcl_fw.fota import DownloadInfo, FileEntry
from tcl_fw.flashpack import _boot_kind
from tcl_fw.puller import PullPlan


def _plan(**kw) -> PullPlan:
    info = DownloadInfo(curef="X-1", tv="tv", fw_id="fw",
                        slave=kw.pop("slave", "slave.example"),
                        encslave="enc.example",
                        files=kw.pop("files", []))
    return PullPlan(info=info, **kw)


# ── 1. destinations are injective ────────────────────────────────────────────

def test_two_files_never_share_a_destination():
    """The .sca join is not injective, so two FILE_IDs can resolve to one name.
    Sharing a path let a resumed body append itself onto the previous image."""
    p = _plan()
    a, a_col = p.claim("lk.img", "101")
    b, b_col = p.claim("lk.img", "102")
    c, c_col = p.claim("lk.img", "103")
    assert (a, a_col) == ("lk.img", False)       # first claimant keeps it clean
    assert a != b != c and a != c                # …and nobody else shares it
    assert b_col and c_col                       # both later ones are flagged
    assert b == "lk_102.img" and c == "lk_103.img"


def test_reclaiming_the_same_name_is_not_a_collision():
    """pull_one may resolve a name twice for one file; that is not a clash."""
    p = _plan()
    assert p.claim("boot.img", "101") == ("boot.img", False)
    assert p.claim("boot.img", "101") == ("boot.img", False)


def test_extensionless_names_still_disambiguate():
    p = _plan()
    p.claim("scatter", "1")
    assert p.claim("scatter", "2") == ("scatter_2", True)


def test_non_injective_sca_join_is_contained():
    """The real upstream defect, end to end: three coded names collapsing onto
    one file_name must still produce three distinct destinations."""
    coded = {"1": "lXXXk1.mbn", "2": "lYYYq7.mbn", "3": "logo9.mbn"}
    sca = {"l": "lk.img", "lk": "lk.img"}
    joined = naming.join_names(coded, sca, {k: "/x" for k in coded})
    assert len(set(joined.values())) == 1        # the join really does collapse
    p = _plan()
    dests = {p.claim(joined[fid], fid)[0] for fid in coded}
    assert len(dests) == 3                       # …but the destinations do not


# ── 2. a failed probe is not an empty body ───────────────────────────────────

def test_probe_failure_does_not_become_a_header_pull(monkeypatch, tmp_path):
    """body_size returns -1 on ANY network error and 0 on a real 416. Treating
    -1 as 'small' made a flaky probe decrypt the encrypted header and write
    that out as the partition image."""
    calls = []

    def boom(slave, rel, timeout=25):
        calls.append(rel)
        return -1                                 # network error, every time

    monkeypatch.setattr(fota, "body_size", boom)
    monkeypatch.setattr(fota, "fetch_header",
                        lambda *a, **k: pytest.fail("must not touch the header"))
    f = FileEntry(file_id="101", rel_url="/a.mbn")
    p = _plan(files=[f], sizes={"101": -1})
    r = puller.pull_one(p, f, str(tmp_path))
    assert r.kind == "skip" and "probe failed" in (r.error or "")
    assert calls == ["/a.mbn"]                    # re-probed once, then gave up
    assert not list(tmp_path.iterdir())           # and wrote nothing


def test_no_slave_means_header_not_probe_failure():
    """With no body server every image legitimately lives in its header. That
    is a real answer (0), and must not be confused with a failed probe."""
    info = DownloadInfo(curef="X", tv="t", fw_id="f", slave=None,
                        encslave="enc", files=[FileEntry("101", "/a")])
    plan = puller.build_plan("X-1", info)
    assert plan.sizes["101"] == 0


# ── 3. a guess never enters the authoritative dict ───────────────────────────

def test_guessed_names_stay_out_of_names(monkeypatch):
    """`names` means 'the server told us'. The GUI used to cache content
    guesses into it, after which nothing could tell the two apart."""
    monkeypatch.setattr(fota, "body_head", lambda *a, **k: b"AVB0" + b"\x00" * 64)
    f = FileEntry(file_id="101", rel_url="/a.img")
    p = _plan(files=[f], sizes={"101": 4096})
    got = puller._resolve_name(p, f, is_small=False)
    assert got == "vbmeta_101.img"
    assert p.names == {}                          # untouched
    assert p.guessed == {"101": got}              # cached apart


def test_authoritative_name_wins_over_a_cached_guess():
    f = FileEntry(file_id="101", rel_url="/a.img")
    p = _plan(files=[f], names={"101": "lk.img"}, guessed={"101": "sparse_101.img"})
    assert puller._resolve_name(p, f, is_small=False) == "lk.img"


# ── 4. alias() is anchored ───────────────────────────────────────────────────

@pytest.mark.parametrize("name,want", [
    ("platform", "platform"),          # used to become "tee" ("atf" in "platform")
    ("vbmeta_atf_x", "vbmeta_atf_x"),  # used to become "tee"
    ("atf", "tee"),                    # exact match still aliases
    ("atf-v1", "tee"),                 # separator-anchored prefix still aliases
    ("tinysys-scp-RV33_A", "scp"),     # the truncated/versioned GFH form
    ("md1rom", "md1img"),
])
def test_alias_is_anchored_not_substring(name, want):
    assert naming.alias(name) == want


def test_filesystem_labels_are_not_aliased():
    """A label is already the real partition name; alias() is for the strings
    an MTK header reports about itself. A partition labelled "platform" used to
    come out named "tee", because "atf" is a substring of "platform"."""
    blk = bytearray(4096)
    blk[0x438:0x43a] = b"\x53\xef"                       # ext4 s_magic
    blk[0x478:0x478 + 8] = b"platform"                   # s_volume_name
    hdr = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 4096, 1, 1, 0)
    chunk = struct.pack("<HHII", 0xCAC1, 0, 1, 12 + 4096)
    img = hdr + chunk + bytes(blk)
    assert naming.magic_name(img)[0] == "platform"
    assert naming.identify(img, len(img)).name == "platform"


# ── 5. boot family is classified by header, not by size ──────────────────────

def _boot_hdr(ver: int, kernel: int, dtbo: int = 0) -> bytes:
    b = bytearray(4096)
    b[0:8] = b"ANDROID!"
    struct.pack_into("<I", b, 8, kernel)
    struct.pack_into("<I", b, 40, ver)
    struct.pack_into("<I", b, 1632, dtbo)
    return bytes(b)


@pytest.mark.parametrize("hdr,want", [
    (_boot_hdr(4, 0), "init_boot"),              # GKI: no kernel => init_boot
    (_boot_hdr(4, 8 << 20), "boot"),
    (_boot_hdr(2, 8 << 20, 4096), "recovery"),   # recovery_dtbo_size set
])
def test_boot_kind_from_header_fields(hdr, want):
    assert _boot_kind(hdr)[0] == want


def test_ambiguous_boot_recovery_refuses_to_guess():
    """A v2 image with no recovery_dtbo could be boot or recovery. The old rule
    sorted by size and renamed the larger to boot.img at 0.9 — above the 0.7
    rename threshold — which silently turned recovery.img into boot.img."""
    kind, conf = _boot_kind(_boot_hdr(2, 8 << 20, 0))
    assert kind is None and conf == 0.0


def test_boot_kind_ignores_non_boot_blobs():
    assert _boot_kind(b"PK\x03\x04" + b"\x00" * 64) == (None, 0.0)

"""Tests for the TCL FOTA header decryptor."""

import pathlib

import pytest
from Crypto.Cipher import AES

from tcl_fw.crypto import KEY, BLOCK, decrypt_header

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def test_universal_key_value():
    # The one universal key for every TCL MediaTek header.
    assert KEY == b"e26baba108b08a28"
    assert KEY.hex() == "65323662616261313038623038613238"
    assert len(KEY) == 16


def test_roundtrip_with_filler_padding():
    """Encrypt a known image + constant filler, then decrypt and assert we get
    the image back with the filler trimmed (mirrors the server's ~4 MiB blob)."""
    image = b"AVB0" + b"\x11\x22\x33\x44" * 7  # 32 bytes, 2 blocks, no dominant repeat
    filler = b"\xAB" * BLOCK
    plain = image + filler * 64  # image followed by many identical filler blocks
    enc = AES.new(KEY, AES.MODE_ECB).encrypt(plain)

    out = decrypt_header(enc)
    assert out == image


def test_roundtrip_no_padding():
    """A blob that is exactly the image (no filler) must come back unchanged,
    except that a trailing run equal to the dominant block is trimmed. Use an
    image whose last block is unique to avoid over-trimming."""
    image = bytes(range(16)) + bytes(range(16, 32)) + b"END_OF_IMAGE!!!\x00"
    enc = AES.new(KEY, AES.MODE_ECB).encrypt(image)
    out = decrypt_header(enc)
    assert out == image


def test_too_short_raises():
    with pytest.raises(ValueError):
        decrypt_header(b"\x00" * 8)
    with pytest.raises(ValueError):
        decrypt_header(b"")


@pytest.mark.skipif(not (FIXTURES / "vbmeta.header.enc").exists(),
                    reason="real header fixtures not present")
def test_real_vbmeta_header_decrypts_to_avb0():
    enc = (FIXTURES / "vbmeta.header.enc").read_bytes()
    img = decrypt_header(enc)
    assert img[:4] == b"AVB0", img[:8].hex()


@pytest.mark.skipif(not (FIXTURES / "scatter.header.enc").exists(),
                    reason="real header fixtures not present")
def test_real_scatter_header_decrypts_to_xml():
    enc = (FIXTURES / "scatter.header.enc").read_bytes()
    img = decrypt_header(enc)
    assert img[:5] == b"<?xml", img[:16]

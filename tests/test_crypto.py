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


def _pkcs7(b: bytes) -> bytes:
    n = BLOCK - len(b) % BLOCK
    return b + bytes([n]) * n


@pytest.mark.parametrize("size", [1, 15, 16, 4096, 85023, 117540, 4 << 20])
def test_roundtrip_is_byte_exact(size):
    """The server PKCS#7-pads, then AES-ECB encrypts. Decrypting must give back
    exactly the image: not one byte more (#16) and not one byte less. Sizes
    include the real n=1 / n=12 / n=16 cases seen live, and a 4 MiB footer."""
    image = bytes((i * 7 + 3) & 0xFF for i in range(size))
    enc = AES.new(KEY, AES.MODE_ECB).encrypt(_pkcs7(image))
    assert decrypt_header(enc) == image


def test_trailing_zero_blocks_are_image_data_not_padding():
    """The old trim removed copies of the most common block. An image that ends
    in zeros (most small partitions do) must keep every one of them."""
    image = b"AVB0" + b"\x00" * (8192 - 4)
    enc = AES.new(KEY, AES.MODE_ECB).encrypt(_pkcs7(image))
    assert decrypt_header(enc) == image


@pytest.mark.parametrize("bad", [
    b"\x00" * 16,                      # pad byte 0
    b"\x00" * 15 + b"\x11",            # pad byte > 16
    b"\x00" * 13 + b"\x01\x02\x03",    # last byte 3, but bytes not all 3
])
def test_invalid_padding_is_refused_not_guessed(bad):
    """A wrong key, an HTML error page, or a corrupt blob must not be cut at
    some guessed length and written out as an image."""
    enc = AES.new(KEY, AES.MODE_ECB).encrypt(bad)
    with pytest.raises(ValueError):
        decrypt_header(enc)


def test_partial_block_is_refused():
    with pytest.raises(ValueError):
        decrypt_header(b"\x00" * 17)


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
    assert len(img) == 4096          # 4112-byte blob = 4096 image + 16 pad


@pytest.mark.skipif(not (FIXTURES / "scatter.header.enc").exists(),
                    reason="real header fixtures not present")
def test_real_scatter_header_decrypts_to_xml():
    enc = (FIXTURES / "scatter.header.enc").read_bytes()
    img = decrypt_header(enc)
    assert img[:5] == b"<?xml", img[:16]

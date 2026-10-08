"""
crypto.py — TCL FOTA .mbn "encrypted header" decryptor.

THE SCHEME  (cracked offline by Littlenine Ennea, https://github.com/LittlenineEnnea)
------------------------------------------------------------------------------------
Small partitions (lk / preloader / atf / gz / tinysys / vbmeta / spmfw / scatter ...)
ship with an EMPTY download body — the real image is delivered inside a ~4 MiB blob
fetched from encrypt_header.php. That blob is AES-128-ECB encrypted with a single
UNIVERSAL key shared by every TCL MediaTek model:

    KEY = ASCII( md5("TeleExtTest" + "t0523" + "jP7GHdmuBz").hexdigest()[:16] )
        = b"e26baba108b08a28"

  * "TeleExtTest" / "t0523"  — the encrypt_header.php service account / password.
  * "jP7GHdmuBz"             — seed recovered from sugar_otu_r.dll.

Verified: the plaintext is standard PKCS#7-padded, and the image itself decrypts to
real magics — vbmeta -> "AVB0", MTK GFH -> 88 16 88 58,
sparse ext4 -> 3a ff 26 ed, ELF -> 7f 45 4c 46, scatter -> "<?xml".
"""

from __future__ import annotations

import hashlib

from Crypto.Cipher import AES

# The encrypt_header.php service credentials, doubling as key material.
ENC_ACCOUNT = "TeleExtTest"
ENC_PASSWORD = "t0523"
# Seed recovered from sugar_otu_r.dll (Littlenine Ennea).
_DLL_SEED = "jP7GHdmuBz"

#: The universal AES-128 key for every TCL MediaTek header. b"e26baba108b08a28".
KEY = hashlib.md5(
    (ENC_ACCOUNT + ENC_PASSWORD + _DLL_SEED).encode()
).hexdigest()[:16].encode()

BLOCK = 16


def decrypt_header(enc: bytes) -> bytes:
    """Decrypt a raw encrypted-header blob into its exact image bytes.

    The blob is AES-128-ECB over standard PKCS#7-padded plaintext: the last
    plaintext byte N (1..16) says how many trailing bytes are padding, and all N
    of them equal N. That is verified against TCL's own checksum.php, whose
    FOOTER value is the SHA-1 of exactly these unpadded bytes (#16).

    For a small partition the result is the whole image; for a large one it is
    the 4 MiB footer that completes the streamed body (#15).

    Raises ValueError if the blob is not whole AES blocks or the padding is not
    valid PKCS#7 — that means a wrong key or a corrupt/error response, and
    guessing where the image ends is how wrong bytes reach a flash tool.
    """
    if enc is None or len(enc) < BLOCK:
        raise ValueError(f"header blob too short: {0 if enc is None else len(enc)} bytes")
    if len(enc) % BLOCK:
        raise ValueError(f"header blob is not whole AES blocks: {len(enc)} bytes")

    dec = AES.new(KEY, AES.MODE_ECB).decrypt(enc)
    n = dec[-1]
    if not 1 <= n <= BLOCK or dec[-n:] != bytes([n]) * n:
        raise ValueError("header blob has invalid PKCS#7 padding "
                         "(wrong key, or not a header blob)")
    return dec[:-n]


def key_hex() -> str:
    """Return the universal key as a lowercase hex string (for --version / docs)."""
    return KEY.hex()

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

Verified: the header's trailing padding decrypts to a constant filler block, and the
image itself decrypts to real magics — vbmeta -> "AVB0", MTK GFH -> 88 16 88 58,
sparse ext4 -> 3a ff 26 ed, ELF -> 7f 45 4c 46, scatter -> "<?xml".
"""

from __future__ import annotations

import hashlib
from collections import Counter

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
    """Decrypt a raw encrypted-header blob into its clean image bytes.

    The blob is AES-128-ECB over the whole (16-aligned) length. It is padded to
    ~4 MiB with a constant filler block, so rather than assume a pad byte we:
      1. ECB-decrypt everything,
      2. find the dominant *ciphertext* block (the repeated filler),
      3. decrypt that one block to learn the pad, and
      4. trim every trailing copy of it.

    Returns the exact image with padding removed. Raises ValueError if the blob
    is too short to contain a single AES block.
    """
    if enc is None or len(enc) < BLOCK:
        raise ValueError(f"header blob too short: {0 if enc is None else len(enc)} bytes")

    n = len(enc) - (len(enc) % BLOCK)
    cipher = AES.new(KEY, AES.MODE_ECB)
    dec = cipher.decrypt(enc[:n])

    # Dominant ciphertext block == the repeated padding filler. Decrypt it once.
    dom_ct = Counter(
        enc[i:i + BLOCK] for i in range(0, n, BLOCK)
    ).most_common(1)[0][0]
    pad = AES.new(KEY, AES.MODE_ECB).decrypt(dom_ct)

    end = len(dec)
    while end >= BLOCK and dec[end - BLOCK:end] == pad:
        end -= BLOCK
    return dec[:end]


def key_hex() -> str:
    """Return the universal key as a lowercase hex string (for --version / docs)."""
    return KEY.hex()

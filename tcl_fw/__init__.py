"""
tcl-fw — pull and decrypt official TCL (MediaTek) FOTA firmware.

A firmware puller + .mbn header decryptor for TCL-made Android devices
(TCL, REVVL, Alcatel). Talks to TCL's own FOTA download servers (no Google,
no account), streams the plaintext bodies, and AES-decrypts the small
partitions that ship inside an encrypted 4 MiB header — producing a clean,
flashable service package fully offline.

The header-decryption scheme (AES-128-ECB, universal key) was cracked by
Littlenine Ennea <https://github.com/LittlenineEnnea>; mode 4 exists because
of that work. See crypto.py.
"""

__version__ = "3.1.0"
__all__ = ["__version__"]

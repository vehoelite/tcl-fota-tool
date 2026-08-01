"""
tcl-fw GUI — a PySide6 desktop front-end over the tcl_fw package.

This is a thin *view*: it never re-implements pull/decrypt logic, it only calls
into tcl_fw (fota / devices / puller / adb). All blocking work runs on QThread
workers (see workers.py) so the window stays responsive.

Header decryption (mode 4) is Littlenine Ennea's work
<https://github.com/LittlenineEnnea>; see tcl_fw/crypto.py.
"""

__all__ = ["main"]


def main() -> int:
    """Console-script / `python -m tcl_fw_gui` entry point."""
    from .app import run
    return run()

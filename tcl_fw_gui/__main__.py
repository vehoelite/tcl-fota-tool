"""Enable `python -m tcl_fw_gui` and serve as the PyInstaller entry point.

Absolute import (not `from .app`) so this works both under `-m` (package
context present) and when PyInstaller runs it as top-level `__main__` (no
parent package — a relative import would raise ImportError there).
"""
from tcl_fw_gui.app import run

if __name__ == "__main__":
    raise SystemExit(run())

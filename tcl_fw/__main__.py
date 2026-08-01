"""Enable `python -m tcl_fw` and serve as the PyInstaller entry point.

Absolute import (not `from .cli`) so this works both under `-m` and when
PyInstaller runs it as top-level `__main__` (no parent package).
"""
from tcl_fw.cli import app

if __name__ == "__main__":
    app()

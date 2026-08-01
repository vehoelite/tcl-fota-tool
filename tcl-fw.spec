# PyInstaller spec — build a standalone `tcl-fw` binary.
#
#   pip install -e ".[dev]"
#   pyinstaller tcl-fw.spec           # -> dist/tcl-fw  (or dist/tcl-fw.exe on Windows)
#
# One self-contained executable; end users need no Python.

block_cipher = None

a = Analysis(
    ["tcl_fw/__main__.py"],
    pathex=["."],
    binaries=[],
    datas=[("tcl_fw/data/devices.json", "tcl_fw/data")],
    hiddenimports=["tcl_fw.cli"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="tcl-fw",
    debug=False,
    strip=False,
    upx=True,
    console=True,
)

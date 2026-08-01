# PyInstaller spec — build the standalone `tcl-fw-gui` desktop app.
#
#   pip install -e ".[dev]"           # dev extra pulls in PySide6 + pyinstaller
#   pyinstaller tcl-fw-gui.spec        # -> dist/tcl-fw-gui(.exe on Windows)
#
# Windowed (no console). PyInstaller's bundled PySide6 hook collects the needed
# Qt plugins automatically. On Windows this produces tcl-fw-gui.exe — the target
# for on-device testing without usbipd (adb runs natively there).

block_cipher = None

a = Analysis(
    ["tcl_fw_gui/__main__.py"],
    pathex=["."],
    binaries=[],
    datas=[("tcl_fw/data/devices.json", "tcl_fw/data")],
    hiddenimports=["tcl_fw_gui.main_window", "tcl_fw_gui.workers", "tcl_fw_gui.app"],
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
    name="tcl-fw-gui",
    debug=False,
    strip=False,
    upx=True,
    console=False,
)

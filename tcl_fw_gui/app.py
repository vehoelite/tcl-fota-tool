"""
app.py — QApplication bootstrap for the tcl-fw GUI.

Kept separate from main_window so tests / packaging can import the window class
without spinning up an event loop.
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .main_window import MainWindow

# A restrained dark theme; Qt falls back gracefully if colours are unsupported.
_QSS = """
QWidget { font-size: 13px; }
QLabel#credit { color: #7fb0ff; font-size: 12px; }
QLabel#info { color: #cfd6e4; }
QLabel#status { color: #9aa4b2; }
QPushButton { padding: 5px 12px; border-radius: 6px; }
QPushButton#primary { background: #2f6df6; color: white; font-weight: 600; }
QPushButton#primary:disabled { background: #3a4152; color: #8a93a3; }
QPlainTextEdit#log {
    background: #12151c; color: #b8c0cf; border: 1px solid #262b36;
    border-radius: 6px; font-family: monospace; font-size: 12px;
}
QTableWidget { gridline-color: #262b36; }
QProgressBar { border: 1px solid #333a47; border-radius: 4px; text-align: center; height: 16px; }
QProgressBar::chunk { background: #2f6df6; border-radius: 3px; }
"""


def run() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("tcl-fw")
    app.setStyleSheet(_QSS)
    win = MainWindow()
    win.show()
    return app.exec()

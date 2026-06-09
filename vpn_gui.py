"""
vpn_gui.py — Entry point for the GOST VPN client GUI application.

Usage:
    python vpn_gui.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

from gui.main_window import MainWindow
from gui.styles import STYLESHEET


def main() -> None:
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("VPN-клиент СКЗИ")
    app.setApplicationVersion("1.0")
    app.setStyleSheet(STYLESHEET)

    win = MainWindow()
    win.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

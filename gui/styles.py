"""
QSS Dark Stylesheet — GitHub Dark theme.

Colours:
  bg       #0d1117   window background
  surface  #161b22   card / panel background
  border   #30363d   borders and dividers
  text     #c9d1d9   primary text
  muted    #8b949e   secondary / muted text
  green    #3fb950   connected / success
  yellow   #e3b341   warning / connecting
  red      #f85149   error / disconnect button
  blue     #388bfd   accent / interactive
"""

STYLESHEET = """
/* ─── Global ──────────────────────────────────────────────── */
QMainWindow, QDialog {
    background-color: #0d1117;
    color: #c9d1d9;
}

QWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: "Segoe UI", "SF Pro Display", "Ubuntu", sans-serif;
    font-size: 13px;
}

/* ─── Header bar ───────────────────────────────────────────── */
QFrame#header {
    background-color: #161b22;
    border-bottom: 1px solid #30363d;
}

/* ─── Card panels ──────────────────────────────────────────── */
QFrame#card {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
}

/* ─── Dividers ─────────────────────────────────────────────── */
QFrame#divider {
    background-color: #30363d;
    max-height: 1px;
    min-height: 1px;
}

/* ─── Labels ───────────────────────────────────────────────── */
QLabel {
    color: #c9d1d9;
    background-color: transparent;
}

QLabel#title {
    color: #c9d1d9;
    font-size: 15px;
    font-weight: 600;
}

QLabel#subtitle {
    color: #8b949e;
    font-size: 11px;
}

QLabel#card_title {
    color: #8b949e;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
}

QLabel#key_label {
    color: #8b949e;
    font-size: 12px;
}

QLabel#key_value {
    color: #c9d1d9;
    font-size: 12px;
    font-family: "Consolas", "Courier New", monospace;
}

QLabel#mono {
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
    color: #c9d1d9;
}

/* ─── Input fields ─────────────────────────────────────────── */
QLineEdit {
    background-color: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    selection-background-color: #388bfd;
    selection-color: #ffffff;
}

QLineEdit:focus {
    border: 1px solid #388bfd;
    outline: none;
}

QLineEdit:hover {
    border: 1px solid #484f58;
}

QLineEdit:disabled {
    color: #484f58;
    border-color: #21262d;
    background-color: #161b22;
}

/* ─── SpinBox ──────────────────────────────────────────────── */
QSpinBox {
    background-color: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 8px;
    font-size: 13px;
}

QSpinBox:focus {
    border: 1px solid #388bfd;
}

QSpinBox:hover {
    border: 1px solid #484f58;
}

QSpinBox::up-button, QSpinBox::down-button {
    background-color: #21262d;
    border: none;
    width: 18px;
}

QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #30363d;
}

QSpinBox::up-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 5px solid #8b949e;
    width: 0;
    height: 0;
}

QSpinBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #8b949e;
    width: 0;
    height: 0;
}

/* ─── Buttons ──────────────────────────────────────────────── */
QPushButton {
    background-color: #238636;
    color: #ffffff;
    border: 1px solid #2ea043;
    border-radius: 6px;
    padding: 7px 16px;
    font-size: 13px;
    font-weight: 600;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #2ea043;
    border-color: #3fb950;
}

QPushButton:pressed {
    background-color: #1a7f37;
}

QPushButton:disabled {
    background-color: #21262d;
    color: #484f58;
    border-color: #30363d;
}

QPushButton#btn_disconnect {
    background-color: #6e1a1a;
    color: #f85149;
    border: 1px solid #a03030;
}

QPushButton#btn_disconnect:hover {
    background-color: #8a1f1f;
    border-color: #f85149;
}

QPushButton#btn_disconnect:pressed {
    background-color: #5a1515;
}

QPushButton#btn_secondary {
    background-color: transparent;
    color: #8b949e;
    border: 1px solid #30363d;
    font-weight: 500;
    padding: 4px 10px;
    min-width: 60px;
}

QPushButton#btn_secondary:hover {
    background-color: #21262d;
    color: #c9d1d9;
    border-color: #484f58;
}

QPushButton#btn_secondary:pressed {
    background-color: #161b22;
}

/* ─── TextEdit (log area) ──────────────────────────────────── */
QTextEdit {
    background-color: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px;
    font-family: "Consolas", "Courier New", "Lucida Console", monospace;
    font-size: 12px;
    selection-background-color: #388bfd;
    selection-color: #ffffff;
}

QTextEdit:focus {
    border: 1px solid #388bfd;
}

/* ─── Radio buttons ────────────────────────────────────────── */
QRadioButton {
    color: #c9d1d9;
    background-color: transparent;
    spacing: 8px;
}

QRadioButton:hover {
    color: #e6edf3;
}

QRadioButton::indicator {
    width: 14px;
    height: 14px;
    border-radius: 7px;
    border: 2px solid #484f58;
    background-color: #0d1117;
}

QRadioButton::indicator:checked {
    border: 2px solid #388bfd;
    background-color: #388bfd;
}

QRadioButton::indicator:hover {
    border-color: #388bfd;
}

/* ─── Scrollbars ───────────────────────────────────────────── */
QScrollBar:vertical {
    background-color: #0d1117;
    width: 10px;
    border: none;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background-color: #30363d;
    min-height: 24px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background-color: #484f58;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}

QScrollBar:horizontal {
    background-color: #0d1117;
    height: 10px;
    border: none;
    border-radius: 5px;
}

QScrollBar::handle:horizontal {
    background-color: #30363d;
    min-width: 24px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #484f58;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* ─── ToolTip ──────────────────────────────────────────────── */
QToolTip {
    background-color: #161b22;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}

/* ─── MessageBox ───────────────────────────────────────────── */
QMessageBox {
    background-color: #161b22;
    color: #c9d1d9;
}

QMessageBox QLabel {
    color: #c9d1d9;
    font-size: 13px;
}

/* ─── Menu (tray context menu) ─────────────────────────────── */
QMenu {
    background-color: #161b22;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 4px 0;
}

QMenu::item {
    padding: 6px 20px;
}

QMenu::item:selected {
    background-color: #21262d;
    color: #e6edf3;
}

QMenu::separator {
    height: 1px;
    background-color: #30363d;
    margin: 4px 0;
}

/* ─── GroupBox ─────────────────────────────────────────────── */
QGroupBox {
    border: 1px solid #30363d;
    border-radius: 6px;
    margin-top: 8px;
    padding-top: 8px;
    color: #8b949e;
    font-size: 11px;
    font-weight: 700;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 4px;
    color: #8b949e;
}
"""

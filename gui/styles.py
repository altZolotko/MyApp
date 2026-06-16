"""
QSS Dark Stylesheet — "Pulse" theme (near-black + warm gradient accent).

Inspired by modern VPN-app reference: pure black background, a single warm
orange→red accent used as the живой/brand colour (instead of conventional
green for "connected"), large soft-glow circular CTA, rounded card surfaces.

Colours:
  bg           #070707   window background (near-black)
  surface      #141414   card / panel background
  surface_alt  #1c1c1c   inputs, pills, raised surfaces
  border       #272727   borders and dividers
  text         #f2f2f2   primary text
  muted        #8a8a8a   secondary / muted text
  muted_dim    #4d4d4d   disabled / faint text
  accent_1/2   #ff8a3d → #ff3b30   brand gradient (connected / hero glow)
  amber_1/2    #ffc857 → #ff9d2e   connecting / warning
  error_1/2    #ff5b52 → #c81e1e   error (flat danger gradient)
  green        #34d399   outbound traffic accent
"""

COLORS = {
    "BG": "#070707",
    "SURFACE": "#141414",
    "SURFACE_ALT": "#1c1c1c",
    "BORDER": "#272727",
    "TEXT": "#f2f2f2",
    "MUTED": "#8a8a8a",
    "MUTED_DIM": "#4d4d4d",
    "ACCENT_1": "#ff8a3d",
    "ACCENT_2": "#ff3b30",
    "AMBER_1": "#ffc857",
    "AMBER_2": "#ff9d2e",
    "ERROR_1": "#ff5b52",
    "ERROR_2": "#c81e1e",
    "GREEN": "#34d399",
    "IDLE_TOP": "#2a2a2a",
    "IDLE_BOTTOM": "#1a1a1a",
    "IDLE_BORDER": "#333333",
}

STYLESHEET = """
/* ─── Global ──────────────────────────────────────────────── */
QMainWindow, QDialog {
    background-color: #070707;
    color: #f2f2f2;
}

QWidget {
    background-color: #070707;
    color: #f2f2f2;
    font-family: "Inter", "Segoe UI", "SF Pro Display", "Ubuntu", sans-serif;
    font-size: 13px;
}

/* ─── Header bar ───────────────────────────────────────────── */
QFrame#header {
    background-color: #141414;
    border-bottom: 1px solid #272727;
}

/* ─── Card panels ──────────────────────────────────────────── */
QFrame#card {
    background-color: #141414;
    border: 1px solid #272727;
    border-radius: 14px;
}

/* ─── Stat pills ───────────────────────────────────────────── */
QFrame#stat_pill {
    background-color: #1c1c1c;
    border: 1px solid #272727;
    border-radius: 16px;
}

QLabel#stat_badge_out {
    background-color: #34d399;
    color: #07150f;
    border-radius: 14px;
    font-weight: 700;
    font-size: 14px;
}

QLabel#stat_badge_in {
    background-color: #ff3b30;
    color: #ffffff;
    border-radius: 14px;
    font-weight: 700;
    font-size: 14px;
}

QLabel#stat_value {
    color: #f2f2f2;
    font-size: 18px;
    font-weight: 700;
}

/* ─── Dividers ─────────────────────────────────────────────── */
QFrame#divider {
    background-color: #272727;
    max-height: 1px;
    min-height: 1px;
}

/* ─── Labels ───────────────────────────────────────────────── */
QLabel {
    color: #f2f2f2;
    background-color: transparent;
}

QLabel#title {
    color: #f2f2f2;
    font-size: 15px;
    font-weight: 600;
}

QLabel#subtitle {
    color: #8a8a8a;
    font-size: 11px;
}

QLabel#card_title {
    color: #8a8a8a;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
}

QLabel#key_label {
    color: #8a8a8a;
    font-size: 12px;
}

QLabel#key_value {
    color: #f2f2f2;
    font-size: 12px;
    font-family: "Consolas", "Courier New", monospace;
}

QLabel#mono {
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
    color: #f2f2f2;
}

QLabel#hero_status {
    font-size: 19px;
    font-weight: 800;
    letter-spacing: 1px;
}

QLabel#hero_timer {
    font-family: "Consolas", "Courier New", monospace;
    font-size: 38px;
    font-weight: 300;
    color: #f2f2f2;
}

/* ─── Input fields ─────────────────────────────────────────── */
QLineEdit {
    background-color: #1c1c1c;
    color: #f2f2f2;
    border: 1px solid #272727;
    border-radius: 8px;
    padding: 6px 10px;
    font-size: 13px;
    selection-background-color: #ff8a3d;
    selection-color: #070707;
}

QLineEdit:focus {
    border: 1px solid #ff8a3d;
    outline: none;
}

QLineEdit:hover {
    border: 1px solid #3a3a3a;
}

QLineEdit:disabled {
    color: #4d4d4d;
    border-color: #1f1f1f;
    background-color: #141414;
}

/* ─── SpinBox ──────────────────────────────────────────────── */
QSpinBox {
    background-color: #1c1c1c;
    color: #f2f2f2;
    border: 1px solid #272727;
    border-radius: 8px;
    padding: 6px 8px;
    font-size: 13px;
}

QSpinBox:focus {
    border: 1px solid #ff8a3d;
}

QSpinBox:hover {
    border: 1px solid #3a3a3a;
}

QSpinBox::up-button, QSpinBox::down-button {
    background-color: #232323;
    border: none;
    width: 18px;
}

QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #2c2c2c;
}

QSpinBox::up-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 5px solid #8a8a8a;
    width: 0;
    height: 0;
}

QSpinBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #8a8a8a;
    width: 0;
    height: 0;
}

/* ─── Buttons ──────────────────────────────────────────────── */
QPushButton {
    background-color: #1c1c1c;
    color: #f2f2f2;
    border: 1px solid #272727;
    border-radius: 8px;
    padding: 7px 16px;
    font-size: 13px;
    font-weight: 600;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #232323;
    border-color: #ff8a3d;
}

QPushButton:pressed {
    background-color: #161616;
}

QPushButton:disabled {
    background-color: #141414;
    color: #4d4d4d;
    border-color: #1f1f1f;
}

QPushButton#btn_secondary {
    background-color: transparent;
    color: #8a8a8a;
    border: 1px solid #272727;
    font-weight: 500;
    padding: 4px 10px;
    min-width: 60px;
}

QPushButton#btn_secondary:hover {
    background-color: #1c1c1c;
    color: #f2f2f2;
    border-color: #3a3a3a;
}

QPushButton#btn_secondary:pressed {
    background-color: #141414;
}

/* ─── TextEdit (log area) ──────────────────────────────────── */
QTextEdit {
    background-color: #070707;
    color: #f2f2f2;
    border: 1px solid #272727;
    border-radius: 10px;
    padding: 8px;
    font-family: "Consolas", "Courier New", "Lucida Console", monospace;
    font-size: 12px;
    selection-background-color: #ff8a3d;
    selection-color: #070707;
}

QTextEdit:focus {
    border: 1px solid #ff8a3d;
}

/* ─── Radio buttons ────────────────────────────────────────── */
QRadioButton {
    color: #f2f2f2;
    background-color: transparent;
    spacing: 8px;
}

QRadioButton:hover {
    color: #ffffff;
}

QRadioButton::indicator {
    width: 14px;
    height: 14px;
    border-radius: 7px;
    border: 2px solid #3a3a3a;
    background-color: #070707;
}

QRadioButton::indicator:checked {
    border: 2px solid #ff8a3d;
    background-color: #ff8a3d;
}

QRadioButton::indicator:hover {
    border-color: #ff8a3d;
}

/* ─── Scrollbars ───────────────────────────────────────────── */
QScrollBar:vertical {
    background-color: #070707;
    width: 10px;
    border: none;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background-color: #272727;
    min-height: 24px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background-color: #3a3a3a;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}

QScrollBar:horizontal {
    background-color: #070707;
    height: 10px;
    border: none;
    border-radius: 5px;
}

QScrollBar::handle:horizontal {
    background-color: #272727;
    min-width: 24px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #3a3a3a;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* ─── ToolTip ──────────────────────────────────────────────── */
QToolTip {
    background-color: #1c1c1c;
    color: #f2f2f2;
    border: 1px solid #272727;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}

/* ─── MessageBox ───────────────────────────────────────────── */
QMessageBox {
    background-color: #141414;
    color: #f2f2f2;
}

QMessageBox QLabel {
    color: #f2f2f2;
    font-size: 13px;
}

/* ─── Menu (tray context menu) ─────────────────────────────── */
QMenu {
    background-color: #141414;
    color: #f2f2f2;
    border: 1px solid #272727;
    border-radius: 6px;
    padding: 4px 0;
}

QMenu::item {
    padding: 6px 20px;
}

QMenu::item:selected {
    background-color: #1c1c1c;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background-color: #272727;
    margin: 4px 0;
}

/* ─── GroupBox ─────────────────────────────────────────────── */
QGroupBox {
    border: 1px solid #272727;
    border-radius: 6px;
    margin-top: 8px;
    padding-top: 8px;
    color: #8a8a8a;
    font-size: 11px;
    font-weight: 700;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 4px;
    color: #8a8a8a;
}
"""

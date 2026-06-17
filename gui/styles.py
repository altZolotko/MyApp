"""
QSS Dark Stylesheet — "WabilVPN" theme (dark green + mint teal accent).

Colours:
  bg           #0C1610   window background (dark green-black)
  surface      #112019   card / panel background
  surface_alt  #172C21   inputs, raised surfaces
  border       #1D3527   borders and dividers
  text         #FFFFFF   primary text
  muted        #A6A6A5   secondary / muted text
  muted_dim    #4A5A52   disabled / faint text
  accent_1/2   #55C69B → #3DAE84   brand gradient (mint teal)
  amber_1/2    #FFC857 → #FF9D2E   connecting / warning
  error_1/2    #FF3232 → #CC0000   error
"""

COLORS = {
    "BG":          "#0C1610",
    "SURFACE":     "#112019",
    "SURFACE_ALT": "#172C21",
    "BORDER":      "#1D3527",
    "TEXT":        "#FFFFFF",
    "MUTED":       "#A6A6A5",
    "MUTED_DIM":   "#4A5A52",
    "ACCENT_1":    "#55C69B",
    "ACCENT_2":    "#3DAE84",
    "AMBER_1":     "#FFC857",
    "AMBER_2":     "#FF9D2E",
    "ERROR_1":     "#FF3232",
    "ERROR_2":     "#CC0000",
    "GREEN":       "#55C69B",
    "IDLE_TOP":    "#172C21",
    "IDLE_BOTTOM": "#0E1D15",
    "IDLE_BORDER": "#2B4536",
}

STYLESHEET = """
/* ─── Global ──────────────────────────────────────────────── */
QMainWindow, QDialog {
    background-color: #0C1610;
    color: #FFFFFF;
}

QWidget {
    background-color: #0C1610;
    color: #FFFFFF;
    font-family: "Inter", "Segoe UI", "SF Pro Display", "Ubuntu", sans-serif;
    font-size: 13px;
}

/* ─── Header bar ───────────────────────────────────────────── */
QFrame#header {
    background-color: #091208;
    border-bottom: 1px solid #1D3527;
}

/* ─── Card panels ──────────────────────────────────────────── */
QFrame#card {
    background-color: #112019;
    border: 1px solid #1D3527;
    border-radius: 16px;
}

/* ─── Security badge ───────────────────────────────────────── */
QFrame#security_badge {
    background-color: #172C21;
    border: 1px solid #2B4536;
    border-radius: 20px;
}

/* ─── IP info card ─────────────────────────────────────────── */
QFrame#ip_card {
    background-color: #112019;
    border: 1px solid #1D3527;
    border-radius: 12px;
}

/* ─── Stat pills ───────────────────────────────────────────── */
QFrame#stat_pill {
    background-color: #112019;
    border: 1px solid #1D3527;
    border-radius: 16px;
}

QLabel#stat_badge_out {
    background-color: #55C69B;
    color: #06120C;
    border-radius: 14px;
    font-weight: 700;
    font-size: 14px;
}

QLabel#stat_badge_in {
    background-color: #172C21;
    color: #55C69B;
    border-radius: 14px;
    font-weight: 700;
    font-size: 14px;
    border: 1px solid #2B4536;
}

QLabel#stat_value {
    color: #FFFFFF;
    font-size: 18px;
    font-weight: 700;
}

/* ─── Dividers ─────────────────────────────────────────────── */
QFrame#divider {
    background-color: #1D3527;
    max-height: 1px;
    min-height: 1px;
}

/* ─── Labels ───────────────────────────────────────────────── */
QLabel {
    color: #FFFFFF;
    background-color: transparent;
}

QLabel#title {
    color: #FFFFFF;
    font-size: 15px;
    font-weight: 600;
}

QLabel#subtitle {
    color: #A6A6A5;
    font-size: 11px;
}

QLabel#card_title {
    color: #55C69B;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.2px;
}

QLabel#key_label {
    color: #A6A6A5;
    font-size: 12px;
}

QLabel#key_value {
    color: #FFFFFF;
    font-size: 12px;
    font-family: "Consolas", "Courier New", monospace;
}

QLabel#mono {
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
    color: #FFFFFF;
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
    color: #FFFFFF;
}

/* ─── Input fields ─────────────────────────────────────────── */
QLineEdit {
    background-color: #172C21;
    color: #FFFFFF;
    border: 1px solid #1D3527;
    border-radius: 8px;
    padding: 6px 10px;
    font-size: 13px;
    selection-background-color: #55C69B;
    selection-color: #06120C;
}

QLineEdit:focus {
    border: 1px solid #55C69B;
    outline: none;
}

QLineEdit:hover {
    border: 1px solid #2B4536;
}

QLineEdit:disabled {
    color: #4A5A52;
    border-color: #1D3527;
    background-color: #112019;
}

/* ─── SpinBox ──────────────────────────────────────────────── */
QSpinBox {
    background-color: #172C21;
    color: #FFFFFF;
    border: 1px solid #1D3527;
    border-radius: 8px;
    padding: 6px 8px;
    font-size: 13px;
}

QSpinBox:focus {
    border: 1px solid #55C69B;
}

QSpinBox:hover {
    border: 1px solid #2B4536;
}

QSpinBox::up-button, QSpinBox::down-button {
    background-color: #1D3527;
    border: none;
    width: 18px;
}

QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #2B4536;
}

QSpinBox::up-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 5px solid #A6A6A5;
    width: 0;
    height: 0;
}

QSpinBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #A6A6A5;
    width: 0;
    height: 0;
}

/* ─── Buttons ──────────────────────────────────────────────── */
QPushButton {
    background-color: #172C21;
    color: #FFFFFF;
    border: 1px solid #1D3527;
    border-radius: 8px;
    padding: 7px 16px;
    font-size: 13px;
    font-weight: 600;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #1D3527;
    border-color: #55C69B;
    color: #55C69B;
}

QPushButton:pressed {
    background-color: #112019;
}

QPushButton:disabled {
    background-color: #112019;
    color: #4A5A52;
    border-color: #1D3527;
}

QPushButton#btn_secondary {
    background-color: transparent;
    color: #A6A6A5;
    border: 1px solid #1D3527;
    font-weight: 500;
    padding: 4px 10px;
    min-width: 60px;
}

QPushButton#btn_secondary:hover {
    background-color: #172C21;
    color: #FFFFFF;
    border-color: #2B4536;
}

QPushButton#btn_secondary:pressed {
    background-color: #112019;
}

/* ─── TextEdit (log area) ──────────────────────────────────── */
QTextEdit {
    background-color: #091208;
    color: #FFFFFF;
    border: 1px solid #1D3527;
    border-radius: 10px;
    padding: 8px;
    font-family: "Consolas", "Courier New", "Lucida Console", monospace;
    font-size: 12px;
    selection-background-color: #55C69B;
    selection-color: #06120C;
}

QTextEdit:focus {
    border: 1px solid #55C69B;
}

/* ─── Radio buttons ────────────────────────────────────────── */
QRadioButton {
    color: #FFFFFF;
    background-color: transparent;
    spacing: 8px;
}

QRadioButton:hover {
    color: #55C69B;
}

QRadioButton::indicator {
    width: 14px;
    height: 14px;
    border-radius: 7px;
    border: 2px solid #2B4536;
    background-color: #0C1610;
}

QRadioButton::indicator:checked {
    border: 2px solid #55C69B;
    background-color: #55C69B;
}

QRadioButton::indicator:hover {
    border-color: #55C69B;
}

/* ─── Scrollbars ───────────────────────────────────────────── */
QScrollBar:vertical {
    background-color: #0C1610;
    width: 8px;
    border: none;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background-color: #1D3527;
    min-height: 24px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #2B4536;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}

QScrollBar:horizontal {
    background-color: #0C1610;
    height: 8px;
    border: none;
    border-radius: 4px;
}

QScrollBar::handle:horizontal {
    background-color: #1D3527;
    min-width: 24px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #2B4536;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* ─── ToolTip ──────────────────────────────────────────────── */
QToolTip {
    background-color: #172C21;
    color: #FFFFFF;
    border: 1px solid #1D3527;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}

/* ─── MessageBox ───────────────────────────────────────────── */
QMessageBox {
    background-color: #112019;
    color: #FFFFFF;
}

QMessageBox QLabel {
    color: #FFFFFF;
    font-size: 13px;
}

/* ─── Menu (tray) ──────────────────────────────────────────── */
QMenu {
    background-color: #112019;
    color: #FFFFFF;
    border: 1px solid #1D3527;
    border-radius: 6px;
    padding: 4px 0;
}

QMenu::item {
    padding: 6px 20px;
}

QMenu::item:selected {
    background-color: #172C21;
    color: #55C69B;
}

QMenu::separator {
    height: 1px;
    background-color: #1D3527;
    margin: 4px 0;
}

/* ─── GroupBox ─────────────────────────────────────────────── */
QGroupBox {
    border: 1px solid #1D3527;
    border-radius: 6px;
    margin-top: 8px;
    padding-top: 8px;
    color: #A6A6A5;
    font-size: 11px;
    font-weight: 700;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 4px;
    color: #A6A6A5;
}
"""

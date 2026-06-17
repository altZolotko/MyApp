"""
MainWindow — PyQt5 GUI for the GOST-cryptography VPN client.
Visual style: WabilVPN-inspired dark green + mint teal theme.

Includes:
  - StatusDot: animated pulsing indicator
  - MainWindow: full application window
"""

import os
from datetime import datetime

from PyQt5.QtCore import (
    QPointF,
    QSize,
    Qt,
    QTimer,
    pyqtSlot,
)
from PyQt5.QtGui import (
    QColor,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSystemTrayIcon,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gui.power_button import PowerButton
from gui.styles import COLORS
from gui.tunnel_worker import TunnelWorker
from gui.vpn_worker import VpnWorker
from vpn_core.tunnel import is_admin
from utils.app_paths import get_default_certs_dir, get_default_config_path


# ---------------------------------------------------------------------------
# StatusDot widget
# ---------------------------------------------------------------------------

class StatusDot(QWidget):
    _COLORS = {
        "idle":       QColor(COLORS["MUTED_DIM"]),
        "connecting": QColor(COLORS["AMBER_2"]),
        "connected":  QColor(COLORS["ACCENT_1"]),
        "error":      QColor(COLORS["ERROR_1"]),
    }

    def __init__(self, diameter: int = 14, parent: QWidget = None):
        super().__init__(parent)
        self._diameter = diameter
        self._state = "idle"
        self._opacity = 1.0
        self._pulse_direction = -1
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_tick)
        self.setFixedSize(diameter, diameter)

    def setState(self, state: str) -> None:
        self._state = state
        self._opacity = 1.0
        self._timer.stop()
        if state == "connected":
            self._timer.start(40)
        elif state == "connecting":
            self._timer.start(20)
        else:
            self.update()

    def _on_tick(self) -> None:
        step = 0.04 if self._state == "connected" else 0.06
        self._opacity += self._pulse_direction * step
        if self._opacity <= 0.3:
            self._opacity = 0.3
            self._pulse_direction = 1
        elif self._opacity >= 1.0:
            self._opacity = 1.0
            self._pulse_direction = -1
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        color = QColor(self._COLORS.get(self._state, self._COLORS["idle"]))
        color.setAlphaF(self._opacity)
        painter.setBrush(color)
        painter.setPen(Qt.NoPen)
        d = self._diameter
        painter.drawEllipse(1, 1, d - 2, d - 2)
        painter.end()

    def sizeHint(self) -> QSize:
        return QSize(self._diameter, self._diameter)


# ---------------------------------------------------------------------------
# Shield icon painter (used for window + tray icons)
# ---------------------------------------------------------------------------

def _make_shield_icon(size: int) -> QPixmap:
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)

    s = size
    m = s * 0.10   # margin

    # Shield path: rounded top, tapered sides, pointed bottom
    path = QPainterPath()
    path.moveTo(s / 2, s - m)          # bottom point
    path.lineTo(m, s * 0.52)           # left mid
    path.lineTo(m, m + s * 0.12)       # left top
    path.quadTo(m, m, m + s * 0.12, m)  # top-left curve
    path.lineTo(s - m - s * 0.12, m)
    path.quadTo(s - m, m, s - m, m + s * 0.12)  # top-right curve
    path.lineTo(s - m, s * 0.52)       # right mid
    path.closeSubpath()

    # Dark-to-teal gradient (top-left bright, bottom-right dark)
    grad = QLinearGradient(QPointF(m, m), QPointF(s - m, s - m))
    grad.setColorAt(0.0, QColor("#55C69B"))
    grad.setColorAt(0.55, QColor("#2E8A62"))
    grad.setColorAt(1.0, QColor("#1A5240"))
    p.setBrush(grad)
    p.setPen(Qt.NoPen)
    p.drawPath(path)

    # Highlight glint on the right edge
    glint = QPainterPath()
    glint.moveTo(s - m, m + s * 0.12)
    glint.lineTo(s - m, s * 0.42)
    glint.lineTo(s * 0.68, s * 0.72)
    glint.lineTo(s * 0.68, s * 0.28)
    glint.closeSubpath()
    highlight = QColor("#FFFFFF")
    highlight.setAlphaF(0.12)
    p.setBrush(highlight)
    p.drawPath(glint)

    p.end()
    return pix


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("card_title")
    return lbl


def _divider() -> QFrame:
    f = QFrame()
    f.setObjectName("divider")
    f.setFrameShape(QFrame.HLine)
    return f


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    else:
        return f"{n / (1024 * 1024 * 1024):.2f} GB"


# ---------------------------------------------------------------------------
# MainWindow
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):

    def __init__(self, parent: QWidget = None, config_path: str = None):
        super().__init__(parent)
        self._config_path = config_path or get_default_config_path()
        self._worker: VpnWorker = None
        self._elapsed: int = 0
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._on_elapsed_tick)
        self._tray_warned = False

        self._setup_window()
        self._build_ui()
        self._setup_tray()

    # ------------------------------------------------------------------ setup

    def _setup_window(self) -> None:
        self.setWindowTitle("VPN-клиент СКЗИ")
        self.setMinimumSize(980, 860)
        self.resize(1100, 940)
        self.setWindowIcon(QIcon(_make_shield_icon(32)))

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_header())

        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(16, 16, 16, 0)
        body_layout.setSpacing(16)
        root_layout.addWidget(body_widget, stretch=1)

        body_layout.addWidget(self._build_left_panel())
        body_layout.addLayout(self._build_right_panel(), stretch=1)

        root_layout.addWidget(self._build_log_panel())

    # ------------------------------------------------------------------ header

    def _build_header(self) -> QFrame:
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(58)
        layout = QHBoxLayout(header)
        layout.setContentsMargins(18, 0, 18, 0)
        layout.setSpacing(10)

        # Shield logo
        logo_lbl = QLabel()
        logo_pix = _make_shield_icon(28)
        logo_lbl.setPixmap(logo_pix)
        logo_lbl.setFixedSize(28, 28)
        logo_lbl.setStyleSheet("background: transparent;")

        title_lbl = QLabel("VPN-клиент СКЗИ")
        title_lbl.setObjectName("title")

        sub_lbl = QLabel("ГОСТ · v1.0")
        sub_lbl.setObjectName("subtitle")
        sub_lbl.setStyleSheet(f"color: {COLORS['MUTED']}; font-size: 11px; background: transparent;")

        layout.addWidget(logo_lbl)
        layout.addWidget(title_lbl)
        layout.addSpacing(4)
        layout.addWidget(sub_lbl)
        layout.addStretch()

        self._header_dot = StatusDot(10, header)
        self._header_status_lbl = QLabel("Не подключено")
        self._header_status_lbl.setObjectName("subtitle")

        layout.addWidget(self._header_dot)
        layout.addWidget(self._header_status_lbl)

        return header

    # ------------------------------------------------------------------ left panel

    def _build_left_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("card")
        panel.setFixedWidth(256)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        # ── Server ──
        layout.addWidget(_section_label("СЕРВЕР"))
        self._host_edit = QLineEdit("127.0.0.1")
        self._host_edit.setPlaceholderText("IP или hostname")
        layout.addWidget(self._host_edit)

        port_row = QHBoxLayout()
        port_row.setSpacing(6)
        port_lbl = QLabel("Порт:")
        port_lbl.setObjectName("key_label")
        port_row.addWidget(port_lbl)
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(8443)
        self._port_spin.setMinimumWidth(80)
        port_row.addWidget(self._port_spin)
        port_row.addStretch()
        layout.addLayout(port_row)

        layout.addWidget(_divider())

        # ── Certificates ──
        layout.addWidget(_section_label("СЕРТИФИКАТЫ"))

        certs_row = QHBoxLayout()
        certs_row.setSpacing(4)
        self._certs_edit = QLineEdit(str(get_default_certs_dir()))
        self._certs_edit.setPlaceholderText("Путь к сертификатам")
        certs_row.addWidget(self._certs_edit, stretch=1)
        browse_btn = QPushButton("…")
        browse_btn.setObjectName("btn_secondary")
        browse_btn.setFixedWidth(32)
        browse_btn.setToolTip("Выбрать директорию")
        browse_btn.clicked.connect(self._browse_certs)
        certs_row.addWidget(browse_btn)
        layout.addLayout(certs_row)

        gen_btn = QPushButton("Создать тестовые сертификаты")
        gen_btn.setObjectName("btn_secondary")
        gen_btn.clicked.connect(self._generate_certs)
        layout.addWidget(gen_btn)

        layout.addWidget(_divider())

        # ── Mode ──
        layout.addWidget(_section_label("РЕЖИМ"))
        self._radio_demo = QRadioButton("Демо (без TUN)")
        self._radio_demo.setChecked(True)
        self._radio_full = QRadioButton("Полный туннель (Admin)")
        layout.addWidget(self._radio_demo)
        layout.addWidget(self._radio_full)

        if is_admin():
            _ft_text = "✓ Права подтверждены. Туннель доступен."
            _ft_style = f"color: {COLORS['ACCENT_1']}; font-size: 11px; background: transparent;"
        else:
            _ft_text = "Требуются права Администратора."
            _ft_style = f"color: {COLORS['AMBER_1']}; font-size: 11px; background: transparent;"
        self._full_tunnel_info = QLabel(_ft_text)
        self._full_tunnel_info.setObjectName("key_label")
        self._full_tunnel_info.setWordWrap(True)
        self._full_tunnel_info.setStyleSheet(_ft_style)
        self._full_tunnel_info.setVisible(False)
        layout.addWidget(self._full_tunnel_info)

        self._radio_full.toggled.connect(
            lambda checked: self._full_tunnel_info.setVisible(checked)
        )

        layout.addStretch()

        return panel

    # ------------------------------------------------------------------ right panel

    def _build_stat_pill(self, badge_name: str, glyph: str, title_text: str):
        pill = QFrame()
        pill.setObjectName("stat_pill")
        row = QHBoxLayout(pill)
        row.setContentsMargins(14, 10, 14, 10)
        row.setSpacing(12)

        badge = QLabel(glyph)
        badge.setObjectName(badge_name)
        badge.setFixedSize(28, 28)
        badge.setAlignment(Qt.AlignCenter)
        row.addWidget(badge)

        col = QVBoxLayout()
        col.setSpacing(2)
        title = QLabel(title_text)
        title.setObjectName("key_label")
        value = QLabel("0 B")
        value.setObjectName("stat_value")
        packets = QLabel("0 пакетов")
        packets.setObjectName("key_label")
        col.addWidget(title)
        col.addWidget(value)
        col.addWidget(packets)
        row.addLayout(col)
        row.addStretch()

        return pill, value, packets

    def _build_right_panel(self) -> QVBoxLayout:
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)

        # ── Security status badge ────────────────────────────────────
        badge_row = QHBoxLayout()
        self._security_badge = QFrame()
        self._security_badge.setObjectName("security_badge")
        badge_inner = QHBoxLayout(self._security_badge)
        badge_inner.setContentsMargins(16, 8, 16, 8)
        badge_inner.setSpacing(8)

        lock_lbl = QLabel("🔒")
        lock_lbl.setStyleSheet("font-size: 13px; background: transparent;")
        badge_key = QLabel("Статус защиты:")
        badge_key.setObjectName("key_label")
        self._badge_val = QLabel("НЕ ПОДКЛЮЧЕНО")
        self._badge_val.setStyleSheet(
            f"color: {COLORS['MUTED']}; font-weight: 700; font-size: 12px;"
        )
        badge_inner.addWidget(lock_lbl)
        badge_inner.addWidget(badge_key)
        badge_inner.addWidget(self._badge_val)

        badge_row.addStretch()
        badge_row.addWidget(self._security_badge)
        badge_row.addStretch()
        layout.addLayout(badge_row)

        # ── Power button ─────────────────────────────────────────────
        btn_row = QHBoxLayout()
        self._power_btn = PowerButton()
        self._power_btn.clicked.connect(self._on_connect_clicked)
        btn_row.addStretch()
        btn_row.addWidget(self._power_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # ── Status + timer ───────────────────────────────────────────
        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self._status_dot = StatusDot(10)
        self._hero_status = QLabel("НЕ ПОДКЛЮЧЕНО")
        self._hero_status.setObjectName("hero_status")
        self._hero_status.setStyleSheet(f"color: {COLORS['TEXT']};")
        status_row.addStretch()
        status_row.addWidget(self._status_dot)
        status_row.addWidget(self._hero_status)
        status_row.addStretch()
        layout.addLayout(status_row)

        self._hero_timer = QLabel("00:00:00")
        self._hero_timer.setObjectName("hero_timer")
        self._hero_timer.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._hero_timer)

        # ── IP info card ─────────────────────────────────────────────
        ip_card = QFrame()
        ip_card.setObjectName("ip_card")
        ip_layout = QHBoxLayout(ip_card)
        ip_layout.setContentsMargins(24, 12, 24, 12)
        ip_layout.setSpacing(0)

        own_col = QVBoxLayout()
        own_col.setSpacing(3)
        own_key = QLabel("Ваш IP")
        own_key.setObjectName("key_label")
        self._own_ip_val = QLabel("—")
        self._own_ip_val.setObjectName("key_value")
        own_col.addWidget(own_key)
        own_col.addWidget(self._own_ip_val)

        ip_sep = QFrame()
        ip_sep.setObjectName("divider")
        ip_sep.setFrameShape(QFrame.VLine)
        ip_sep.setFixedWidth(1)

        vpn_col = QVBoxLayout()
        vpn_col.setSpacing(3)
        vpn_key = QLabel("VPN IP")
        vpn_key.setObjectName("key_label")
        self._vpn_ip_val = QLabel("—")
        self._vpn_ip_val.setObjectName("key_value")
        vpn_col.addWidget(vpn_key)
        vpn_col.addWidget(self._vpn_ip_val)

        ip_layout.addStretch()
        ip_layout.addLayout(own_col)
        ip_layout.addSpacing(36)
        ip_layout.addWidget(ip_sep)
        ip_layout.addSpacing(36)
        ip_layout.addLayout(vpn_col)
        ip_layout.addStretch()

        # Session row inside ip_card
        session_col = QVBoxLayout()
        session_col.setSpacing(3)
        session_key = QLabel("Сессия")
        session_key.setObjectName("key_label")
        self._session_val = QLabel("—")
        self._session_val.setObjectName("key_value")
        session_col.addWidget(session_key)
        session_col.addWidget(self._session_val)

        ip_layout.addSpacing(20)
        ip_layout.addWidget(ip_sep)
        ip_layout.addSpacing(20)
        ip_layout.addLayout(session_col)
        ip_layout.addStretch()

        layout.addWidget(ip_card)

        # ── Traffic stat pills ───────────────────────────────────────
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        out_pill, self._bytes_out_val, self._packets_out_val = self._build_stat_pill(
            "stat_badge_out", "↑", "ОТПРАВЛЕНО"
        )
        in_pill, self._bytes_in_val, self._packets_in_val = self._build_stat_pill(
            "stat_badge_in", "↓", "ПОЛУЧЕНО"
        )
        stats_row.addWidget(out_pill, stretch=1)
        stats_row.addWidget(in_pill, stretch=1)
        layout.addLayout(stats_row)

        # ── Crypto card ──────────────────────────────────────────────
        crypto_card = QFrame()
        crypto_card.setObjectName("card")
        crypto_layout = QVBoxLayout(crypto_card)
        crypto_layout.setContentsMargins(16, 12, 16, 12)
        crypto_layout.setSpacing(6)

        crypto_layout.addWidget(_section_label("КРИПТОГРАФИЧЕСКИЕ ПАРАМЕТРЫ"))

        for attr, lbl_text in [
            ("_alg_val",     "Алгоритм:"),
            ("_enc_key_val", "Ключ шифр.:"),
            ("_mac_key_val", "Ключ имит.:"),
        ]:
            row = QHBoxLayout()
            key = QLabel(lbl_text)
            key.setObjectName("key_label")
            val = QLabel("—")
            val.setObjectName("key_value")
            setattr(self, attr, val)
            row.addWidget(key)
            row.addSpacing(4)
            row.addWidget(val)
            row.addStretch()
            crypto_layout.addLayout(row)

        layout.addWidget(crypto_card)
        layout.addStretch()

        return layout

    # ------------------------------------------------------------------ log panel

    def _build_log_panel(self) -> QWidget:
        container = QWidget()
        inner = QVBoxLayout(container)
        inner.setContentsMargins(16, 8, 16, 12)
        inner.setSpacing(4)

        log_header = QHBoxLayout()
        log_title = _section_label("ЖУРНАЛ СОБЫТИЙ")
        log_header.addWidget(log_title)
        log_header.addStretch()
        clear_btn = QPushButton("Очистить")
        clear_btn.setObjectName("btn_secondary")
        clear_btn.setFixedWidth(80)
        clear_btn.clicked.connect(self._clear_log)
        log_header.addWidget(clear_btn)
        inner.addLayout(log_header)

        self._log_edit = QTextEdit()
        self._log_edit.setObjectName("log")
        self._log_edit.setReadOnly(True)
        self._log_edit.setMinimumHeight(140)
        self._log_edit.setMaximumHeight(180)
        inner.addWidget(self._log_edit)

        return container

    # ------------------------------------------------------------------ tray

    def _setup_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self._tray = None
            return

        self._tray = QSystemTrayIcon(QIcon(_make_shield_icon(16)), self)
        self._tray.setToolTip("VPN-клиент СКЗИ")

        tray_menu = QMenu()
        show_action = QAction("Показать", self)
        show_action.triggered.connect(self._tray_show)
        tray_menu.addAction(show_action)
        tray_menu.addSeparator()
        disconnect_action = QAction("Отключить", self)
        disconnect_action.triggered.connect(self._tray_disconnect)
        tray_menu.addAction(disconnect_action)
        tray_menu.addSeparator()
        quit_action = QAction("Выход", self)
        quit_action.triggered.connect(self._quit_app)
        tray_menu.addAction(quit_action)

        self._tray.setContextMenu(tray_menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _tray_show(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _tray_disconnect(self) -> None:
        if self._worker is not None:
            self._stop_worker()

    def _quit_app(self) -> None:
        if self._worker is not None:
            self._stop_worker()
        if self._tray:
            self._tray.hide()
        QApplication.quit()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.DoubleClick:
            self._tray_show()

    def closeEvent(self, event) -> None:
        if self._tray and self._tray.isVisible():
            if not self._tray_warned:
                self._tray_warned = True
                reply = QMessageBox.question(
                    self,
                    "Свернуть в трей?",
                    "Приложение будет свёрнуто в системный трей.\n"
                    "Для выхода используйте меню трея → «Выход».",
                    QMessageBox.Ok | QMessageBox.Cancel,
                    QMessageBox.Ok,
                )
                if reply == QMessageBox.Cancel:
                    event.ignore()
                    return
            event.ignore()
            self.hide()
        else:
            if self._worker is not None:
                self._stop_worker()
            event.accept()

    # ------------------------------------------------------------------ slots

    @pyqtSlot()
    def _on_connect_clicked(self) -> None:
        if self._worker is not None:
            self._stop_worker()
            return

        host = self._host_edit.text().strip() or "127.0.0.1"
        port = self._port_spin.value()
        certs_dir = self._certs_edit.text().strip() or str(get_default_certs_dir())

        if not os.path.isabs(certs_dir):
            certs_dir = os.path.normpath(
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", certs_dir)
            )

        if self._radio_full.isChecked():
            if not is_admin():
                QMessageBox.warning(
                    self,
                    "Требуются права Администратора",
                    "Полный туннельный режим требует прав Администратора.\n\n"
                    "Запустите приложение от имени Администратора.",
                )
                return

            self._worker = TunnelWorker(host, port, certs_dir, self._config_path)
            self._worker.status_changed.connect(self.on_status_changed)
            self._worker.log_line.connect(self.on_log_line)
            self._worker.stats_updated.connect(self.on_stats_updated)
            self._worker.session_ready.connect(self.on_session_ready)
            self._worker.finished.connect(self._on_worker_finished)
            self._set_controls_enabled(False)
            self._log_message("INFO", f"Запуск полного туннеля к {host}:{port}...")
            self._worker.start()
            return

        self._worker = VpnWorker(host, port, certs_dir)
        self._worker.status_changed.connect(self.on_status_changed)
        self._worker.log_line.connect(self.on_log_line)
        self._worker.stats_updated.connect(self.on_stats_updated)
        self._worker.session_ready.connect(self.on_session_ready)
        self._worker.frame_exchanged.connect(self.on_frame_exchanged)
        self._worker.finished.connect(self._on_worker_finished)
        self._set_controls_enabled(False)
        self._log_message("INFO", f"Запуск подключения к {host}:{port}...")
        self._worker.start()

    @pyqtSlot(str, str)
    def on_status_changed(self, state: str, msg: str) -> None:
        self._status_dot.setState(state)
        self._header_dot.setState(state)
        self._power_btn.setState(state)

        if state == "connected":
            host = self._host_edit.text().strip() or "127.0.0.1"
            self._hero_status.setText("ПОДКЛЮЧЕНО")
            self._hero_status.setStyleSheet(f"color: {COLORS['ACCENT_1']};")
            self._header_status_lbl.setText("Подключено")
            self._header_status_lbl.setStyleSheet(
                f"color: {COLORS['ACCENT_1']}; font-size: 12px;"
            )
            self._badge_val.setText("ЗАЩИЩЕНО")
            self._badge_val.setStyleSheet(
                f"color: {COLORS['ACCENT_1']}; font-weight: 700; font-size: 12px;"
            )
            self._vpn_ip_val.setText(host)
            self._elapsed = 0
            self._elapsed_timer.start()
        elif state == "connecting":
            self._hero_status.setText("ПОДКЛЮЧЕНИЕ...")
            self._hero_status.setStyleSheet(f"color: {COLORS['AMBER_1']};")
            self._header_status_lbl.setText("Подключение...")
            self._header_status_lbl.setStyleSheet(
                f"color: {COLORS['AMBER_1']}; font-size: 12px;"
            )
            self._badge_val.setText("ПОДКЛЮЧЕНИЕ...")
            self._badge_val.setStyleSheet(
                f"color: {COLORS['AMBER_1']}; font-weight: 700; font-size: 12px;"
            )
        elif state == "error":
            self._hero_status.setText("ОШИБКА")
            self._hero_status.setStyleSheet(f"color: {COLORS['ERROR_1']};")
            self._header_status_lbl.setText("Ошибка")
            self._header_status_lbl.setStyleSheet(
                f"color: {COLORS['ERROR_1']}; font-size: 12px;"
            )
            self._badge_val.setText("ОШИБКА СОЕДИНЕНИЯ")
            self._badge_val.setStyleSheet(
                f"color: {COLORS['ERROR_1']}; font-weight: 700; font-size: 12px;"
            )
            self._vpn_ip_val.setText("—")
            self._elapsed_timer.stop()
        else:
            self._hero_status.setText("НЕ ПОДКЛЮЧЕНО")
            self._hero_status.setStyleSheet(f"color: {COLORS['TEXT']};")
            self._header_status_lbl.setText("Не подключено")
            self._header_status_lbl.setStyleSheet(
                f"color: {COLORS['MUTED']}; font-size: 12px;"
            )
            self._badge_val.setText("НЕ ПОДКЛЮЧЕНО")
            self._badge_val.setStyleSheet(
                f"color: {COLORS['MUTED']}; font-weight: 700; font-size: 12px;"
            )
            self._vpn_ip_val.setText("—")
            self._elapsed_timer.stop()

        self._log_message("INFO" if state != "error" else "ERROR", msg)

    @pyqtSlot(str, str)
    def on_log_line(self, level: str, text: str) -> None:
        self._log_message(level, text)

    @pyqtSlot(dict)
    def on_stats_updated(self, d: dict) -> None:
        self._bytes_out_val.setText(_format_bytes(d.get("bytes_out", 0)))
        self._bytes_in_val.setText(_format_bytes(d.get("bytes_in", 0)))
        self._packets_out_val.setText(f"{d.get('packets_out', 0)} пакетов")
        self._packets_in_val.setText(f"{d.get('packets_in', 0)} пакетов")

    @pyqtSlot(dict)
    def on_session_ready(self, d: dict) -> None:
        self._session_val.setText(d.get("session_id", "—"))
        self._alg_val.setText(d.get("algorithm", "—"))
        self._enc_key_val.setText(d.get("enc_key_preview", "—"))
        self._mac_key_val.setText(d.get("mac_key_preview", "—"))

    @pyqtSlot(str, int, str)
    def on_frame_exchanged(self, direction: str, seq: int, text_preview: str) -> None:
        if direction == "OUT":
            self._log_message("DEBUG", f"--> [seq={seq}] Отправлен кадр: {text_preview[:60]}")
        else:
            self._log_message("DEBUG", f"<-- [seq={seq}] Получен эхо: {text_preview[:60]}")

    @pyqtSlot()
    def _on_worker_finished(self) -> None:
        self._worker = None
        self._power_btn.setState("idle")
        self._set_controls_enabled(True)
        self._elapsed_timer.stop()

    # ------------------------------------------------------------------ helpers

    def _stop_worker(self) -> None:
        if self._worker is not None:
            self._log_message("INFO", "Отключение...")
            self._worker.stop()

    def _set_controls_enabled(self, enabled: bool) -> None:
        self._host_edit.setEnabled(enabled)
        self._port_spin.setEnabled(enabled)
        self._certs_edit.setEnabled(enabled)
        self._radio_demo.setEnabled(enabled)
        self._radio_full.setEnabled(enabled)

    @pyqtSlot()
    def _browse_certs(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self,
            "Выберите директорию с сертификатами",
            self._certs_edit.text() or ".",
        )
        if directory:
            self._certs_edit.setText(directory)

    @pyqtSlot()
    def _generate_certs(self) -> None:
        from utils.cert_gen import generate_test_infrastructure
        certs_dir = self._certs_edit.text().strip() or str(get_default_certs_dir())
        self._log_message("INFO", f"Генерация тестовых сертификатов в {certs_dir} ...")
        try:
            generate_test_infrastructure(certs_dir)
            self._log_message("SUCCESS", f"Сертификаты созданы в '{certs_dir}'")
        except Exception as exc:
            self._log_message("ERROR", f"Ошибка генерации сертификатов: {exc}")

    @pyqtSlot()
    def _on_elapsed_tick(self) -> None:
        self._elapsed += 1
        h = self._elapsed // 3600
        m = (self._elapsed % 3600) // 60
        s = self._elapsed % 60
        self._hero_timer.setText(f"{h:02d}:{m:02d}:{s:02d}")

    @pyqtSlot()
    def _clear_log(self) -> None:
        self._log_edit.clear()

    def _log_message(self, level: str, text: str) -> None:
        color_map = {
            "INFO":    "#E8E8E8",
            "WARNING": "#FFC857",
            "ERROR":   "#FF3232",
            "SUCCESS": "#55C69B",
            "DEBUG":   "#A6A6A5",
        }
        level_color_map = {
            "INFO":    "#A6A6A5",
            "WARNING": "#FFC857",
            "ERROR":   "#FF3232",
            "SUCCESS": "#55C69B",
            "DEBUG":   "#4A5A52",
        }
        color = color_map.get(level, "#E8E8E8")
        level_color = level_color_map.get(level, "#A6A6A5")

        now = datetime.now().strftime("%H:%M:%S")
        safe_text = (
            text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
        )
        html = (
            f'<span style="color:#4A5A52;">[{now}]</span> '
            f'<span style="color:{level_color}; font-weight:600;">{level:7s}</span> '
            f'<span style="color:{color};">{safe_text}</span>'
        )
        self._log_edit.append(html)
        sb = self._log_edit.verticalScrollBar()
        sb.setValue(sb.maximum())

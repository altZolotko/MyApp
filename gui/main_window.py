"""
MainWindow — Complete PyQt5 GUI for the GOST-cryptography VPN client.

Includes:
  - StatusDot: animated pulsing indicator widget
  - MainWindow: full application window with header, left config panel,
    right status/stats/crypto cards, bottom log, system tray
"""

import os
import subprocess
import sys
from datetime import datetime

from PyQt5.QtCore import (
    QSize,
    Qt,
    QTimer,
    pyqtSlot,
)
from PyQt5.QtGui import (
    QColor,
    QIcon,
    QPainter,
    QPainterPath,
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


# ---------------------------------------------------------------------------
# StatusDot widget
# ---------------------------------------------------------------------------

class StatusDot(QWidget):
    """
    A small filled-circle indicator that pulses when active.

    States
    ------
    idle        grey         — static
    connecting  amber        — fast pulse
    connected   brand accent — slow pulse
    error       red          — static
    """

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
        self._pulse_direction = -1  # -1 fade out, +1 fade in
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_tick)
        self.setFixedSize(diameter, diameter)

    def setState(self, state: str) -> None:
        self._state = state
        self._opacity = 1.0
        self._timer.stop()
        if state == "connected":
            self._timer.start(40)   # ~25 fps, slow 2-second pulse
        elif state == "connecting":
            self._timer.start(20)   # ~50 fps, faster pulse
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
        margin = 1
        painter.drawEllipse(margin, margin, d - 2 * margin, d - 2 * margin)
        painter.end()

    def sizeHint(self) -> QSize:
        return QSize(self._diameter, self._diameter)


# ---------------------------------------------------------------------------
# Helper: section label
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
    """
    Primary application window for the GOST-VPN client GUI.
    """

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._worker: VpnWorker = None
        self._elapsed: int = 0
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._on_elapsed_tick)
        self._tray_warned = False  # first close: ask user

        self._setup_window()
        self._build_ui()
        self._setup_tray()

    # ------------------------------------------------------------------ setup

    def _setup_window(self) -> None:
        self.setWindowTitle("VPN-клиент СКЗИ")
        self.setMinimumSize(980, 900)
        self.resize(1100, 960)
        # Window icon (generated programmatically)
        icon_pix = QPixmap(32, 32)
        icon_pix.fill(Qt.transparent)
        p = QPainter(icon_pix)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(COLORS["ACCENT_1"]))
        p.setPen(Qt.NoPen)
        p.drawEllipse(4, 4, 24, 24)
        p.setBrush(QColor(COLORS["BG"]))
        p.drawEllipse(10, 10, 12, 12)
        p.end()
        self.setWindowIcon(QIcon(icon_pix))

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Header ──────────────────────────────────────────────────
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(56)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 0, 16, 0)
        header_layout.setSpacing(8)

        shield_lbl = QLabel("🛡")
        shield_lbl.setStyleSheet("font-size: 22px; background: transparent;")
        title_lbl = QLabel("VPN-клиент СКЗИ")
        title_lbl.setObjectName("title")
        sub_lbl = QLabel("ГОСТ · v1.0")
        sub_lbl.setObjectName("subtitle")

        header_layout.addWidget(shield_lbl)
        header_layout.addWidget(title_lbl)
        header_layout.addSpacing(6)
        header_layout.addWidget(sub_lbl)
        header_layout.addStretch()

        self._header_dot = StatusDot(12, header)
        self._header_status_lbl = QLabel("Не подключено")
        self._header_status_lbl.setObjectName("subtitle")

        header_layout.addWidget(self._header_dot)
        header_layout.addWidget(self._header_status_lbl)

        root_layout.addWidget(header)

        # ── Body area ───────────────────────────────────────────────
        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(16, 16, 16, 0)
        body_layout.setSpacing(16)
        root_layout.addWidget(body_widget, stretch=1)

        # Left panel
        body_layout.addWidget(self._build_left_panel())

        # Right panel
        body_layout.addLayout(self._build_right_panel(), stretch=1)

        # ── Log panel ───────────────────────────────────────────────
        log_container = QWidget()
        log_container_layout = QVBoxLayout(log_container)
        log_container_layout.setContentsMargins(16, 8, 16, 12)
        log_container_layout.setSpacing(4)

        log_header = QHBoxLayout()
        log_title = _section_label("ЖУРНАЛ СОБЫТИЙ")
        log_header.addWidget(log_title)
        log_header.addStretch()
        clear_btn = QPushButton("Очистить")
        clear_btn.setObjectName("btn_secondary")
        clear_btn.setFixedWidth(80)
        clear_btn.clicked.connect(self._clear_log)
        log_header.addWidget(clear_btn)
        log_container_layout.addLayout(log_header)

        self._log_edit = QTextEdit()
        self._log_edit.setObjectName("log")
        self._log_edit.setReadOnly(True)
        self._log_edit.setMinimumHeight(150)
        self._log_edit.setMaximumHeight(190)
        log_container_layout.addWidget(self._log_edit)

        root_layout.addWidget(log_container)

    # ── Left panel ──────────────────────────────────────────────────

    def _build_left_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("card")
        panel.setFixedWidth(256)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)
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
        self._certs_edit = QLineEdit("certs")
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
        self._radio_full = QRadioButton("Полный туннель (sudo/Admin)")
        layout.addWidget(self._radio_demo)
        layout.addWidget(self._radio_full)

        if is_admin():
            _ft_text = "✓ Права root подтверждены. Полный туннель доступен."
            _ft_style = f"color: {COLORS['ACCENT_1']}; font-size: 11px; background: transparent;"
        else:
            _ft_text = (
                "Требуются права root/Administrator.\n"
                "Запустите: sudo python vpn_gui.py"
            )
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

    # ── Right panel ─────────────────────────────────────────────────

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

        # ── Hero card: status, big timer, power button, session id ──
        hero_card = QFrame()
        hero_card.setObjectName("card")
        hero_layout = QVBoxLayout(hero_card)
        hero_layout.setContentsMargins(24, 20, 24, 20)
        hero_layout.setSpacing(4)

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
        hero_layout.addLayout(status_row)

        self._hero_timer = QLabel("00:00:00")
        self._hero_timer.setObjectName("hero_timer")
        self._hero_timer.setAlignment(Qt.AlignCenter)
        hero_layout.addWidget(self._hero_timer)

        hero_layout.addSpacing(10)

        btn_row = QHBoxLayout()
        self._power_btn = PowerButton()
        self._power_btn.clicked.connect(self._on_connect_clicked)
        btn_row.addStretch()
        btn_row.addWidget(self._power_btn)
        btn_row.addStretch()
        hero_layout.addLayout(btn_row)

        hero_layout.addSpacing(10)

        session_row = QHBoxLayout()
        session_key = QLabel("Сессия:")
        session_key.setObjectName("key_label")
        self._session_val = QLabel("—")
        self._session_val.setObjectName("key_value")
        session_row.addStretch()
        session_row.addWidget(session_key)
        session_row.addSpacing(4)
        session_row.addWidget(self._session_val)
        session_row.addStretch()
        hero_layout.addLayout(session_row)

        layout.addWidget(hero_card)

        # ── Stat pills: outbound / inbound traffic ──
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

        # Crypto info card
        crypto_card = QFrame()
        crypto_card.setObjectName("card")
        crypto_layout = QVBoxLayout(crypto_card)
        crypto_layout.setContentsMargins(16, 12, 16, 12)
        crypto_layout.setSpacing(6)

        crypto_layout.addWidget(_section_label("КРИПТОГРАФИЧЕСКИЕ ПАРАМЕТРЫ"))

        alg_row = QHBoxLayout()
        alg_key = QLabel("Алгоритм:")
        alg_key.setObjectName("key_label")
        self._alg_val = QLabel("—")
        self._alg_val.setObjectName("key_value")
        alg_row.addWidget(alg_key)
        alg_row.addSpacing(4)
        alg_row.addWidget(self._alg_val)
        alg_row.addStretch()
        crypto_layout.addLayout(alg_row)

        enc_row = QHBoxLayout()
        enc_key_lbl = QLabel("Ключ шифр.:")
        enc_key_lbl.setObjectName("key_label")
        self._enc_key_val = QLabel("—")
        self._enc_key_val.setObjectName("key_value")
        enc_row.addWidget(enc_key_lbl)
        enc_row.addSpacing(4)
        enc_row.addWidget(self._enc_key_val)
        enc_row.addStretch()
        crypto_layout.addLayout(enc_row)

        mac_row = QHBoxLayout()
        mac_key_lbl = QLabel("Ключ имит.:")
        mac_key_lbl.setObjectName("key_label")
        self._mac_key_val = QLabel("—")
        self._mac_key_val.setObjectName("key_value")
        mac_row.addWidget(mac_key_lbl)
        mac_row.addSpacing(4)
        mac_row.addWidget(self._mac_key_val)
        mac_row.addStretch()
        crypto_layout.addLayout(mac_row)

        layout.addWidget(crypto_card)
        layout.addStretch()

        return layout

    # ------------------------------------------------------------------ tray

    def _setup_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self._tray = None
            return

        # Generate tray icon
        pix = QPixmap(16, 16)
        pix.fill(Qt.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(COLORS["ACCENT_1"]))
        p.setPen(Qt.NoPen)
        p.drawEllipse(1, 1, 14, 14)
        p.setBrush(QColor(COLORS["BG"]))
        p.drawEllipse(5, 5, 6, 6)
        p.end()

        self._tray = QSystemTrayIcon(QIcon(pix), self)
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
            # Disconnect
            self._stop_worker()
            return

        host = self._host_edit.text().strip() or "127.0.0.1"
        port = self._port_spin.value()
        certs_dir = self._certs_edit.text().strip() or "certs"

        if not os.path.isabs(certs_dir):
            certs_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "..", certs_dir
            )
        certs_dir = os.path.normpath(certs_dir)

        if self._radio_full.isChecked():
            if not is_admin():
                QMessageBox.warning(
                    self,
                    "Требуются права root",
                    "Полный туннельный режим требует прав суперпользователя.\n\n"
                    "Запустите от имени root/Administrator:\n"
                    "    sudo python vpn_gui.py",
                )
                return

            config_path = os.path.normpath(
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    "..",
                    "config_bootstrap.json",
                )
            )

            self._worker = TunnelWorker(host, port, certs_dir, config_path)
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
            self._hero_status.setText("ПОДКЛЮЧЕНО")
            self._hero_status.setStyleSheet(f"color: {COLORS['ACCENT_1']};")
            self._header_status_lbl.setText("Подключено")
            self._header_status_lbl.setStyleSheet(
                f"color: {COLORS['ACCENT_1']}; font-size: 12px;"
            )
            self._elapsed = 0
            self._elapsed_timer.start()
        elif state == "connecting":
            self._hero_status.setText("ПОДКЛЮЧЕНИЕ...")
            self._hero_status.setStyleSheet(f"color: {COLORS['AMBER_1']};")
            self._header_status_lbl.setText("Подключение...")
            self._header_status_lbl.setStyleSheet(
                f"color: {COLORS['AMBER_1']}; font-size: 12px;"
            )
        elif state == "error":
            self._hero_status.setText("ОШИБКА")
            self._hero_status.setStyleSheet(f"color: {COLORS['ERROR_1']};")
            self._header_status_lbl.setText("Ошибка")
            self._header_status_lbl.setStyleSheet(
                f"color: {COLORS['ERROR_1']}; font-size: 12px;"
            )
            self._elapsed_timer.stop()
        else:  # disconnected
            self._hero_status.setText("НЕ ПОДКЛЮЧЕНО")
            self._hero_status.setStyleSheet(f"color: {COLORS['TEXT']};")
            self._header_status_lbl.setText("Не подключено")
            self._header_status_lbl.setStyleSheet(
                f"color: {COLORS['MUTED']}; font-size: 12px;"
            )
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
            self._log_message(
                "DEBUG",
                f"--> [seq={seq}] Отправлен кадр: {text_preview[:60]}",
            )
        else:
            self._log_message(
                "DEBUG",
                f"<-- [seq={seq}] Получен эхо: {text_preview[:60]}",
            )

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
        self._log_message("INFO", "Генерация тестовых сертификатов...")
        certs_dir = self._certs_edit.text().strip() or "certs"
        try:
            result = subprocess.run(
                [sys.executable, "-m", "utils.cert_gen"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            )
            if result.returncode == 0:
                self._log_message(
                    "SUCCESS",
                    f"Сертификаты успешно созданы в директории '{certs_dir}'",
                )
            else:
                stderr = result.stderr.strip()
                self._log_message("ERROR", f"Ошибка генерации: {stderr or 'неизвестная ошибка'}")
        except subprocess.TimeoutExpired:
            self._log_message("ERROR", "Таймаут генерации сертификатов")
        except Exception as exc:
            self._log_message("ERROR", f"Ошибка запуска cert_gen: {exc}")

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
        """Append a colored HTML line with timestamp to the log."""
        color_map = {
            "INFO":    "#c9d1d9",
            "WARNING": "#e3b341",
            "ERROR":   "#f85149",
            "SUCCESS": "#3fb950",
            "DEBUG":   "#8b949e",
        }
        level_color_map = {
            "INFO":    "#8b949e",
            "WARNING": "#e3b341",
            "ERROR":   "#f85149",
            "SUCCESS": "#3fb950",
            "DEBUG":   "#484f58",
        }
        color = color_map.get(level, "#c9d1d9")
        level_color = level_color_map.get(level, "#8b949e")

        now = datetime.now().strftime("%H:%M:%S")
        # Escape HTML special chars
        safe_text = (
            text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
        )
        html = (
            f'<span style="color:#484f58;">[{now}]</span> '
            f'<span style="color:{level_color}; font-weight:600;">{level:7s}</span> '
            f'<span style="color:{color};">{safe_text}</span>'
        )
        self._log_edit.append(html)
        # Auto-scroll
        sb = self._log_edit.verticalScrollBar()
        sb.setValue(sb.maximum())

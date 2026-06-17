"""
PowerButton — ring-style circular CTA matching the WabilVPN aesthetic.

Dark disc with a glowing teal ring border and animated outer halo.
States: "idle", "connecting", "connected", "error".
"""

from PyQt5.QtCore import QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QPainter, QPainterPath, QPen, QRadialGradient
from PyQt5.QtWidgets import QWidget

from gui.styles import COLORS


class PowerButton(QWidget):
    clicked = pyqtSignal()

    _DIAMETER = 160
    _GLOW_MARGIN = 44
    _RING_WIDTH = 9.0

    _RING_COLORS = {
        "idle":       COLORS["IDLE_BORDER"],
        "connecting": COLORS["AMBER_2"],
        "connected":  COLORS["ACCENT_1"],
        "error":      COLORS["ERROR_1"],
    }

    _ICON_COLORS = {
        "idle":       COLORS["MUTED_DIM"],
        "connecting": COLORS["AMBER_1"],
        "connected":  COLORS["ACCENT_1"],
        "error":      COLORS["ERROR_1"],
    }

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._state = "idle"
        self._pressed = False
        self._press_scale = 1.0
        self._glow_phase = 0.0
        self._glow_direction = 1

        side = self._DIAMETER + 2 * self._GLOW_MARGIN
        self.setFixedSize(side, side)
        self.setCursor(Qt.PointingHandCursor)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_tick)
        self._timer.start(30)

    # ------------------------------------------------------------------ public

    def setState(self, state: str) -> None:
        if state not in self._RING_COLORS:
            state = "idle"
        self._state = state
        self.update()

    def state(self) -> str:
        return self._state

    # ------------------------------------------------------------------ animation

    def _on_tick(self) -> None:
        step = {"connected": 0.018, "connecting": 0.05}.get(self._state)
        if step is None:
            return
        self._glow_phase += self._glow_direction * step
        if self._glow_phase >= 1.0:
            self._glow_phase = 1.0
            self._glow_direction = -1
        elif self._glow_phase <= 0.0:
            self._glow_phase = 0.0
            self._glow_direction = 1
        self.update()

    # ------------------------------------------------------------------ mouse

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self._pressed = True
            self._press_scale = 0.96
            self.update()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self._pressed:
            self._pressed = False
            self._press_scale = 1.0
            self.update()
            if self.rect().contains(event.pos()):
                self.clicked.emit()

    # ------------------------------------------------------------------ paint

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        cx = self.width() / 2.0
        cy = self.height() / 2.0
        radius = (self._DIAMETER / 2.0) * self._press_scale

        ring_color = self._RING_COLORS[self._state]
        icon_color = self._ICON_COLORS[self._state]

        self._paint_glow(painter, cx, cy, radius, ring_color)
        self._paint_disc(painter, cx, cy, radius)
        self._paint_ring(painter, cx, cy, radius, ring_color)
        self._paint_icon(painter, cx, cy, radius, icon_color)

        painter.end()

    def _paint_glow(self, painter: QPainter, cx, cy, radius, glow_color) -> None:
        if self._state == "idle":
            return

        intensity = 0.65 if self._state == "error" else 0.35 + 0.65 * self._glow_phase
        glow_radius = radius + self._GLOW_MARGIN

        gradient = QRadialGradient(QPointF(cx, cy), glow_radius)
        c_inner = QColor(glow_color)
        c_inner.setAlphaF(0.48 * intensity)
        c_mid = QColor(glow_color)
        c_mid.setAlphaF(0.16 * intensity)
        c_outer = QColor(glow_color)
        c_outer.setAlphaF(0.0)
        gradient.setColorAt(0.55, c_inner)
        gradient.setColorAt(0.78, c_mid)
        gradient.setColorAt(1.0,  c_outer)

        painter.setPen(Qt.NoPen)
        painter.setBrush(gradient)
        painter.drawEllipse(QPointF(cx, cy), glow_radius, glow_radius)

    def _paint_disc(self, painter: QPainter, cx, cy, radius) -> None:
        gradient = QRadialGradient(QPointF(cx, cy - radius * 0.15), radius * 1.1)
        gradient.setColorAt(0.0, QColor("#1E3828"))
        gradient.setColorAt(1.0, QColor("#0C1610"))
        painter.setBrush(gradient)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(cx, cy), radius, radius)

    def _paint_ring(self, painter: QPainter, cx, cy, radius, ring_color) -> None:
        pen = QPen(QColor(ring_color))
        pen.setWidthF(self._RING_WIDTH)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        r = radius - self._RING_WIDTH / 2.0
        painter.drawEllipse(QPointF(cx, cy), r, r)

    def _paint_icon(self, painter: QPainter, cx, cy, radius, icon_color) -> None:
        icon_radius = radius * 0.30
        rect = QRectF(cx - icon_radius, cy - icon_radius, icon_radius * 2, icon_radius * 2)

        pen = QPen(QColor(icon_color))
        pen.setWidthF(max(2.5, radius * 0.09))
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)

        arc = QPainterPath()
        arc.arcMoveTo(rect, 125)
        arc.arcTo(rect, 125, 290)
        painter.strokePath(arc, pen)

        painter.drawLine(
            QPointF(cx, cy - icon_radius * 1.15),
            QPointF(cx, cy - icon_radius * 0.05),
        )

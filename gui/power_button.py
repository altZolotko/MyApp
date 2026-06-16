"""
PowerButton — custom QWidget: large circular gradient CTA with a soft glow
halo and a hand-drawn power icon. Used as the hero connect/disconnect
control in the "Pulse" theme.
"""

from PyQt5.QtCore import QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QPainter, QPainterPath, QPen, QRadialGradient
from PyQt5.QtWidgets import QWidget

from gui.styles import COLORS


class PowerButton(QWidget):
    """
    Large circular power button with an animated glow halo.

    States: "idle", "connecting", "connected", "error".
    """

    clicked = pyqtSignal()

    _DIAMETER = 168
    _GLOW_MARGIN = 46

    _GRADIENTS = {
        "idle":       (COLORS["IDLE_TOP"], COLORS["IDLE_BOTTOM"]),
        "connecting": (COLORS["AMBER_1"], COLORS["AMBER_2"]),
        "connected":  (COLORS["ACCENT_1"], COLORS["ACCENT_2"]),
        "error":      (COLORS["ERROR_1"], COLORS["ERROR_2"]),
    }

    _BORDERS = {
        "idle":       COLORS["IDLE_BORDER"],
        "connecting": COLORS["AMBER_2"],
        "connected":  COLORS["ACCENT_2"],
        "error":      COLORS["ERROR_2"],
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
        if state not in self._GRADIENTS:
            state = "idle"
        self._state = state
        self.update()

    def state(self) -> str:
        return self._state

    # ------------------------------------------------------------------ animation

    def _on_tick(self) -> None:
        step = {"connected": 0.018, "connecting": 0.04}.get(self._state)
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

        top_color, bottom_color = self._GRADIENTS[self._state]
        border_color = self._BORDERS[self._state]

        self._paint_glow(painter, cx, cy, radius, top_color)
        self._paint_disc(painter, cx, cy, radius, top_color, bottom_color, border_color)
        self._paint_icon(painter, cx, cy, radius)

        painter.end()

    def _paint_glow(self, painter: QPainter, cx, cy, radius, glow_color) -> None:
        if self._state == "idle":
            return

        intensity = 0.55 if self._state == "error" else 0.45 + 0.55 * self._glow_phase
        glow_radius = radius + self._GLOW_MARGIN * (0.55 + 0.45 * intensity)

        gradient = QRadialGradient(QPointF(cx, cy), glow_radius)
        inner = QColor(glow_color)
        inner.setAlphaF(0.55 * intensity)
        mid = QColor(glow_color)
        mid.setAlphaF(0.22 * intensity)
        outer = QColor(glow_color)
        outer.setAlphaF(0.0)
        gradient.setColorAt(0.0, inner)
        gradient.setColorAt(0.55, mid)
        gradient.setColorAt(1.0, outer)

        painter.setPen(Qt.NoPen)
        painter.setBrush(gradient)
        painter.drawEllipse(QPointF(cx, cy), glow_radius, glow_radius)

    def _paint_disc(self, painter: QPainter, cx, cy, radius, top_color, bottom_color, border_color) -> None:
        gradient = QRadialGradient(QPointF(cx - radius * 0.3, cy - radius * 0.35), radius * 1.5)
        gradient.setColorAt(0.0, QColor(top_color))
        gradient.setColorAt(1.0, QColor(bottom_color))

        pen = QPen(QColor(border_color))
        pen.setWidthF(1.5)
        painter.setPen(pen)
        painter.setBrush(gradient)
        painter.drawEllipse(QPointF(cx, cy), radius, radius)

    def _paint_icon(self, painter: QPainter, cx, cy, radius) -> None:
        icon_radius = radius * 0.32
        rect = QRectF(cx - icon_radius, cy - icon_radius, icon_radius * 2, icon_radius * 2)

        pen = QPen(QColor("#ffffff"))
        pen.setWidthF(max(2.5, radius * 0.11))
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)

        # Power glyph: a near-full ring with a gap at the top, plus a stem
        # poking up through the gap (the universal ⏻ symbol).
        arc = QPainterPath()
        arc.arcMoveTo(rect, 125)
        arc.arcTo(rect, 125, 290)
        painter.strokePath(arc, pen)

        painter.drawLine(
            QPointF(cx, cy - icon_radius * 1.15),
            QPointF(cx, cy - icon_radius * 0.05),
        )

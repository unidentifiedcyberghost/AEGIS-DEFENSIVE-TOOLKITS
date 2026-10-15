"""
Aegis Tactical HUD Widgets
Custom PyQt6 UI components for Sci-Fi / Cyberpunk telemetry and gauges.
"""

from datetime import datetime
from PyQt6.QtWidgets import QWidget, QFrame, QVBoxLayout, QLabel, QTextEdit
from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QPainter, QColor, QPen, QFont


class ScoreGaugeWidget(QWidget):
    """Circular HUD tactical posture score gauge."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.score = 100
        self.grade = "A+"
        self.setMinimumSize(170, 170)

    def set_score(self, score: int, grade: str):
        self.score = max(0, min(100, score))
        self.grade = grade
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        size = min(w, h) - 20
        rect = QRectF((w - size) / 2, (h - size) / 2, size, size)

        # Determine color by score
        if self.score >= 90:
            glow_color = QColor("#00FF88") # Green
        elif self.score >= 80:
            glow_color = QColor("#00F0FF") # Cyan
        elif self.score >= 70:
            glow_color = QColor("#FFB800") # Amber
        else:
            glow_color = QColor("#FF3366") # Red

        # Background track
        bg_pen = QPen(QColor("#152033"), 6)
        painter.setPen(bg_pen)
        painter.drawArc(rect, 0, 360 * 16)

        # Active progress arc
        progress_angle = int((self.score / 100.0) * 360 * 16)
        glow_pen = QPen(glow_color, 8)
        glow_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(glow_pen)
        # Start from top (90 deg in Qt = 90 * 16)
        painter.drawArc(rect, 90 * 16, -progress_angle)

        # Center Score Text
        painter.setPen(QColor("#FFFFFF"))
        font_score = QFont("Consolas", 24, QFont.Weight.Bold)
        painter.setFont(font_score)
        painter.drawText(QRectF(0, (h / 2) - 30, w, 35), Qt.AlignmentFlag.AlignCenter, f"{self.score}")

        # Posture Grade Text
        painter.setPen(glow_color)
        font_grade = QFont("Consolas", 11, QFont.Weight.Bold)
        painter.setFont(font_grade)
        painter.drawText(QRectF(0, (h / 2) + 10, w, 25), Qt.AlignmentFlag.AlignCenter, f"GRADE: {self.grade}")


class TelemetryCard(QFrame):
    """Sci-Fi metric card displaying a single telemetry value."""

    def __init__(self, title: str, value: str, subtext: str = "", accent_color: str = "#00F0FF", parent=None):
        super().__init__(parent)
        self.setObjectName("hudCard")
        self.accent_color = accent_color

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        self.lbl_title = QLabel(title.upper())
        self.lbl_title.setStyleSheet(f"color: #8899B5; font-size: 10px; font-weight: bold; letter-spacing: 1px;")

        self.lbl_value = QLabel(value)
        self.lbl_value.setStyleSheet(f"color: {accent_color}; font-size: 20px; font-weight: bold;")

        self.lbl_subtext = QLabel(subtext)
        self.lbl_subtext.setStyleSheet("color: #64748B; font-size: 9px;")

        layout.addWidget(self.lbl_title)
        layout.addWidget(self.lbl_value)
        layout.addWidget(self.lbl_subtext)

    def set_value(self, value: str, subtext: str = None):
        self.lbl_value.setText(str(value))
        if subtext is not None:
            self.lbl_subtext.setText(subtext)


class HudTerminal(QTextEdit):
    """High-tech scrolling tactical console with color-coded log entries."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

    def log(self, message: str, level: str = "INFO"):
        now = datetime.now().strftime("%H:%M:%S")
        color = "#00F0FF" # Cyan
        if level == "PASS":
            color = "#00FF88"
        elif level == "WARN":
            color = "#FFB800"
        elif level in ("CRIT", "THREAT", "FAIL"):
            color = "#FF3366"
        elif level == "DEBUG":
            color = "#64748B"

        formatted = f'<span style="color: #64748B;">[{now}]</span> <b style="color: {color};">[{level}]</b> <span style="color: #CBD5E1;">{message}</span>'
        self.append(formatted)
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

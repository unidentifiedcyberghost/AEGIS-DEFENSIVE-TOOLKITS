"""
Aegis Tactical HUD Style System
Defines high-tech Sci-Fi CIA/Cyberpunk color palettes, fonts, and Qt Style Sheets (QSS).
"""

HUD_COLORS = {
    "bg_black": "#05080E",
    "bg_panel": "#0A0F1D",
    "bg_card": "#10172A",
    "bg_input": "#0E1526",
    "border_dim": "#1E2A44",
    "border_glow": "#00F0FF",
    "cyan": "#00F0FF",
    "green": "#00FF88",
    "amber": "#FFB800",
    "red": "#FF3366",
    "text_bright": "#F8FAFC",
    "text_main": "#CBD5E1",
    "text_muted": "#64748B",
    "scrollbar": "#1E293B"
}

HUD_STYLESHEET = """
QMainWindow {
    background-color: #05080E;
    color: #CBD5E1;
}

QWidget {
    font-family: 'Consolas', 'Cascadia Code', 'Fira Code', 'Courier New', monospace;
    font-size: 12px;
    color: #CBD5E1;
}

/* Panel Containers */
QFrame#hudPanel {
    background-color: #0A0F1D;
    border: 1px solid #1E2A44;
    border-radius: 6px;
}

QFrame#hudCard {
    background-color: #10172A;
    border: 1px solid #1E2A44;
    border-radius: 4px;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #1E2A44;
    background-color: #0A0F1D;
    top: -1px;
}

QTabBar::tab {
    background: #0B1220;
    color: #8899B5;
    padding: 8px 18px;
    margin-right: 4px;
    border: 1px solid #1E2A44;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    font-weight: bold;
    letter-spacing: 1px;
}

QTabBar::tab:selected {
    background: #101A2E;
    color: #00F0FF;
    border: 1px solid #00F0FF;
    border-bottom: 2px solid #00F0FF;
}

QTabBar::tab:hover:!selected {
    background: #0F172A;
    color: #CBD5E1;
    border-color: #334155;
}

/* Buttons */
QPushButton {
    background-color: #0E1628;
    color: #00F0FF;
    border: 1px solid #00F0FF;
    border-radius: 4px;
    padding: 6px 14px;
    font-weight: bold;
    letter-spacing: 1px;
}

QPushButton:hover {
    background-color: #00F0FF;
    color: #05080E;
}

QPushButton:pressed {
    background-color: #00B8C4;
    color: #05080E;
}

QPushButton#btnPrimary {
    background-color: #00F0FF;
    color: #05080E;
    font-weight: bold;
}

QPushButton#btnPrimary:hover {
    background-color: #38F8FF;
}

QPushButton#btnDanger {
    border: 1px solid #FF3366;
    color: #FF3366;
}

QPushButton#btnDanger:hover {
    background-color: #FF3366;
    color: #05080E;
}

/* Line Edit / Input */
QLineEdit {
    background-color: #0E1526;
    border: 1px solid #1E2A44;
    border-radius: 4px;
    padding: 6px 10px;
    color: #F8FAFC;
    selection-background-color: #00F0FF;
    selection-color: #05080E;
}

QLineEdit:focus {
    border: 1px solid #00F0FF;
}

/* Tables */
QTableWidget {
    background-color: #070B14;
    border: 1px solid #1E2A44;
    gridline-color: #152033;
    color: #CBD5E1;
    selection-background-color: #10243E;
    selection-color: #00F0FF;
}

QHeaderView::section {
    background-color: #0B1222;
    color: #00F0FF;
    padding: 6px;
    border: 1px solid #1E2A44;
    font-weight: bold;
    letter-spacing: 1px;
}

/* Progress Bar */
QProgressBar {
    border: 1px solid #1E2A44;
    border-radius: 3px;
    background-color: #0A0F1D;
    text-align: center;
    color: #00F0FF;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00A3FF, stop:1 #00FF88);
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background: #070B14;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #1E293B;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #00F0FF;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* Text Edit / Terminal */
QTextEdit {
    background-color: #04070D;
    border: 1px solid #1E2A44;
    color: #00FF88;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
    line-height: 1.4;
}

/* Combo Box */
QComboBox {
    background-color: #0E1526;
    border: 1px solid #1E2A44;
    border-radius: 4px;
    padding: 5px 10px;
    color: #00F0FF;
}

QComboBox:hover {
    border: 1px solid #00F0FF;
}

QComboBox QAbstractItemView {
    background-color: #0A0F1D;
    border: 1px solid #00F0FF;
    selection-background-color: #10243E;
    selection-color: #00F0FF;
}
"""

"""
Aegis Main HUD Window
High-tech Sci-Fi CIA/Cyberpunk style graphical interface built with PyQt6.
Categorized architecture for:
- [CAT 1] Vulnerability Auditor & Compliance
- [CAT 2] Cyber OSINT & Attack Surface Intelligence
- [CAT 3] Malware, Web Shell & Suspicious Path Scanner
- [CAT 4] Anti-XSS & Data Injection Defense Shield
- [CAT 5] Localhost & Network Sockets Monitor
- [CAT 6] Attacker Tracker & IDS Log Engine
- [CAT 7] Hardening Playbooks & Active Defense
- [CAT 8] Tactical Streaming Console
Developed by Team White Hat.
"""

import sys
import os
import urllib.parse
from datetime import datetime
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QLineEdit, QPushButton, QProgressBar, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QFrame, QSplitter, QTextEdit,
    QFileDialog, QMessageBox, QComboBox, QApplication,
    QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QColor, QFont, QClipboard, QDesktopServices

from aegis.gui.hud_theme import HUD_STYLESHEET, HUD_COLORS
from aegis.gui.widgets import ScoreGaugeWidget, TelemetryCard, HudTerminal
from aegis.gui.workers import (
    AuditWorker, PortWorker, LogAnalysisWorker, OsintWorker,
    MalwareScanWorker, InjectionAuditWorker, ServerAuditWorker
)
from aegis.log_ids import LogIntrusionDetector
from aegis.osint_engine import OsintEngine
from aegis.malware_scanner import MalwareScanner
from aegis.injection_defense import InjectionDefenseEngine
from aegis.server_auditor import ServerSystemAuditor
from aegis.attack_matrix import ATTACK_MATRIX
from aegis.active_defense import ActiveDefenseManager
from aegis.playbook import PLAYBOOKS
from aegis.reporter import ReportGenerator


class AegisMainWindow(QMainWindow):
    """Main window for the Aegis Defensive Security Suite."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AEGIS // DEFENSIVE LOCALHOST & WEB AUDIT SUITE [TACTICAL HUD]")
        self.resize(1340, 880)
        self.setMinimumSize(1100, 740)

        self.last_report = None
        self.current_attackers = []
        self.last_osint = None
        self.last_malware_scan = None
        self.scanner_engine = MalwareScanner()

        self.setStyleSheet(HUD_STYLESHEET)
        self._init_ui()
        self.terminal.log("Aegis Defensive System initialized. Telemetry channels online.", "INFO")
        self.terminal.log("Core Suite Developed by Team White Hat (Defensive Cyber Research).", "INFO")

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(14, 12, 14, 10)
        main_layout.setSpacing(10)

        # 1. Top HUD Tactical Header
        header_frame = self._build_header()
        main_layout.addWidget(header_frame)

        # 2. Category Quick Ribbon
        category_ribbon = self._build_category_ribbon()
        main_layout.addWidget(category_ribbon)

        # 3. Main Categorized Tabs
        self.tabs = QTabWidget()
        self.tab_overview = self._build_overview_tab()
        self.tab_web = self._build_web_tab()
        self.tab_osint = self._build_osint_tab()
        self.tab_malware = self._build_malware_tab()
        self.tab_injection = self._build_injection_tab()
        self.tab_ports = self._build_ports_tab()
        self.tab_attackers = self._build_attackers_tab()
        self.tab_attack_matrix = self._build_attack_matrix_tab()
        self.tab_playbooks = self._build_playbooks_tab()
        self.tab_terminal = self._build_terminal_tab()

        self.tabs.addTab(self.tab_overview, "🛡️ OVERVIEW & SCORE")
        self.tabs.addTab(self.tab_web, "🌐 OWASP VULN AUDIT")
        self.tabs.addTab(self.tab_osint, "🕵️ CYBER OSINT, IP ROUTES & TABLES")
        self.tabs.addTab(self.tab_malware, "🦠 MALWARE & WEBSHELL SCANNER")
        self.tabs.addTab(self.tab_injection, "💉 ANTI-XSS & DATA INJECTION")
        self.tabs.addTab(self.tab_ports, "📡 LOCALHOST & PORTS")
        self.tabs.addTab(self.tab_attackers, "🚨 ATTACKER IDS & LOGS")
        self.tabs.addTab(self.tab_attack_matrix, "⚔️ ATTACK MATRIX & HOW TO FIX")
        self.tabs.addTab(self.tab_playbooks, "📋 HARDENING PLAYBOOKS")
        self.tabs.addTab(self.tab_terminal, "🖥️ TACTICAL CONSOLE")

        main_layout.addWidget(self.tabs, stretch=1)

        # 4. Status Bar & Progress
        bottom_layout = QHBoxLayout()
        self.lbl_status = QLabel("STATUS: STANDBY // READY FOR AUDIT")
        self.lbl_status.setStyleSheet("color: #00F0FF; font-weight: bold; font-size: 11px;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(12)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)

        bottom_layout.addWidget(self.lbl_status, stretch=1)
        bottom_layout.addWidget(self.progress_bar, stretch=2)
        main_layout.addLayout(bottom_layout)

        # 5. Developer Footer Frame (Team White Hat)
        footer_frame = self._build_footer()
        main_layout.addWidget(footer_frame)

    def _build_header(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("hudPanel")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(8)

        # Title Row
        top_row = QHBoxLayout()
        lbl_brand = QLabel("AEGIS // DEFENSIVE SECURITY SUITE")
        lbl_brand.setStyleSheet("color: #00F0FF; font-size: 16px; font-weight: bold; letter-spacing: 2px;")
        
        lbl_mode = QLabel("[POSTURE: DEFENSIVE]  [CLASSIFICATION: AUTHORIZED]")
        lbl_mode.setStyleSheet("color: #00FF88; font-size: 11px; font-weight: bold;")

        top_row.addWidget(lbl_brand)
        top_row.addStretch()
        top_row.addWidget(lbl_mode)
        layout.addLayout(top_row)

        # Input & Action Controls (Organized in 2 Well-Aligned Rows to Prevent Any Overlap)
        ctrl_layout = QVBoxLayout()
        ctrl_layout.setSpacing(8)

        # Row 1: Target Host / IP and Presets
        row_target = QHBoxLayout()
        row_target.setSpacing(8)
        lbl_target = QLabel("TARGET URL / HOST / IP:")
        lbl_target.setStyleSheet("color: #8899B5; font-weight: bold; font-size: 11px;")
        
        self.txt_target = QLineEdit("http://127.0.0.1:8000")
        self.txt_target.setPlaceholderText("e.g., http://localhost:3000, http://127.0.0.1:8080, 192.168.1.1, google.com")
        self.txt_target.setFixedHeight(32)

        btn_preset1 = QPushButton("localhost:3000")
        btn_preset1.setFixedHeight(30)
        btn_preset1.clicked.connect(lambda: self.txt_target.setText("http://localhost:3000"))

        btn_preset2 = QPushButton("localhost:8000")
        btn_preset2.setFixedHeight(30)
        btn_preset2.clicked.connect(lambda: self.txt_target.setText("http://localhost:8000"))

        row_target.addWidget(lbl_target)
        row_target.addWidget(self.txt_target, stretch=1)
        row_target.addWidget(btn_preset1)
        row_target.addWidget(btn_preset2)
        ctrl_layout.addLayout(row_target)

        # Row 2: Defense Actions (Well-Spaced, Cyber Highlighting, Zero Overlap)
        row_actions = QHBoxLayout()
        row_actions.setSpacing(10)

        self.btn_master = QPushButton("🚀 RUN MASTER DEFENSE SCAN (ALL PANELS)")
        self.btn_master.setFixedHeight(34)
        self.btn_master.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00F0FF, stop:1 #00FF88);
                color: #05080E;
                font-weight: 900;
                font-size: 11px;
                padding: 6px 16px;
                border: 2px solid #FFFFFF;
                border-radius: 4px;
                margin: 2px 4px;
            }
            QPushButton:hover {
                background: #00FF88;
                border-color: #00F0FF;
            }
        """)
        self.btn_master.clicked.connect(self.start_master_scan)

        self.btn_scan = QPushButton("🛡️ INITIATE DEFENSIVE AUDIT")
        self.btn_scan.setObjectName("btnPrimary")
        self.btn_scan.setFixedHeight(34)
        self.btn_scan.clicked.connect(self.start_audit)

        self.btn_export = QPushButton("💾 EXPORT REPORT")
        self.btn_export.setFixedHeight(34)
        self.btn_export.clicked.connect(self.export_report)

        row_actions.addWidget(self.btn_master)
        row_actions.addWidget(self.btn_scan)
        row_actions.addWidget(self.btn_export)
        row_actions.addStretch()

        ctrl_layout.addLayout(row_actions)
        layout.addLayout(ctrl_layout)
        return frame

    def _build_category_ribbon(self) -> QFrame:
        """Ribbon providing instant category navigation with zero border overlapping."""
        frame = QFrame()
        frame.setObjectName("hudPanel")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(6)

        # Top Category Label
        top_lbl_row = QHBoxLayout()
        lbl = QLabel("CYBER DEFENSE CATEGORIES // QUICK ACCESS NAVIGATION:")
        lbl.setStyleSheet("color: #00F0FF; font-weight: 800; font-size: 10px; letter-spacing: 1.5px;")
        top_lbl_row.addWidget(lbl)
        top_lbl_row.addStretch()
        layout.addLayout(top_lbl_row)

        # Row 1 (Categories 1 - 5)
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        cats_row1 = [
            ("🛡️ VULNERABILITY AUDITOR", 1, "#00F0FF"),
            ("🕵️ CYBER OSINT ENGINE", 2, "#00FF88"),
            ("🦠 MALWARE SCANNER", 3, "#FF3366"),
            ("💉 ANTI-XSS & INJECTION", 4, "#00F0FF"),
            ("📡 LOCALHOST & PORTS", 5, "#FFB800"),
        ]
        for text, tab_idx, col in cats_row1:
            btn = QPushButton(text)
            btn.setFixedHeight(28)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: rgba(15, 23, 42, 0.85);
                    color: {col};
                    border: 1.5px solid {col};
                    padding: 4px 10px;
                    border-radius: 4px;
                    font-size: 10.5px;
                    font-weight: 800;
                    margin: 2px 3px;
                }}
                QPushButton:hover {{
                    background: {col};
                    color: #05080E;
                    border-color: #FFFFFF;
                }}
            """)
            btn.clicked.connect(lambda checked, idx=tab_idx: self.tabs.setCurrentIndex(idx))
            row1.addWidget(btn)
        row1.addStretch()
        layout.addLayout(row1)

        # Row 2 (Categories 6 - 9)
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        cats_row2 = [
            ("🚨 ATTACKER IDS & LOGS", 6, "#FF3366"),
            ("⚔️ ATTACK MATRIX & HOW TO FIX", 7, "#00FF88"),
            ("📋 HARDENING PLAYBOOKS", 8, "#38BDF8"),
            ("🖥️ STREAMING TACTICAL CONSOLE", 9, "#94A3B8")
        ]
        for text, tab_idx, col in cats_row2:
            btn = QPushButton(text)
            btn.setFixedHeight(28)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: rgba(15, 23, 42, 0.85);
                    color: {col};
                    border: 1.5px solid {col};
                    padding: 4px 10px;
                    border-radius: 4px;
                    font-size: 10.5px;
                    font-weight: 800;
                    margin: 2px 3px;
                }}
                QPushButton:hover {{
                    background: {col};
                    color: #05080E;
                    border-color: #FFFFFF;
                }}
            """)
            btn.clicked.connect(lambda checked, idx=tab_idx: self.tabs.setCurrentIndex(idx))
            row2.addWidget(btn)
        row2.addStretch()
        layout.addLayout(row2)

        return frame

    def _build_footer(self) -> QFrame:
        """Bottom HUD footer showing developer credits (Team White Hat) and links."""
        frame = QFrame()
        frame.setObjectName("hudPanel")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(12, 5, 12, 5)

        lbl_dev = QLabel("🛡️ DEVELOPED BY TEAM WHITE HAT")
        lbl_dev.setStyleSheet("color: #00F0FF; font-weight: bold; font-size: 11px; letter-spacing: 1px;")
        layout.addWidget(lbl_dev)

        layout.addStretch()

        links = [
            ("GitHub: @unidentifiedcyberghost", "https://github.com/unidentifiedcyberghost"),
            ("GitHub: @pinoyUnknown", "https://github.com/pinoyUnknown"),
            ("X / Twitter: @TeamWhiteHatDev", "https://x.com/TeamWhiteHatDev")
        ]

        for text, url_str in links:
            btn = QPushButton(text)
            btn.setStyleSheet("""
                QPushButton {
                    background: transparent;
                    color: #00FF88;
                    border: 1px solid #1E293B;
                    padding: 2px 7px;
                    border-radius: 3px;
                    font-size: 10px;
                }
                QPushButton:hover {
                    color: #00F0FF;
                    border-color: #00F0FF;
                    background: rgba(0, 240, 255, 0.1);
                }
            """)
            btn.clicked.connect(lambda checked, u=url_str: QDesktopServices.openUrl(QUrl(u)))
            layout.addWidget(btn)

        return frame

    def _build_overview_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Top Metric Cards Row
        cards_row = QHBoxLayout()
        self.gauge = ScoreGaugeWidget()
        cards_row.addWidget(self.gauge)

        self.card_crit = TelemetryCard("Critical Threats", "0", "Requires Immediate Action", "#FF3366")
        self.card_high = TelemetryCard("High Severity", "0", "Missing Critical Defenses", "#FFB800")
        self.card_med = TelemetryCard("Medium Warnings", "0", "Informational Leakage", "#00F0FF")
        self.card_pass = TelemetryCard("Hardened Passes", "0", "Verified Secure Controls", "#00FF88")

        cards_row.addWidget(self.card_crit)
        cards_row.addWidget(self.card_high)
        cards_row.addWidget(self.card_med)
        cards_row.addWidget(self.card_pass)
        layout.addLayout(cards_row)

        # Overview Findings Table
        lbl_recent = QLabel("SECURITY AUDIT FINDINGS TELEMETRY:")
        lbl_recent.setStyleSheet("color: #00F0FF; font-weight: bold; font-size: 12px; margin-top: 6px;")
        layout.addWidget(lbl_recent)

        self.table_overview = QTableWidget(0, 3)
        self.table_overview.setHorizontalHeaderLabels(["SEVERITY", "AUDIT CATEGORY", "FINDING & RECOMMENDATION"])
        self.table_overview.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_overview.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_overview.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_overview.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_overview.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_overview.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_overview.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout.addWidget(self.table_overview)
        return widget

    def _build_web_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Filters Row
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)
        lbl_filter = QLabel("FILTER FINDINGS:")
        lbl_filter.setStyleSheet("color: #00F0FF; font-weight: bold; font-size: 11px;")
        btn_all = QPushButton("ALL RESULTS")
        btn_all.setFixedHeight(28)
        btn_all.clicked.connect(lambda: self._filter_findings("all"))
        btn_threats = QPushButton("THREATS ONLY")
        btn_threats.setFixedHeight(28)
        btn_threats.clicked.connect(lambda: self._filter_findings("threats"))
        btn_passes = QPushButton("PASSES ONLY")
        btn_passes.setFixedHeight(28)
        btn_passes.clicked.connect(lambda: self._filter_findings("passes"))

        filter_row.addWidget(lbl_filter)
        filter_row.addWidget(btn_all)
        filter_row.addWidget(btn_threats)
        filter_row.addWidget(btn_passes)
        filter_row.addStretch()
        layout.addLayout(filter_row)

        # Table
        self.table_web = QTableWidget(0, 4)
        self.table_web.setHorizontalHeaderLabels(["SEVERITY", "FINDING TITLE", "DESCRIPTION", "REMEDIATION"])
        self.table_web.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_web.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_web.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_web.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table_web.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_web.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_web.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_web.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table_web)

        return widget

    def _build_osint_tab(self) -> QWidget:
        """Category 2: Comprehensive Cyber OSINT & Attack Surface Engine."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # OSINT Sub-header / Target controls
        top_frame = QFrame()
        top_frame.setObjectName("hudPanel")
        top_layout = QHBoxLayout(top_frame)
        top_layout.setContentsMargins(10, 8, 10, 8)

        lbl_recon = QLabel("OSINT TARGET DOMAIN / HOST / IP:")
        lbl_recon.setStyleSheet("color: #00FF88; font-weight: bold; font-size: 11px;")
        top_layout.addWidget(lbl_recon)

        self.txt_osint_target = QLineEdit("google.com")
        self.txt_osint_target.setPlaceholderText("Enter domain or IP (e.g., example.com, 1.1.1.1, localhost)")
        self.txt_osint_target.setFixedHeight(30)
        top_layout.addWidget(self.txt_osint_target, stretch=1)

        # Quick preset buttons
        btn_use_cur = QPushButton("Sync Target Host")
        btn_use_cur.clicked.connect(self._sync_osint_target)
        top_layout.addWidget(btn_use_cur)

        btn_preset_ex = QPushButton("example.com")
        btn_preset_ex.clicked.connect(lambda: self.txt_osint_target.setText("example.com"))
        top_layout.addWidget(btn_preset_ex)

        btn_run_osint = QPushButton("🕵️ RUN PASSIVE OSINT RECON")
        btn_run_osint.setObjectName("btnPrimary")
        btn_run_osint.setFixedHeight(30)
        btn_run_osint.clicked.connect(self.start_osint_recon)
        top_layout.addWidget(btn_run_osint)

        layout.addWidget(top_frame)

        # Telemetry Cards Row
        cards_row = QHBoxLayout()
        self.osint_card_risk = TelemetryCard("Attack Surface Risk", "STANDBY", "Overall Exposure", "#00FF88")
        self.osint_card_ssl = TelemetryCard("SSL/TLS Cryptography", "STANDBY", "Cipher & Expiration", "#00F0FF")
        self.osint_card_email = TelemetryCard("Email Anti-Spoofing", "STANDBY", "SPF & DMARC", "#FFB800")
        self.osint_card_subs = TelemetryCard("Discovered Subdomains", "0", "SAN & CRT.SH Discovery", "#00F0FF")

        cards_row.addWidget(self.osint_card_risk)
        cards_row.addWidget(self.osint_card_ssl)
        cards_row.addWidget(self.osint_card_email)
        cards_row.addWidget(self.osint_card_subs)
        layout.addLayout(cards_row)

        # Sub-tabs for deep OSINT drilldown
        osint_subtabs = QTabWidget()

        # Sub-tab 0: IP Infrastructure, Routes, Tables, Details & Origins
        tab_ip_infra = QWidget()
        infra_layout = QGridLayout(tab_ip_infra)
        infra_layout.setContentsMargins(8, 8, 8, 8)
        infra_layout.setSpacing(10)

        # 1. IP Details
        box_details = QFrame()
        box_details.setObjectName("hudPanel")
        b_det_layout = QVBoxLayout(box_details)
        b_det_layout.addWidget(QLabel("📌 TARGET IP DETAILS & BOGON STATUS:"))
        self.table_osint_ip_details = QTableWidget(0, 2)
        self.table_osint_ip_details.setHorizontalHeaderLabels(["PROPERTY", "VALUE / VERIFICATION"])
        self.table_osint_ip_details.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_ip_details.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_osint_ip_details.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_ip_details.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_ip_details.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_osint_ip_details.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        b_det_layout.addWidget(self.table_osint_ip_details)
        infra_layout.addWidget(box_details, 0, 0)

        # 2. IP Origins
        box_origins = QFrame()
        box_origins.setObjectName("hudPanel")
        b_orig_layout = QVBoxLayout(box_origins)
        b_orig_layout.addWidget(QLabel("🌍 IP ORIGINS & GEOLOCATION TELEMETRY:"))
        self.table_osint_ip_origins = QTableWidget(0, 2)
        self.table_osint_ip_origins.setHorizontalHeaderLabels(["ORIGIN ATTRIBUTE", "TELEMETRY DATA"])
        self.table_osint_ip_origins.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_ip_origins.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_osint_ip_origins.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_ip_origins.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_ip_origins.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_osint_ip_origins.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        b_orig_layout.addWidget(self.table_osint_ip_origins)
        infra_layout.addWidget(box_origins, 0, 1)

        # 3. IP Routes
        box_routes = QFrame()
        box_routes.setObjectName("hudPanel")
        b_rt_layout = QVBoxLayout(box_routes)
        b_rt_layout.addWidget(QLabel("🛣️ IP ROUTES & BGP ASN INFRASTRUCTURE:"))
        self.table_osint_ip_routes = QTableWidget(0, 2)
        self.table_osint_ip_routes.setHorizontalHeaderLabels(["ROUTING LAYER", "PATHWAY / METRIC"])
        self.table_osint_ip_routes.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_ip_routes.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_osint_ip_routes.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_ip_routes.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_ip_routes.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_osint_ip_routes.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        b_rt_layout.addWidget(self.table_osint_ip_routes)
        infra_layout.addWidget(box_routes, 1, 0)

        # 4. IP Tables
        box_tables = QFrame()
        box_tables.setObjectName("hudPanel")
        b_tbl_layout = QVBoxLayout(box_tables)
        b_tbl_layout.addWidget(QLabel("🛡️ IP TABLES & DEFENSIVE FIREWALL DROP RULES:"))
        self.table_osint_ip_tables = QTableWidget(0, 2)
        self.table_osint_ip_tables.setHorizontalHeaderLabels(["FIREWALL ENGINE", "SYNTHESIZED RULE / INTERFACE"])
        self.table_osint_ip_tables.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_ip_tables.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_osint_ip_tables.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_ip_tables.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_ip_tables.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_osint_ip_tables.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        b_tbl_layout.addWidget(self.table_osint_ip_tables)
        infra_layout.addWidget(box_tables, 1, 1)

        osint_subtabs.addTab(tab_ip_infra, "📡 IP TABLES, ROUTES, DETAILS & ORIGINS")

        # Sub-tab 1: DNS & Email Security
        tab_dns = QWidget()
        dns_layout = QVBoxLayout(tab_dns)
        self.table_osint_dns = QTableWidget(0, 3)
        self.table_osint_dns.setHorizontalHeaderLabels(["RECORD TYPE", "RECORD VALUE / TARGET", "SECURITY PURPOSE"])
        self.table_osint_dns.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_dns.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_osint_dns.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_dns.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_dns.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_dns.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_osint_dns.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        dns_layout.addWidget(self.table_osint_dns)
        osint_subtabs.addTab(tab_dns, "📡 DNS & EMAIL ANTI-SPOOFING")

        # Sub-tab 2: SSL/TLS & Cryptography
        tab_ssl = QWidget()
        ssl_layout = QVBoxLayout(tab_ssl)
        self.table_osint_ssl = QTableWidget(0, 3)
        self.table_osint_ssl.setHorizontalHeaderLabels(["CRYPTOGRAPHIC PARAMETER", "VALUE", "SECURITY STANDARD"])
        self.table_osint_ssl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_ssl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_osint_ssl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_ssl.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_ssl.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_ssl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_osint_ssl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        ssl_layout.addWidget(self.table_osint_ssl)
        osint_subtabs.addTab(tab_ssl, "🔒 SSL/TLS & CIPHER SUITES")

        # Sub-tab 3: Subdomain Enumeration
        tab_subs = QWidget()
        subs_layout = QVBoxLayout(tab_subs)
        top_subs_row = QHBoxLayout()
        lbl_subs_info = QLabel("PASSIVELY DISCOVERED SUBDOMAINS (NO TARGET PACKETS SENT):")
        lbl_subs_info.setStyleSheet("color: #00F0FF; font-weight: bold; font-size: 11px;")
        btn_copy_subs = QPushButton("📋 COPY ALL SUBDOMAINS")
        btn_copy_subs.clicked.connect(self._copy_subdomains_to_clipboard)
        top_subs_row.addWidget(lbl_subs_info)
        top_subs_row.addStretch()
        top_subs_row.addWidget(btn_copy_subs)
        subs_layout.addLayout(top_subs_row)

        self.table_osint_subs = QTableWidget(0, 2)
        self.table_osint_subs.setHorizontalHeaderLabels(["DISCOVERED SUBDOMAIN", "SOURCE DISCOVERY"])
        self.table_osint_subs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_osint_subs.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_subs.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_subs.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_subs.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_osint_subs.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        subs_layout.addWidget(self.table_osint_subs)
        osint_subtabs.addTab(tab_subs, "🌐 SUBDOMAIN DISCOVERY (CRT.SH & SAN)")

        # Sub-tab 4: BGP, ASN & Geolocation
        tab_bgp = QWidget()
        bgp_layout = QVBoxLayout(tab_bgp)
        self.table_osint_bgp = QTableWidget(0, 2)
        self.table_osint_bgp.setHorizontalHeaderLabels(["NETWORK TELEMETRY", "VALUE"])
        self.table_osint_bgp.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_bgp.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_osint_bgp.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_bgp.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_bgp.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_osint_bgp.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        bgp_layout.addWidget(self.table_osint_bgp)
        osint_subtabs.addTab(tab_bgp, "🗺️ BGP ROUTING, ASN & ORIGIN")

        # Sub-tab 5: Tech Stack & Perimeter
        tab_tech = QWidget()
        tech_layout = QVBoxLayout(tab_tech)
        self.table_osint_tech = QTableWidget(0, 2)
        self.table_osint_tech.setHorizontalHeaderLabels(["PERIMETER COMPONENT", "DETECTED TECHNOLOGY"])
        self.table_osint_tech.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_osint_tech.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_osint_tech.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_tech.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_osint_tech.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_osint_tech.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tech_layout.addWidget(self.table_osint_tech)
        osint_subtabs.addTab(tab_tech, "⚙️ TECH STACK & CLOUD WAF/CDN")

        # Sub-tab 6: External Pivots (Shodan, Censys, VirusTotal)
        tab_pivots = QWidget()
        pivots_layout = QVBoxLayout(tab_pivots)
        self.txt_pivots = QTextEdit()
        self.txt_pivots.setReadOnly(True)
        self.txt_pivots.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_pivots.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_pivots.setPlaceholderText("External threat intelligence search links will appear here after running reconnaissance...")
        pivots_layout.addWidget(self.txt_pivots)
        osint_subtabs.addTab(tab_pivots, "🔍 CYBER THREAT PIVOTS (SHODAN/CENSYS)")

        layout.addWidget(osint_subtabs, stretch=1)
        return widget

    def _sync_osint_target(self):
        target = self.txt_target.text().strip()
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or target.replace("http://", "").replace("https://", "").split(":")[0]
        self.txt_osint_target.setText(host)

    def start_osint_recon(self):
        target = self.txt_osint_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Invalid Host", "Please enter a domain or IP for OSINT reconnaissance.")
            return

        self.lbl_status.setText(f"GATHERING PASSIVE OSINT TELEMETRY FOR: {target}...")
        self.progress_bar.setValue(20)
        self.terminal.log(f"Initiating professional passive OSINT against: {target}", "INFO")

        self.osint_worker = OsintWorker(target)
        self.osint_worker.progress.connect(self._on_audit_progress)
        self.osint_worker.finished.connect(self._on_osint_finished)
        self.osint_worker.error.connect(self._on_audit_error)
        self.osint_worker.start()

    def _on_osint_finished(self, recon: dict):
        self.last_osint = recon
        self.progress_bar.setValue(100)
        self.lbl_status.setText(f"STATUS: OSINT RECONNAISSANCE COMPLETE FOR {recon.get('target')}")

        # Update Telemetry Cards
        risk = recon.get("attack_surface_risk", "Low")
        risk_color = "#FF3366" if risk == "High" else ("#FFB800" if risk == "Medium" else "#00FF88")
        self.osint_card_risk.set_value(risk.upper(), f"Score: {recon.get('risk_score', 0)}/100")
        self.osint_card_risk.lbl_value.setStyleSheet(f"color: {risk_color}; font-size: 20px; font-weight: bold;")

        ssl_data = recon.get("ssl_certificate", {})
        if ssl_data.get("valid"):
            days = ssl_data.get("expires_in_days", "N/A")
            self.osint_card_ssl.set_value(f"VALID ({days}d)", ssl_data.get("cipher", "TLS"))
        else:
            self.osint_card_ssl.set_value("NO SSL", "Unencrypted or Local")

        email_data = recon.get("email_security", {})
        if email_data.get("spf_present") and email_data.get("dmarc_present"):
            self.osint_card_email.set_value("PROTECTED", "SPF & DMARC Enforced")
        elif email_data.get("spf_present"):
            self.osint_card_email.set_value("PARTIAL", "SPF Only (No DMARC)")
        else:
            self.osint_card_email.set_value("VULNERABLE", "High Spoofing Risk")

        subs = recon.get("subdomains_discovered", [])
        self.osint_card_subs.set_value(str(len(subs)), "Discovered Hosts")

        # 0. Populate IP Infrastructure Tables (Details, Origins, Routes, Tables)
        self.table_osint_ip_details.setRowCount(0)
        details = recon.get("ip_details", {})
        self._add_row_2col(self.table_osint_ip_details, "Target IP Address", details.get("target_ip", "N/A"))
        self._add_row_2col(self.table_osint_ip_details, "Target Hostname", details.get("hostname", "N/A"))
        self._add_row_2col(self.table_osint_ip_details, "Reverse DNS (PTR)", details.get("reverse_dns", "N/A"))
        self._add_row_2col(self.table_osint_ip_details, "Scope / Classification", details.get("ip_type", "N/A"))
        self._add_row_2col(self.table_osint_ip_details, "IP Version", details.get("ip_version", "IPv4"))
        self._add_row_2col(self.table_osint_ip_details, "Bogon Status", details.get("bogon_status", "Legitimate Routable"))

        self.table_osint_ip_origins.setRowCount(0)
        origins = recon.get("ip_origins", {})
        self._add_row_2col(self.table_osint_ip_origins, "Origin Country", f"{origins.get('country', 'Unknown')} ({origins.get('country_code', '--')})")
        self._add_row_2col(self.table_osint_ip_origins, "Region / City", f"{origins.get('city', 'Unknown')}, {origins.get('region', '')}")
        self._add_row_2col(self.table_osint_ip_origins, "GPS Coordinates", origins.get("coordinates", "N/A"))
        self._add_row_2col(self.table_osint_ip_origins, "Timezone", origins.get("timezone", "UTC"))
        self._add_row_2col(self.table_osint_ip_origins, "ISP / Organization", f"{origins.get('isp', 'N/A')} / {origins.get('org', 'N/A')}")
        self._add_row_2col(self.table_osint_ip_origins, "Public Origin Gateway IP", origins.get("public_origin_ip", origins.get("ip", "N/A")))
        self._add_row_2col(self.table_osint_ip_origins, "Hosting / VPN / Proxy", "⚠️ YES (Datacenter / Proxy IP)" if origins.get("is_vpn_or_hosting") else "🛡️ NO (Residential / Direct Origin)")

        self.table_osint_ip_routes.setRowCount(0)
        routes = recon.get("ip_routes", {})
        self._add_row_2col(self.table_osint_ip_routes, "Autonomous System (ASN)", f"{routes.get('asn', 'N/A')} ({routes.get('as_name', 'N/A')})")
        self._add_row_2col(self.table_osint_ip_routes, "BGP Routing CIDR", routes.get("bgp_prefix", "N/A"))
        self._add_row_2col(self.table_osint_ip_routes, "Default Gateway", routes.get("default_gateway", "127.0.0.1"))
        for idx, r in enumerate(routes.get("active_system_routes", [])[:6]):
            self._add_row_2col(self.table_osint_ip_routes, f"Active Route [{idx}]", f"Dest: {r.get('destination')} | Mask: {r.get('netmask')} | Gateway: {r.get('gateway')} | Iface: {r.get('interface')}")

        self.table_osint_ip_tables.setRowCount(0)
        tables = recon.get("ip_tables", {})
        self._add_row_2col(self.table_osint_ip_tables, "Linux iptables Drop", tables.get("iptables_drop", "N/A"))
        self._add_row_2col(self.table_osint_ip_tables, "Linux nftables Drop", tables.get("nftables_drop", "N/A"))
        self._add_row_2col(self.table_osint_ip_tables, "Windows PowerShell Block", tables.get("powershell_block", "N/A"))
        self._add_row_2col(self.table_osint_ip_tables, "Nginx Deny Rule", tables.get("nginx_deny", "N/A"))
        self._add_row_2col(self.table_osint_ip_tables, "Apache Deny Rule", tables.get("apache_deny", "N/A"))
        for iface in tables.get("active_interfaces", [])[:4]:
            self._add_row_2col(self.table_osint_ip_tables, f"Interface: {iface.get('name')}", f"IP: {iface.get('ip')} | MAC: {iface.get('mac')}")

        # 1. Populate DNS Table
        self.table_osint_dns.setRowCount(0)
        dns = recon.get("dns", {})
        for ip in dns.get("ipv4_addresses", []):
            self._add_dns_row("A (IPv4)", ip, "Primary Public/Local Host IP Address")
        for ip in dns.get("ipv6_addresses", []):
            self._add_dns_row("AAAA (IPv6)", ip, "Next-Gen IP Address")
        if dns.get("reverse_dns") and dns["reverse_dns"] != "None":
            self._add_dns_row("PTR (rDNS)", dns["reverse_dns"], "Reverse DNS Validation")
        for mx in dns.get("mx_records", []):
            self._add_dns_row("MX", mx, "Mail Exchange Server")
        if email_data.get("spf_record") != "None":
            self._add_dns_row("TXT (SPF)", email_data["spf_record"], "Sender Policy Framework")
        if email_data.get("dmarc_record") != "None":
            self._add_dns_row("TXT (DMARC)", email_data["dmarc_record"], "DMARC Phishing Defense")
        for ns in dns.get("ns_records", []):
            self._add_dns_row("NS", ns, "Authoritative Nameserver")

        # 2. Populate SSL Table
        self.table_osint_ssl.setRowCount(0)
        if ssl_data.get("valid"):
            self._add_ssl_row("Validation Status", "VALID", "TLS Handshake Successful")
            issuer = ssl_data.get("issuer", {})
            self._add_ssl_row("Issuer Authority", issuer.get("organizationName", issuer.get("commonName", "Unknown")), "Certificate Authority")
            subject = ssl_data.get("subject", {})
            self._add_ssl_row("Subject CN", subject.get("commonName", "Unknown"), "Target Domain Identity")
            self._add_ssl_row("Cipher Suite", ssl_data.get("cipher", "Unknown"), "Cryptographic Algorithm")
            self._add_ssl_row("TLS Protocol", ssl_data.get("tls_version", "Unknown"), "Security Standard")
            self._add_ssl_row("Expiration Date", f"{ssl_data.get('valid_until')} ({ssl_data.get('expires_in_days')} days left)", "Certificate Life")
        else:
            self._add_ssl_row("Status", "No SSL / Inactive", "Target does not serve TLS on port 443")

        # 3. Populate Subdomains Table
        self.table_osint_subs.setRowCount(0)
        for s in subs:
            r = self.table_osint_subs.rowCount()
            self.table_osint_subs.insertRow(r)
            self.table_osint_subs.setItem(r, 0, QTableWidgetItem(s))
            self.table_osint_subs.setItem(r, 1, QTableWidgetItem("Crt.sh CT Logs / SAN"))

        # 4. Populate BGP & Network Table
        self.table_osint_bgp.setRowCount(0)
        bgp = recon.get("network_routing", {})
        self._add_bgp_row("Primary Target IP", bgp.get("ip", "N/A"))
        self._add_bgp_row("Autonomous System (ASN)", bgp.get("asn", "N/A"))
        self._add_bgp_row("Internet Service Provider (ISP)", bgp.get("isp", "N/A"))
        self._add_bgp_row("Organization", bgp.get("org", "N/A"))
        self._add_bgp_row("Geographic Location", f"{bgp.get('city')}, {bgp.get('country')}")
        self._add_bgp_row("Hosting / VPN Detection", "Yes (Datacenter / Proxy IP)" if bgp.get("is_vpn_or_hosting") else "No (Residential/Origin)")

        # 5. Populate Tech Stack Table
        self.table_osint_tech.setRowCount(0)
        tech = recon.get("technologies", {})
        self._add_tech_row("Edge CDN / Cloud WAF", tech.get("cdn_waf", "Direct Origin"))
        self._add_tech_row("Server Header Banner", tech.get("server_banner", "Hidden"))
        self._add_tech_row("X-Powered-By Header", tech.get("powered_by", "Hidden"))
        fws = ", ".join(tech.get("detected_frameworks", [])) or "None Detected"
        self._add_tech_row("Web Frameworks Fingerprinted", fws)
        sec_txt = recon.get("security_txt", {})
        self._add_tech_row("RFC 9116 security.txt", "Present (Compliance Verified)" if sec_txt.get("present") else "Missing")

        # 6. Populate Threat Pivots
        pivots_text = f"EXTERNAL THREAT INTELLIGENCE PIVOTS FOR: {recon.get('target')}\n"
        pivots_text += "=" * 65 + "\n\n"
        for name, link in recon.get("external_intelligence_links", {}).items():
            pivots_text += f"[{name}]\n  --> {link}\n\n"
        self.txt_pivots.setPlainText(pivots_text)

        self.terminal.log(f"Passive OSINT completed for {recon.get('target')}. Subdomains: {len(subs)}, Risk: {risk}.", "PASS")

    def _add_dns_row(self, rtype: str, val: str, purp: str):
        r = self.table_osint_dns.rowCount()
        self.table_osint_dns.insertRow(r)
        self.table_osint_dns.setItem(r, 0, QTableWidgetItem(rtype))
        self.table_osint_dns.setItem(r, 1, QTableWidgetItem(val))
        self.table_osint_dns.setItem(r, 2, QTableWidgetItem(purp))

    def _add_ssl_row(self, param: str, val: str, note: str):
        r = self.table_osint_ssl.rowCount()
        self.table_osint_ssl.insertRow(r)
        self.table_osint_ssl.setItem(r, 0, QTableWidgetItem(param))
        self.table_osint_ssl.setItem(r, 1, QTableWidgetItem(val))
        self.table_osint_ssl.setItem(r, 2, QTableWidgetItem(note))

    def _add_bgp_row(self, param: str, val: str):
        r = self.table_osint_bgp.rowCount()
        self.table_osint_bgp.insertRow(r)
        self.table_osint_bgp.setItem(r, 0, QTableWidgetItem(param))
        self.table_osint_bgp.setItem(r, 1, QTableWidgetItem(val))

    def _add_tech_row(self, comp: str, tech: str):
        r = self.table_osint_tech.rowCount()
        self.table_osint_tech.insertRow(r)
        self.table_osint_tech.setItem(r, 0, QTableWidgetItem(comp))
        self.table_osint_tech.setItem(r, 1, QTableWidgetItem(tech))

    def _add_row_2col(self, table: QTableWidget, col1: str, col2: str):
        r = table.rowCount()
        table.insertRow(r)
        table.setItem(r, 0, QTableWidgetItem(col1))
        table.setItem(r, 1, QTableWidgetItem(str(col2)))

    def start_master_scan(self):
        """Runs the complete defensive audit across all panels: Web Audit, OSINT, Ports, Malware, Injection, Server Integrity, and Sample Logs."""
        self.terminal.log("🚀 MASTER DEFENSE SCAN ENGAGED: Executing comprehensive audit across all panels...", "INFO")
        self.start_audit()
        self._sync_osint_target()
        self.start_osint_recon()
        self.scan_ports()
        self.start_malware_scan()
        self.start_injection_audit()
        self.start_server_audit()
        self._load_sample_logs()
        self.terminal.log("✅ Master defense scan initiated across all panels.", "PASS")

    def _copy_subdomains_to_clipboard(self):
        if not self.last_osint or not self.last_osint.get("subdomains_discovered"):
            QMessageBox.information(self, "No Subdomains", "Run an OSINT reconnaissance first.")
            return
        subs = "\n".join(self.last_osint.get("subdomains_discovered", []))
        QApplication.clipboard().setText(subs)
        self.terminal.log("Copied all discovered subdomains to clipboard.", "PASS")
        QMessageBox.information(self, "Copied", f"Copied {len(self.last_osint['subdomains_discovered'])} subdomains to clipboard!")

    # -------------------------------------------------------------
    # Category 3: Malware & Web Shell Scanner
    # -------------------------------------------------------------
    def _build_malware_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Top controls
        top_frame = QFrame()
        top_frame.setObjectName("hudPanel")
        top_layout = QHBoxLayout(top_frame)
        top_layout.setContentsMargins(10, 8, 10, 8)

        lbl = QLabel("PROJECT / WEBSITE DIRECTORY PATH:")
        lbl.setStyleSheet("color: #FF3366; font-weight: bold; font-size: 11px;")
        top_layout.addWidget(lbl)

        self.txt_malware_dir = QLineEdit(".")
        self.txt_malware_dir.setPlaceholderText("Path to website root or uploads folder (e.g., C:/www/html, ./uploads)")
        self.txt_malware_dir.setFixedHeight(30)
        top_layout.addWidget(self.txt_malware_dir, stretch=1)

        btn_browse = QPushButton("📁 Browse...")
        btn_browse.clicked.connect(self._browse_malware_dir)
        top_layout.addWidget(btn_browse)

        btn_preset_cur = QPushButton("Current Directory")
        btn_preset_cur.clicked.connect(lambda: self.txt_malware_dir.setText("."))
        top_layout.addWidget(btn_preset_cur)

        btn_scan_malware = QPushButton("🔍 SCAN PATHS FOR MALWARE / WEBSHELLS")
        btn_scan_malware.setObjectName("btnDanger")
        btn_scan_malware.setFixedHeight(30)
        btn_scan_malware.clicked.connect(self.start_malware_scan)
        top_layout.addWidget(btn_scan_malware)

        layout.addWidget(top_frame)

        # Telemetry cards
        cards_row = QHBoxLayout()
        self.malware_card_status = TelemetryCard("Infection Status", "CLEAN", "System Posture", "#00FF88")
        self.malware_card_threats = TelemetryCard("Threats Detected", "0", "Backdoors & Web Shells", "#FF3366")
        self.malware_card_scanned = TelemetryCard("Files Scanned", "0", "Total Inspected Paths", "#00F0FF")

        cards_row.addWidget(self.malware_card_status)
        cards_row.addWidget(self.malware_card_threats)
        cards_row.addWidget(self.malware_card_scanned)
        layout.addLayout(cards_row)

        # Splitter: Table of infected files on Left, Remediation / Quarantine action on Right
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Table
        pnl_left = QFrame()
        pnl_left.setObjectName("hudPanel")
        left_layout = QVBoxLayout(pnl_left)
        left_layout.addWidget(QLabel("DETECTED SUSPICIOUS / INFECTED WEBSITE PATHS:"))

        self.table_malware = QTableWidget(0, 5)
        self.table_malware.setHorizontalHeaderLabels([
            "SEVERITY", "INFECTED FILE PATH / DIRECTORY [SUSPICIOUS]", "THREAT CLASSIFICATION", "LINE #", "MALICIOUS CODE / PARAMETER"
        ])
        self.table_malware.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_malware.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_malware.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_malware.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_malware.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_malware.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_malware.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_malware.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_malware.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_malware.itemSelectionChanged.connect(self._on_malware_selected)

        left_layout.addWidget(self.table_malware)
        splitter.addWidget(pnl_left)

        # Right: Quarantine & Action Panel
        pnl_right = QFrame()
        pnl_right.setObjectName("hudPanel")
        right_layout = QVBoxLayout(pnl_right)
        
        lbl_act = QLabel("MALWARE DEFENSE & REMEDIATION ACTIONS")
        lbl_act.setStyleSheet("color: #FF3366; font-weight: bold;")
        right_layout.addWidget(lbl_act)

        act_btn_row = QHBoxLayout()
        btn_quarantine = QPushButton("🔒 QUARANTINE SELECTED FILE")
        btn_quarantine.setObjectName("btnDanger")
        btn_quarantine.clicked.connect(self._quarantine_selected_malware)
        btn_remove = QPushButton("🗑️ PERMANENTLY REMOVE")
        btn_remove.clicked.connect(self._remove_selected_malware)
        act_btn_row.addWidget(btn_quarantine)
        act_btn_row.addWidget(btn_remove)
        right_layout.addLayout(act_btn_row)

        self.txt_malware_log = QTextEdit()
        self.txt_malware_log.setReadOnly(True)
        self.txt_malware_log.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_malware_log.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_malware_log.setPlaceholderText("Select an infected file from the table to view remediation actions, or view anti-execution web server rules below...")
        right_layout.addWidget(self.txt_malware_log)

        splitter.addWidget(pnl_right)
        splitter.setSizes([700, 480])
        layout.addWidget(splitter, stretch=1)

        return widget

    def _browse_malware_dir(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Website Root or Uploads Directory", ".")
        if folder:
            self.txt_malware_dir.setText(folder)

    def start_malware_scan(self):
        target_dir = self.txt_malware_dir.text().strip() or "."
        self.lbl_status.setText(f"SCANNING DIRECTORY FOR MALWARE & WEB SHELLS: {target_dir}...")
        self.progress_bar.setValue(20)
        self.terminal.log(f"Initiating malware path scanner on: {target_dir}", "INFO")

        self.malware_worker = MalwareScanWorker(target_dir)
        self.malware_worker.progress.connect(self._on_audit_progress)
        self.malware_worker.finished.connect(self._on_malware_finished)
        self.malware_worker.error.connect(self._on_audit_error)
        self.malware_worker.start()

    def _on_malware_finished(self, result: dict):
        self.last_malware_scan = result
        self.progress_bar.setValue(100)
        inf_count = result.get("infected_files_count", 0)
        scanned_count = result.get("scanned_files_count", 0)

        self.lbl_status.setText(f"MALWARE SCAN COMPLETE // {scanned_count} FILES SCANNED // {inf_count} THREATS FOUND")
        self.malware_card_scanned.set_value(str(scanned_count), "Files Checked")
        self.malware_card_threats.set_value(str(inf_count), "Infected Paths")

        if inf_count > 0:
            self.malware_card_status.set_value("INFECTED", "Action Required")
            self.malware_card_status.lbl_value.setStyleSheet("color: #FF3366; font-size: 20px; font-weight: bold;")
        else:
            self.malware_card_status.set_value("CLEAN", "No Web Shells")
            self.malware_card_status.lbl_value.setStyleSheet("color: #00FF88; font-size: 20px; font-weight: bold;")

        self.table_malware.setRowCount(0)
        for inf in result.get("infected_files", []):
            r = self.table_malware.rowCount()
            self.table_malware.insertRow(r)

            sev = inf["severity"].upper()
            sev_item = QTableWidgetItem(sev)
            col = "#FF3366" if sev == "CRITICAL" else "#FFB800"
            sev_item.setForeground(QColor(col))
            sev_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))

            path_item = QTableWidgetItem(f"🚨 {inf['relative_path']}")
            path_item.setForeground(QColor("#FF3366"))
            path_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))

            self.table_malware.setItem(r, 0, sev_item)
            self.table_malware.setItem(r, 1, path_item)
            self.table_malware.setItem(r, 2, QTableWidgetItem(inf["threat_type"]))
            self.table_malware.setItem(r, 3, QTableWidgetItem(str(inf.get("matched_line", 1))))
            self.table_malware.setItem(r, 4, QTableWidgetItem(inf.get("code_snippet", "Disguised File Extension")))

        # Show Anti-execution configs in log box
        rules = MalwareScanner.generate_anti_execution_config()
        guide = f"""=====================================================
MALWARE & SUSPICIOUS PATH SCAN SUMMARY:
=====================================================
Total Files Inspected: {scanned_count}
Infected Files Found:  {inf_count}
Scan Status:           {result.get('status')}

RECOMMENDED DEFENSIVE ANTI-EXECUTION RULES:
Deploy these rules in your Nginx or Apache server to block
attackers from executing uploaded PHP/CGI scripts in upload folders:

[NGINX CONFIGURATION]
{rules['nginx']}

[APACHE .HTACCESS (Place in /uploads/)]
{rules['apache']}
"""
        self.txt_malware_log.setPlainText(guide)
        self.terminal.log(f"Malware scan finished: {inf_count} suspicious files identified out of {scanned_count}.", "WARN" if inf_count > 0 else "PASS")

    def _on_malware_selected(self):
        idxs = self.table_malware.selectedIndexes()
        if not idxs or not self.last_malware_scan:
            return
        row = idxs[0].row()
        files = self.last_malware_scan.get("infected_files", [])
        if row < len(files):
            inf = files[row]
            detail = f"""=====================================================
INFECTED FILE TELEMETRY:
=====================================================
File Path:     {inf['file_path']}
Severity:      {inf['severity'].upper()}
Threat Name:   {inf['threat_type']}
Signature ID:  {inf['matched_signature']}
Line Number:   {inf.get('matched_line', 'N/A')}

[EXTRACTED CODE SNIPPET]
{inf.get('code_snippet', 'No code snippet (Double extension threat)')}

[RECOMMENDED ACTION]
{inf.get('remediation')}

Click 'QUARANTINE SELECTED FILE' to safely isolate this file with
read-only non-executable permissions into .aegis_quarantine/.
"""
            self.txt_malware_log.setPlainText(detail)

    def _quarantine_selected_malware(self):
        idxs = self.table_malware.selectedIndexes()
        if not idxs or not self.last_malware_scan:
            QMessageBox.information(self, "No Selection", "Please select an infected file from the table first.")
            return
        row = idxs[0].row()
        files = self.last_malware_scan.get("infected_files", [])
        if row < len(files):
            fpath = files[row]["file_path"]
            res = self.scanner_engine.quarantine_file(fpath)
            if res.get("success"):
                QMessageBox.information(self, "Quarantine Success", res["message"])
                self.terminal.log(f"Quarantined infected file: {fpath}", "PASS")
                self.start_malware_scan()
            else:
                QMessageBox.critical(self, "Quarantine Failed", res.get("error", "Unknown error"))

    def _remove_selected_malware(self):
        idxs = self.table_malware.selectedIndexes()
        if not idxs or not self.last_malware_scan:
            QMessageBox.information(self, "No Selection", "Please select an infected file from the table first.")
            return
        row = idxs[0].row()
        files = self.last_malware_scan.get("infected_files", [])
        if row < len(files):
            fpath = files[row]["file_path"]
            confirm = QMessageBox.question(self, "Confirm Delete", f"Are you sure you want to permanently delete:\n{fpath}?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if confirm == QMessageBox.StandardButton.Yes:
                res = self.scanner_engine.remove_file(fpath)
                if res.get("success"):
                    QMessageBox.information(self, "Deleted", res["message"])
                    self.terminal.log(f"Permanently removed malicious file: {fpath}", "PASS")
                    self.start_malware_scan()
                else:
                    QMessageBox.critical(self, "Delete Failed", res.get("error", "Unknown error"))

    # -------------------------------------------------------------
    # Category 4: Anti-XSS & Data Injection Defense
    # -------------------------------------------------------------
    def _build_injection_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Top controls
        top_frame = QFrame()
        top_frame.setObjectName("hudPanel")
        top_layout = QHBoxLayout(top_frame)
        top_layout.setContentsMargins(10, 8, 10, 8)

        lbl = QLabel("TARGET WEB APPLICATION:")
        lbl.setStyleSheet("color: #00F0FF; font-weight: bold; font-size: 11px;")
        top_layout.addWidget(lbl)

        self.txt_inj_target = QLineEdit("http://127.0.0.1:8000")
        self.txt_inj_target.setFixedHeight(30)
        top_layout.addWidget(self.txt_inj_target, stretch=1)

        btn_sync = QPushButton("Sync Current Target")
        btn_sync.clicked.connect(lambda: self.txt_inj_target.setText(self.txt_target.text().strip()))
        top_layout.addWidget(btn_sync)

        btn_audit_inj = QPushButton("💉 AUDIT ANTI-XSS & SCRIPT EXECUTION DEFENSES")
        btn_audit_inj.setObjectName("btnPrimary")
        btn_audit_inj.setFixedHeight(30)
        btn_audit_inj.clicked.connect(self.start_injection_audit)
        top_layout.addWidget(btn_audit_inj)

        layout.addWidget(top_frame)

        # Telemetry cards
        cards_row = QHBoxLayout()
        self.inj_card_posture = TelemetryCard("Script Defense Posture", "STANDBY", "Overall Security", "#00FF88")
        self.inj_card_csp = TelemetryCard("Content-Security-Policy", "STANDBY", "Script Execution Policy", "#00F0FF")
        self.inj_card_nosniff = TelemetryCard("MIME Sniffing Defense", "STANDBY", "X-Content-Type-Options", "#FFB800")
        self.inj_card_clickjack = TelemetryCard("Frame Ancestors", "STANDBY", "Clickjacking Defense", "#00F0FF")

        cards_row.addWidget(self.inj_card_posture)
        cards_row.addWidget(self.inj_card_csp)
        cards_row.addWidget(self.inj_card_nosniff)
        cards_row.addWidget(self.inj_card_clickjack)
        layout.addLayout(cards_row)

        # Splitter: Left Table of findings, Right Generated CSP & Sanitization rules
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Findings
        pnl_left = QFrame()
        pnl_left.setObjectName("hudPanel")
        left_layout = QVBoxLayout(pnl_left)
        left_layout.addWidget(QLabel("SCRIPT EXECUTION & INJECTION AUDIT TELEMETRY:"))

        self.table_inj = QTableWidget(0, 4)
        self.table_inj.setHorizontalHeaderLabels(["DEFENSE", "STATUS", "ISSUE DETECTED", "RECOMMENDED MITIGATION"])
        self.table_inj.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_inj.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_inj.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_inj.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table_inj.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_inj.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_inj.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_inj.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        left_layout.addWidget(self.table_inj)
        splitter.addWidget(pnl_left)

        # Right: Hardened Protection Code
        pnl_right = QFrame()
        pnl_right.setObjectName("hudPanel")
        right_layout = QVBoxLayout(pnl_right)
        
        lbl_code = QLabel("HARDENED ANTI-XSS & ANTI-INJECTION SHIELD CODE:")
        lbl_code.setStyleSheet("color: #00FF88; font-weight: bold;")
        right_layout.addWidget(lbl_code)

        inj_subtabs = QTabWidget()
        
        # Sub-tab 1: CSP Header
        tab_csp = QWidget()
        csp_layout = QVBoxLayout(tab_csp)
        self.txt_gen_csp = QTextEdit()
        self.txt_gen_csp.setReadOnly(True)
        self.txt_gen_csp.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_gen_csp.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        csp = InjectionDefenseEngine.generate_bulletproof_csp()
        self.txt_gen_csp.setPlainText(f"// Strict Production CSP:\nContent-Security-Policy: {csp['strict_production']}\n\n// Balanced CDN CSP:\nContent-Security-Policy: {csp['balanced_cdn']}")
        csp_layout.addWidget(self.txt_gen_csp)
        inj_subtabs.addTab(tab_csp, "🔒 STRICT CSP HEADER")

        # Sub-tab 2: Python Defense Code
        tab_py = QWidget()
        py_layout = QVBoxLayout(tab_py)
        txt_py = QTextEdit()
        txt_py.setReadOnly(True)
        txt_py.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        txt_py.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        txt_py.setPlainText(InjectionDefenseEngine.generate_anti_injection_code("python"))
        py_layout.addWidget(txt_py)
        inj_subtabs.addTab(tab_py, "🐍 PYTHON (FLASK/FASTAPI)")

        # Sub-tab 3: Node.js Defense Code
        tab_js = QWidget()
        js_layout = QVBoxLayout(tab_js)
        txt_js = QTextEdit()
        txt_js.setReadOnly(True)
        txt_js.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        txt_js.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        txt_js.setPlainText(InjectionDefenseEngine.generate_anti_injection_code("javascript"))
        js_layout.addWidget(txt_js)
        inj_subtabs.addTab(tab_js, "⚡ NODE.JS (EXPRESS)")

        # Sub-tab 4: ModSecurity WAF
        tab_waf = QWidget()
        waf_layout = QVBoxLayout(tab_waf)
        txt_waf = QTextEdit()
        txt_waf.setReadOnly(True)
        txt_waf.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        txt_waf.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        txt_waf.setPlainText(InjectionDefenseEngine.generate_modsecurity_waf_rules())
        waf_layout.addWidget(txt_waf)
        inj_subtabs.addTab(tab_waf, "🛡️ MODSECURITY WAF RULES")

        right_layout.addWidget(inj_subtabs)
        splitter.addWidget(pnl_right)
        splitter.setSizes([650, 520])

        layout.addWidget(splitter, stretch=1)
        return widget

    def start_injection_audit(self):
        target = self.txt_inj_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Invalid URL", "Please enter a target web application URL.")
            return

        self.lbl_status.setText(f"AUDITING ANTI-XSS & DATA INJECTION DEFENSES: {target}...")
        self.progress_bar.setValue(30)
        self.terminal.log(f"Auditing script execution and XSS defenses for: {target}", "INFO")

        self.inj_worker = InjectionAuditWorker(target)
        self.inj_worker.progress.connect(self._on_audit_progress)
        self.inj_worker.finished.connect(self._on_injection_finished)
        self.inj_worker.error.connect(self._on_audit_error)
        self.inj_worker.start()

    def _on_injection_finished(self, result: dict):
        self.progress_bar.setValue(100)
        score = result.get("xss_defense_score", 100)
        status = result.get("overall_status", "Secure")
        self.lbl_status.setText(f"ANTI-XSS AUDIT COMPLETE // SCORE: {score}/100 // STATUS: {status.upper()}")

        col = "#00FF88" if score >= 85 else ("#FFB800" if score >= 60 else "#FF3366")
        self.inj_card_posture.set_value(f"{score}/100", status)
        self.inj_card_posture.lbl_value.setStyleSheet(f"color: {col}; font-size: 20px; font-weight: bold;")

        findings = result.get("findings", [])
        self.table_inj.setRowCount(0)

        for f in findings:
            r = self.table_inj.rowCount()
            self.table_inj.insertRow(r)

            sev = f["status"].upper()
            sev_item = QTableWidgetItem(sev)
            s_col = "#FF3366" if "CRITICAL" in sev else ("#FFB800" if "WARNING" in sev or "HIGH" in sev else "#00F0FF")
            sev_item.setForeground(QColor(s_col))
            sev_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))

            self.table_inj.setItem(r, 0, QTableWidgetItem(f["defense"]))
            self.table_inj.setItem(r, 1, sev_item)
            self.table_inj.setItem(r, 2, QTableWidgetItem(f["issue"]))
            self.table_inj.setItem(r, 3, QTableWidgetItem(f["mitigation"]))

        self.terminal.log(f"Anti-XSS & Script Execution audit finished for {result.get('target')}. Score: {score}/100.", "PASS" if score >= 80 else "WARN")

    # -------------------------------------------------------------
    # Category 5: Localhost Ports & Server Machine Auditor
    # -------------------------------------------------------------
    def _build_ports_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        ports_subtabs = QTabWidget()

        # ---------------- Sub-tab 1: Sockets & Open Ports ----------------
        tab_sockets = QWidget()
        sock_layout = QVBoxLayout(tab_sockets)
        sock_layout.setContentsMargins(8, 8, 8, 8)
        sock_layout.setSpacing(8)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)
        lbl_info = QLabel("ACTIVE LISTENING SOCKETS & ACCIDENTAL EXPOSURE AUDIT")
        lbl_info.setStyleSheet("color: #00F0FF; font-weight: bold;")
        btn_refresh = QPushButton("🔄 SCAN LOCAL PORTS NOW")
        btn_refresh.setFixedHeight(28)
        btn_refresh.clicked.connect(self.scan_ports)

        top_row.addWidget(lbl_info)
        top_row.addStretch()
        top_row.addWidget(btn_refresh)
        sock_layout.addLayout(top_row)

        self.table_ports = QTableWidget(0, 6)
        self.table_ports.setHorizontalHeaderLabels(["PORT", "INTERFACE BINDING", "PROCESS", "PID", "RISK LEVEL", "DEFENSIVE STATUS & REMEDIATION"])
        self.table_ports.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table_ports.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_ports.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_ports.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_ports.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        sock_layout.addWidget(self.table_ports)

        ports_subtabs.addTab(tab_sockets, "📡 ACTIVE LISTENING PORTS & BINDINGS")

        # ---------------- Sub-tab 2: Host Server & Computer Machine Auditor ----------------
        tab_server = QWidget()
        srv_layout = QVBoxLayout(tab_server)
        srv_layout.setContentsMargins(8, 8, 8, 8)
        srv_layout.setSpacing(8)

        srv_top = QHBoxLayout()
        srv_top.setSpacing(8)
        lbl_srv = QLabel("SERVER MACHINE / COMPUTER MALWARE, MINERS & ROOTKIT AUDITOR")
        lbl_srv.setStyleSheet("color: #00FF88; font-weight: bold;")
        btn_scan_srv = QPushButton("💻 RUN FULL SYSTEM & SERVER INTEGRITY SCAN")
        btn_scan_srv.setObjectName("btnDanger")
        btn_scan_srv.setFixedHeight(28)
        btn_scan_srv.clicked.connect(self.start_server_audit)

        srv_top.addWidget(lbl_srv)
        srv_top.addStretch()
        srv_top.addWidget(btn_scan_srv)
        srv_layout.addLayout(srv_top)

        # Server telemetry cards
        srv_cards = QHBoxLayout()
        self.server_card_status = TelemetryCard("Infection Status", "READY", "Host Health", "#00FF88")
        self.server_card_procs = TelemetryCard("Suspicious Processes", "0", "Rogue PIDs", "#FF3366")
        self.server_card_scanned = TelemetryCard("Processes Checked", "0", "Running Tasks", "#00F0FF")

        srv_cards.addWidget(self.server_card_status)
        srv_cards.addWidget(self.server_card_procs)
        srv_cards.addWidget(self.server_card_scanned)
        srv_layout.addLayout(srv_cards)

        srv_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Server threats table
        pnl_srv_left = QFrame()
        pnl_srv_left.setObjectName("hudPanel")
        sl_layout = QVBoxLayout(pnl_srv_left)
        sl_layout.addWidget(QLabel("DETECTED ROGUE PROCESSES, SUSPICIOUS SOCKETS & TEMP DROPS:"))

        self.table_server_threats = QTableWidget(0, 5)
        self.table_server_threats.setHorizontalHeaderLabels(["SEVERITY", "COMPONENT / INFECTED TARGET", "THREAT CLASSIFICATION", "DETECTION REASON", "METADATA / CMDLINE"])
        self.table_server_threats.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_server_threats.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_server_threats.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_server_threats.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table_server_threats.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_server_threats.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_server_threats.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_server_threats.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_server_threats.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        sl_layout.addWidget(self.table_server_threats)
        srv_splitter.addWidget(pnl_srv_left)

        # Right: Server telemetry & action
        pnl_srv_right = QFrame()
        pnl_right.setObjectName("hudPanel")
        sr_layout = QVBoxLayout(pnl_srv_right)
        sr_layout.addWidget(QLabel("HOST INTEGRITY TELEMETRY & REMEDIATION:"))

        self.txt_server_log = QTextEdit()
        self.txt_server_log.setReadOnly(True)
        self.txt_server_log.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_server_log.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_server_log.setPlaceholderText("Click 'RUN FULL SYSTEM & SERVER INTEGRITY SCAN' to audit running processes, cryptominers, reverse shells, and persistence mechanisms...")
        sr_layout.addWidget(self.txt_server_log)

        btn_kill_proc = QPushButton("⚡ TERMINATE SELECTED ROGUE PROCESS (KILL PID)")
        btn_kill_proc.setObjectName("btnDanger")
        btn_kill_proc.setFixedHeight(28)
        btn_kill_proc.clicked.connect(self._kill_selected_server_process)
        sr_layout.addWidget(btn_kill_proc)

        srv_splitter.addWidget(pnl_srv_right)
        srv_splitter.setSizes([650, 480])

        srv_layout.addWidget(srv_splitter, stretch=1)
        ports_subtabs.addTab(tab_server, "💻 HOST COMPUTER / SERVER ROOTKIT AUDITOR")

        layout.addWidget(ports_subtabs)
        return widget

    def start_server_audit(self):
        self.lbl_status.setText("AUDITING SERVER MACHINE INTEGRITY & HOST PROCESSES...")
        self.progress_bar.setValue(30)
        self.terminal.log("Scanning host machine for cryptominers, reverse shells, and persistence...", "INFO")
        self.server_worker = ServerAuditWorker()
        self.server_worker.finished.connect(self._on_server_audit_finished)
        self.server_worker.error.connect(self._on_audit_error)
        self.server_worker.start()

    def _on_server_audit_finished(self, report: dict):
        self.progress_bar.setValue(100)
        status = report.get("infection_status", "UNKNOWN")
        score = report.get("system_health_score", 100)
        self.lbl_status.setText(f"SERVER AUDIT COMPLETE // STATUS: {status} // HEALTH: {score}/100")
        
        self.server_card_status.set_value(f"{score}/100", status)
        col = "#00FF88" if score >= 85 else ("#FFB800" if score >= 60 else "#FF3366")
        self.server_card_status.lbl_value.setStyleSheet(f"color: {col}; font-size: 20px; font-weight: bold;")
        
        procs = report.get("suspicious_processes", [])
        self.server_card_procs.set_value(str(len(procs)), "Suspicious PIDs")
        scanned_count = report["summary"].get("processes_scanned", 0)
        self.server_card_scanned.set_value(str(scanned_count), "Running Tasks")
        
        self.table_server_threats.setRowCount(0)
        # 1. Suspicious processes
        for p in procs:
            r = self.table_server_threats.rowCount()
            self.table_server_threats.insertRow(r)
            sev_item = QTableWidgetItem(p["severity"])
            sev_item.setForeground(QColor("#FF3366" if p["severity"] == "CRITICAL" else "#FFB800"))
            sev_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            
            comp_item = QTableWidgetItem(f"PROCESS: {p['name']} (PID: {p['pid']})")
            comp_item.setForeground(QColor("#FF3366"))
            comp_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            
            self.table_server_threats.setItem(r, 0, sev_item)
            self.table_server_threats.setItem(r, 1, comp_item)
            self.table_server_threats.setItem(r, 2, QTableWidgetItem(p["threat_type"]))
            self.table_server_threats.setItem(r, 3, QTableWidgetItem(p["details"]))
            self.table_server_threats.setItem(r, 4, QTableWidgetItem(p.get("cmdline", "")))

        # 2. Rogue connections
        for c in report.get("rogue_connections", []):
            r = self.table_server_threats.rowCount()
            self.table_server_threats.insertRow(r)
            sev_item = QTableWidgetItem(c["severity"])
            sev_item.setForeground(QColor("#FF3366"))
            sev_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            
            comp_item = QTableWidgetItem(f"SOCKET: Port {c['local_port']} / Remote {c['remote_ip']}:{c['remote_port']}")
            comp_item.setForeground(QColor("#FF3366"))
            comp_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            
            self.table_server_threats.setItem(r, 0, sev_item)
            self.table_server_threats.setItem(r, 1, comp_item)
            self.table_server_threats.setItem(r, 2, QTableWidgetItem("BACKDOOR SOCKET"))
            self.table_server_threats.setItem(r, 3, QTableWidgetItem(c["threat"]))
            self.table_server_threats.setItem(r, 4, QTableWidgetItem(f"Process: {c['process']} (PID: {c['pid']})"))

        # 3. Temp infections
        for t in report.get("temp_infections", []):
            r = self.table_server_threats.rowCount()
            self.table_server_threats.insertRow(r)
            sev_item = QTableWidgetItem(t["severity"])
            sev_item.setForeground(QColor("#FFB800"))
            sev_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            
            path_item = QTableWidgetItem(f"🚨 {t['file_path']}")
            path_item.setForeground(QColor("#FF3366"))
            path_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            
            self.table_server_threats.setItem(r, 0, sev_item)
            self.table_server_threats.setItem(r, 1, path_item)
            self.table_server_threats.setItem(r, 2, QTableWidgetItem("DROPPED EXECUTABLE"))
            self.table_server_threats.setItem(r, 3, QTableWidgetItem(t["threat"]))
            self.table_server_threats.setItem(r, 4, QTableWidgetItem(f"Size: {t['size_bytes']} bytes"))

        summary_txt = f"""=====================================================
HOST MACHINE / SERVER SECURITY AUDIT REPORT:
=====================================================
Host Name:          {report.get('hostname')}
Operating System:   {report.get('os')}
Infection Status:   {report.get('infection_status')}
Health Score:       {score}/100
Processes Scanned:  {scanned_count}
Threats Detected:   {report['summary'].get('threats_detected')}
Critical Alerts:    {report['summary'].get('critical_alerts')}

[DEFENSIVE RECOMMENDATION]
If any suspicious processes or backdoor connections are detected,
select the row and click 'TERMINATE ROGUE PROCESS' to safely isolate
the system. Ensure all dropped executables in Temp are removed.
"""
        self.txt_server_log.setPlainText(summary_txt)
        self.terminal.log(f"Server system audit finished. Status: {status}.", "PASS" if score >= 80 else "WARN")

    def _kill_selected_server_process(self):
        idxs = self.table_server_threats.selectedIndexes()
        if not idxs:
            QMessageBox.information(self, "No Selection", "Please select a suspicious process row from the table first.")
            return
        row = idxs[0].row()
        target_str = self.table_server_threats.item(row, 1).text()
        if "PID:" not in target_str:
            QMessageBox.information(self, "Not a Process", "Selected item is not a process with a PID.")
            return
        import re
        match = re.search(r"PID:\s*(\d+)", target_str)
        if match:
            pid = int(match.group(1))
            confirm = QMessageBox.question(self, "Confirm Terminate", f"Terminate process PID {pid}?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if confirm == QMessageBox.StandardButton.Yes:
                res = ServerSystemAuditor.kill_process(pid)
                if res.get("success"):
                    QMessageBox.information(self, "Terminated", res["message"])
                    self.terminal.log(f"Terminated rogue process PID {pid}.", "PASS")
                    self.start_server_audit()
                else:
                    QMessageBox.critical(self, "Failed", res.get("error", "Failed to terminate process"))

    # -------------------------------------------------------------
    # Category 6: Attacker Tracking & IDS Handlers
    # -------------------------------------------------------------
    def _build_attackers_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Controls Row
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(8)
        btn_load_file = QPushButton("📁 LOAD ACCESS LOG FILE")
        btn_load_file.setFixedHeight(28)
        btn_load_file.clicked.connect(self._load_log_file)
        btn_sample = QPushButton("⚡ LOAD SAMPLE ATTACK TELEMETRY")
        btn_sample.setFixedHeight(28)
        btn_sample.clicked.connect(self._load_sample_logs)

        ctrl_row.addWidget(QLabel("ATTACKER INTRUSION DETECTION & GEO-INTEL TRACKING:"))
        ctrl_row.addStretch()
        ctrl_row.addWidget(btn_sample)
        ctrl_row.addWidget(btn_load_file)
        layout.addLayout(ctrl_row)

        # Splitter: Table of Attackers on Left, Attacker Dossier on Right
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Attackers Table
        pnl_left = QFrame()
        pnl_left.setObjectName("hudPanel")
        left_layout = QVBoxLayout(pnl_left)
        left_layout.addWidget(QLabel("DETECTED ATTACKER IP ADDRESSES & CLIENT HARDWARE"))

        self.table_attackers = QTableWidget(0, 7)
        self.table_attackers.setHorizontalHeaderLabels(["ATTACKER IP", "GEO / COUNTRY", "CONNECTION TYPE", "DEVICE HARDWARE", "HITS", "SEVERITY", "ATTACK VECTORS"])
        self.table_attackers.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table_attackers.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_attackers.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table_attackers.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_attackers.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_attackers.itemSelectionChanged.connect(self._on_attacker_selected)

        left_layout.addWidget(self.table_attackers)
        splitter.addWidget(pnl_left)

        # Right: Attacker Dossier & Firewall Generator
        pnl_right = QFrame()
        pnl_right.setObjectName("hudPanel")
        right_layout = QVBoxLayout(pnl_right)
        
        lbl_dossier = QLabel("ATTACKER DOSSIER & POLICE EVIDENCE PRESERVATION")
        lbl_dossier.setStyleSheet("color: #FF3366; font-weight: bold;")
        right_layout.addWidget(lbl_dossier)

        self.txt_dossier = QTextEdit()
        self.txt_dossier.setReadOnly(True)
        self.txt_dossier.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_dossier.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_dossier.setPlaceholderText("Select an attacker IP from the table to view intelligence dossier, reverse DNS, device fingerprint, and firewall block rules...")
        right_layout.addWidget(self.txt_dossier)

        btn_copy_rule = QPushButton("📋 COPY FIREWALL BLOCK RULE (POWERSHELL / IPTABLES)")
        btn_copy_rule.setObjectName("btnDanger")
        btn_copy_rule.setFixedHeight(30)
        btn_copy_rule.clicked.connect(self._copy_current_firewall_rule)
        right_layout.addWidget(btn_copy_rule)

        splitter.addWidget(pnl_right)
        splitter.setSizes([680, 480])

        layout.addWidget(splitter, stretch=1)
        return widget

    # -------------------------------------------------------------
    # Category 7: Attack Matrix & How to Fix (All Attacks Dashboard)
    # -------------------------------------------------------------
    def _build_attack_matrix_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Top title banner
        banner = QFrame()
        banner.setObjectName("hudPanel")
        b_layout = QHBoxLayout(banner)
        b_layout.setContentsMargins(10, 8, 10, 8)
        
        lbl_title = QLabel("⚔️ CYBER ATTACK MATRIX & DEFENSE RUNBOOK [ALL ATTACKS & HOW TO FIX]")
        lbl_title.setStyleSheet("color: #00F0FF; font-weight: bold; font-size: 13px; letter-spacing: 1px;")
        b_layout.addWidget(lbl_title)
        b_layout.addStretch()

        btn_lockdown = QPushButton("⚡ ONE-CLICK EMERGENCY FIREWALL DROP SCRIPT")
        btn_lockdown.setObjectName("btnDanger")
        btn_lockdown.setFixedHeight(30)
        btn_lockdown.clicked.connect(self._generate_emergency_lockdown_script)
        b_layout.addWidget(btn_lockdown)

        layout.addWidget(banner)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel: List of all attacks
        pnl_left = QFrame()
        pnl_left.setObjectName("hudPanel")
        left_layout = QVBoxLayout(pnl_left)
        left_layout.setContentsMargins(8, 8, 8, 8)
        
        lbl_list = QLabel("SELECT ATTACK VECTOR TO VIEW DEFENSIVE RUNBOOK:")
        lbl_list.setStyleSheet("color: #8899B5; font-size: 11px; font-weight: bold;")
        left_layout.addWidget(lbl_list)

        self.list_matrix = QListWidget()
        self.list_matrix.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list_matrix.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list_matrix.setStyleSheet("""
            QListWidget {
                background: #070B14;
                border: 1px solid #182338;
                border-radius: 4px;
                color: #CBD5E1;
                font-size: 11.5px;
                padding: 4px;
            }
            QListWidget::item {
                padding: 10px 8px;
                border-bottom: 1px solid #0F172A;
                border-radius: 4px;
            }
            QListWidget::item:hover {
                background: rgba(0, 240, 255, 0.08);
                color: #00F0FF;
            }
            QListWidget::item:selected {
                background: rgba(0, 240, 255, 0.18);
                color: #00F0FF;
                border: 1px solid #00F0FF;
            }
        """)

        for aid, att in ATTACK_MATRIX.items():
            item = QListWidgetItem(f"{att['icon']} {att['name']}  [{att['severity']}]")
            item.setData(Qt.ItemDataRole.UserRole, aid)
            self.list_matrix.addItem(item)

        self.list_matrix.currentRowChanged.connect(self._on_attack_matrix_selected)
        left_layout.addWidget(self.list_matrix)
        splitter.addWidget(pnl_left)

        # Right panel: Detailed guide & fix tabs
        pnl_right = QFrame()
        pnl_right.setObjectName("hudPanel")
        right_layout = QVBoxLayout(pnl_right)
        right_layout.setContentsMargins(10, 8, 10, 8)
        right_layout.setSpacing(8)

        # Header details
        self.lbl_mat_name = QLabel()
        self.lbl_mat_name.setStyleSheet("color: #00F0FF; font-size: 15px; font-weight: bold;")
        right_layout.addWidget(self.lbl_mat_name)

        self.lbl_mat_meta = QLabel()
        self.lbl_mat_meta.setStyleSheet("color: #FFB800; font-size: 11px; font-weight: bold;")
        right_layout.addWidget(self.lbl_mat_meta)

        self.lbl_mat_status = QLabel()
        self.lbl_mat_status.setStyleSheet("padding: 6px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;")
        right_layout.addWidget(self.lbl_mat_status)

        # Tabs for details
        self.tab_mat_details = QTabWidget()

        # Tab 1: Overview & Symptoms
        tab_symptoms = QWidget()
        sym_layout = QVBoxLayout(tab_symptoms)
        self.txt_mat_symptoms = QTextEdit()
        self.txt_mat_symptoms.setReadOnly(True)
        self.txt_mat_symptoms.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_mat_symptoms.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sym_layout.addWidget(self.txt_mat_symptoms)
        self.tab_mat_details.addTab(tab_symptoms, "🔍 OVERVIEW & SYMPTOMS")

        # Tab 2: Immediate Emergency Action
        tab_immediate = QWidget()
        imm_layout = QVBoxLayout(tab_immediate)
        self.txt_mat_immediate = QTextEdit()
        self.txt_mat_immediate.setReadOnly(True)
        self.txt_mat_immediate.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_mat_immediate.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        imm_layout.addWidget(self.txt_mat_immediate)
        self.tab_mat_details.addTab(tab_immediate, "⚡ EMERGENCY ACTION (WHAT TO DO NOW)")

        # Tab 3: Permanent Fix Guide
        tab_perm = QWidget()
        perm_layout = QVBoxLayout(tab_perm)
        self.txt_mat_perm = QTextEdit()
        self.txt_mat_perm.setReadOnly(True)
        self.txt_mat_perm.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_mat_perm.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        perm_layout.addWidget(self.txt_mat_perm)
        self.tab_mat_details.addTab(tab_perm, "🛠️ PERMANENT FIX (HOW TO RESOLVE)")

        # Tab 4: Code Fixes
        tab_codes = QWidget()
        code_layout = QVBoxLayout(tab_codes)
        
        self.combo_code_stack = QComboBox()
        self.combo_code_stack.currentIndexChanged.connect(self._on_mat_code_stack_changed)
        code_layout.addWidget(self.combo_code_stack)

        self.txt_mat_code = QTextEdit()
        self.txt_mat_code.setReadOnly(True)
        self.txt_mat_code.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_mat_code.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        code_layout.addWidget(self.txt_mat_code)

        btn_copy_code = QPushButton("📋 COPY READY-TO-DEPLOY CODE FIX")
        btn_copy_code.setFixedHeight(30)
        btn_copy_code.clicked.connect(lambda: QApplication.clipboard().setText(self.txt_mat_code.toPlainText()))
        code_layout.addWidget(btn_copy_code)

        self.tab_mat_details.addTab(tab_codes, "💻 READY-TO-DEPLOY CODE FIXES")

        right_layout.addWidget(self.tab_mat_details, stretch=1)
        splitter.addWidget(pnl_right)
        splitter.setSizes([340, 800])

        layout.addWidget(splitter, stretch=1)

        # Trigger selection of first item
        if self.list_matrix.count() > 0:
            self.list_matrix.setCurrentRow(0)

        return widget

    def _on_attack_matrix_selected(self, row: int):
        if row < 0 or row >= self.list_matrix.count():
            return
        item = self.list_matrix.item(row)
        aid = item.data(Qt.ItemDataRole.UserRole)
        att = ATTACK_MATRIX.get(aid)
        if not att:
            return

        self.lbl_mat_name.setText(f"{att['icon']} {att['name']}")
        self.lbl_mat_meta.setText(f"CATEGORY: {att['category'].upper()}  |  SEVERITY: {att['severity']}  |  CLASSIFICATION: {att['owasp_cwe']}")

        # Check if active threats match this attack in logs or audit findings
        has_active_threat = False
        if self.current_attackers:
            for attacker in self.current_attackers:
                for vec in attacker.get("attack_types", []):
                    if aid in vec.lower() or vec.lower() in aid:
                        has_active_threat = True
                        break

        if has_active_threat:
            self.lbl_mat_status.setText("🚨 LIVE ATTACK DETECTED: OFFENDING PROBES INTERCEPTED ON TARGET SERVER!")
            self.lbl_mat_status.setStyleSheet("background: rgba(255, 51, 102, 0.2); color: #FF3366; border: 1px solid #FF3366; padding: 6px 10px; border-radius: 4px; font-weight: bold;")
        else:
            self.lbl_mat_status.setText("🟢 THREAT STATUS: STANDBY // READY FOR MITIGATION DEPLOYMENT")
            self.lbl_mat_status.setStyleSheet("background: rgba(0, 255, 136, 0.1); color: #00FF88; border: 1px solid #00FF88; padding: 6px 10px; border-radius: 4px; font-weight: bold;")

        # Symptoms text
        sym_txt = f"=== ATTACK DESCRIPTION ===\n{att['description']}\n\n"
        sym_txt += "=== SYMPTOMS & HOW TO TELL IF YOU ARE BEING ATTACKED ===\n"
        for s in att['symptoms']:
            sym_txt += f"• {s}\n"
        self.txt_mat_symptoms.setPlainText(sym_txt)

        # Immediate Actions
        imm_txt = "=== IMMEDIATE EMERGENCY ACTIONS (WHAT TO DO RIGHT NOW) ===\n\n"
        for a in att['immediate_actions']:
            imm_txt += f"{a}\n\n"
        self.txt_mat_immediate.setPlainText(imm_txt)

        # Permanent Fix
        perm_txt = "=== PERMANENT ARCHITECTURAL REMEDIATION (HOW TO FIX IT) ===\n\n"
        for f in att['permanent_fix']:
            perm_txt += f"{f}\n\n"
        self.txt_mat_perm.setPlainText(perm_txt)

        # Code Fixes Combo
        self.combo_code_stack.blockSignals(True)
        self.combo_code_stack.clear()
        for stack in att.get("code_fixes", {}).keys():
            self.combo_code_stack.addItem(f"Framework / Server: {stack.upper()}", stack)
        self.combo_code_stack.blockSignals(False)
        self._on_mat_code_stack_changed(0)

    def _on_mat_code_stack_changed(self, idx: int):
        row = self.list_matrix.currentRow()
        if row < 0:
            return
        aid = self.list_matrix.item(row).data(Qt.ItemDataRole.UserRole)
        att = ATTACK_MATRIX.get(aid)
        if not att:
            return
        stack = self.combo_code_stack.currentData()
        code = att.get("code_fixes", {}).get(stack, "# No code snippet available for this stack.")
        self.txt_mat_code.setPlainText(code)

    def _generate_emergency_lockdown_script(self):
        ips = [a.get("ip") for a in self.current_attackers if a.get("ip")]
        if not ips:
            ips = ["198.51.100.45", "203.0.113.19", "185.220.101.5"]
        
        script = ActiveDefenseManager.generate_batch_firewall_script(ips, "windows")
        fpath, _ = QFileDialog.getSaveFileName(self, "Save Emergency Firewall Script", "aegis_emergency_drop.ps1", "PowerShell Script (*.ps1)")
        if fpath:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(script)
            QMessageBox.information(self, "Lockdown Script Generated", f"Saved emergency drop rules for {len(ips)} attacker IPs to:\n{fpath}\n\nRight-click and Run with PowerShell as Administrator to drop all attackers immediately.")
            self.terminal.log(f"Generated emergency firewall drop script: {fpath}", "PASS")

    def _build_playbooks_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel("SELECT TARGET WEB SERVER / STACK:"))
        self.combo_playbook = QComboBox()
        for k in PLAYBOOKS.keys():
            self.combo_playbook.addItem(PLAYBOOKS[k]["title"], k)
        self.combo_playbook.currentIndexChanged.connect(self._on_playbook_changed)
        top_row.addWidget(self.combo_playbook, stretch=1)

        btn_copy_playbook = QPushButton("📋 COPY HARDENED CONFIGURATION")
        btn_copy_playbook.setFixedHeight(30)
        btn_copy_playbook.clicked.connect(self._copy_playbook)
        top_row.addWidget(btn_copy_playbook)
        layout.addLayout(top_row)

        self.lbl_playbook_desc = QLabel()
        self.lbl_playbook_desc.setStyleSheet("color: #8899B5; font-size: 11px;")
        layout.addWidget(self.lbl_playbook_desc)

        self.txt_playbook = QTextEdit()
        self.txt_playbook.setReadOnly(True)
        self.txt_playbook.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.txt_playbook.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(self.txt_playbook, stretch=1)

        self._on_playbook_changed(0)
        return widget

    def _build_terminal_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        lbl = QLabel("STREAMING DEFENSIVE HUD TELEMETRY & EVENT LOG:")
        lbl.setStyleSheet("color: #00FF88; font-weight: bold;")
        layout.addWidget(lbl)

        self.terminal = HudTerminal()
        layout.addWidget(self.terminal, stretch=1)

        btn_clear = QPushButton("CLEAR TERMINAL")
        btn_clear.clicked.connect(self.terminal.clear)
        layout.addWidget(btn_clear, alignment=Qt.AlignmentFlag.AlignRight)

        return widget

    # -------------------------------------------------------------
    # General Handlers
    # -------------------------------------------------------------
    def start_audit(self):
        target = self.txt_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Invalid Target", "Please enter a valid target URL or localhost address.")
            return

        self.btn_scan.setEnabled(False)
        self.lbl_status.setText(f"AUDITING DEFENSIVE POSTURE: {target}...")
        self.terminal.log(f"Initiating defensive security audit against: {target}", "INFO")
        self.progress_bar.setValue(10)

        self.worker = AuditWorker(target)
        self.worker.progress.connect(self._on_audit_progress)
        self.worker.finished.connect(self._on_audit_finished)
        self.worker.error.connect(self._on_audit_error)
        self.worker.start()

    def _on_audit_progress(self, percent: int, msg: str):
        self.progress_bar.setValue(percent)
        self.lbl_status.setText(f"STATUS: {msg}")
        self.terminal.log(msg, "DEBUG")

    def _on_audit_finished(self, report: dict):
        self.last_report = report
        self.btn_scan.setEnabled(True)
        self.progress_bar.setValue(100)
        self.lbl_status.setText(f"AUDIT COMPLETE // TARGET: {report['target']} // GRADE: {report['score_grade']}")

        self.gauge.set_score(report["score"], report["score_grade"])
        self.card_crit.set_value(report["critical_count"])
        self.card_high.set_value(report["high_count"])
        self.card_med.set_value(report["medium_count"])
        self.card_pass.set_value(report["pass_count"])

        self._populate_findings_tables(report["findings"])
        self.tabs.setCurrentIndex(1)
        self.terminal.log(f"Audit completed: Score {report['score']}/100, Grade {report['score_grade']}.", "PASS")

    def _on_audit_error(self, err_msg: str):
        self.btn_scan.setEnabled(True)
        self.progress_bar.setValue(0)
        self.lbl_status.setText(f"ERROR: {err_msg}")
        self.terminal.log(f"Operation failed: {err_msg}", "CRIT")
        QMessageBox.critical(self, "Audit Error", f"Encountered error during audit:\n\n{err_msg}")

    def _populate_findings_tables(self, findings: list):
        self.table_web.setRowCount(0)
        self.table_overview.setRowCount(0)

        for f in findings:
            row = self.table_web.rowCount()
            self.table_web.insertRow(row)

            sev = f["severity"]
            sev_item = QTableWidgetItem(sev.upper())
            sev_color = "#FF3366" if sev == "Critical" else ("#FFB800" if sev == "High" else ("#00F0FF" if sev == "Medium" else "#00FF88"))
            sev_item.setForeground(QColor(sev_color))
            sev_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))

            self.table_web.setItem(row, 0, sev_item)
            self.table_web.setItem(row, 1, QTableWidgetItem(f["title"]))
            self.table_web.setItem(row, 2, QTableWidgetItem(f["description"]))
            self.table_web.setItem(row, 3, QTableWidgetItem(f["remediation"]))

            if sev in ["Critical", "High", "Medium"]:
                ov_row = self.table_overview.rowCount()
                self.table_overview.insertRow(ov_row)
                s_item = QTableWidgetItem(sev.upper())
                s_item.setForeground(QColor(sev_color))
                s_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
                self.table_overview.setItem(ov_row, 0, s_item)
                self.table_overview.setItem(ov_row, 1, QTableWidgetItem(f["category"]))
                self.table_overview.setItem(ov_row, 2, QTableWidgetItem(f"{f['title']}: {f['description']}"))

    def _filter_findings(self, mode: str):
        if not self.last_report:
            return
        findings = self.last_report.get("findings", [])
        if mode == "threats":
            filtered = [f for f in findings if f["severity"] != "Pass"]
        elif mode == "passes":
            filtered = [f for f in findings if f["severity"] == "Pass"]
        else:
            filtered = findings
        self._populate_findings_tables(filtered)

    def scan_ports(self):
        self.lbl_status.setText("AUDITING LOCAL OPEN PORTS & SOCKETS...")
        self.progress_bar.setValue(50)
        self.terminal.log("Scanning system sockets for wildcard 0.0.0.0 exposures...", "INFO")
        self.port_worker = PortWorker()
        self.port_worker.finished.connect(self._on_ports_finished)
        self.port_worker.error.connect(self._on_audit_error)
        self.port_worker.start()

    def _on_ports_finished(self, listeners: list):
        self.table_ports.setRowCount(0)
        self.progress_bar.setValue(100)
        self.lbl_status.setText("STATUS: LOCALHOST PORT AUDIT COMPLETE")

        for l in listeners:
            row = self.table_ports.rowCount()
            self.table_ports.insertRow(row)

            port_item = QTableWidgetItem(str(l["port"]))
            bind_item = QTableWidgetItem(f"{l['ip']}:{l['port']}")
            pname_item = QTableWidgetItem(l["process_name"])
            pid_item = QTableWidgetItem(str(l["pid"] or "N/A"))

            risk = l["risk_level"]
            risk_item = QTableWidgetItem(risk.upper())
            if risk == "Critical":
                risk_item.setForeground(QColor("#FF3366"))
            elif risk == "Medium":
                risk_item.setForeground(QColor("#FFB800"))
            else:
                risk_item.setForeground(QColor("#00FF88"))
            risk_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))

            msg_item = QTableWidgetItem(f"{l['risk_message']} -> {l['remediation']}")

            self.table_ports.setItem(row, 0, port_item)
            self.table_ports.setItem(row, 1, bind_item)
            self.table_ports.setItem(row, 2, pname_item)
            self.table_ports.setItem(row, 3, pid_item)
            self.table_ports.setItem(row, 4, risk_item)
            self.table_ports.setItem(row, 5, msg_item)

        self.terminal.log(f"Port audit complete. Audited {len(listeners)} active listening sockets.", "PASS")

    def _load_sample_logs(self):
        sample_logs = LogIntrusionDetector.generate_sample_attack_log()
        self.terminal.log("Loaded representative attack log telemetry. Initiating threat correlation...", "INFO")
        self._analyze_log_content(sample_logs)

    def _load_log_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Web Server Access Log", "", "Log Files (*.log *.txt);;All Files (*)")
        if file_path and os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self.terminal.log(f"Loaded access log from: {file_path}", "INFO")
            self._analyze_log_content(content)

    def _analyze_log_content(self, content: str):
        self.lbl_status.setText("STATUS: ANALYZING ATTACKER TELEMETRY & RESOLVING IP INTEL...")
        self.progress_bar.setValue(30)
        self.log_worker = LogAnalysisWorker(content)
        self.log_worker.progress.connect(self._on_audit_progress)
        self.log_worker.finished.connect(self._on_attackers_finished)
        self.log_worker.start()

    def _on_attackers_finished(self, attackers: list):
        self.current_attackers = attackers
        self.table_attackers.setRowCount(0)
        self.progress_bar.setValue(100)
        self.lbl_status.setText("STATUS: ATTACKER TELEMETRY ANALYSIS COMPLETE")

        for att in attackers:
            row = self.table_attackers.rowCount()
            self.table_attackers.insertRow(row)

            geo = att.get("threat_profile", {})
            geo_str = f"{geo.get('country_code', 'XX')} - {geo.get('country', 'Unknown')}"

            conn_type = geo.get("connection_type", "Residential / Mobile Carrier")
            if geo.get("is_vpn_proxy"):
                conn_type = "VPN / Tor / Proxy [HIGH RISK]"

            hw = att.get("device_hardware", {})
            hw_str = f"{hw.get('mobile_brand', '')} {hw.get('hardware_model', 'Generic')}".strip()

            sev = att.get("highest_severity", "Low")
            sev_item = QTableWidgetItem(sev.upper())
            sev_color = "#FF3366" if sev == "Critical" else ("#FFB800" if sev == "High" else "#00F0FF")
            sev_item.setForeground(QColor(sev_color))
            sev_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))

            vectors = ", ".join(att.get("attack_types", []))

            self.table_attackers.setItem(row, 0, QTableWidgetItem(att["ip"]))
            self.table_attackers.setItem(row, 1, QTableWidgetItem(geo_str))
            self.table_attackers.setItem(row, 2, QTableWidgetItem(conn_type))
            self.table_attackers.setItem(row, 3, QTableWidgetItem(hw_str))
            self.table_attackers.setItem(row, 4, QTableWidgetItem(str(att["malicious_hits"])))
            self.table_attackers.setItem(row, 5, sev_item)
            self.table_attackers.setItem(row, 6, QTableWidgetItem(vectors))

        if attackers:
            self.table_attackers.selectRow(0)
            self.tabs.setCurrentWidget(self.tab_attackers)
            self.terminal.log(f"Identified {len(attackers)} malicious attacker IPs hitting your server.", "THREAT")

    def _on_attacker_selected(self):
        selected_rows = self.table_attackers.selectedIndexes()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        if row < len(self.current_attackers):
            att = self.current_attackers[row]
            geo = att.get("threat_profile", {})
            hw = att.get("device_hardware", {})
            fw = att.get("firewall_rules", {})
            mitre = att.get("mitre_mappings", [])

            mitre_text = "\n".join([f"  - {m['category']}: {m['owasp']} | {m['mitre']}\n    Defensive Fix: {m['defensive_control']}" for m in mitre])
            payloads = "\n".join([f"  * {p}" for p in att.get("sample_payloads", [])])

            vpn_status = "VPN / Tor / Anonymous Proxy (DETECTED - High Anonymization Risk)" if geo.get("is_vpn_proxy") else "Direct Public IP (No VPN detected)"

            dossier_text = f"""=====================================================
ATTACKER DOSSIER // IP: {att['ip']}
DEVELOPED BY: TEAM WHITE HAT
=====================================================
[GEOLOCATION & NETWORK PROFILE]
  Country / City:   {geo.get('country')} ({geo.get('country_code')}), {geo.get('city')}
  ISP / Carrier:    {geo.get('isp')}
  Organization:     {geo.get('org')}
  AS Number:        {geo.get('as_number')}
  Reverse DNS:      {geo.get('reverse_dns')}
  VPN/Proxy Status: {vpn_status}

[DEVICE HARDWARE & CLIENT MODEL FINGERPRINT]
  Device Category:  {hw.get('device_category', 'Desktop / Workstation')}
  Operating System: {hw.get('operating_system', 'Unknown OS')}
  Hardware Model:   {hw.get('hardware_model', 'Generic Model')}
  Mobile Brand:     {hw.get('mobile_brand', 'N/A')}
  Spoofing Status:  {hw.get('spoofing_suspicion', 'Low')}

[PROBING ACTIVITY]
  Severity:         {att['highest_severity'].upper()}
  Attacks:          {att['malicious_hits']} malicious / {att['total_requests']} total requests
  First Seen:       {att['first_seen']}
  Last Seen:        {att['last_seen']}
  Categories:       {att['attack_types']}

[MITRE ATT&CK & OWASP]
{mitre_text if mitre_text else '  None mapped'}

[CAPTURED ATTACK PROBES]
{payloads if payloads else '  None recorded'}

=====================================================
POLICE & CARRIER SUBPOENA INVESTIGATION PROTOCOL:
=====================================================
To legally identify the physical perpetrator (SIM, IMEI, GPS):
1. Law Enforcement issues an expedited preservation order to ISP: {geo.get('isp')}
2. Subpoena carrier NAT logs for IP {att['ip']} at timestamp {att['last_seen']}.
3. Request Mobile Subscriber Name, MSISDN, Registered SIM Card ICCID,
   and Hardware IMEI number associated with this connection.
4. Obtain cellular tower sector and timing-advance triangulation GPS data.

=====================================================
INSTANT DEFENSIVE FIREWALL MITIGATION RULES:
=====================================================
[Windows Defender Firewall (PowerShell)]
{fw.get('powershell')}

[Linux UFW]
{fw.get('ufw')}

[Nginx Block Directive]
{fw.get('nginx')}
"""
            self.txt_dossier.setPlainText(dossier_text)

    def _copy_current_firewall_rule(self):
        selected_rows = self.table_attackers.selectedIndexes()
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select an attacker IP from the table first.")
            return
        row = selected_rows[0].row()
        if row < len(self.current_attackers):
            att = self.current_attackers[row]
            fw = att.get("firewall_rules", {})
            clipboard = QApplication.clipboard()
            clipboard.setText(fw.get("powershell", ""))
            self.terminal.log(f"Copied Windows Firewall block rule for {att['ip']} to clipboard.", "PASS")
            QMessageBox.information(self, "Rule Copied", f"Firewall block command for {att['ip']} copied to clipboard:\n\n{fw.get('powershell')}")

    def _on_playbook_changed(self, index: int):
        key = self.combo_playbook.currentData()
        if key in PLAYBOOKS:
            pb = PLAYBOOKS[key]
            self.lbl_playbook_desc.setText(pb["description"])
            self.txt_playbook.setPlainText(pb["snippet"])

    def _copy_playbook(self):
        text = self.txt_playbook.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.terminal.log("Hardening configuration playbook copied to clipboard.", "PASS")
            QMessageBox.information(self, "Playbook Copied", "Configuration snippet copied to clipboard!")

    def export_report(self):
        if not self.last_report:
            QMessageBox.warning(self, "No Audit Data", "Please run a defensive audit first before exporting.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Export Defensive Audit Report", "Aegis_Security_Report.html", "HTML Files (*.html);;JSON Files (*.json)")
        if file_path:
            try:
                if file_path.endswith(".json"):
                    content = ReportGenerator.to_json(self.last_report)
                else:
                    content = ReportGenerator.to_html(self.last_report)

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                self.terminal.log(f"Exported defensive security audit report to: {file_path}", "PASS")
                QMessageBox.information(self, "Report Exported", f"Successfully saved audit report:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to save report: {e}")


def launch_gui():
    app = QApplication(sys.argv)
    window = AegisMainWindow()
    window.show()
    sys.exit(app.exec())

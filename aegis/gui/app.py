"""
Aegis Main HUD Window
High-tech Sci-Fi CIA/Cyberpunk style graphical interface built with PyQt6.
"""

import sys
import os
from datetime import datetime
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QProgressBar, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QFrame, QSplitter, QTextEdit,
    QFileDialog, QMessageBox, QComboBox, QApplication
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QClipboard

from aegis.gui.hud_theme import HUD_STYLESHEET, HUD_COLORS
from aegis.gui.widgets import ScoreGaugeWidget, TelemetryCard, HudTerminal
from aegis.gui.workers import AuditWorker, PortWorker, LogAnalysisWorker
from aegis.log_ids import LogIntrusionDetector
from aegis.playbook import PLAYBOOKS
from aegis.reporter import ReportGenerator


class AegisMainWindow(QMainWindow):
    """Main window for the Aegis Defensive Security Suite."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AEGIS // DEFENSIVE LOCALHOST & WEB AUDIT SUITE [TACTICAL HUD]")
        self.resize(1280, 840)
        self.setMinimumSize(1050, 700)

        self.last_report = None
        self.current_attackers = []

        self.setStyleSheet(HUD_STYLESHEET)
        self._init_ui()
        self.terminal.log("Aegis Defensive System initialized. Telemetry channels online.", "INFO")

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 14, 16, 14)
        main_layout.setSpacing(12)

        # 1. Top HUD Tactical Header
        header_frame = self._build_header()
        main_layout.addWidget(header_frame)

        # 2. Main Tabs
        self.tabs = QTabWidget()
        self.tab_overview = self._build_overview_tab()
        self.tab_web = self._build_web_tab()
        self.tab_ports = self._build_ports_tab()
        self.tab_attackers = self._build_attackers_tab()
        self.tab_playbooks = self._build_playbooks_tab()
        self.tab_terminal = self._build_terminal_tab()

        self.tabs.addTab(self.tab_overview, "🛡️ OVERVIEW & SCORE")
        self.tabs.addTab(self.tab_web, "🌐 WEB & OWASP AUDIT")
        self.tabs.addTab(self.tab_ports, "📡 LOCALHOST PORT AUDIT")
        self.tabs.addTab(self.tab_attackers, "🚨 ATTACKER TRACKER & IDS")
        self.tabs.addTab(self.tab_playbooks, "📋 HARDENING PLAYBOOKS")
        self.tabs.addTab(self.tab_terminal, "🖥️ TACTICAL CONSOLE")

        main_layout.addWidget(self.tabs, stretch=1)

        # 3. Bottom Progress Bar & Status
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

    def _build_header(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("hudPanel")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

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

        # Input & Action Controls
        ctrl_row = QHBoxLayout()
        lbl_target = QLabel("TARGET URL / HOST:")
        lbl_target.setStyleSheet("color: #8899B5; font-weight: bold;")
        
        self.txt_target = QLineEdit("http://127.0.0.1:8000")
        self.txt_target.setPlaceholderText("e.g., http://localhost:3000, http://127.0.0.1:8080")
        self.txt_target.setFixedHeight(34)

        # Preset Quick Targets
        btn_preset1 = QPushButton("localhost:3000")
        btn_preset1.clicked.connect(lambda: self.txt_target.setText("http://localhost:3000"))
        btn_preset2 = QPushButton("localhost:8000")
        btn_preset2.clicked.connect(lambda: self.txt_target.setText("http://localhost:8000"))

        self.btn_scan = QPushButton("🛡️ INITIATE DEFENSIVE AUDIT")
        self.btn_scan.setObjectName("btnPrimary")
        self.btn_scan.setFixedHeight(34)
        self.btn_scan.clicked.connect(self.start_audit)

        self.btn_export = QPushButton("💾 EXPORT REPORT")
        self.btn_export.setFixedHeight(34)
        self.btn_export.clicked.connect(self.export_report)

        ctrl_row.addWidget(lbl_target)
        ctrl_row.addWidget(self.txt_target, stretch=1)
        ctrl_row.addWidget(btn_preset1)
        ctrl_row.addWidget(btn_preset2)
        ctrl_row.addWidget(self.btn_scan)
        ctrl_row.addWidget(self.btn_export)

        layout.addLayout(ctrl_row)
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
        self.card_med = TelemetryCard("Medium Warnings", "0", "Information Leaks / Minor", "#00F0FF")
        self.card_pass = TelemetryCard("Hardened Passes", "0", "OWASP Aligned", "#00FF88")

        cards_row.addWidget(self.card_crit)
        cards_row.addWidget(self.card_high)
        cards_row.addWidget(self.card_med)
        cards_row.addWidget(self.card_pass)
        layout.addLayout(cards_row)

        # Bottom Executive Summary & Action Items Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Target Diagnostics
        pnl_diag = QFrame()
        pnl_diag.setObjectName("hudPanel")
        diag_layout = QVBoxLayout(pnl_diag)
        diag_layout.addWidget(QLabel("HOST TELEMETRY & NETWORK PROFILE"))
        self.txt_diag = QTextEdit()
        self.txt_diag.setReadOnly(True)
        self.txt_diag.setPlaceholderText("Target host diagnostics will display here once audit begins...")
        diag_layout.addWidget(self.txt_diag)
        splitter.addWidget(pnl_diag)

        # Right: Key Remediation Recommendations
        pnl_rem = QFrame()
        pnl_rem.setObjectName("hudPanel")
        rem_layout = QVBoxLayout(pnl_rem)
        rem_layout.addWidget(QLabel("DEFENSIVE ACTION PLAN // TOP PRIORITIES"))
        self.txt_rem = QTextEdit()
        self.txt_rem.setReadOnly(True)
        self.txt_rem.setPlaceholderText("Top security recommendations will be populated after audit...")
        rem_layout.addWidget(self.txt_rem)
        splitter.addWidget(pnl_rem)

        layout.addWidget(splitter, stretch=1)
        return widget

    def _build_web_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Filters Row
        filter_row = QHBoxLayout()
        lbl_filter = QLabel("VIEW FILTER:")
        lbl_filter.setStyleSheet("font-weight: bold; color: #8899B5;")
        btn_all = QPushButton("ALL FINDINGS")
        btn_all.clicked.connect(lambda: self._filter_findings("all"))
        btn_threats = QPushButton("THREATS ONLY")
        btn_threats.clicked.connect(lambda: self._filter_findings("threats"))
        btn_passes = QPushButton("PASSES ONLY")
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
        self.table_web.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_web.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table_web)

        return widget

    def _build_ports_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        lbl_info = QLabel("ACTIVE LISTENING SOCKETS & ACCIDENTAL EXPOSURE AUDIT")
        lbl_info.setStyleSheet("color: #00F0FF; font-weight: bold;")
        btn_refresh = QPushButton("🔄 SCAN LOCAL PORTS NOW")
        btn_refresh.clicked.connect(self.scan_ports)

        top_row.addWidget(lbl_info)
        top_row.addStretch()
        top_row.addWidget(btn_refresh)
        layout.addLayout(top_row)

        self.table_ports = QTableWidget(0, 6)
        self.table_ports.setHorizontalHeaderLabels(["PORT", "INTERFACE BINDING", "PROCESS", "PID", "RISK LEVEL", "DEFENSIVE STATUS & REMEDIATION"])
        self.table_ports.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_ports.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table_ports.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_ports.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout.addWidget(self.table_ports)
        return widget

    def _build_attackers_tab(self) -> QWidget:
        """Attacker tracking, threat telemetry, and automated firewall generator tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Controls Row
        ctrl_row = QHBoxLayout()
        btn_load_file = QPushButton("📁 LOAD ACCESS LOG FILE")
        btn_load_file.clicked.connect(self._load_log_file)
        btn_sample = QPushButton("⚡ LOAD SAMPLE ATTACK TELEMETRY")
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
        left_layout.addWidget(QLabel("DETECTED ATTACKER IP ADDRESSES"))

        self.table_attackers = QTableWidget(0, 6)
        self.table_attackers.setHorizontalHeaderLabels(["ATTACKER IP", "GEO / COUNTRY", "HITS", "SEVERITY", "ATTACK VECTORS", "IDENTIFIED TOOL"])
        self.table_attackers.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_attackers.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_attackers.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_attackers.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_attackers.itemSelectionChanged.connect(self._on_attacker_selected)

        left_layout.addWidget(self.table_attackers)
        splitter.addWidget(pnl_left)

        # Right: Attacker Dossier & Firewall Generator
        pnl_right = QFrame()
        pnl_right.setObjectName("hudPanel")
        right_layout = QVBoxLayout(pnl_right)
        
        lbl_dossier = QLabel("ATTACKER DOSSIER & FIREWALL MITIGATION")
        lbl_dossier.setStyleSheet("color: #FF3366; font-weight: bold;")
        right_layout.addWidget(lbl_dossier)

        self.txt_dossier = QTextEdit()
        self.txt_dossier.setReadOnly(True)
        self.txt_dossier.setPlaceholderText("Select an attacker IP from the table to view intelligence dossier, reverse DNS, and generated firewall block rules...")
        right_layout.addWidget(self.txt_dossier)

        btn_copy_rule = QPushButton("📋 COPY FIREWALL BLOCK RULE (POWERSHELL / IPTABLES)")
        btn_copy_rule.setObjectName("btnDanger")
        btn_copy_rule.clicked.connect(self._copy_current_firewall_rule)
        right_layout.addWidget(btn_copy_rule)

        splitter.addWidget(pnl_right)
        splitter.setSizes([650, 450])

        layout.addWidget(splitter, stretch=1)
        return widget

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
        btn_copy_playbook.clicked.connect(self._copy_playbook)
        top_row.addWidget(btn_copy_playbook)
        layout.addLayout(top_row)

        self.lbl_playbook_desc = QLabel()
        self.lbl_playbook_desc.setStyleSheet("color: #8899B5; font-size: 11px;")
        layout.addWidget(self.lbl_playbook_desc)

        self.txt_playbook = QTextEdit()
        self.txt_playbook.setReadOnly(True)
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
    # Action Handlers
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
        self.lbl_status.setText("STATUS: AUDIT COMPLETE // READY")

        score = report.get("score", 0)
        grade = report.get("grade", "F")
        self.gauge.set_score(score, grade)

        summary = report.get("summary", {})
        self.card_crit.set_value(str(summary.get("critical", 0)))
        self.card_high.set_value(str(summary.get("high", 0)))
        self.card_med.set_value(str(summary.get("medium", 0)))
        self.card_pass.set_value(str(summary.get("pass", 0)))

        # Update Overview Diagnostics Text
        diag_text = (
            f"TARGET URL: {report.get('target')}\n"
            f"RESOLVED IP(s): {', '.join(report.get('ip_resolution', []))}\n"
            f"HTTP STATUS: {report.get('status_code')}\n"
            f"LATENCY: {report.get('latency_ms')} ms\n"
            f"POSTURE SCORE: {score}/100 [GRADE: {grade}]\n\n"
            f"SUMMARY BREAKDOWN:\n"
            f"  - Critical Findings: {summary.get('critical', 0)}\n"
            f"  - High Severity:     {summary.get('high', 0)}\n"
            f"  - Medium Warnings:   {summary.get('medium', 0)}\n"
            f"  - Hardened Passes:   {summary.get('pass', 0)}"
        )
        self.txt_diag.setPlainText(diag_text)

        # Update Recommendations Text
        findings = report.get("findings", [])
        rem_lines = []
        for idx, f in enumerate(findings):
            if f.get("severity") in ("Critical", "High", "Medium"):
                rem_lines.append(f"[{f.get('severity').upper()}] {f.get('title')}\n -> {f.get('remediation')}\n")
        self.txt_rem.setPlainText("\n".join(rem_lines) if rem_lines else "All audited security headers and controls are properly configured!")

        # Populate Findings Table
        self._populate_findings_table(findings)
        self.terminal.log(f"Audit completed. Posture Score: {score}/100 (Grade: {grade})", "PASS" if score >= 80 else "WARN")

        # Automatically check listening sockets as part of total assessment
        self.scan_ports()

    def _on_audit_error(self, err_msg: str):
        self.btn_scan.setEnabled(True)
        self.lbl_status.setText("STATUS: AUDIT FAILED // ERROR OCCURRED")
        self.terminal.log(f"Audit execution error: {err_msg}", "CRIT")
        QMessageBox.critical(self, "Audit Error", f"An error occurred during audit:\n{err_msg}")

    def _populate_findings_table(self, findings: list):
        self.table_web.setRowCount(0)
        sev_colors = {
            "Critical": "#FF3366",
            "High": "#FFB800",
            "Medium": "#00F0FF",
            "Low": "#8899B5",
            "Pass": "#00FF88"
        }
        for f in findings:
            row = self.table_web.rowCount()
            self.table_web.insertRow(row)

            sev = f.get("severity", "Info")
            item_sev = QTableWidgetItem(sev.upper())
            item_sev.setForeground(QColor(sev_colors.get(sev, "#CBD5E1")))
            item_sev.setFont(QFont("Consolas", 10, QFont.Weight.Bold))

            item_title = QTableWidgetItem(f.get("title", ""))
            item_desc = QTableWidgetItem(f.get("description", ""))
            item_rem = QTableWidgetItem(f.get("remediation", ""))

            self.table_web.setItem(row, 0, item_sev)
            self.table_web.setItem(row, 1, item_title)
            self.table_web.setItem(row, 2, item_desc)
            self.table_web.setItem(row, 3, item_rem)

    def _filter_findings(self, mode: str):
        if not self.last_report:
            return
        findings = self.last_report.get("findings", [])
        if mode == "threats":
            filtered = [f for f in findings if f.get("severity") in ("Critical", "High", "Medium", "Low")]
        elif mode == "passes":
            filtered = [f for f in findings if f.get("severity") == "Pass"]
        else:
            filtered = findings
        self._populate_findings_table(filtered)

    def scan_ports(self):
        self.terminal.log("Scanning local listening sockets and interface bindings...", "INFO")
        self.port_worker = PortWorker()
        self.port_worker.finished.connect(self._on_ports_finished)
        self.port_worker.start()

    def _on_ports_finished(self, listeners: list):
        self.table_ports.setRowCount(0)
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

    # -------------------------------------------------------------
    # Attacker Tracking & IDS Handlers
    # -------------------------------------------------------------

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

            sev = att.get("highest_severity", "Low")
            sev_item = QTableWidgetItem(sev.upper())
            sev_color = "#FF3366" if sev == "Critical" else ("#FFB800" if sev == "High" else "#00F0FF")
            sev_item.setForeground(QColor(sev_color))
            sev_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))

            vectors = ", ".join(att.get("attack_types", []))
            
            tools = [t["tool"] for t in att.get("identified_tools", [])]
            tools_str = ", ".join(tools) if tools else "Custom/Scripted"

            self.table_attackers.setItem(row, 0, QTableWidgetItem(att["ip"]))
            self.table_attackers.setItem(row, 1, QTableWidgetItem(geo_str))
            self.table_attackers.setItem(row, 2, QTableWidgetItem(str(att["malicious_hits"])))
            self.table_attackers.setItem(row, 3, sev_item)
            self.table_attackers.setItem(row, 4, QTableWidgetItem(vectors))
            self.table_attackers.setItem(row, 5, QTableWidgetItem(tools_str))

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
            fw = att.get("firewall_rules", {})
            mitre = att.get("mitre_mappings", [])

            mitre_text = "\n".join([f"  - {m['category']}: {m['owasp']} | {m['mitre']}\n    Defensive Fix: {m['defensive_control']}" for m in mitre])
            payloads = "\n".join([f"  * {p}" for p in att.get("sample_payloads", [])])

            dossier_text = f"""=====================================================
ATTACKER INTELLIGENCE DOSSIER // IP: {att['ip']}
=====================================================
[GEOLOCATION & NETWORK TELEMETRY]
  Country / City: {geo.get('country')} ({geo.get('country_code')}), {geo.get('city')}
  ISP / Hosting:  {geo.get('isp')}
  Organization:   {geo.get('org')}
  AS Number:      {geo.get('as_number')}
  Reverse DNS:    {geo.get('reverse_dns')}

[ATTACK ACTIVITY & VOLUME]
  Threat Severity: {att['highest_severity'].upper()}
  Malicious Probes: {att['malicious_hits']} / Total Requests: {att['total_requests']}
  First Detected:   {att['first_seen']}
  Last Detected:    {att['last_seen']}
  Attack Categories: {', '.join(att['attack_types'])}

[MITRE ATT&CK & OWASP MAPPING]
{mitre_text if mitre_text else '  None mapped'}

[SAMPLE ATTACK PAYLOADS INTERCEPTED]
{payloads if payloads else '  No payload samples recorded'}

=====================================================
INSTANT DEFENSIVE FIREWALL MITIGATION RULES:
=====================================================
[Windows Defender Firewall (PowerShell)]
{fw.get('powershell')}

[Linux UFW]
{fw.get('ufw')}

[Linux iptables]
{fw.get('iptables')}

[Nginx Block Directive]
{fw.get('nginx')}

[Apache .htaccess]
{fw.get('apache')}
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
            # Copy Windows powershell command on Windows, or multi-format text
            clipboard = QApplication.clipboard()
            clipboard.setText(fw.get("powershell", ""))
            self.terminal.log(f"Copied Windows Firewall block rule for {att['ip']} to clipboard.", "PASS")
            QMessageBox.information(self, "Rule Copied", f"Firewall block command for {att['ip']} copied to clipboard:\n\n{fw.get('powershell')}")

    # -------------------------------------------------------------
    # Playbooks & Reporting
    # -------------------------------------------------------------

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

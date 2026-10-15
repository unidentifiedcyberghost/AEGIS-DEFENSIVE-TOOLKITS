"""
Aegis QThread Workers for Asynchronous Background Telemetry
Ensures the PyQt6 HUD interface remains buttery-smooth and responsive during network operations.
"""

from PyQt6.QtCore import QThread, pyqtSignal
from aegis.auditor import WebAuditor
from aegis.port_auditor import PortAuditor
from aegis.log_ids import LogIntrusionDetector
from aegis.threat_intel import ThreatIntelAnalyzer


class AuditWorker(QThread):
    """Executes full defensive web security audit in a background thread."""

    progress = pyqtSignal(int, str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, target_url: str):
        super().__init__()
        self.target_url = target_url

    def run(self):
        try:
            auditor = WebAuditor(self.target_url)
            report = auditor.run_full_audit(progress_callback=self._on_progress)
            self.finished.emit(report)
        except Exception as e:
            self.error.emit(str(e))

    def _on_progress(self, percent: int, msg: str):
        self.progress.emit(percent, msg)


class PortWorker(QThread):
    """Audits local listening sockets in background."""

    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def run(self):
        try:
            listeners = PortAuditor.audit_listeners()
            self.finished.emit(listeners)
        except Exception as e:
            self.error.emit(str(e))


class LogAnalysisWorker(QThread):
    """Analyzes server access logs and enriches attacker IPs with threat intelligence."""

    progress = pyqtSignal(int, str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, log_content: str):
        super().__init__()
        self.log_content = log_content

    def run(self):
        try:
            self.progress.emit(20, "Parsing access log lines and detecting attack signatures...")
            detector = LogIntrusionDetector()
            attackers = detector.parse_log_text(self.log_content)

            self.progress.emit(50, "Correlating threat telemetry & resolving GeoIP/ASN...")
            intel = ThreatIntelAnalyzer()
            enriched_attackers = []

            total = len(attackers)
            for idx, att in enumerate(attackers):
                self.progress.emit(50 + int((idx / max(1, total)) * 40), f"Enriching threat profile for IP: {att['ip']}...")
                geo_profile = intel.enrich_attacker_ip(att["ip"])
                tool_fingerprints = intel.fingerprint_user_agents(att["user_agents"])
                mitre_mappings = intel.map_to_mitre_and_owasp(att["attack_types"])

                att["threat_profile"] = geo_profile
                att["identified_tools"] = tool_fingerprints
                att["mitre_mappings"] = mitre_mappings
                enriched_attackers.append(att)

            self.progress.emit(100, "Attacker threat analysis complete.")
            self.finished.emit(enriched_attackers)
        except Exception as e:
            self.error.emit(str(e))

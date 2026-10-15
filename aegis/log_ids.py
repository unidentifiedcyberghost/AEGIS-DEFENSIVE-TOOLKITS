"""
Aegis Defensive Intrusion Detection System (IDS) & Attacker Telemetry
Analyzes web server access logs to detect malicious probes, extract attacker IPs,
and generate instant defensive firewall rules.
"""

import re
from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime

# Regex for standard Combined Log Format (Nginx, Apache, Caddy, Express)
# Format: 127.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /path HTTP/1.1" 200 2326 "referer" "user-agent"
COMBINED_LOG_REGEX = re.compile(
    r'(?P<ip>[\w\.\:]+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>[^\s"]+)\s*(?P<proto>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)'
)

# Attack signatures and heuristic patterns
ATTACK_SIGNATURES = [
    {
        "category": "Path Traversal / LFI",
        "severity": "Critical",
        "pattern": re.compile(r"(\.\./|\.\.\\|\%2e\%2e|/etc/passwd|win\.ini|boot\.ini)", re.IGNORECASE),
        "desc": "Attempted directory traversal to access restricted filesystem files."
    },
    {
        "category": "SQL Injection Probe",
        "severity": "Critical",
        "pattern": re.compile(r"('|\%27|union\s+select|select.*from|sleep\(|\bbenchmark\(|information_schema|--\s)", re.IGNORECASE),
        "desc": "Malicious SQL syntax probe injected into URL or query parameters."
    },
    {
        "category": "Sensitive File Harvesting",
        "severity": "High",
        "pattern": re.compile(r"(\.env|\.git/|id_rsa|\.aws/|docker-compose|wp-config\.php|web\.config|\.bak\b)", re.IGNORECASE),
        "desc": "Automated scanner probing for exposed environment or source credentials."
    },
    {
        "category": "Admin & Backdoor Probing",
        "severity": "High",
        "pattern": re.compile(r"(/phpmyadmin|/wp-login\.php|/actuator|/shell\.php|/c99\.php|/eval-stdin)", re.IGNORECASE),
        "desc": "Probing for administrative dashboards, actuators, or webshell backdoors."
    },
    {
        "category": "XSS / Script Injection",
        "severity": "Medium",
        "pattern": re.compile(r"(<script|javascript:|onerror=|onload=|\%3cscript)", re.IGNORECASE),
        "desc": "Cross-Site Scripting (XSS) payload embedded in request target."
    }
]


class LogIntrusionDetector:
    """Parses access logs, detects attacker patterns, and generates defensive block rules."""

    def __init__(self):
        self.attackers = defaultdict(lambda: {
            "ip": "",
            "total_requests": 0,
            "malicious_hits": 0,
            "attack_types": set(),
            "first_seen": None,
            "last_seen": None,
            "sample_payloads": [],
            "user_agents": set(),
            "highest_severity": "Low",
            "blocked": False
        })
        self.total_lines_analyzed = 0
        self.total_threats_detected = 0

    def parse_log_text(self, log_content: str) -> List[Dict[str, Any]]:
        """Parses a multi-line string containing web server access logs."""
        lines = log_content.strip().split("\n")
        return self.parse_log_lines(lines)

    def parse_log_lines(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Parses individual log lines and correlates threat telemetry."""
        for line in lines:
            line = line.strip()
            if not line:
                continue
            self.total_lines_analyzed += 1

            match = COMBINED_LOG_REGEX.search(line)
            if not match:
                # Try simple format fallback: "IP ... /path"
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    path = parts[2] if len(parts) > 2 else parts[1]
                    self._evaluate_request(ip, path, "200", "Custom-Log-Agent", "N/A")
                continue

            ip = match.group("ip")
            path = match.group("path")
            status = match.group("status")
            ua = match.group("ua")
            time_str = match.group("time")

            self._evaluate_request(ip, path, status, ua, time_str)

        return self.get_attacker_summary()

    def _evaluate_request(self, ip: str, path: str, status: str, ua: str, time_str: str):
        record = self.attackers[ip]
        record["ip"] = ip
        record["total_requests"] += 1
        record["user_agents"].add(ua[:80])

        if not record["first_seen"]:
            record["first_seen"] = time_str
        record["last_seen"] = time_str

        # Test against attack patterns
        for sig in ATTACK_SIGNATURES:
            if sig["pattern"].search(path):
                self.total_threats_detected += 1
                record["malicious_hits"] += 1
                record["attack_types"].add(sig["category"])

                if len(record["sample_payloads"]) < 5:
                    record["sample_payloads"].append(path[:120])

                # Severity update
                if sig["severity"] == "Critical":
                    record["highest_severity"] = "Critical"
                elif sig["severity"] == "High" and record["highest_severity"] != "Critical":
                    record["highest_severity"] = "High"
                elif sig["severity"] == "Medium" and record["highest_severity"] not in ("Critical", "High"):
                    record["highest_severity"] = "Medium"

    def get_attacker_summary(self) -> List[Dict[str, Any]]:
        """Returns sorted list of detected attacker IPs with actionable defensive intelligence."""
        result = []
        for ip, data in self.attackers.items():
            if data["malicious_hits"] > 0:
                result.append({
                    "ip": ip,
                    "malicious_hits": data["malicious_hits"],
                    "total_requests": data["total_requests"],
                    "highest_severity": data["highest_severity"],
                    "attack_types": list(data["attack_types"]),
                    "first_seen": data["first_seen"] or "N/A",
                    "last_seen": data["last_seen"] or "N/A",
                    "sample_payloads": data["sample_payloads"],
                    "user_agents": list(data["user_agents"]),
                    "firewall_rules": self.generate_firewall_rules(ip)
                })

        # Sort by severity and malicious hit count
        sev_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
        result.sort(key=lambda x: (sev_order.get(x["highest_severity"], 0), x["malicious_hits"]), reverse=True)
        return result

    @staticmethod
    def generate_firewall_rules(ip: str) -> Dict[str, str]:
        """Generates exact defensive drop rules across major operating systems & web servers."""
        safe_ip = ip.strip()
        return {
            "ufw": f"sudo ufw deny from {safe_ip}",
            "iptables": f"sudo iptables -I INPUT -s {safe_ip} -j DROP",
            "powershell": f'New-NetFirewallRule -DisplayName "Aegis_Block_{safe_ip}" -Direction Inbound -Action Block -RemoteAddress "{safe_ip}"',
            "nginx": f"deny {safe_ip};",
            "apache": f"Require not ip {safe_ip}"
        }

    @staticmethod
    def generate_sample_attack_log() -> str:
        """Generates representative web server logs containing both benign traffic and probe attempts."""
        now = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f"""
127.0.0.1 - - [{now}] "GET /index.html HTTP/1.1" 200 4520 "https://localhost" "Mozilla/5.0"
127.0.0.1 - - [{now}] "GET /assets/style.css HTTP/1.1" 200 1204 "https://localhost" "Mozilla/5.0"
198.51.100.45 - - [{now}] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.68.0"
198.51.100.45 - - [{now}] "GET /.git/config HTTP/1.1" 404 162 "-" "curl/7.68.0"
198.51.100.45 - - [{now}] "GET /docker-compose.yml HTTP/1.1" 404 162 "-" "curl/7.68.0"
203.0.113.88 - - [{now}] "GET /api/user?id=1'%20OR%201=1-- HTTP/1.1" 500 523 "-" "sqlmap/1.6"
203.0.113.88 - - [{now}] "GET /api/user?id=1%20UNION%20SELECT%20null,null,null-- HTTP/1.1" 500 523 "-" "sqlmap/1.6"
192.0.2.140 - - [{now}] "GET /../../../../etc/passwd HTTP/1.1" 400 240 "-" "DirBuster/1.0"
192.0.2.140 - - [{now}] "GET /phpmyadmin/index.php HTTP/1.1" 404 162 "-" "DirBuster/1.0"
192.0.2.140 - - [{now}] "GET /wp-login.php HTTP/1.1" 404 162 "-" "DirBuster/1.0"
127.0.0.1 - - [{now}] "GET /api/health HTTP/1.1" 200 84 "-" "Go-http-client/1.1"
""".strip()

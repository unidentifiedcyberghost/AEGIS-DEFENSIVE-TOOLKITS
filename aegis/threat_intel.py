"""
Aegis Defensive Threat Intelligence & Attacker Profiler
Enriches attacker IP telemetry with Reverse DNS, ASN/ISP lookup, scanner fingerprinting,
and OWASP / MITRE ATT&CK threat mapping for incident response.
"""

import socket
import ipaddress
from typing import Dict, Any, List
import requests

KNOWN_SCANNER_TOOLS = {
    "sqlmap": ("SQLMap Automated Exploit Engine", "High-threat automated SQL injection utility"),
    "nikto": ("Nikto Web Vulnerability Scanner", "Open-source web server scanner"),
    "dirbuster": ("DirBuster / OWASP", "Directory & file brute-forcing tool"),
    "gobuster": ("Gobuster Scanner", "High-speed URI & DNS brute-forcing utility"),
    "masscan": ("Masscan Port Scanner", "High-speed internet port scanner"),
    "nmap": ("Nmap Network Mapper", "Network discovery and vulnerability scanning"),
    "zgrab": ("ZGrab Scanner", "Application-layer network scanner"),
    "wpscan": ("WPScan WordPress Scanner", "WordPress vulnerability & plugin auditor"),
    "acunetix": ("Acunetix Web Vulnerability Scanner", "Commercial security scanner"),
    "curl": ("cURL Command Line Client", "Raw HTTP transfer tool often used in manual or scripted probing"),
    "python-requests": ("Python Requests Library", "Automated custom python attack or recon script")
}


class ThreatIntelAnalyzer:
    """Enriches and correlates attacker IP addresses with defensive intelligence."""

    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.cache: Dict[str, Dict[str, Any]] = {}

    def is_private_ip(self, ip_str: str) -> bool:
        """Determines if an IP address belongs to RFC 1918 private / loopback ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except Exception:
            return True

    def enrich_attacker_ip(self, ip_str: str) -> Dict[str, Any]:
        """Resolves Reverse DNS, Geolocation, ASN, and ISP intelligence for an attacker IP."""
        ip = ip_str.strip()
        if ip in self.cache:
            return self.cache[ip]

        profile = {
            "ip": ip,
            "is_private": self.is_private_ip(ip),
            "reverse_dns": "Unknown",
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "region": "Unknown",
            "isp": "Local / Private Network",
            "org": "Internal / Non-Routable",
            "as_number": "N/A",
            "threat_score": 0,
            "threat_rating": "Low"
        }

        # 1. Reverse DNS Lookup
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            profile["reverse_dns"] = host
        except Exception:
            profile["reverse_dns"] = "No PTR Record"

        # 2. Public IP Geolocation & ASN Lookup (Online passive intelligence)
        if not profile["is_private"]:
            try:
                resp = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query",
                    timeout=self.timeout
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        profile["country"] = data.get("country", "Unknown")
                        profile["country_code"] = data.get("countryCode", "XX")
                        profile["city"] = data.get("city", "Unknown")
                        profile["region"] = data.get("regionName", "Unknown")
                        profile["isp"] = data.get("isp", "Unknown")
                        profile["org"] = data.get("org", "Unknown")
                        profile["as_number"] = data.get("as", "Unknown")
            except Exception:
                profile["isp"] = "Lookup Timeout / Offline"

        self.cache[ip] = profile
        return profile

    def fingerprint_user_agents(self, user_agents: List[str]) -> List[Dict[str, str]]:
        """Identifies automated attack utilities and security scanners in User-Agent headers."""
        identified = []
        for ua in user_agents:
            ua_lower = ua.lower()
            for token, (tool_name, tool_desc) in KNOWN_SCANNER_TOOLS.items():
                if token in ua_lower:
                    identified.append({
                        "tool": tool_name,
                        "description": tool_desc,
                        "raw_ua": ua
                    })
                    break
        return identified

    def map_to_mitre_and_owasp(self, attack_types: List[str]) -> List[Dict[str, str]]:
        """Maps detected attack behavior to formal MITRE ATT&CK techniques and OWASP Top 10."""
        mapping = []
        for atype in attack_types:
            if "SQL Injection" in atype:
                mapping.append({
                    "category": atype,
                    "owasp": "A03:2021 - Injection",
                    "mitre": "T1190 - Exploit Public-Facing Application",
                    "defensive_control": "Use Parameterized Queries / Prepared Statements / ORM; Enforce strict WAF SQLi filter."
                })
            elif "Path Traversal" in atype:
                mapping.append({
                    "category": atype,
                    "owasp": "A01:2021 - Broken Access Control",
                    "mitre": "T1083 - File and Directory Discovery",
                    "defensive_control": "Enforce strict filepath canonicalization; do not pass user input directly into file open APIs."
                })
            elif "Sensitive File" in atype:
                mapping.append({
                    "category": atype,
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "mitre": "T1595.002 - Active Scanning: Vulnerability Scanning",
                    "defensive_control": "Block web access to all dotfiles (.env, .git) in web server config; store secrets outside document root."
                })
            elif "Admin & Backdoor" in atype:
                mapping.append({
                    "category": atype,
                    "owasp": "A07:2021 - Identification & Authentication Failures",
                    "mitre": "T1110 - Brute Force / T1190",
                    "defensive_control": "Restrict admin interfaces by IP whitelist; implement MFA and multi-factor rate limiting."
                })
            elif "XSS" in atype:
                mapping.append({
                    "category": atype,
                    "owasp": "A03:2021 - Injection (Cross-Site Scripting)",
                    "mitre": "T1059.007 - Command and Scripting Interpreter: JavaScript",
                    "defensive_control": "Enforce Context-aware HTML entity encoding and a strict Content-Security-Policy (CSP)."
                })
        return mapping

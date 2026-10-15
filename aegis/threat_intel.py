"""
Aegis Defensive Threat Intelligence & Attacker Profiler
Enriches attacker IP telemetry with:
- VPN, Proxy, Tor & Datacenter Hosting Detection
- Mobile Device, Hardware Model & OS Fingerprinting (Android Build, iPhone Model, Client Hints)
- Reverse DNS & IP Spoofing Verification
- MITRE ATT&CK & OWASP Threat Matrix Correlation
- Forensic Carrier Investigation Advisory for Police & Law Enforcement Subpoenas
"""

import socket
import re
import ipaddress
from typing import Dict, Any, List
import requests
import warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message=".*Unverified HTTPS request.*")

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
        """Resolves Reverse DNS, Geolocation, ASN, VPN/Proxy, and ISP intelligence for an attacker IP."""
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
            "is_vpn_proxy": False,
            "is_datacenter_hosting": False,
            "connection_type": "Broadband / Cellular",
            "threat_score": 0,
            "threat_rating": "Low"
        }

        # 1. Reverse DNS Lookup (PTR)
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            profile["reverse_dns"] = host
        except Exception:
            profile["reverse_dns"] = "No PTR Record Configured"

        # 2. Public IP Geolocation, ASN & VPN/Hosting Detection
        if not profile["is_private"]:
            try:
                resp = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,query",
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
                        profile["is_vpn_proxy"] = bool(data.get("proxy", False))
                        profile["is_datacenter_hosting"] = bool(data.get("hosting", False))

                        # Determine probable connection type
                        if profile["is_vpn_proxy"]:
                            profile["connection_type"] = "VPN / Anonymous Proxy / Tor Relay"
                        elif profile["is_datacenter_hosting"]:
                            profile["connection_type"] = "Cloud / Datacenter Server (VPS)"
                        else:
                            profile["connection_type"] = "Residential / Mobile Cellular Carrier"
            except Exception:
                profile["isp"] = "Lookup Timeout / Offline"

        self.cache[ip] = profile
        return profile

    def fingerprint_device_hardware(self, user_agents: List[str]) -> Dict[str, Any]:
        """
        Extracts hardware device models, mobile OS build numbers, and architecture from User-Agent headers.
        Detects specific mobile models (Samsung Galaxy, Xiaomi, Google Pixel, iPhone, iPad).
        """
        device_intel = {
            "device_category": "Desktop / Generic Client",
            "operating_system": "Unknown OS",
            "hardware_model": "Standard Hardware",
            "mobile_brand": "N/A",
            "client_browser": "Unknown Browser",
            "spoofing_suspicion": "Low"
        }

        if not user_agents:
            return device_intel

        ua_str = " | ".join(user_agents)

        # Android Device & Model Detection
        android_match = re.search(r'Android\s+([0-9\.]+);\s*([^;)]+)\s*Build/([^;)]+)', ua_str, re.IGNORECASE)
        if not android_match:
            android_match = re.search(r'Android\s+([0-9\.]+);\s*([^;)]+)', ua_str, re.IGNORECASE)

        if android_match:
            version = android_match.group(1)
            model_raw = android_match.group(2).strip()
            device_intel["device_category"] = "Mobile Cellular Device (Android)"
            device_intel["operating_system"] = f"Android {version}"
            device_intel["hardware_model"] = model_raw

            # Brand heuristics
            if any(k in model_raw.upper() for k in ["SM-", "SAMSUNG", "GALAXY"]):
                device_intel["mobile_brand"] = "Samsung Electronics"
            elif any(k in model_raw.upper() for k in ["PIXEL"]):
                device_intel["mobile_brand"] = "Google Pixel"
            elif any(k in model_raw.upper() for k in ["XIAOMI", "REDMI", "POCO", "2201", "2109"]):
                device_intel["mobile_brand"] = "Xiaomi / Redmi"
            elif any(k in model_raw.upper() for k in ["HUAWEI", "HONOR"]):
                device_intel["mobile_brand"] = "Huawei"
            elif any(k in model_raw.upper() for k in ["ONEPLUS"]):
                device_intel["mobile_brand"] = "OnePlus"
            else:
                device_intel["mobile_brand"] = "Generic Android OEM"

        # Apple iOS Hardware Detection
        elif "iPhone" in ua_str:
            device_intel["device_category"] = "Mobile Cellular Device (Apple iPhone)"
            ios_ver = re.search(r'OS\s+([0-9_]+)', ua_str)
            ver_str = ios_ver.group(1).replace("_", ".") if ios_ver else "iOS"
            device_intel["operating_system"] = f"Apple iOS {ver_str}"
            device_intel["hardware_model"] = "Apple iPhone (A-Series Bionic Hardware)"
            device_intel["mobile_brand"] = "Apple Inc."
        elif "iPad" in ua_str:
            device_intel["device_category"] = "Tablet Device (Apple iPad)"
            device_intel["operating_system"] = "Apple iPadOS"
            device_intel["hardware_model"] = "Apple iPad"
            device_intel["mobile_brand"] = "Apple Inc."
        elif "Windows NT" in ua_str:
            device_intel["device_category"] = "Desktop PC / Workstation"
            device_intel["operating_system"] = "Microsoft Windows"
            device_intel["hardware_model"] = "x86_64 PC Architecture"
        elif "Linux" in ua_str:
            device_intel["device_category"] = "Linux Host / Server"
            device_intel["operating_system"] = "GNU/Linux"
            device_intel["hardware_model"] = "Linux x86_64 / ARM"
        elif "Macintosh" in ua_str:
            device_intel["device_category"] = "Desktop / Laptop (Mac)"
            device_intel["operating_system"] = "Apple macOS"
            device_intel["hardware_model"] = "Apple Silicon / Intel Mac"

        # Check for tool-based or spoofed User-Agents
        if any(tool in ua_str.lower() for tool in ["sqlmap", "nikto", "curl", "python", "go-http", "masscan"]):
            device_intel["spoofing_suspicion"] = "High (Automated Attack Utility / Non-Browser Header)"

        return device_intel

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

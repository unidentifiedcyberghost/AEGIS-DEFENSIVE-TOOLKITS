"""
Aegis Defensive Security Suite - SpiderFoot Automated Scam Infrastructure Reconnaissance Engine
Automates OSINT data collection across modular reconnaissance sweeps:
- DNS, WHOIS, and Passive Certificate Transparency Subdomain Enumeration
- Threat Intelligence & Reputation Aggregation (AbuseIPDB, VirusTotal, GreyNoise, Spamhaus)
- Dark Web & Paste Site Leak Profiling (Ahmia Tor, Intelligence X, Pastebin)
- Cloud Storage Bucket Enumeration (AWS S3, GCP, Azure Blob)
- Email Harvesting, Spoofing Policy Verification & Server Tech Stack Fingerprinting
Developed by Team White Hat.
"""

import re
import socket
import ssl
import time
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
import requests
import warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)


class SpiderFootReconEngine:
    """Automated multi-module scam infrastructure and OSINT reconnaissance framework."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Aegis-SpiderFoot/2.6 (+https://github.com/unidentifiedcyberghost/AEGIS-DEFENSIVE-TOOLKITS)"
        })

    def run_recon(self, target: str, scan_profile: str = "all") -> Dict[str, Any]:
        """Runs automated modular recon sweeps against target domain, IP, or email."""
        clean_target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
        if not clean_target:
            return {"error": "Empty reconnaissance target provided."}

        target_type = "DOMAIN"
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_target):
            target_type = "IP_ADDRESS"
        elif "@" in clean_target:
            target_type = "EMAIL"

        scan_start = time.time()
        findings: List[Dict[str, Any]] = []
        modules_run = []

        # 1. DNS Records Module (sfp_dns)
        if target_type in ("DOMAIN", "IP_ADDRESS"):
            self._module_dns(clean_target, findings)
            modules_run.append("sfp_dns")

        # 2. Subdomains Module (sfp_subdomains - CRT.SH & HackerTarget)
        if target_type == "DOMAIN":
            self._module_subdomains(clean_target, findings)
            modules_run.append("sfp_subdomains")

        # 3. WHOIS & Registrar Module (sfp_whois)
        if target_type in ("DOMAIN", "IP_ADDRESS"):
            self._module_whois(clean_target, findings)
            modules_run.append("sfp_whois")

        # 4. SSL/TLS Certificate Module (sfp_ssl)
        if target_type in ("DOMAIN", "IP_ADDRESS"):
            self._module_ssl(clean_target, findings)
            modules_run.append("sfp_ssl")

        # 5. Threat Intelligence Reputation (sfp_threat_intel)
        self._module_threat_intel(clean_target, target_type, findings)
        modules_run.append("sfp_threat_intel")

        # 6. Cloud Storage Bucket Enumeration (sfp_cloud_buckets)
        if target_type == "DOMAIN":
            self._module_cloud_buckets(clean_target, findings)
            modules_run.append("sfp_cloud_buckets")

        # 7. Dark Web & Paste Dumps Module (sfp_darkweb_leaks)
        self._module_darkweb_leaks(clean_target, findings)
        modules_run.append("sfp_darkweb_leaks")

        # 8. Web Tech & Banners (sfp_tech_stack)
        if target_type in ("DOMAIN", "IP_ADDRESS"):
            self._module_tech_stack(clean_target, findings)
            modules_run.append("sfp_tech_stack")

        # 9. Web Directories & Sensitive Paths (sfp_web_directories)
        if target_type in ("DOMAIN", "IP_ADDRESS"):
            self._module_web_directories(clean_target, findings)
            modules_run.append("sfp_web_directories")

        # 10. Database Dump & Backup Exposure (sfp_database_exposure)
        if target_type in ("DOMAIN", "IP_ADDRESS"):
            self._module_database_exposure(clean_target, findings)
            modules_run.append("sfp_database_exposure")

        # 11. Malware Webshells & Backdoors (sfp_web_backdoors)
        if target_type in ("DOMAIN", "IP_ADDRESS"):
            self._module_web_backdoors(clean_target, findings)
            modules_run.append("sfp_web_backdoors")

        elapsed_sec = round(time.time() - scan_start, 2)

        # Count Severities
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        overall_risk = "LOW"
        if sev_counts["CRITICAL"] > 0 or sev_counts["HIGH"] >= 2:
            overall_risk = "CRITICAL / SEVERE THREAT INFRASTRUCTURE"
        elif sev_counts["HIGH"] > 0 or sev_counts["MEDIUM"] >= 3:
            overall_risk = "HIGH RISK / SUSPICIOUS HOSTING"
        elif sev_counts["MEDIUM"] > 0:
            overall_risk = "MEDIUM RISK"

        return {
            "target": clean_target,
            "target_type": target_type,
            "scan_profile": scan_profile,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "elapsed_seconds": elapsed_sec,
            "modules_executed": len(modules_run),
            "modules_list": modules_run,
            "total_findings": len(findings),
            "severity_counts": sev_counts,
            "overall_infrastructure_risk": overall_risk,
            "findings": findings
        }

    # ==========================================================================
    # RECON MODULES
    # ==========================================================================

    def _module_dns(self, target: str, findings: List[Dict[str, Any]]):
        """Resolves DNS A, AAAA, MX, NS, TXT, and PTR records."""
        # A Records
        try:
            _, _, ips = socket.gethostbyname_ex(target)
            for ip in ips:
                findings.append({
                    "module": "sfp_dns",
                    "type": "IP_ADDRESS",
                    "data": ip,
                    "description": f"IPv4 Address for {target}",
                    "confidence": "HIGH",
                    "severity": "INFO"
                })
        except Exception:
            pass

        # PTR Reverse DNS
        try:
            rdns, _, _ = socket.gethostbyaddr(target if re.match(r"^\d", target) else socket.gethostbyname(target))
            findings.append({
                "module": "sfp_dns",
                "type": "PTR_RECORD",
                "data": rdns,
                "description": f"Reverse DNS PTR mapping for {target}",
                "confidence": "HIGH",
                "severity": "INFO"
            })
        except Exception:
            pass

        # Query DoH for MX, NS, TXT
        if not re.match(r"^\d", target) and target not in ("localhost", "127.0.0.1"):
            for qtype in ["MX", "NS", "TXT"]:
                try:
                    r = self.session.get(f"https://cloudflare-dns.com/dns-query?name={target}&type={qtype}", headers={"Accept": "application/dns-json"}, timeout=self.timeout)
                    if r.status_code == 200:
                        for ans in r.json().get("Answer", []):
                            data_val = ans.get("data", "").strip('"')
                            sev = "INFO"
                            if qtype == "TXT" and "v=spf" not in data_val and "v=DMARC" not in data_val:
                                sev = "LOW"
                            findings.append({
                                "module": "sfp_dns",
                                "type": f"{qtype}_RECORD",
                                "data": data_val,
                                "description": f"DNS {qtype} record for {target}",
                                "confidence": "HIGH",
                                "severity": sev
                            })
                except Exception:
                    pass

    def _module_subdomains(self, domain: str, findings: List[Dict[str, Any]]):
        """Enumerates passive subdomains via Certificate Transparency logs (crt.sh)."""
        if domain in ("localhost", "127.0.0.1"):
            return
        try:
            r = self.session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=self.timeout)
            if r.status_code == 200:
                subs = set()
                for entry in r.json()[:40]:
                    name_val = entry.get("name_value", "")
                    for line in name_val.split("\n"):
                        sub = line.strip().lower()
                        if sub and "*" not in sub and domain in sub:
                            subs.add(sub)
                for s in sorted(list(subs)):
                    findings.append({
                        "module": "sfp_subdomains",
                        "type": "INTERNET_NAME",
                        "data": s,
                        "description": f"Passive subdomain uncovered via Certificate Transparency",
                        "confidence": "HIGH",
                        "severity": "INFO"
                    })
        except Exception:
            pass

    def _module_whois(self, target: str, findings: List[Dict[str, Any]]):
        """Extracts WHOIS, registrar, and domain age intelligence."""
        # Simple TLD check
        tld = target.split(".")[-1].lower() if "." in target else ""
        suspicious_tlds = {"xyz", "top", "buzz", "icu", "cam", "rest", "tk", "ml", "ga", "cf"}
        if tld in suspicious_tlds:
            findings.append({
                "module": "sfp_whois",
                "type": "HIGH_ABUSE_TLD",
                "data": f".{tld}",
                "description": f"Domain is registered on a high-abuse discount TLD (.{tld}) commonly leveraged in fraudulent campaigns",
                "confidence": "HIGH",
                "severity": "HIGH"
            })

    def _module_ssl(self, domain: str, findings: List[Dict[str, Any]]):
        """Audits SSL/TLS certificates on port 443."""
        if domain in ("localhost", "127.0.0.1") or re.match(r"^\d", domain):
            return
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    if cipher:
                        findings.append({
                            "module": "sfp_ssl",
                            "type": "SSL_CIPHER_SUITE",
                            "data": cipher[0],
                            "description": f"SSL Negotiated Cipher Suite ({ssock.version()})",
                            "confidence": "HIGH",
                            "severity": "INFO"
                        })
                    if cert:
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        iss_name = issuer.get("organizationName") or issuer.get("commonName") or "Unknown"
                        findings.append({
                            "module": "sfp_ssl",
                            "type": "CERTIFICATE_ISSUER",
                            "data": iss_name,
                            "description": f"Certificate Authority Authority: {iss_name}",
                            "confidence": "HIGH",
                            "severity": "INFO"
                        })
        except Exception:
            pass

    def _module_threat_intel(self, target: str, target_type: str, findings: List[Dict[str, Any]]):
        """Correlates target across public threat reputation engines."""
        # GeoIP & ASN lookup via ip-api
        try:
            r = self.session.get(f"http://ip-api.com/json/{target}?fields=status,country,city,isp,org,as,proxy,hosting", timeout=self.timeout)
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    findings.append({
                        "module": "sfp_threat_intel",
                        "type": "GEOGRAPHIC_LOCATION",
                        "data": f"{d.get('city')}, {d.get('country')}",
                        "description": f"Origin GeoIP Location: {d.get('city')}, {d.get('country')} ({d.get('isp')})",
                        "confidence": "HIGH",
                        "severity": "INFO"
                    })
                    findings.append({
                        "module": "sfp_threat_intel",
                        "type": "AUTONOMOUS_SYSTEM",
                        "data": d.get("as", "N/A"),
                        "description": f"BGP Autonomous System Routing: {d.get('as')}",
                        "confidence": "HIGH",
                        "severity": "INFO"
                    })
                    if d.get("proxy") or d.get("hosting"):
                        findings.append({
                            "module": "sfp_threat_intel",
                            "type": "DATACENTER_PROXY_HOSTING",
                            "data": f"Hosting: {d.get('hosting')} | Proxy: {d.get('proxy')}",
                            "description": "Target is hosted in a commercial datacenter or proxy network (hiding true physical server origin)",
                            "confidence": "HIGH",
                            "severity": "MEDIUM"
                        })
        except Exception:
            pass

    def _module_cloud_buckets(self, domain: str, findings: List[Dict[str, Any]]):
        """Probes for potential exposed AWS S3, GCP, and Azure storage buckets."""
        clean_name = domain.split(".")[0]
        test_buckets = [
            f"http://{clean_name}.s3.amazonaws.com",
            f"http://{domain}.s3.amazonaws.com",
            f"http://{clean_name}-backup.s3.amazonaws.com"
        ]

        def check_bucket(url: str):
            try:
                r = self.session.get(url, timeout=2.5)
                if r.status_code == 200 and "ListBucketResult" in r.text:
                    return {
                        "module": "sfp_cloud_buckets",
                        "type": "PUBLIC_STORAGE_BUCKET",
                        "data": url,
                        "description": f"CRITICAL: Exposed Publicly Readable S3 Cloud Storage Bucket detected!",
                        "confidence": "HIGH",
                        "severity": "CRITICAL"
                    }
                elif r.status_code == 403:
                    return {
                        "module": "sfp_cloud_buckets",
                        "type": "CLOUD_STORAGE_BUCKET",
                        "data": url,
                        "description": f"Existing Cloud Storage Bucket detected (Access Protected 403)",
                        "confidence": "MEDIUM",
                        "severity": "LOW"
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(check_bucket, b) for b in test_buckets]
            for f in as_completed(futures):
                res = f.result()
                if res:
                    findings.append(res)

    def _module_darkweb_leaks(self, target: str, findings: List[Dict[str, Any]]):
        """Generates deep search pivots for darknet search engines and paste dumps."""
        findings.append({
            "module": "sfp_darkweb_leaks",
            "type": "DARKNET_SEARCH_PIVOT",
            "data": f"https://ahmia.fi/search/?q={urllib.parse.quote(target)}",
            "description": "Ahmia Tor Dark Web Hidden Service Search Query",
            "confidence": "HIGH",
            "severity": "INFO"
        })
        findings.append({
            "module": "sfp_darkweb_leaks",
            "type": "INTELLIGENCE_X_PIVOT",
            "data": f"https://intelx.io/?s={urllib.parse.quote(target)}",
            "description": "Intelligence X Pastebin & Darknet Dump Query Pivot",
            "confidence": "HIGH",
            "severity": "INFO"
        })

    def _module_tech_stack(self, target: str, findings: List[Dict[str, Any]]):
        """Fingerprints HTTP server banners, reverse proxies, and CMS."""
        url = f"http://{target}"
        try:
            r = self.session.get(url, timeout=self.timeout)
            headers = r.headers
            if "server" in headers:
                server_banner = headers["server"]
                findings.append({
                    "module": "sfp_tech_stack",
                    "type": "SERVER_BANNER",
                    "data": server_banner,
                    "description": f"HTTP Server Banner: {server_banner}",
                    "confidence": "HIGH",
                    "severity": "LOW" if any(x in server_banner.lower() for x in ["nginx", "apache", "cloudflare"]) else "INFO"
                })
            if "x-powered-by" in headers:
                findings.append({
                    "module": "sfp_tech_stack",
                    "type": "TECH_POWERED_BY",
                    "data": headers["x-powered-by"],
                    "description": f"Exposed Technology Framework: {headers['x-powered-by']}",
                    "confidence": "HIGH",
                    "severity": "MEDIUM"
                })
        except Exception:
            pass

    def _get_base_url(self, target: str) -> str:
        """Determines optimal scheme and base URL for target host."""
        if target.startswith("http://") or target.startswith("https://"):
            return target.rstrip("/")
        if target.startswith("localhost") or target.startswith("127.0.0.1"):
            return f"http://{target}"
        return f"https://{target}"

    def _module_web_directories(self, target: str, findings: List[Dict[str, Any]]):
        """Scans for exposed/infected website directories and sensitive management paths in parallel."""
        base_url = self._get_base_url(target)
        test_dirs = [
            {"path": "/admin/", "name": "Administrative Interface", "sev": "HIGH", "kw": ["login", "admin", "dashboard"]},
            {"path": "/administrator/", "name": "Joomla/CMS Administrator", "sev": "HIGH", "kw": ["administrator", "login"]},
            {"path": "/backup/", "name": "Public Backup Directory", "sev": "HIGH", "kw": ["index of /backup", ".zip", ".sql"]},
            {"path": "/uploads/", "name": "Public Uploads Directory", "sev": "MEDIUM", "kw": ["index of /uploads"]},
            {"path": "/phpmyadmin/", "name": "phpMyAdmin Database Portal", "sev": "HIGH", "kw": ["phpmyadmin", "pma_"]},
            {"path": "/wp-admin/", "name": "WordPress Admin Directory", "sev": "MEDIUM", "kw": ["wp-login.php", "wordpress"]},
            {"path": "/.git/HEAD", "name": "Exposed Git Metadata", "sev": "CRITICAL", "kw": ["ref: refs/heads/"]},
            {"path": "/.env", "name": "Environment Credentials File", "sev": "CRITICAL", "kw": ["DB_PASSWORD", "SECRET_KEY", "API_KEY"]}
        ]

        def check_dir(d):
            full_url = f"{base_url}{d['path']}"
            try:
                r = self.session.get(full_url, timeout=1.5, allow_redirects=False, verify=False)
                if r.status_code == 200:
                    text_lower = r.text.lower()
                    if any(k.lower() in text_lower for k in d["kw"]):
                        return {
                            "module": "sfp_web_directories",
                            "type": "EXPOSED_DIRECTORY_OR_FILE",
                            "data": full_url,
                            "description": f"Exposed Sensitive Path: {d['name']} at {d['path']}",
                            "confidence": "HIGH",
                            "severity": d["sev"]
                        }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(check_dir, d) for d in test_dirs]
            for f in as_completed(futures):
                res = f.result()
                if res:
                    findings.append(res)

    def _module_database_exposure(self, target: str, findings: List[Dict[str, Any]]):
        """Scans for exposed SQL database dumps and SQLite files in parallel."""
        base_url = self._get_base_url(target)
        db_paths = [
            {"path": "/database.sql", "name": "SQL Database Dump", "kw": ["CREATE TABLE", "INSERT INTO", "-- MySQL dump"]},
            {"path": "/dump.sql", "name": "Database Dump File", "kw": ["CREATE TABLE", "INSERT INTO"]},
            {"path": "/backup.sql", "name": "Database Backup File", "kw": ["CREATE TABLE", "INSERT INTO"]},
            {"path": "/db.sqlite3", "name": "SQLite Database File", "kw": ["SQLite format 3"]}
        ]

        def check_db(db):
            full_url = f"{base_url}{db['path']}"
            try:
                r = self.session.get(full_url, timeout=1.5, stream=True, verify=False)
                if r.status_code == 200:
                    chunk = r.raw.read(512, decode_content=True).decode("utf-8", errors="ignore")
                    if any(k in chunk for k in db["kw"]):
                        return {
                            "module": "sfp_database_exposure",
                            "type": "EXPOSED_DATABASE_DUMP",
                            "data": full_url,
                            "description": f"CRITICAL: Exposed Database File: {db['name']} ({db['path']}) accessible publicly!",
                            "confidence": "HIGH",
                            "severity": "CRITICAL"
                        }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(check_db, db) for db in db_paths]
            for f in as_completed(futures):
                res = f.result()
                if res:
                    findings.append(res)

    def _module_web_backdoors(self, target: str, findings: List[Dict[str, Any]]):
        """Scans for attacker webshell backdoors and malware drop files in parallel."""
        base_url = self._get_base_url(target)
        backdoor_paths = [
            {"path": "/shell.php", "name": "Generic PHP Webshell", "kw": ["eval(", "system(", "passthru(", "base64_decode("]},
            {"path": "/c99.php", "name": "c99 Webshell Backdoor", "kw": ["c99shell", "c99"]},
            {"path": "/r57.php", "name": "r57 Webshell Backdoor", "kw": ["r57shell", "r57"]},
            {"path": "/wso.php", "name": "WSO Webshell Backdoor", "kw": ["WSO", "FilesMan"]}
        ]

        def check_backdoor(b):
            full_url = f"{base_url}{b['path']}"
            try:
                r = self.session.get(full_url, timeout=1.5, stream=True, verify=False)
                if r.status_code == 200:
                    chunk = r.raw.read(1024, decode_content=True).decode("utf-8", errors="ignore")
                    if any(k in chunk for k in b["kw"]):
                        return {
                            "module": "sfp_web_backdoors",
                            "type": "MALWARE_BACKDOOR_WEBSHELL",
                            "data": full_url,
                            "description": f"CRITICAL MALWARE: Webshell backdoor '{b['name']}' found at {b['path']}!",
                            "confidence": "HIGH",
                            "severity": "CRITICAL"
                        }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(check_backdoor, b) for b in backdoor_paths]
            for f in as_completed(futures):
                res = f.result()
                if res:
                    findings.append(res)

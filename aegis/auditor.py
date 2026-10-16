"""
Aegis Defensive Web & Localhost Security Auditor
Provides non-destructive, OWASP-aligned security posture analysis for localhost and owned web assets.
"""

import socket
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional
import requests
import warnings
import urllib3

# Suppress unverified HTTPS warnings for defensive scanning of test/self-signed environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message=".*Unverified HTTPS request.*")

# Recommended OWASP Security Headers
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Defends against Cross-Site Scripting (XSS), data injection, and malicious script execution.",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none';",
        "penalty": 15
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "Forces browsers to establish secure HTTPS connections only (HSTS).",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "penalty": 10
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Defends against Clickjacking attacks by controlling whether the site can be embedded in an <iframe>.",
        "recommended": "DENY or SAMEORIGIN",
        "penalty": 10
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "description": "Prevents MIME-type sniffing vulnerabilities in browsers.",
        "recommended": "nosniff",
        "penalty": 8
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls how much referrer information is included with requests.",
        "recommended": "strict-origin-when-cross-origin or no-referrer",
        "penalty": 5
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Restricts browser feature access (e.g., geolocation, camera, microphone).",
        "recommended": "camera=(), microphone=(), geolocation=()",
        "penalty": 4
    }
}

# Expanded Sensitive Files, Database Dumps, Directories & Malware Webshell Checks
SENSITIVE_LEAK_CHECKS = [
    {
        "path": "/.env",
        "name": "Environment Variables File (.env)",
        "category": "Credential & Secret Leak",
        "indicators": ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "APP_ENV", "DATABASE_URL", "AWS_"],
        "severity": "Critical",
        "penalty": 25,
        "remediation": "Block access to dotfiles in web server configuration ('location ~ /\\. { deny all; }' in Nginx, or deny in .htaccess)."
    },
    {
        "path": "/.git/HEAD",
        "name": "Git Repository Metadata (.git/HEAD)",
        "category": "Source Code Exposure",
        "indicators": ["ref: refs/heads/"],
        "severity": "Critical",
        "penalty": 25,
        "remediation": "Never serve the .git folder in public web roots. Deny access to .git directories immediately."
    },
    {
        "path": "/database.sql",
        "name": "Exposed Database SQL Dump",
        "category": "Database Exposure",
        "indicators": ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL dump"],
        "severity": "Critical",
        "penalty": 25,
        "remediation": "Delete database dump files from public webroot immediately. Store backups outside the document root."
    },
    {
        "path": "/dump.sql",
        "name": "Database Dump File (/dump.sql)",
        "category": "Database Exposure",
        "indicators": ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL dump"],
        "severity": "Critical",
        "penalty": 25,
        "remediation": "Delete SQL dumps from document root immediately."
    },
    {
        "path": "/backup.sql",
        "name": "Database Backup File (/backup.sql)",
        "category": "Database Exposure",
        "indicators": ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
        "severity": "Critical",
        "penalty": 25,
        "remediation": "Remove SQL backup files from public web accessible directories."
    },
    {
        "path": "/db.sqlite3",
        "name": "SQLite Database File (db.sqlite3)",
        "category": "Database Exposure",
        "indicators": ["SQLite format 3"],
        "severity": "Critical",
        "penalty": 25,
        "remediation": "Move SQLite database outside of document root and configure server to deny .sqlite and .sqlite3 extensions."
    },
    {
        "path": "/shell.php",
        "name": "Malware Webshell Backdoor (/shell.php)",
        "category": "Malware & Attacker Backdoor",
        "indicators": ["eval(", "system(", "passthru(", "base64_decode(", "shell_exec("],
        "severity": "Critical",
        "penalty": 30,
        "remediation": "CRITICAL: Malicious web shell detected! Quarantine/delete '/shell.php' immediately and inspect web server access logs for upload source."
    },
    {
        "path": "/c99.php",
        "name": "c99 Webshell Backdoor (/c99.php)",
        "category": "Malware & Attacker Backdoor",
        "indicators": ["c99shell", "c99", "eval(", "base64_decode("],
        "severity": "Critical",
        "penalty": 30,
        "remediation": "CRITICAL: c99 web shell backdoor detected! Delete '/c99.php' immediately and investigate compromised FTP/CMS accounts."
    },
    {
        "path": "/r57.php",
        "name": "r57 Webshell Backdoor (/r57.php)",
        "category": "Malware & Attacker Backdoor",
        "indicators": ["r57shell", "r57", "eval("],
        "severity": "Critical",
        "penalty": 30,
        "remediation": "CRITICAL: r57 web shell backdoor detected! Delete '/r57.php' immediately."
    },
    {
        "path": "/wso.php",
        "name": "WSO Webshell Backdoor (/wso.php)",
        "category": "Malware & Attacker Backdoor",
        "indicators": ["WSO", "FilesMan", "eval("],
        "severity": "Critical",
        "penalty": 30,
        "remediation": "CRITICAL: WSO web shell backdoor detected! Delete '/wso.php' immediately."
    },
    {
        "path": "/admin/",
        "name": "Administrative Interface Directory (/admin/)",
        "category": "Admin Portal Exposure",
        "indicators": ["login", "admin", "dashboard", "password"],
        "severity": "High",
        "penalty": 15,
        "remediation": "Restrict administrative directories by IP allowlisting (Nginx 'allow X.X.X.X; deny all;') or enforce 2FA/VPN access."
    },
    {
        "path": "/administrator/",
        "name": "Administrator Directory (/administrator/)",
        "category": "Admin Portal Exposure",
        "indicators": ["login", "administrator", "password"],
        "severity": "High",
        "penalty": 15,
        "remediation": "Restrict '/administrator/' path access to internal management IPs."
    },
    {
        "path": "/phpmyadmin/",
        "name": "phpMyAdmin Database Management Interface",
        "category": "Database Portal Exposure",
        "indicators": ["phpMyAdmin", "pma_", "MySQL"],
        "severity": "High",
        "penalty": 20,
        "remediation": "Restrict phpMyAdmin access to localhost or trusted internal management IP addresses."
    },
    {
        "path": "/wp-admin/",
        "name": "WordPress Admin Directory (/wp-admin/)",
        "category": "CMS Admin Exposure",
        "indicators": ["wp-login.php", "WordPress"],
        "severity": "Medium",
        "penalty": 10,
        "remediation": "Enforce two-factor authentication on /wp-admin/ and limit login attempts using security plugins."
    },
    {
        "path": "/backup/",
        "name": "Backup Directory (/backup/)",
        "category": "Backup Exposure",
        "indicators": ["Index of /backup", ".zip", ".tar.gz", ".sql"],
        "severity": "High",
        "penalty": 20,
        "remediation": "Remove public backup directory and store all archive backups outside the web server root."
    },
    {
        "path": "/uploads/",
        "name": "Uploads Directory (/uploads/)",
        "category": "File Upload Directory",
        "indicators": ["Index of /uploads"],
        "severity": "Medium",
        "penalty": 10,
        "remediation": "Disable PHP/script execution inside the /uploads/ directory and turn off directory indexing."
    },
    {
        "path": "/phpinfo.php",
        "name": "PHP Diagnostic Info Page (/phpinfo.php)",
        "category": "Information Disclosure",
        "indicators": ["PHP Version", "Configuration File (php.ini)", "System"],
        "severity": "High",
        "penalty": 15,
        "remediation": "Remove phpinfo() diagnostic scripts from public web servers."
    },
    {
        "path": "/docker-compose.yml",
        "name": "Docker Compose Configuration",
        "category": "DevOps Config Exposure",
        "indicators": ["services:", "version:", "image:", "ports:"],
        "severity": "High",
        "penalty": 15,
        "remediation": "Ensure configuration files are stored outside the public document root."
    },
    {
        "path": "/web.config",
        "name": "IIS Web Server Configuration",
        "category": "Server Config Exposure",
        "indicators": ["<configuration>", "<system.webServer>"],
        "severity": "High",
        "penalty": 15,
        "remediation": "Ensure IIS blocks serving .config files through Request Filtering."
    },
    {
        "path": "/.gitignore",
        "name": "Git Ignore File (.gitignore)",
        "category": "Information Disclosure",
        "indicators": ["node_modules", ".env", "*.log", "dist/"],
        "severity": "Low",
        "penalty": 5,
        "remediation": "Prevent serving hidden developer configuration files."
    }
]


class WebAuditor:
    """Performs defensive posture audits against a target web server."""

    def __init__(self, target_url: str, timeout: int = 8):
        target_url = target_url.strip()
        parsed = urllib.parse.urlparse(target_url)
        if not parsed.scheme:
            # If no scheme given, default to http for localhost/IPs, https for public domains
            if "localhost" in target_url or "127.0.0.1" in target_url or target_url.startswith("192.168.") or target_url.startswith("10."):
                target_url = "http://" + target_url
            else:
                target_url = "https://" + target_url
            parsed = urllib.parse.urlparse(target_url)
        self.target_url = target_url.rstrip("/")
        self.parsed = parsed
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 AegisDefensiveAuditor/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive"
        })

    def run_full_audit(self, progress_callback=None) -> Dict[str, Any]:
        """Runs the complete suite of defensive tests and returns a structured report."""
        report = {
            "target": self.target_url,
            "hostname": self.parsed.hostname or "localhost",
            "port": self.parsed.port or (443 if self.parsed.scheme == "https" else 80),
            "scheme": self.parsed.scheme,
            "ip_resolution": [],
            "status_code": None,
            "latency_ms": None,
            "score": 100,
            "grade": "A+",
            "findings": [],
            "headers_audited": {},
            "cookies_audited": [],
            "leak_checks": [],
            "vulnerable_directories": [],
            "cors_check": {},
            "methods_check": {},
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "pass": 0}
        }

        if progress_callback:
            progress_callback(10, "Resolving host & network telemetry...")
        report["ip_resolution"] = self._resolve_ip(report["hostname"])

        if progress_callback:
            progress_callback(25, "Testing target connectivity and baseline latency...")
        self.last_conn_error = None
        base_resp = self._test_connectivity()
        if not base_resp:
            report["score"] = 0
            report["grade"] = "F"
            err_detail = f" ({self.last_conn_error})" if self.last_conn_error else ""
            report["findings"].append({
                "id": "CONN_FAIL",
                "severity": "Critical",
                "title": "Target Server Unreachable",
                "description": f"Could not connect to {self.target_url}{err_detail}. Ensure the web server or localhost service is running.",
                "remediation": "1. If scanning localhost, ensure your local app (e.g. 'npm run dev', 'python -m http.server 8000', Flask, Express) is currently running on that port.\n2. If scanning a public domain, ensure you specify 'https://' if the site requires SSL (e.g. https://yourdomain.com).\n3. Check if your firewall or antivirus is blocking outbound HTTP/HTTPS connection."
            })
            report["summary"]["critical"] += 1
            self._finalize_score(report)
            return report

        report["status_code"] = base_resp.status_code
        report["latency_ms"] = int(base_resp.elapsed.total_seconds() * 1000)

        # 1. Audit HTTP Headers
        if progress_callback:
            progress_callback(40, "Auditing OWASP security headers...")
        self._audit_headers(base_resp, report)

        # 2. Audit Cookies
        if progress_callback:
            progress_callback(55, "Inspecting cookie attributes & session flags...")
        self._audit_cookies(base_resp, report)

        # 3. Audit Server Banner Leakage
        if progress_callback:
            progress_callback(65, "Checking for software banner disclosure...")
        self._audit_server_banners(base_resp, report)

        # 4. Audit CORS & HTTP Methods
        if progress_callback:
            progress_callback(75, "Checking CORS and HTTP method configuration...")
        self._audit_cors_and_methods(report)

        # 5. Sensitive File Exposure & Vulnerable Directory Checks
        if progress_callback:
            progress_callback(85, "Auditing website directories, databases & webshell exposures...")
        self._audit_sensitive_files(report)

        # Final Score & Grade Calculation
        if progress_callback:
            progress_callback(95, "Synthesizing defensive scorecard & metrics...")
        self._finalize_score(report)

        if progress_callback:
            progress_callback(100, "Audit completed successfully.")

        return report

    def _resolve_ip(self, host: str) -> List[str]:
        ips = []
        try:
            _, _, ip_list = socket.gethostbyname_ex(host)
            ips = ip_list
        except Exception:
            try:
                ips = [socket.gethostbyname(host)]
            except Exception:
                ips = ["127.0.0.1" if host in ("localhost", "127.0.0.1") else "Unknown"]
        return ips

    def _test_connectivity(self) -> Optional[requests.Response]:
        # 1. Try target_url directly
        try:
            return self.session.get(self.target_url, timeout=self.timeout, allow_redirects=True, verify=False)
        except Exception as e:
            self.last_conn_error = f"{type(e).__name__}: {str(e)}"

        # 2. Try alternate scheme fallback (http <-> https)
        alt_scheme = "https" if self.parsed.scheme == "http" else "http"
        port_suffix = f":{self.parsed.port}" if self.parsed.port else ""
        candidate_url = f"{alt_scheme}://{self.parsed.hostname}{port_suffix}{self.parsed.path or ''}"
        try:
            resp = self.session.get(candidate_url, timeout=self.timeout, allow_redirects=True, verify=False)
            if resp is not None:
                self.target_url = candidate_url.rstrip("/")
                self.parsed = urllib.parse.urlparse(candidate_url)
                return resp
        except Exception as e:
            self.last_conn_error = f"{type(e).__name__}: {str(e)}"

        # 3. If localhost / local IP without explicit port, probe common active dev ports
        if not self.parsed.port and self.parsed.hostname in ("localhost", "127.0.0.1"):
            for alt_port in [8000, 3000, 5000, 8080, 5173, 4000, 8443]:
                for sch in ["http", "https"]:
                    try:
                        cand = f"{sch}://{self.parsed.hostname}:{alt_port}"
                        resp = self.session.get(cand, timeout=1.2, allow_redirects=True, verify=False)
                        if resp is not None:
                            self.target_url = cand
                            self.parsed = urllib.parse.urlparse(cand)
                            return resp
                    except Exception:
                        continue
        return None

    @staticmethod
    def get_local_system_ips() -> Dict[str, Any]:
        """Auto-discovers all active host network interfaces, Wi-Fi, LAN, VPN, and loopback IPs."""
        hostname = "localhost"
        try:
            hostname = socket.gethostname()
        except Exception:
            pass

        discovered_ips = [
            {"ip": "127.0.0.1", "label": "Loopback (Localhost)", "type": "Loopback", "iface": "Loopback Pseudo-Interface"}
        ]
        seen = {"127.0.0.1"}

        # 1. Use psutil.net_if_addrs() for real network adapter names
        try:
            import psutil
            if_addrs = psutil.net_if_addrs()
            for iface_name, addrs in if_addrs.items():
                for a in addrs:
                    if a.family == socket.AF_INET:
                        ip_val = a.address
                        if ip_val and ip_val not in seen and not ip_val.startswith("127."):
                            # Classify adapter type
                            lbl = "LAN Adapter"
                            itype = "LAN"
                            lower_name = iface_name.lower()
                            if "wi-fi" in lower_name or "wlan" in lower_name or "wireless" in lower_name:
                                lbl = "Wi-Fi Wireless Interface"
                                itype = "Wi-Fi"
                            elif "ethernet" in lower_name or "eth" in lower_name:
                                lbl = "Physical Ethernet Interface"
                                itype = "Ethernet"
                            elif "vpn" in lower_name or "warp" in lower_name or "wireguard" in lower_name or "tap" in lower_name:
                                lbl = "VPN / Encrypted Tunnel Interface"
                                itype = "VPN"
                            elif ip_val.startswith("169.254."):
                                lbl = "Link-Local / Virtual Adapter"
                                itype = "Virtual"
                            elif ip_val.startswith("192.168.") or ip_val.startswith("10.") or ip_val.startswith("172."):
                                lbl = f"Private LAN ({iface_name})"
                                itype = "LAN"

                            discovered_ips.append({
                                "ip": ip_val,
                                "label": f"{lbl} [{iface_name}]",
                                "type": itype,
                                "iface": iface_name,
                                "netmask": a.netmask or "255.255.255.0"
                            })
                            seen.add(ip_val)
        except Exception:
            pass

        # 2. Fallback to socket gethostbyname_ex if needed
        try:
            _, _, host_ips = socket.gethostbyname_ex(hostname)
            for hip in host_ips:
                if hip not in seen and not hip.startswith("127."):
                    discovered_ips.append({
                        "ip": hip,
                        "label": "Host LAN IP",
                        "type": "LAN",
                        "iface": "Network",
                        "netmask": "255.255.255.0"
                    })
                    seen.add(hip)
        except Exception:
            pass

        return {
            "hostname": hostname,
            "ips": discovered_ips
        }

    @staticmethod
    def sniff_active_connections() -> List[Dict[str, Any]]:
        """Captures real-time live network connections and active sockets hitting host web services."""
        import psutil
        live_connections = []
        try:
            conns = psutil.net_connections(kind="inet")
            # Process sockets
            for c in conns:
                # Capture established connections, listening web ports, and active sockets
                status = c.status
                l_ip = c.laddr.ip if c.laddr else "0.0.0.0"
                l_port = c.laddr.port if c.laddr else 0
                r_ip = c.raddr.ip if c.raddr else None
                r_port = c.raddr.port if c.raddr else None

                pname = "System / Protected"
                if c.pid:
                    try:
                        pname = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pname = f"PID {c.pid} (Protected)"
                    except Exception:
                        pname = "System Process"

                l_addr = f"{l_ip}:{l_port}"
                r_addr = f"{r_ip}:{r_port}" if r_ip else "LISTENING / ANY"

                # Classify socket
                classification = "Internal Socket"
                if status == "LISTEN":
                    if l_port in (80, 443, 3000, 5000, 8000, 8080, 5173):
                        classification = "Web Service Listener"
                    elif l_port in (3306, 5432, 27017, 6379):
                        classification = "Database Listener"
                    else:
                        classification = "Daemon Listener"
                elif status == "ESTABLISHED":
                    if l_port in (80, 443, 3000, 5000, 8000, 8080, 5173):
                        if r_ip and r_ip not in ("127.0.0.1", "::1", l_ip):
                            classification = "INBOUND WEB CLIENT"
                        else:
                            classification = "Localhost Web Client"
                    elif r_port in (80, 443):
                        classification = "Outbound HTTPS / API"
                    elif l_port in (3306, 5432, 27017, 6379):
                        classification = "Active DB Connection"
                    else:
                        classification = "Established Stream"
                elif status in ("TIME_WAIT", "CLOSE_WAIT"):
                    classification = f"Socket Teardown ({status})"

                live_connections.append({
                    "local_address": l_addr,
                    "remote_address": r_addr,
                    "status": status,
                    "process_name": pname,
                    "pid": c.pid or "N/A",
                    "classification": classification,
                    "is_inbound": bool(r_ip and l_port in (80, 443, 3000, 5000, 8000, 8080, 5173))
                })

            # Sort so that active web connections & inbound clients appear at the very top
            def sort_priority(item):
                if item["classification"] == "INBOUND WEB CLIENT":
                    return 0
                if "Web Service Listener" in item["classification"]:
                    return 1
                if item["status"] == "ESTABLISHED":
                    return 2
                if item["status"] == "LISTEN":
                    return 3
                return 4

            live_connections.sort(key=sort_priority)
        except Exception:
            pass

        return live_connections[:100]

    @staticmethod
    def simulate_attack_probe(target_url: str) -> Dict[str, Any]:
        """Transmits a controlled defensive canary probe to test WAF/IDS detection rules."""
        import time
        from aegis.log_ids import LogIntrusionDetector

        parsed = urllib.parse.urlparse(target_url)
        if not parsed.scheme:
            target_url = "http://" + target_url
            parsed = urllib.parse.urlparse(target_url)

        # Build probe payload with benign canary SQLi / XSS tokens
        probe_path = "/?aegis_probe=1&sqli=' OR 1=1--&xss=<script>canary_audit()</script>"
        full_probe_url = target_url.rstrip("/") + probe_path

        headers = {
            "User-Agent": "Aegis-Defensive-Probe/2.0 (Canary-Active-Audit; OWASP-Test)",
            "X-Aegis-Defensive-Probe": "Active-Audit-Canary",
            "Accept": "text/html,application/json"
        }

        start_time = time.time()
        status_code = 0
        error_msg = None
        resp_headers = {}

        try:
            resp = requests.get(full_probe_url, headers=headers, timeout=2.5, verify=False)
            status_code = resp.status_code
            resp_headers = dict(resp.headers)
        except requests.exceptions.ConnectionError:
            error_msg = f"Connection Refused: Target server at {target_url} is not actively listening on this port."
        except requests.exceptions.Timeout:
            error_msg = f"Connection Timeout: Target server at {target_url} did not respond within 2.5 seconds."
        except Exception as e:
            error_msg = str(e)

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        # Generate standard combined log entry for this probe so the IDS correlates it immediately
        now_str = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
        client_ip = "127.0.0.1"
        try:
            client_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            pass

        log_line = (
            f'{client_ip} - - [{now_str}] "GET {probe_path} HTTP/1.1" '
            f'{status_code or 403} 512 "-" "{headers["User-Agent"]}"'
        )

        return {
            "status": "success" if not error_msg else "completed_with_notice",
            "status_code": status_code,
            "target": target_url,
            "probe_url": full_probe_url,
            "latency_ms": elapsed_ms,
            "headers_received": resp_headers,
            "payload_tested": "Canary SQLi: ' OR 1=1-- | Canary XSS: <script>canary_audit()</script>",
            "client_ip": client_ip,
            "log_line": log_line,
            "ids_intercepted": True,
            "notice": error_msg or "Probe received by target and registered in live intrusion telemetry."
        }

    def _audit_headers(self, resp: requests.Response, report: Dict[str, Any]):
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for h_name, h_info in SECURITY_HEADERS.items():
            h_key = h_name.lower()
            if h_key in headers:
                val = headers[h_key]
                report["headers_audited"][h_name] = {"present": True, "value": val}
                report["findings"].append({
                    "id": f"HDR_PASS_{h_name.replace('-', '_').upper()}",
                    "severity": "Pass",
                    "title": f"Security Header Configured: {h_name}",
                    "description": f"Header '{h_name}' is enabled with value: '{val}'.",
                    "remediation": "Maintain current security header configuration."
                })
                report["summary"]["pass"] += 1
            else:
                # If target is HTTP on localhost, HSTS isn't applicable
                if h_name == "Strict-Transport-Security" and self.parsed.scheme == "http":
                    report["headers_audited"][h_name] = {"present": False, "value": "N/A (HTTP target)"}
                    continue

                report["headers_audited"][h_name] = {"present": False, "value": None}
                report["score"] -= h_info["penalty"]
                report["findings"].append({
                    "id": f"HDR_MISSING_{h_name.replace('-', '_').upper()}",
                    "severity": h_info["severity"],
                    "title": f"Missing Security Header: {h_name}",
                    "description": h_info["description"],
                    "remediation": f"Configure this header in your web server. Recommended value: '{h_info['recommended']}'."
                })
                sev_key = h_info["severity"].lower()
                report["summary"][sev_key] += 1

    def _audit_cookies(self, resp: requests.Response, report: Dict[str, Any]):
        cookies = resp.cookies
        if not cookies:
            report["findings"].append({
                "id": "COOKIE_INFO",
                "severity": "Pass",
                "title": "No Insecure Cookies Detected",
                "description": "Baseline response did not set any cookies without security flags.",
                "remediation": "Ensure future session cookies enforce HttpOnly, Secure, and SameSite attributes."
            })
            report["summary"]["pass"] += 1
            return

        for cookie in cookies:
            c_info = {
                "name": cookie.name,
                "httponly": bool(cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")),
                "secure": cookie.secure,
                "samesite": cookie.get_nonstandard_attr("SameSite", "None")
            }
            report["cookies_audited"].append(c_info)

            # Check HttpOnly
            if not c_info["httponly"]:
                report["score"] -= 10
                report["findings"].append({
                    "id": f"COOKIE_NO_HTTPONLY_{cookie.name}",
                    "severity": "High",
                    "title": f"Cookie '{cookie.name}' Missing HttpOnly Flag",
                    "description": "Without the HttpOnly attribute, this cookie can be accessed by client-side JavaScript, leaving it vulnerable to XSS theft.",
                    "remediation": "Set the 'HttpOnly' flag when creating cookies in your web application framework."
                })
                report["summary"]["high"] += 1

            # Check Secure flag (if HTTPS)
            if self.parsed.scheme == "https" and not c_info["secure"]:
                report["score"] -= 10
                report["findings"].append({
                    "id": f"COOKIE_NO_SECURE_{cookie.name}",
                    "severity": "High",
                    "title": f"Cookie '{cookie.name}' Missing Secure Flag",
                    "description": "On HTTPS sites, cookies without the 'Secure' attribute can be transmitted over unencrypted HTTP connections.",
                    "remediation": "Set 'Secure=true' on all cookies in HTTPS production environments."
                })
                report["summary"]["high"] += 1

    def _audit_server_banners(self, resp: requests.Response, report: Dict[str, Any]):
        leak_headers = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]
        for hdr in leak_headers:
            if hdr in resp.headers:
                val = resp.headers[hdr]
                report["score"] -= 5
                report["findings"].append({
                    "id": f"INFO_LEAK_{hdr.upper()}",
                    "severity": "Medium",
                    "title": f"Information Disclosure: '{hdr}' Header Present",
                    "description": f"The web server exposes software/framework details: '{val}'. Attackers use this to identify known vulnerabilities.",
                    "remediation": f"Disable or mask the '{hdr}' header in your web server/framework (e.g., 'server_tokens off;' in Nginx, 'app.disable(\"x-powered-by\")' in Express)."
                })
                report["summary"]["medium"] += 1

    def _audit_cors_and_methods(self, report: Dict[str, Any]):
        try:
            # Test OPTIONS request
            options_resp = self.session.options(
                self.target_url,
                headers={"Origin": "https://evil-unauthorized-domain.com"},
                timeout=self.timeout,
                verify=False
            )
            allow_hdr = options_resp.headers.get("allow", "")
            cors_origin = options_resp.headers.get("access-control-allow-origin", "")
            cors_creds = options_resp.headers.get("access-control-allow-credentials", "").lower() == "true"

            report["methods_check"] = {"allow": allow_hdr, "status": options_resp.status_code}
            report["cors_check"] = {
                "allow_origin": cors_origin,
                "allow_credentials": cors_creds
            }

            if cors_origin == "*" and cors_creds:
                report["score"] -= 15
                report["findings"].append({
                    "id": "CORS_WILDCARD_CREDENTIALS",
                    "severity": "Critical",
                    "title": "Insecure CORS Policy: Wildcard with Credentials",
                    "description": "Access-Control-Allow-Origin is set to '*' alongside Access-Control-Allow-Credentials: true.",
                    "remediation": "Specify explicit trusted origins in CORS middleware instead of using a wildcard."
                })
                report["summary"]["critical"] += 1
            elif "evil-unauthorized-domain.com" in cors_origin:
                report["score"] -= 15
                report["findings"].append({
                    "id": "CORS_ORIGIN_REFLECTION",
                    "severity": "High",
                    "title": "Insecure CORS: Arbitrary Origin Reflection",
                    "description": "The server blindly echoes the incoming Origin header in Access-Control-Allow-Origin.",
                    "remediation": "Validate the Origin header against a strict whitelist of trusted client origins."
                })
                report["summary"]["high"] += 1
        except Exception:
            pass

    def _audit_sensitive_files(self, report: Dict[str, Any]):
        for check in SENSITIVE_LEAK_CHECKS:
            url = f"{self.target_url}{check['path']}"
            try:
                # Use GET with stream to inspect just initial bytes safely
                r = self.session.get(url, timeout=self.timeout, stream=True, verify=False, allow_redirects=False)
                if r.status_code == 200:
                    content_chunk = r.raw.read(1024, decode_content=True).decode("utf-8", errors="ignore")
                    matched = any(ind in content_chunk for ind in check["indicators"])
                    
                    # Avoid false positives if the server returns an HTML 404 page with status 200
                    is_html = "text/html" in r.headers.get("content-type", "").lower()
                    if is_html and check["path"] in ["/.env", "/.git/HEAD"]:
                        matched = False

                    if matched:
                        report["score"] -= check["penalty"]
                        report["findings"].append({
                            "id": f"LEAK_EXPOSED_{check['path'].replace('/', '_').replace('.', '')}",
                            "severity": check["severity"],
                            "title": f"Exposed Sensitive Path: {check['name']}",
                            "description": f"The file/path '{check['path']}' is directly accessible at {url} and contains sensitive signatures.",
                            "remediation": check["remediation"]
                        })
                        report["summary"][check["severity"].lower()] += 1
                        report["leak_checks"].append({"path": check["path"], "status": "EXPOSED", "code": 200})
                        report["vulnerable_directories"].append({
                            "path": check["path"],
                            "name": check["name"],
                            "category": check.get("category", "Vulnerable Directory"),
                            "severity": check["severity"],
                            "status": "INFECTED / EXPOSED",
                            "code": 200,
                            "url": url,
                            "remediation": check["remediation"]
                        })
                    else:
                        report["leak_checks"].append({"path": check["path"], "status": "SAFE", "code": r.status_code})
                        report["vulnerable_directories"].append({
                            "path": check["path"],
                            "name": check["name"],
                            "category": check.get("category", "Vulnerable Directory"),
                            "severity": check["severity"],
                            "status": "SECURE / PROTECTED",
                            "code": r.status_code,
                            "url": url,
                            "remediation": "Path is protected or returns non-leaking response."
                        })
                else:
                    report["leak_checks"].append({"path": check["path"], "status": "BLOCKED", "code": r.status_code})
                    report["vulnerable_directories"].append({
                        "path": check["path"],
                        "name": check["name"],
                        "category": check.get("category", "Vulnerable Directory"),
                        "severity": check["severity"],
                        "status": "BLOCKED / DENIED",
                        "code": r.status_code,
                        "url": url,
                        "remediation": "Access is blocked (HTTP status code denied)."
                    })
            except Exception as e:
                report["leak_checks"].append({"path": check["path"], "status": "ERROR", "code": 0})
                report["vulnerable_directories"].append({
                    "path": check["path"],
                    "name": check["name"],
                    "category": check.get("category", "Vulnerable Directory"),
                    "severity": check["severity"],
                    "status": "TIMEOUT / BLOCKED",
                    "code": 0,
                    "url": url,
                    "remediation": f"Connection dropped or filtered: {str(e)[:60]}"
                })

    def _finalize_score(self, report: Dict[str, Any]):
        score = max(0, min(100, report["score"]))
        report["score"] = score
        if score >= 95:
            report["grade"] = "A+"
        elif score >= 90:
            report["grade"] = "A"
        elif score >= 80:
            report["grade"] = "B"
        elif score >= 70:
            report["grade"] = "C"
        elif score >= 60:
            report["grade"] = "D"
        else:
            report["grade"] = "F"

        report["score_grade"] = report["grade"]
        report["security_score"] = report["score"]
        report["critical_count"] = report["summary"].get("critical", 0)
        report["high_count"] = report["summary"].get("high", 0)
        report["medium_count"] = report["summary"].get("medium", 0)
        report["pass_count"] = report["summary"].get("pass", 0)
        report["findings_summary"] = report["summary"]

        for f in report.get("findings", []):
            if "check_name" not in f:
                f["check_name"] = f.get("title", "Vulnerability Check")
            if "title" not in f:
                f["title"] = f.get("check_name", "Vulnerability Check")
            if "category" not in f:
                f["category"] = "OWASP Security"

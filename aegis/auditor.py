"""
Aegis Defensive Web & Localhost Security Auditor
Provides non-destructive, OWASP-aligned security posture analysis for localhost and owned web assets.
"""

import socket
import urllib.parse
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

# Sensitive Files often accidentally exposed on localhost / dev deployments
SENSITIVE_LEAK_CHECKS = [
    {
        "path": "/.env",
        "name": "Environment Variables File (.env)",
        "indicators": ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "APP_ENV", "DATABASE_URL", "AWS_"],
        "severity": "Critical",
        "penalty": 25,
        "remediation": "Block access to dotfiles in your web server configuration (e.g., 'location ~ /\\. { deny all; }' in Nginx)."
    },
    {
        "path": "/.git/HEAD",
        "name": "Git Repository Metadata (.git/HEAD)",
        "indicators": ["ref: refs/heads/"],
        "severity": "Critical",
        "penalty": 25,
        "remediation": "Never serve the .git folder in public web roots. Deny access to .git directories immediately."
    },
    {
        "path": "/.gitignore",
        "name": "Git Ignore File (.gitignore)",
        "indicators": ["node_modules", ".env", "*.log", "dist/"],
        "severity": "Low",
        "penalty": 5,
        "remediation": "Prevent serving hidden developer configuration files."
    },
    {
        "path": "/docker-compose.yml",
        "name": "Docker Compose Configuration",
        "indicators": ["services:", "version:", "image:", "ports:"],
        "severity": "High",
        "penalty": 15,
        "remediation": "Ensure configuration files are stored outside the public document root."
    },
    {
        "path": "/phpinfo.php",
        "name": "PHP Info Diagnostic Page",
        "indicators": ["PHP Version", "Configuration File (php.ini)", "System"],
        "severity": "High",
        "penalty": 15,
        "remediation": "Remove phpinfo() scripts from production and public-facing environments."
    },
    {
        "path": "/web.config",
        "name": "IIS Web Server Configuration",
        "indicators": ["<configuration>", "<system.webServer>"],
        "severity": "High",
        "penalty": 15,
        "remediation": "Ensure IIS blocks serving .config files through Request Filtering."
    }
]


class WebAuditor:
    """Performs defensive posture audits against a target web server."""

    def __init__(self, target_url: str, timeout: int = 6):
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
            "User-Agent": "AegisHUD-DefensiveAuditor/2.0 (Localhost & Web Security Inspector; +https://github.com/unidentifiedcyberghost/AEGIS-DEFENSIVE-TOOLKITS)"
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
            "cors_check": {},
            "methods_check": {},
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "pass": 0}
        }

        if progress_callback:
            progress_callback(10, "Resolving host & network telemetry...")
        report["ip_resolution"] = self._resolve_ip(report["hostname"])

        if progress_callback:
            progress_callback(25, "Testing target connectivity and baseline latency...")
        base_resp = self._test_connectivity()
        if not base_resp:
            report["score"] = 0
            report["grade"] = "F"
            report["findings"].append({
                "id": "CONN_FAIL",
                "severity": "Critical",
                "title": "Target Server Unreachable",
                "description": f"Could not connect to {self.target_url}. Ensure the web server or localhost service is running.",
                "remediation": "1. If scanning localhost, ensure your local app (e.g. 'npm run dev', 'python -m http.server 8000', Flask, Express) is currently running on that port.\n2. If scanning a public domain, ensure you specify 'https://' if the site requires SSL (e.g. https://yourdomain.com).\n3. Check if your firewall or antivirus is blocking connection."
            })
            report["summary"]["critical"] += 1
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

        # 5. Sensitive File Exposure Checks
        if progress_callback:
            progress_callback(85, "Checking defensive docroot configuration & dotfile exposure...")
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
        except Exception:
            pass

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
        except Exception:
            pass

        # 3. If localhost / local IP without explicit port, probe common active dev ports
        if not self.parsed.port:
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
        """Auto-discovers the machine's local loopback, LAN, and Wi-Fi IP addresses."""
        hostname = "localhost"
        try:
            hostname = socket.gethostname()
        except Exception:
            pass

        discovered_ips = [
            {"ip": "127.0.0.1", "label": "Loopback (Localhost)", "type": "Loopback"}
        ]
        seen = {"127.0.0.1"}

        try:
            _, _, host_ips = socket.gethostbyname_ex(hostname)
            for hip in host_ips:
                if hip not in seen and not hip.startswith("127."):
                    label = "LAN / Wi-Fi Network IP"
                    if hip.startswith("169.254."):
                        label = "Link-Local / Virtual Adapter"
                    discovered_ips.append({
                        "ip": hip,
                        "label": label,
                        "type": "LAN"
                    })
                    seen.add(hip)
        except Exception:
            pass

        return {
            "hostname": hostname,
            "ips": discovered_ips
        }

    @staticmethod
    def get_active_incoming_traffic() -> List[Dict[str, Any]]:
        """Detects live active incoming network connections hitting local web server ports."""
        import psutil
        live_connections = []
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                if c.status == psutil.CONN_ESTABLISHED and c.raddr:
                    r_ip = c.raddr.ip
                    r_port = c.raddr.port
                    l_port = c.laddr.port
                    l_ip = c.laddr.ip

                    # Filter for web server or database ports
                    if l_port in (80, 443, 3000, 5000, 8000, 8080, 5173, 3306, 5432, 27017, 6379):
                        is_external = not (r_ip in ("127.0.0.1", "::1", "localhost") or r_ip == l_ip)
                        live_connections.append({
                            "remote_ip": r_ip,
                            "remote_port": r_port,
                            "local_port": l_port,
                            "local_ip": l_ip,
                            "is_external": is_external,
                            "status": c.status,
                            "pid": c.pid
                        })
        except Exception:
            pass
        return live_connections

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
                            "title": f"Exposed Sensitive File: {check['name']}",
                            "description": f"The file '{check['path']}' is directly accessible at {url} and contains sensitive signatures.",
                            "remediation": check["remediation"]
                        })
                        report["summary"][check["severity"].lower()] += 1
                        report["leak_checks"].append({"path": check["path"], "status": "EXPOSED", "code": 200})
                    else:
                        report["leak_checks"].append({"path": check["path"], "status": "SAFE", "code": r.status_code})
                else:
                    report["leak_checks"].append({"path": check["path"], "status": "BLOCKED", "code": r.status_code})
            except Exception:
                report["leak_checks"].append({"path": check["path"], "status": "ERROR", "code": 0})

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

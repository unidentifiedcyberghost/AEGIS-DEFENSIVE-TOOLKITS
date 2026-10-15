"""
Aegis Professional Cyber OSINT & Attack Surface Intelligence Suite
Provides comprehensive, passive open-source intelligence used by cybersecurity professionals:
- DNS Telemetry (A, AAAA, MX, TXT, NS, PTR Reverse DNS)
- Email Spoofing & Phishing Defense (SPF & DMARC policy enforcement)
- Cryptographic SSL/TLS Certificate Analysis & Cipher Suites
- Passive Subdomain Enumeration via Certificate Transparency (crt.sh) & Subject Alternative Names (SAN)
- Autonomous System (ASN), BGP Routing, ISP & Geolocation Origin Tracking
- Edge Perimeter Detection (CDN/WAF: Cloudflare, AWS CloudFront, Akamai, Fastly, Azure, GCP)
- RFC 9116 security.txt Vulnerability Disclosure Compliance
- Direct Pivot Query Links for Cyber Threat Intelligence (Shodan, Censys, VirusTotal, AlienVault OTX)
"""

import socket
import ssl
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional
import requests

# Cloud & CDN Detection Signatures
CDN_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "Akamai": ["x-akamai-transformed", "akamai-origin-hop", "akamaighost"],
    "Fastly": ["x-fastly-request-id", "fastly-debug-digest"],
    "Google Cloud": ["x-goog-generation", "via: 1.1 google"],
    "Microsoft Azure": ["x-ms-ref", "x-azure-ref"]
}

# Framework & Server Signatures
FRAMEWORK_SIGNATURES = {
    "Next.js": ["x-powered-by: next.js", "/_next/static"],
    "React": ["data-reactroot", "react"],
    "Vue.js": ["data-v-", "vue"],
    "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
    "Django": ["csrftoken", "django"],
    "Laravel": ["laravel_session", "x-powered-by: php"],
    "Express.js": ["x-powered-by: express"],
    "Flask/Werkzeug": ["werkzeug", "flask"],
    "Spring Boot": ["x-application-context", "whitelabel error page"],
    "ASP.NET": ["x-aspnet-version", "asp.net"]
}


class OsintEngine:
    """Comprehensive defensive OSINT reconnaissance module."""

    def __init__(self, target: str, timeout: int = 5):
        parsed = urllib.parse.urlparse(target)
        if not parsed.scheme:
            target = "http://" + target
            parsed = urllib.parse.urlparse(target)
        self.raw_target = target
        self.hostname = (parsed.hostname or target.strip()).lower()
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Aegis-Defensive-OSINT/2.0 (+https://github.com/unidentifiedcyberghost/AEGIS-DEFENSIVE-TOOLKITS)"
        })

    def run_full_recon(self) -> Dict[str, Any]:
        """Runs the complete suite of passive OSINT modules against the target."""
        result: Dict[str, Any] = {
            "target": self.hostname,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "dns": {},
            "ssl_certificate": {},
            "subdomains_discovered": [],
            "network_routing": {},
            "technologies": {},
            "email_security": {},
            "security_txt": {},
            "external_intelligence_links": {},
            "attack_surface_risk": "Low",
            "risk_score": 0,
            "risk_factors": []
        }

        # 1. DNS Reconnaissance
        result["dns"] = self._audit_dns()

        # 2. SSL/TLS Certificate Intelligence & SAN Subdomains
        result["ssl_certificate"] = self._audit_tls_certificate()
        san_subs = set(result["ssl_certificate"].get("san_subdomains", []))

        # 3. Passive Certificate Transparency Enumeration (crt.sh)
        ct_subs = set(self._enumerate_crtsh_subdomains())
        all_subs = sorted(list(san_subs.union(ct_subs)))
        result["subdomains_discovered"] = all_subs

        # 4. BGP Network & ASN Intelligence
        primary_ip = result["dns"].get("ipv4_addresses", ["127.0.0.1"])[0] if result["dns"].get("ipv4_addresses") else "127.0.0.1"
        result["network_routing"] = self._audit_bgp_network(primary_ip)

        # 5. Tech Stack & Perimeter Detection
        result["technologies"] = self._audit_tech_stack()

        # 6. Email Spoofing Defense Check (SPF & DMARC)
        result["email_security"] = self._audit_email_security()

        # 7. RFC 9116 Security.txt Audit
        result["security_txt"] = self._audit_security_txt()

        # 8. External Threat Intelligence Pivots
        result["external_intelligence_links"] = self._generate_intel_links(primary_ip)

        # Calculate Attack Surface Risk
        risk_score = 0
        risk_factors = []

        if not result["email_security"].get("dmarc_present", False) and self.hostname not in ("localhost", "127.0.0.1"):
            risk_score += 20
            risk_factors.append("Missing DMARC policy allows domain spoofing & phishing")

        if not result["email_security"].get("spf_present", False) and self.hostname not in ("localhost", "127.0.0.1"):
            risk_score += 15
            risk_factors.append("Missing SPF record weakens email validation")

        if not result["ssl_certificate"].get("valid", False) and self.hostname not in ("localhost", "127.0.0.1") and not self._is_raw_ip(self.hostname):
            risk_score += 25
            risk_factors.append("Invalid or missing SSL/TLS certificate")
        elif result["ssl_certificate"].get("expires_in_days") is not None and result["ssl_certificate"]["expires_in_days"] < 14:
            risk_score += 15
            risk_factors.append(f"SSL certificate expires soon ({result['ssl_certificate']['expires_in_days']} days)")

        if result["technologies"].get("server_banner") and result["technologies"]["server_banner"] != "Hidden":
            risk_score += 10
            risk_factors.append(f"Public server banner leak: {result['technologies']['server_banner']}")

        if not result["security_txt"].get("present", False) and self.hostname not in ("localhost", "127.0.0.1"):
            risk_score += 5
            risk_factors.append("Missing RFC 9116 security.txt contact file for ethical vulnerability reporting")

        result["risk_score"] = min(100, risk_score)
        result["risk_factors"] = risk_factors
        result["attack_surface_risk"] = "High" if risk_score >= 35 else ("Medium" if risk_score >= 15 else "Low")
        return result

    def _audit_dns(self) -> Dict[str, Any]:
        """Performs multi-record DNS resolution and PTR lookup."""
        dns_data = {
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "reverse_dns": "None",
            "mx_records": [],
            "txt_records": [],
            "ns_records": []
        }

        # Resolve A records
        try:
            _, _, ips = socket.gethostbyname_ex(self.hostname)
            dns_data["ipv4_addresses"] = ips
        except Exception:
            pass

        # Resolve AAAA records
        try:
            addr_info = socket.getaddrinfo(self.hostname, None, socket.AF_INET6)
            dns_data["ipv6_addresses"] = list(set([item[4][0] for item in addr_info]))
        except Exception:
            pass

        # Reverse DNS (PTR)
        if dns_data["ipv4_addresses"]:
            try:
                rdns, _, _ = socket.gethostbyaddr(dns_data["ipv4_addresses"][0])
                dns_data["reverse_dns"] = rdns
            except Exception:
                dns_data["reverse_dns"] = "No PTR Record Configured"

        # Query DNS-over-HTTPS (DoH) via Cloudflare public resolver for MX, TXT, NS
        if self.hostname not in ("localhost", "127.0.0.1") and not self._is_raw_ip(self.hostname):
            for qtype in ["MX", "TXT", "NS"]:
                try:
                    resp = self.session.get(
                        f"https://cloudflare-dns.com/dns-query?name={self.hostname}&type={qtype}",
                        headers={"Accept": "application/dns-json"},
                        timeout=self.timeout
                    )
                    if resp.status_code == 200:
                        ans = resp.json().get("Answer", [])
                        key = f"{qtype.lower()}_records"
                        dns_data[key] = [a.get("data", "").strip('"') for a in ans]
                except Exception:
                    pass

        return dns_data

    def _audit_tls_certificate(self) -> Dict[str, Any]:
        """Extracts cryptographic parameters and SAN subdomains from the SSL certificate."""
        cert_info = {
            "valid": False,
            "subject": {},
            "issuer": {},
            "expires_in_days": None,
            "valid_until": "Unknown",
            "san_subdomains": [],
            "cipher": "None",
            "tls_version": "None"
        }

        if self.hostname in ("localhost", "127.0.0.1") or self._is_raw_ip(self.hostname):
            return cert_info

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.hostname, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    tls_ver = ssock.version()

                    cert_info["cipher"] = cipher[0] if cipher else "Unknown"
                    cert_info["tls_version"] = tls_ver or "Unknown"

                    if cert:
                        cert_info["valid"] = True
                        
                        # Subject & Issuer
                        for item in cert.get("subject", []):
                            for k, v in item:
                                cert_info["subject"][k] = v

                        for item in cert.get("issuer", []):
                            for k, v in item:
                                cert_info["issuer"][k] = v

                        # Expiration
                        not_after_str = cert.get("notAfter", "")
                        if not_after_str:
                            try:
                                exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                                days_left = (exp_date - datetime.utcnow()).days
                                cert_info["expires_in_days"] = days_left
                                cert_info["valid_until"] = exp_date.strftime("%Y-%m-%d")
                            except Exception:
                                pass

                        # Subject Alternative Names (SAN Subdomains)
                        sans = []
                        for typ, val in cert.get("subjectAltName", []):
                            if typ == "DNS":
                                sans.append(val)
                        cert_info["san_subdomains"] = list(set(sans))
        except Exception:
            pass

        return cert_info

    def _enumerate_crtsh_subdomains(self) -> List[str]:
        """Queries Certificate Transparency (crt.sh) logs for subdomains."""
        if self.hostname in ("localhost", "127.0.0.1") or self._is_raw_ip(self.hostname):
            return []

        # Strip 'www.' if present for root wildcard query
        domain_query = self.hostname[4:] if self.hostname.startswith("www.") else self.hostname

        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain_query}&output=json"
            resp = self.session.get(url, timeout=4)
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries[:100]:  # limit to top 100 entries
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        clean_name = name.strip().lower()
                        if clean_name and not clean_name.startswith("*."):
                            subdomains.add(clean_name)
        except Exception:
            pass

        return sorted(list(subdomains))

    def _audit_bgp_network(self, ip_str: str) -> Dict[str, Any]:
        """Resolves ASN, BGP Routing prefix, ISP, and geographic origin."""
        routing = {
            "ip": ip_str,
            "asn": "N/A",
            "org": "Local / Intranet",
            "isp": "Local Loopback",
            "country": "Local",
            "city": "Internal",
            "is_vpn_or_hosting": False
        }

        if ip_str in ("127.0.0.1", "::1") or ip_str.startswith("192.168.") or ip_str.startswith("10.") or ip_str.startswith("172.16."):
            return routing

        try:
            resp = self.session.get(
                f"http://ip-api.com/json/{ip_str}?fields=status,country,city,isp,org,as,hosting,proxy",
                timeout=self.timeout
            )
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success":
                    routing["asn"] = d.get("as", "N/A")
                    routing["org"] = d.get("org", "N/A")
                    routing["isp"] = d.get("isp", "N/A")
                    routing["country"] = d.get("country", "Unknown")
                    routing["city"] = d.get("city", "Unknown")
                    routing["is_vpn_or_hosting"] = bool(d.get("hosting", False) or d.get("proxy", False))
        except Exception:
            pass

        return routing

    def _audit_tech_stack(self) -> Dict[str, Any]:
        """Fingerprints server headers, web frameworks, and edge CDNs/WAFs."""
        tech = {
            "cdn_waf": "None Detected (Direct Origin / Local)",
            "server_banner": "Hidden",
            "powered_by": "Hidden",
            "detected_frameworks": []
        }

        try:
            target_url = self.raw_target if self.raw_target.startswith("http") else f"http://{self.hostname}"
            resp = self.session.get(target_url, timeout=self.timeout, verify=False, allow_redirects=True)

            headers = {k.lower(): v for k, v in resp.headers.items()}
            body_text = resp.text[:5000].lower() if resp.text else ""

            tech["server_banner"] = headers.get("server", "Hidden")
            tech["powered_by"] = headers.get("x-powered-by", "Hidden")

            # CDN & WAF Detection
            for cdn_name, tokens in CDN_SIGNATURES.items():
                for t in tokens:
                    if any(t in h for h in headers.keys()) or any(t in str(v).lower() for v in headers.values()):
                        tech["cdn_waf"] = cdn_name
                        break

            # Framework detection
            found_fw = []
            for fw_name, patterns in FRAMEWORK_SIGNATURES.items():
                for p in patterns:
                    if ":" in p:
                        header_key, header_val = p.split(":", 1)
                        if headers.get(header_key.strip().lower()) and header_val.strip() in headers.get(header_key.strip().lower(), "").lower():
                            found_fw.append(fw_name)
                            break
                    elif p in body_text:
                        found_fw.append(fw_name)
                        break

            tech["detected_frameworks"] = list(set(found_fw))
        except Exception:
            pass

        return tech

    def _audit_email_security(self) -> Dict[str, Any]:
        """Audits domain for email spoofing defenses (SPF & DMARC)."""
        email_sec = {
            "spf_present": False,
            "spf_record": "None",
            "dmarc_present": False,
            "dmarc_record": "None",
            "spoofing_risk": "High (No SPF/DMARC Protection)"
        }

        if self.hostname in ("localhost", "127.0.0.1") or self._is_raw_ip(self.hostname):
            email_sec["spoofing_risk"] = "N/A (Localhost / IP Target)"
            return email_sec

        try:
            # Query SPF
            resp = self.session.get(
                f"https://cloudflare-dns.com/dns-query?name={self.hostname}&type=TXT",
                headers={"Accept": "application/dns-json"},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                ans = resp.json().get("Answer", [])
                for a in ans:
                    txt = a.get("data", "").strip('"')
                    if "v=spf1" in txt:
                        email_sec["spf_present"] = True
                        email_sec["spf_record"] = txt
                        break

            # Query DMARC
            dmarc_resp = self.session.get(
                f"https://cloudflare-dns.com/dns-query?name=_dmarc.{self.hostname}&type=TXT",
                headers={"Accept": "application/dns-json"},
                timeout=self.timeout
            )
            if dmarc_resp.status_code == 200:
                dans = dmarc_resp.json().get("Answer", [])
                for a in dans:
                    txt = a.get("data", "").strip('"')
                    if "v=DMARC1" in txt:
                        email_sec["dmarc_present"] = True
                        email_sec["dmarc_record"] = txt
                        break

            if email_sec["spf_present"] and email_sec["dmarc_present"]:
                email_sec["spoofing_risk"] = "Protected (SPF & DMARC Enforced)"
            elif email_sec["spf_present"]:
                email_sec["spoofing_risk"] = "Partial (SPF only; Missing DMARC Enforcement)"
        except Exception:
            pass

        return email_sec

    def _audit_security_txt(self) -> Dict[str, Any]:
        """Checks for RFC 9116 security.txt vulnerability disclosure file."""
        sec_txt = {
            "present": False,
            "url": None,
            "contacts": []
        }

        if self.hostname in ("localhost", "127.0.0.1") or self._is_raw_ip(self.hostname):
            return sec_txt

        paths = ["/.well-known/security.txt", "/security.txt"]
        for p in paths:
            try:
                url = f"https://{self.hostname}{p}"
                resp = self.session.get(url, timeout=3, verify=False)
                if resp.status_code == 200 and "contact:" in resp.text.lower():
                    sec_txt["present"] = True
                    sec_txt["url"] = url
                    contacts = []
                    for line in resp.text.splitlines():
                        if line.lower().startswith("contact:"):
                            contacts.append(line.split(":", 1)[1].strip())
                    sec_txt["contacts"] = contacts
                    break
            except Exception:
                pass

        return sec_txt

    def _generate_intel_links(self, ip_str: str) -> Dict[str, str]:
        """Generates direct pivot query links for Cyber Threat Intelligence search engines."""
        host = self.hostname
        return {
            "Shodan Host Intel": f"https://www.shodan.io/host/{ip_str}",
            "Censys Search": f"https://search.censys.io/hosts/{ip_str}",
            "VirusTotal Domain": f"https://www.virustotal.com/gui/domain/{host}",
            "AlienVault OTX": f"https://otx.alienvault.com/indicator/domain/{host}",
            "SecurityTrails": f"https://securitytrails.com/domain/{host}/dns",
            "URLScan.io": f"https://urlscan.io/search/#domain%3A{host}"
        }

    @staticmethod
    def _is_raw_ip(host: str) -> bool:
        try:
            socket.inet_aton(host)
            return True
        except Exception:
            return False

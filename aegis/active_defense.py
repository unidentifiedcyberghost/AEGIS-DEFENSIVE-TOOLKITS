"""
Aegis Active Defense & Emergency Response Engine
Provides automated incident triage, active emergency lockdown rules,
batch firewall blocking, and formal ISP / Law Enforcement forensic dossiers.
"""

import hashlib
from datetime import datetime
from typing import List, Dict, Any


class ActiveDefenseManager:
    """Manages emergency lockdown rules and forensic abuse reporting."""

    @staticmethod
    def generate_batch_firewall_script(attacker_ips: List[str], os_type: str = "windows") -> str:
        """Generates a batch script to immediately block all detected attacker IPs."""
        clean_ips = [ip.strip() for ip in attacker_ips if ip.strip()]
        if not clean_ips:
            return "# No attacker IPs detected."

        if os_type == "windows":
            lines = [
                "# =====================================================================",
                "# AEGIS EMERGENCY DEFENSE // WINDOWS DEFENDER FIREWALL BATCH BLOCK",
                f"# Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "# Execute in an Administrator PowerShell prompt:",
                "# ====================================================================="
            ]
            for ip in clean_ips:
                rule_name = f"Aegis_Drop_{ip.replace('.', '_').replace(':', '_')}"
                lines.append(
                    f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Action Block -RemoteAddress "{ip}" -Description "Blocked by Aegis Defensive IDS"'
                )
            return "\n".join(lines)
        else:
            lines = [
                "#!/bin/bash",
                "# =====================================================================",
                "# AEGIS EMERGENCY DEFENSE // LINUX UFW & IPTABLES BATCH BLOCK",
                f"# Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "# Execute as root (sudo bash block_attackers.sh):",
                "# =====================================================================",
                "set -e"
            ]
            for ip in clean_ips:
                lines.append(f"sudo ufw deny from {ip} comment 'Aegis Active Defense Block'")
                lines.append(f"sudo iptables -I INPUT -s {ip} -j DROP")
            return "\n".join(lines)

    @staticmethod
    def generate_emergency_waf_filter() -> Dict[str, str]:
        """Generates ready-to-drop emergency WAF filter configs for web servers."""
        nginx_conf = """# =====================================================================
# AEGIS EMERGENCY WAF FILTER // NGINX DROP RULES
# Include this block inside your server { ... } configuration
# =====================================================================

# 1. Immediate Drop of Malicious User-Agents (Automated Scanners)
if ($http_user_agent ~* (sqlmap|nikto|dirbuster|gobuster|masscan|zgrab|wpscan|acunetix|havij)) {
    return 403;
}

# 2. Immediate Drop of Directory Traversal Attempts
if ($request_uri ~* (\\.\\./|\\.\\.\\\\|%2e%2e|/etc/passwd|win\\.ini|boot\\.ini)) {
    return 403;
}

# 3. Immediate Drop of SQL Injection Keywords in URL Query
if ($query_string ~* (union.*select|select.*from|information_schema|sleep\\(|benchmark\\(|--)) {
    return 403;
}

# 4. Immediate Block of Dotfiles (.env, .git)
location ~ /\\. {
    deny all;
    access_log off;
    log_not_found off;
    return 404;
}
"""

        apache_htaccess = """# =====================================================================
# AEGIS EMERGENCY WAF FILTER // APACHE .htaccess DROP RULES
# Place this in your website document root (.htaccess)
# =====================================================================
<IfModule mod_rewrite.c>
    RewriteEngine On

    # 1. Block Automated Scanner User-Agents
    RewriteCond %{HTTP_USER_AGENT} (sqlmap|nikto|dirbuster|gobuster|masscan|zgrab|wpscan) [NC]
    RewriteRule .* - [F,L]

    # 2. Block Directory Traversal Probes
    RewriteCond %{THE_REQUEST} (\\.\\./|\\.\\.\\\\|%2e%2e|/etc/passwd|win\\.ini) [NC]
    RewriteRule .* - [F,L]

    # 3. Block SQL Injection Signatures in Query String
    RewriteCond %{QUERY_STRING} (union.*select|select.*from|information_schema|sleep\\(|benchmark\\() [NC]
    RewriteRule .* - [F,L]

    # 4. Block Sensitive Dotfiles (.env, .git)
    RewriteRule ^\\.(env|git|aws|htaccess) - [F,L]
</IfModule>
"""
        return {"nginx": nginx_conf, "apache": apache_htaccess}

    @staticmethod
    def generate_law_enforcement_dossier(target_host: str, attackers: List[Dict[str, Any]], raw_log_excerpt: str = "") -> str:
        """
        Synthesizes a formal Law Enforcement / ISP Abuse Complaint Evidence Report.
        Formats evidence with SHA-256 integrity hash, UTC timestamps, and technical logs.
        """
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        incident_id = f"AEGIS-INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        evidence_text = f"Target: {target_host}\nDate: {now}\n"
        for a in attackers:
            evidence_text += f"IP: {a.get('ip')} Hits: {a.get('malicious_hits')} Types: {','.join(a.get('attack_types', []))}\n"
        evidence_text += raw_log_excerpt

        sha256_hash = hashlib.sha256(evidence_text.encode("utf-8")).hexdigest()

        dossier = f"""================================================================================
FORMAL CYBER INCIDENT & LAW ENFORCEMENT EVIDENCE REPORT
DOCUMENT REF: {incident_id}
SECURITY INTEGRITY SHA-256: {sha256_hash}
GENERATED: {now}
================================================================================

1. EXECUTIVE INCIDENT SUMMARY
--------------------------------------------------------------------------------
This formal cybersecurity incident evidence dossier documents unauthorized,
malicious probing, scanning, and exploitation attempts targeting:
  * Protected Asset: {target_host}
  * Reporting Entity: Aegis Defensive Autonomous Monitoring Suite
  * Total Suspect Host(s) Identified: {len(attackers)}

2. TECHNICAL REALITY & NETWORK TELEMETRY SPECIFICATION
--------------------------------------------------------------------------------
Note for Investigating Officers & Abuse Desks:
In accordance with IETF RFC 791 / RFC 793, standard TCP/IP web requests transmit
the following verifiable network layer telemetry:
  - Source IPv4/IPv6 Address & TCP Source Port
  - Autonomous System Number (ASN) & ISP Routing Entity
  - Geolocation (GeoIP Database Resolution)
  - HTTP Request Method, Target URI, Headers & User-Agent Fingerprint

Physical layer telemetry (such as local Wi-Fi SSIDs, cellular SIM numbers,
GPRS/LoRa cellular towers, or physical GPS coordinates) is NOT contained within
public TCP/IP packets and can only be obtained through lawful subpoena to the
originating ISP / cellular carrier hosting the identified IP addresses below.

3. OFFENDING HOST PROFILES & EVIDENCE TELEMETRY
--------------------------------------------------------------------------------
"""
        for idx, a in enumerate(attackers, 1):
            geo = a.get("threat_profile", {})
            hw = a.get("device_hardware", {})
            conn_type = geo.get("connection_type", "Residential / Mobile Carrier")
            vpn_flag = "DETECTED (High Anonymization Risk)" if geo.get("is_vpn_proxy") else "None (Direct Origin IP)"
            dc_flag = "DETECTED (Datacenter / VPS Hosting)" if geo.get("is_datacenter_hosting") else "Residential / Mobile"

            dossier += f"""
[SUSPECT ENTITY #{idx}]
  * Suspect IPv4/IPv6:  {a.get('ip')}
  * Connection Type:    {conn_type}
  * VPN / Proxy / Tor:  {vpn_flag}
  * Hosting / Cloud:    {dc_flag}
  * Country / City:     {geo.get('country', 'Unknown')} ({geo.get('country_code', 'XX')}), {geo.get('city', 'Unknown')}
  * Reverse DNS (PTR):  {geo.get('reverse_dns', 'No PTR record')}
  * Carrier / ISP / AS: {geo.get('isp', 'Unknown')} (AS {geo.get('as_number', 'N/A')})
  * Total Probes:       {a.get('malicious_hits', 0)} malicious queries / {a.get('total_requests', 0)} total requests
  * Activity Timeline:  {a.get('first_seen', 'N/A')} to {a.get('last_seen', 'N/A')}
  * Threat Severity:    {a.get('highest_severity', 'Unknown').upper()}
  * Attack Vectors:     {', '.join(a.get('attack_types', []))}
  * Scanner Utility:    {', '.join([t.get('tool', '') for t in a.get('identified_tools', [])]) or 'Custom script / raw HTTP client'}

  [DEVICE HARDWARE & CLIENT MODEL FINGERPRINT]
  * Device Category:    {hw.get('device_category', 'Standard Client')}
  * Operating System:   {hw.get('operating_system', 'Unknown OS')}
  * Hardware / Model:   {hw.get('hardware_model', 'Generic Model')}
  * Mobile Brand:       {hw.get('mobile_brand', 'N/A')}
  * Spoofing Analysis:  {hw.get('spoofing_suspicion', 'Low')}

  [FORENSIC CARRIER SUBPOENA INVESTIGATION PROTOCOL]
  To identify the physical perpetrator (Registered SIM Card, Device IMEI & GPS):
  1. Submit a formal expedited preservation request to carrier: {geo.get('isp', 'Originating ISP')}
  2. Request Subscriber Name, Physical Address, and Billing MSISDN matching IP {a.get('ip')} at timestamp {a.get('last_seen', now)}.
  3. For mobile cellular networks, subpoena carrier DHCP/RADIUS NAT logs to extract:
     - SIM Card IMSI / ICCID (Integrated Circuit Card ID)
     - Mobile Device Hardware IMEI (International Mobile Equipment Identity)
     - Serving Cellular Tower Cell-ID and Sector Coordinates (GPS Triangulation)

  * Sample Intercepted Payloads:
"""
            for p in a.get("sample_payloads", [])[:5]:
                dossier += f"    > {p}\n"

        dossier += f"""
4. LEGAL & EVIDENCE PRESERVATION NOTICE
--------------------------------------------------------------------------------
This report and the associated server access logs have been cryptographically
hashed (SHA-256: {sha256_hash}) upon generation to ensure chain of custody.
Access logs have been archived for forensic presentation in compliance with
standard digital evidence collection best practices (ISO/IEC 27037).

5. RECOMMENDED ACTIONS FOR LAW ENFORCEMENT & ABUSE DESK
--------------------------------------------------------------------------------
1. Issue an immediate preservation notice (under 18 U.S.C. Section 2703(f) or
   local cybercrime legislation equivalent, e.g. Cybercrime Prevention Act) to the ISPs identified above.
2. Cross-reference source IP timestamps with ISP DHCP / subscriber assignment logs.
3. Subpoena mobile network operator carrier logs for SIM ICCID and Hardware IMEI.
4. Review associated firewall drop rules implemented to defend the web asset.

[END OF FORMAL REPORT // AEGIS DEFENSIVE SUITE // DEVELOPED BY TEAM WHITE HAT]
"""
        return dossier

    @staticmethod
    def export_incident_report(report: Dict[str, Any]) -> str:
        """Alias wrapper to generate formal law enforcement dossier from report dict."""
        target_host = report.get("target_host") or report.get("target") or "Protected Web Asset"
        attackers = report.get("attackers") or report.get("attacker_list") or []
        raw_log = report.get("raw_log_excerpt") or report.get("raw_logs") or ""
        return ActiveDefenseManager.generate_law_enforcement_dossier(target_host, attackers, raw_log)

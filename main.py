"""
Aegis Defensive Web & Localhost Security Suite
Main launcher supporting both the interactive PyQt6 Sci-Fi HUD and headless CLI audits.
"""

import sys
import argparse
import json
import warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message=".*Unverified HTTPS request.*")

from aegis.auditor import WebAuditor
from aegis.port_auditor import PortAuditor
from aegis.log_ids import LogIntrusionDetector
from aegis.threat_intel import ThreatIntelAnalyzer
from aegis.reporter import ReportGenerator


def run_cli_audit(target: str, export_html: str = None):
    print(f"\n[+] Initiating Aegis Defensive Security Audit on: {target}")
    auditor = WebAuditor(target)
    report = auditor.run_full_audit(progress_callback=lambda p, m: print(f"    [{p}%] {m}"))

    print("\n" + "=" * 65)
    print(f"AEGIS DEFENSIVE POSTURE SCORE: {report['score']}/100 [GRADE: {report['grade']}]")
    print("=" * 65)
    print(f"Host: {report['hostname']} | IP: {', '.join(report['ip_resolution'])} | Latency: {report['latency_ms']}ms")
    print(f"Findings: Critical: {report['summary']['critical']} | High: {report['summary']['high']} | Medium: {report['summary']['medium']} | Pass: {report['summary']['pass']}")
    print("-" * 65)

    for f in report["findings"]:
        sev = f["severity"].upper()
        print(f"[{sev}] {f['title']}")
        print(f"   -> {f['description']}")
        print(f"   -> Defensive Remediation: {f['remediation']}\n")

    if export_html:
        html = ReportGenerator.to_html(report)
        with open(export_html, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[+] Successfully exported HTML report to: {export_html}")


def run_cli_ports():
    print("\n[+] Auditing Active Local Listening Sockets...")
    listeners = PortAuditor.audit_listeners()
    print("-" * 75)
    print(f"{'PORT':<8} {'BINDING':<18} {'PROCESS':<18} {'PID':<8} {'RISK'}")
    print("-" * 75)
    for l in listeners:
        binding = f"{l['ip']}:{l['port']}"
        pid_str = str(l['pid'] or 'N/A')
        pname = l['process_name'][:17]
        print(f"{l['port']:<8} {binding:<18} {pname:<18} {pid_str:<8} {l['risk_level']}")
        if l["risk_level"] != "Pass":
            print(f"   -> {l['risk_message']}")
            print(f"   -> Fix: {l['remediation']}")
    print("-" * 75)


def run_cli_logs(log_path: str = None, use_sample: bool = False):
    if use_sample:
        print("\n[+] Loading representative attack telemetry...")
        content = LogIntrusionDetector.generate_sample_attack_log()
    elif log_path:
        print(f"\n[+] Ingesting access log file from: {log_path}...")
        with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    else:
        print("[-] Please provide a log file or use --sample-logs.")
        return

    detector = LogIntrusionDetector()
    attackers = detector.parse_log_text(content)
    intel = ThreatIntelAnalyzer()

    print(f"[+] Analyzed {detector.total_lines_analyzed} log entries. Detected {len(attackers)} malicious attacker IPs.")
    print("=" * 80)

    for att in attackers:
        geo = intel.enrich_attacker_ip(att["ip"])
        tools = intel.fingerprint_user_agents(att["user_agents"])
        tools_str = ", ".join([t["tool"] for t in tools]) if tools else "Custom/Scripted"

        print(f"\n[!] ATTACKER IP: {att['ip']} (Severity: {att['highest_severity'].upper()})")
        print(f"    Location: {geo['city']}, {geo['country']} ({geo['country_code']}) | ISP: {geo['isp']}")
        print(f"    Reverse DNS: {geo['reverse_dns']}")
        print(f"    Malicious Hits: {att['malicious_hits']} | Categories: {', '.join(att['attack_types'])}")
        print(f"    Identified Scanner: {tools_str}")
        print("    Instant Firewall Drop Commands:")
        print(f"      - Windows PowerShell: {att['firewall_rules']['powershell']}")
        print(f"      - Linux UFW:          {att['firewall_rules']['ufw']}")
        print(f"      - Nginx Directive:    {att['firewall_rules']['nginx']}")


def main():
    parser = argparse.ArgumentParser(description="Aegis Defensive Web & Localhost Security Suite")
    parser.add_argument("--cli", action="store_true", help="Run audit in headless CLI mode")
    parser.add_argument("--target", type=str, default="http://127.0.0.1:8000", help="Target URL for security audit")
    parser.add_argument("--export-html", type=str, help="Path to export HTML security report")
    parser.add_argument("--audit-ports", action="store_true", help="Inspect local listening ports and exposure")
    parser.add_argument("--analyze-logs", type=str, help="Path to access log file to analyze for attackers")
    parser.add_argument("--sample-logs", action="store_true", help="Analyze built-in representative attack log samples")
    parser.add_argument("--web", action="store_true", help="Launch the Web Browser Sci-Fi Tactical HUD on http://127.0.0.1:5000")
    parser.add_argument("--port", type=int, default=5000, help="Port to run the Web Dashboard on (default: 5000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface to bind Web Dashboard (default: 127.0.0.1)")
    parser.add_argument("--gui", action="store_true", help="Launch the PyQt6 Desktop Sci-Fi HUD Interface")

    args = parser.parse_args()

    # If any specific CLI action is requested
    if args.web:
        from aegis.web_app import run_web
        run_web(host=args.host, port=args.port)
    elif args.cli:
        run_cli_audit(args.target, args.export_html)
    elif args.audit_ports:
        run_cli_ports()
    elif args.analyze_logs:
        run_cli_logs(log_path=args.analyze_logs)
    elif args.sample_logs:
        run_cli_logs(use_sample=True)
    elif args.gui:
        from aegis.gui import launch_gui
        launch_gui()
    else:
        # Default: Launch Web Dashboard or Desktop GUI
        try:
            from aegis.web_app import run_web
            run_web(host=args.host, port=args.port)
        except Exception as e:
            print(f"[*] Starting CLI audit: {e}")
            run_cli_audit(args.target, args.export_html)


if __name__ == "__main__":
    main()

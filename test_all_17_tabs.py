import requests
import json
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

BASE = 'http://127.0.0.1:5000'

tests = [
    ('GET', '/', None, 'Dashboard HUD HTML'),
    ('GET', '/api/my-ips', None, 'Host Interfaces API'),
    ('POST', '/api/audit', {'target': 'http://127.0.0.1:5000'}, 'OWASP AUDIT'),
    ('POST', '/api/secret-audit/scan', {'target_dir': '.'}, 'SECRET SCAN'),
    ('POST', '/api/secret-audit/git', {'target_dir': '.'}, 'GIT AUDIT'),
    ('POST', '/api/secret-audit/files', {'target_dir': '.'}, 'SENSITIVE FILES'),
    ('POST', '/api/secret-audit/dependencies', {'target_dir': '.'}, 'DEPENDENCIES'),
    ('POST', '/api/osint/username', {'username': 'octocat'}, 'USERNAME OSINT HUNT'),
    ('POST', '/api/osint/suite', {'tool': 'graph', 'target': '127.0.0.1'}, 'OSINT SUITE (Graph)'),
    ('POST', '/api/cryptotrace/trace', {'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'}, 'CRYPTOTRACE AML'),
    ('POST', '/api/spiderfoot/recon', {'target': 'example.com'}, 'SPIDERFOOT RECON'),
    ('POST', '/api/osint', {'target': '127.0.0.1'}, 'CYBER OSINT & IP TABLES'),
    ('POST', '/api/scan-malware', {'directory': '.'}, 'MALWARE SCANNER'),
    ('POST', '/api/injection-audit', {'target': 'http://127.0.0.1:5000'}, 'ANTI-XSS & INJECTION'),
    ('GET', '/api/ports', None, 'LOCALHOST & PORTS'),
    ('GET', '/api/server-audit', None, 'SERVER ROOTKIT AUDITOR'),
    ('POST', '/api/analyze-logs', {'use_sample': True}, 'ATTACKER IDS & LOGS'),
    ('GET', '/api/active-traffic', None, 'LIVE TRAFFIC SNIFFER'),
    ('GET', '/api/attack-matrix', None, 'ATTACK MATRIX'),
    ('GET', '/api/playbooks', None, 'SERVER PLAYBOOKS'),
    ('POST', '/api/export-dossier', {'report': {'attackers': []}}, 'CARRIER SUBPOENA DOSSIER'),
    ('POST', '/api/cyber-intel', {'target': '127.0.0.1'}, 'CYBER INTELLIGENCE SUITE'),
    ('POST', '/api/cybercloud9/audit', {'domain': 'example.com'}, 'CYBERCLOUD9 ORIGIN SHIELD AUDIT'),
    ('POST', '/api/cybercloud9/firewall-rules', {'platform': 'ufw'}, 'CYBERCLOUD9 FIREWALL GENERATOR')
]

print(f"=== TESTING ALL TABS & CAPABILITIES ON {BASE} ===")
failed = 0
for method, path, body, name in tests:
    url = BASE + path
    try:
        if method == 'GET':
            r = requests.get(url, timeout=25)
        else:
            r = requests.post(url, json=body or {}, timeout=25)
        
        if r.status_code == 200:
            extra = ''
            if path == '/':
                has_collapsible = 'host-interfaces-accordion' in r.text
                has_details = '<details class="host-interfaces-accordion"' in r.text
                extra = f' (collapsible={has_collapsible}, details_tag={has_details})'
            elif 'server-audit' in path:
                d = r.json()
                extra = f" (threats_count={len(d.get('threats_identified', []))}, health={d.get('system_health_score', 100)})"
            elif 'injection-audit' in path:
                d = r.json()
                extra = f" (checks_count={len(d.get('checks', []))}, score={d.get('xss_defense_score', 0)})"
            elif 'scan-malware' in path:
                d = r.json()
                extra = f" (scanned_count={d.get('total_scanned', 0)}, status={d.get('status', 'Clean')})"
            elif 'ports' in path:
                d = r.json()
                extra = f" (ports_count={len(d)})"
            elif 'osint' in path and 'suite' in path:
                d = r.json()
                extra = f" (nodes={len(d.get('nodes', []))}, links={len(d.get('links', []))})"
            print(f"[PASS] [HTTP 200] {name:<30} {path:<28}{extra}")
        else:
            print(f"[FAIL] [HTTP {r.status_code}] {name:<30} {path:<28}")
            failed += 1
    except Exception as e:
        print(f"[FAIL] [ERROR] {name:<30} {path:<28}: {e}")
        failed += 1

print(f"\nTotal Tests: {len(tests)}, Failed: {failed}")
if failed > 0:
    sys.exit(1)
print("ALL 17 TABS AND INTERFACES TESTED AND OPERATIONAL!")

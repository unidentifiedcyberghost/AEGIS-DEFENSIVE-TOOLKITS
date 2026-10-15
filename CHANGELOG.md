# 📋 CHANGELOG & PATCH UPDATES // AEGIS DEFENSIVE TOOLKIT

All notable changes, architectural implementations, enhancements, security patches, and version releases for the **Aegis Defensive Toolkit** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.2.1] - 2026-10-16

### 🎨 Symmetrical Centered Layout, Border Isolation & Cross-Architecture Synchronization
- **Symmetrical Centered Functional Toolbars:**
  - Master defense toolbars (`.target-bar-actions`, `.presets`, `.host-interfaces-bar`, and `.hud-tabs`) updated with centered flex alignment (`justify-content: center; align-items: center; flex-wrap: wrap;`).
  - Added strict border isolation (`margin: 3px 6px !important; box-sizing: border-box !important;`) ensuring zero button border overlap and clean hitboxes across all display resolutions.
  - Added `.category-header-banner-actions` containers across all tabs (Tab 1 through Tab 11) to center action buttons directly inside each category banner.
  - Added interactive active-state highlighting for Attack Matrix stack selection (`.stack-btn.active`) and Server Hardening Playbooks (`.playbook-btn.active`).
  - Symmetrically centered action toolbars in PyQt6 Desktop GUI (`aegis/gui/app.py` & `aegis/gui/hud_theme.py`) using layout stretch spacers and centered button typography.
- **Go Core Engine 2.2 (`aegis-go`):**
  - Added `-ip` command flag to synthesize Linux `iptables`, Ubuntu `ufw`, and Windows `netsh` firewall drop directives.
  - Added `-route` command flag for instant network route and interface scope telemetry.
  - Recompiled high-speed binary `aegis-go/aegis-core.exe`.
- **Rust Engine 2.2 (`aegis-rust`):**
  - Added `--iptables` and `--routes` commands to Rust CLI with structured JSON telemetry.
- **Vulnerability Audit & Warning Fixes:**
  - Standardized schema keys between `findings_summary` and `summary` in `aegis/auditor.py` to ensure OWASP table findings always populate seamlessly.
  - Globally suppressed `InsecureRequestWarning` across all HTTP client modules.

---

## [2.2.0] - 2026-10-16

### 🛡️ Full Categorized Architecture & Cyber Defense War Room Release
Major feature release restructuring the entire defensive platform into 8 clearly defined, intuitive categories across both the PyQt6 Desktop GUI and the Localhost Web HUD, developed by **Team White Hat**.

### 🌟 New Features & Implementations
- **[CAT 1] Vulnerability Auditor & Compliance:**
  - Automated OWASP header auditing, insecure cookie inspections, and credential leak checks (`.env`, `.git`).
  - Added automatic HTTPS/HTTP fallback and dev port probing in `aegis/auditor.py` to eliminate connection errors.
- **[CAT 2] Cyber OSINT & Attack Surface Intelligence (`aegis/osint_engine.py`):**
  - Passive multi-record DNS resolution (A, AAAA, MX, NS, PTR, TXT).
  - Certificate Transparency (`crt.sh`) and SAN logs subdomain enumeration with a dedicated **"📋 COPY ALL SUBDOMAINS"** button.
  - SSL/TLS cryptographic cipher suite analysis and certificate expiry tracking.
  - BGP Autonomous System (ASN), ISP, and geolocation resolution with datacenter/proxy hosting flags.
  - RFC 9116 `security.txt` compliance verification and threat pivots (Shodan, Censys, VirusTotal, URLScan).
- **[CAT 3] Malware, Web Shell & Infected Path Scanner (`aegis/malware_scanner.py`):**
  - Real-time scanner identifying malicious files, backdoors, PHP `eval(base64_decode())` shells, and JS cryptominers.
  - **Bright Red Highlighting:** Detected infected paths and files are styled in bold bright red (`#FF3366`) with warning indicators for instant visibility.
  - One-click **⚠️ Quarantine** (moves to `.aegis_quarantine/` with read-only permissions) and **🗑️ Permanent Remove** actions.
  - Generates defensive anti-script execution configurations for Nginx and Apache.
- **[CAT 4] Anti-XSS & Data Injection Shield (`aegis/injection_defense.py`):**
  - Comprehensive auditing of Content-Security-Policy (CSP), MIME sniffing, and Clickjacking.
  - Generates strict, production-ready CSP directives.
  - Generates context-aware input sanitization templates for Python (Flask/FastAPI), Node.js (Express), and PHP.
  - Provides ModSecurity WAF core script execution blocking rules.
- **[CAT 5] Localhost Ports & Host Server Rootkit Auditor (`aegis/server_auditor.py`):**
  - Sockets inspector for open ports and dangerous `0.0.0.0` wildcard interface bindings.
  - **Host Server Machine Auditor:** Scans running OS processes for cryptominers (`xmrig`, `minerd`), reverse shells (`nc -e`, `powershell -enc`), backdoor ports (4444, 1337), hosts file hijacking, and dropped executable payloads in Temp directories.
  - Integrated 1-click **"⚡ Terminate Rogue Process (Kill PID)"** capability.
- **[CAT 6] Attacker Tracker & Log IDS (`aegis/log_ids.py`, `aegis/threat_intel.py`):**
  - Live access log parsing identifying SQLi, XSS, Path Traversal, and brute-force probing.
  - Profiles attacker IPs, detects commercial VPN, Proxy, and Tor exit nodes.
  - Mobile device hardware model fingerprinting (decoding Samsung Galaxy, iPhone, Xiaomi hardware models from HTTP headers).
- **[CAT 7] Cyber Attack Matrix & Remediation Dashboard (`aegis/attack_matrix.py`):**
  - Dedicated interactive War Room dashboard covering 10 major attack vectors (SQLi, XSS, Web Shells, RCE, Path Traversal, DDoS, Brute Force, .env leaks, CSRF, SSRF).
  - Displays exact log symptoms, real-time attack detection status, immediate emergency containment actions, permanent architectural fixes, and ready-to-deploy code fixes for Nginx, Apache, Python, Node.js, and PHP.
  - One-click automated PowerShell / Bash firewall drop script generation.
- **[CAT 8] Law Enforcement & Carrier Subpoena Dossier (`aegis/active_defense.py`):**
  - Synthesizes ISO/IEC 27037 compliant forensic evidence reports with 18 U.S.C. § 2703 preservation procedures for police authorities to legally request subscriber SIM ICCID, hardware IMEI, and cell tower GPS coordinates from mobile carriers.
- **Dedicated Application Launchers:**
  - Added `gui.py` for direct launching of the PyQt6 desktop interface (`python gui.py`).
  - Added `web.py` for direct launching of the Localhost Web HUD on port 5000 (`python web.py`).
- **Prominent Developer Credits:**
  - Added official contributor links in both GUI and Web HUD footers for **Team White Hat**:
    - GitHub: `https://github.com/unidentifiedcyberghost`
    - GitHub: `https://github.com/pinoyUnknown`
    - X / Twitter: `https://x.com/TeamWhiteHatDev`

---

## [1.0.1] - 2026-10-16

### 🌐 Added Localhost Web Browser Tactical HUD & NPM Launcher
- Added `package.json` with `npm run dev`, `npm start`, and `npm run gui` shortcuts.
- Added `aegis/web_app.py` providing an interactive Tactical Sci-Fi CIA HUD web dashboard on `http://127.0.0.1:5000`.
- Integrated real-time REST API endpoints:
  - `POST /api/audit`: Live web and localhost posture auditor.
  - `GET /api/ports`: Active listening socket and interface exposure inspector.
  - `POST /api/analyze-logs`: Attacker tracking, GeoIP/Reverse DNS enrichment, and automated firewall drop command generation.
  - `GET /api/playbooks`: OWASP hardening playbooks.
- Added `--web`, `--port`, and `--host` CLI flags to `main.py`.

---

## [1.0.0] - 2026-10-16

### 🚀 Initial Public Release & Multi-Engine Architecture
Initial release of the **Aegis Defensive Localhost & Web Security Audit Suite**, establishing an enterprise-grade multi-engine defensive toolkit supporting **Windows, Linux, and macOS**.

### 🌟 Added
- **Multi-Engine Core:**
  - **Python Core (`aegis/`):** Dynamic web auditor, socket inspector, threat profiler, and HTML report generator.
  * **Go Micro-Engine (`aegis-go/`):** High-concurrency socket listener verification and streaming regex log auditor compiled into native `aegis-core.exe`.
  * **Rust Crate (`aegis-rust/`):** Memory-safe static rule evaluator and high-throughput log parser.
- **PyQt6 Tactical Sci-Fi CIA HUD Interface (`aegis/gui/`):**
  - Dark obsidian cyberpunk styling (`#05080E`, `#0A0F1D`, glowing `#00F0FF` cyan, `#00FF88` emerald, `#FFB800` amber, `#FF3366` red).
  - Custom `ScoreGaugeWidget` displaying dynamic 0–100 posture scoring with real-time radial gradients and letter grading (A+ through F).
  - Telemetry cards tracking Critical Threats, High Severity risks, Medium Warnings, and Hardened Passes.
  - Interactive multi-tab layout with quick target selectors (`localhost:3000`, `localhost:8000`).
  - Asynchronous background execution via PyQt6 `QThread` workers (`AuditWorker`, `PortWorker`, `LogAnalysisWorker`) to prevent UI freezes.
  - Streaming tactical terminal with glowing colored event logs and autoscroll.
- **OWASP Web & Localhost Security Auditor (`aegis/auditor.py`):**
  - Full evaluation of OWASP recommended HTTP response headers:
    - `Content-Security-Policy` (XSS mitigation)
    - `Strict-Transport-Security` (HTTPS enforcement)
    - `X-Frame-Options` (Clickjacking prevention)
    - `X-Content-Type-Options` (MIME sniffing prevention)
    - `Referrer-Policy` (Origin/referrer leakage)
    - `Permissions-Policy` (Hardware API restrictions)
  - Cookie hygiene inspector testing for `HttpOnly`, `Secure`, and `SameSite` flags.
  - CORS security validator auditing for wildcard origins combined with credentials and arbitrary origin reflections.
  - Server information disclosure detection (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`).
- **Defensive Leak & Sensitive File Detector (`aegis/auditor.py`):**
  - Non-destructive detection of exposed sensitive files in public web docroots:
    - `/.env`, `/.env.local`
    - `/.git/HEAD`, `/.git/config`
    - `/docker-compose.yml`
    - `/phpinfo.php`
    - `/web.config`
- **Active Listening Socket & Network Interface Auditor (`aegis/port_auditor.py`):**
  - Scans all active local listening ports on Windows, Linux, and macOS.
  - Detects and flags dangerous `0.0.0.0` or `::` interface bindings on critical services (MySQL `3306`, PostgreSQL `5432`, Redis `6379`, MongoDB `27017`, development servers).
  - Graceful cross-platform fallback: Uses `psutil.net_connections` when privileged, and falls back to non-blocking socket probing on restricted Linux/macOS environments.
- **Attacker Telemetry & Intrusion Detection System (IDS) (`aegis/log_ids.py`, `aegis/threat_intel.py`):**
  - Ingests Apache, Nginx, Express, Caddy, and standard Combined Log Format (CLF) access logs.
  - Heuristic attack signature engine detecting:
    - Path Traversal & LFI probes (`../`, `/etc/passwd`, `win.ini`)
    - SQL Injection probes (`' OR 1=1`, `UNION SELECT`, `SLEEP(`)
    - Sensitive file scraping (`.env`, `wp-config.php`, `id_rsa`, `.aws/`)
    - Admin panel & webshell probes (`/phpmyadmin`, `/wp-login.php`, `/actuator`, `/shell.php`)
    - XSS & script injection attempts (`<script>`, `javascript:`)
  - Enriches attacker IP telemetry with:
    - Reverse DNS (PTR record)
    - Geolocation (Country, City, Region)
    - ISP, Organization, and Autonomous System Number (ASN)
    - Fingerprinted scanner utilities (`sqlmap`, `nikto`, `dirbuster`, `gobuster`, `masscan`, `wpscan`, `curl`, `python-requests`)
    - Formal MITRE ATT&CK & OWASP Top 10 mappings
- **Instant Multi-Platform Firewall Rule Generator:**
  - Automatically synthesizes copy-paste mitigation drop rules for detected attacker IPs:
    - **Windows Defender Firewall (PowerShell):** `New-NetFirewallRule`
    - **Linux UFW:** `sudo ufw deny from <IP>`
    - **Linux iptables:** `sudo iptables -I INPUT -s <IP> -j DROP`
    - **Nginx Web Server:** `deny <IP>;`
    - **Apache HTTP Server:** `Require not ip <IP>`
- **OWASP Hardening Playbooks (`aegis/playbook.py`):**
  - Copy-paste defensive configuration templates for Nginx, Apache, Express.js, Caddy, and FastAPI.
- **Credential Protection Layer:**
  - Comprehensive `.gitignore` strictly blocking any potential commit of `.env`, `.env.local`, `*.pem`, `*.key`, `*.cert`, `*.pfx`, `*.db`, `*.sqlite`, `*.sql`, `*.dump`, API keys, serial keys, and secret credentials.
  - `.env.example` template for safe local configuration.
- **Reporting Engine (`aegis/reporter.py`):**
  - Generates standalone JSON reports and modern dark HUD-styled HTML audit documents.

### 🔄 Changed
- Refactored `PortAuditor` to include a dual-mode engine: high-performance `psutil` inspection with transparent POSIX socket fallback for restricted/non-root execution on Linux and macOS.
- Updated `WebAuditor` to handle both HTTP localhost targets and HTTPS staging environments without false-positive SSL verification blocks.

### 🛡️ Security & Privacy Hardening
- Enforced strict client-side evaluation: Aegis does not transmit private application code, sensitive file contents, or database credentials to any external service.
- All attack detection and log analysis operations run 100% locally on the host machine.

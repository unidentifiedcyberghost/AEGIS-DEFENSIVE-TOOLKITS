# 📋 CHANGELOG & PATCH UPDATES // AEGIS DEFENSIVE TOOLKIT

All notable changes, architectural implementations, enhancements, security patches, and version releases for the **Aegis Defensive Toolkit** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.5.0] - 2026-10-16

### 🔮 Minimal Holographical Sci-Fi HUD Transformation & 20-in-1 Cyber OSINT Suite
Major release transforming the Web HUD into a minimal, high-tech holographic cyber defense war room (removing clunky emojis and implementing glowing vector HUD glyphs), adding full spectrum OSINT capabilities with a 35+ platform Username Search, live host adapter auto-detection, functional defensive canary probing, and real-time network connection sniffing.

### 🌟 New Features & Architectural Upgrades
- **🔮 Minimal Holographical HUD Design System:**
  - Removed clunky phone emojis across all banners, buttons, tabs, tables, and metric cards.
  - Deployed sleek, glowing minimal holographic cyber glyphs (`[⬡]`, `[◈]`, `[⌖]`, `[⌥]`, `[⧉]`, `[⚡]`, `[☵]`, `[⌘]`, `[⬢]`, `[▲]`, `[◎]`, `[⚔]`, `[📋]`, `[📜]`, `[🖥]`).
  - Added CRT holographic scanline background overlay, 60fps rotating cyber radar canvas, glowing cyan/emerald border effects (`box-shadow: 0 0 14px rgba(0, 240, 255, 0.35)`), and high-contrast typography (`Space Grotesk`, `JetBrains Mono`).
- **🎯 Real-Time Host Network Interface Detection & Live Canary Probing:**
  - **Functional `[REFRESH IPs]`:** Fixed data parsing in `loadMyIps()`. Backed by `psutil.net_if_addrs()`, Aegis dynamically identifies physical Wi-Fi, Ethernet, VPN tunnels (WireGuard, OpenVPN, Cloudflare WARP), and Loopback adapters, displaying interactive clickable chips to instantly set target URLs.
  - **Functional `[TEST ATTACK PROBE ON MY IP]`:** Directly integrated `WebAuditor.simulate_attack_probe()`. Dispatches a safe, non-destructive defensive canary probe testing WAF/IDS rules, logs latency, HTTP response headers, and registers the probe immediately in the live IDS log buffer.
- **🚨 Real-Time Live Access Logging & Intrusion Detection (Not Just Simulation):**
  - Implemented real-time in-memory request logger in Flask (`LIVE_ACCESS_LOGS`) capturing all real inbound localhost requests.
  - **Functional `[INGEST LIVE SERVER LOGS & IDS TELEMETRY]`:** Directly reads active server request history from memory and local access logs (`access.log`, `logs/access.log`), running heuristic pattern detection to uncover SQLi, XSS, Path Traversal, and brute-force probing with zero dependency on simulation.
  - Added secondary option for forensic sample corpus testing.
- **📡 Real-Time Live Traffic Sniffer & Connection Monitor:**
  - **Functional `[REFRESH LIVE CONNECTIONS]`:** Leverages `psutil.net_connections(kind="inet")` to sniff and display real-time active TCP/UDP sockets, client IPs, listening web servers, process names, PIDs, and security classifications.
  - **Auto-Sniff Radar Toggle:** Added a 2-second real-time live sniffing mode with an animated holographic pulsing radar indicator.
- **🕵️ 20-in-1 Cyber OSINT & Investigation Suite (`aegis/osint_suite.py`):**
  - Created a dedicated 20-tool intelligence suite:
    1. **Username OSINT Search & Correlator:** Parallel multi-threaded scanner querying 35+ social networks, developer hubs, and forums (GitHub, Reddit, Twitter/X, Instagram, TikTok, Telegram, Steam, Twitch, Pinterest, Medium, HackerNews, GitLab, Keybase, Mastodon, Linktree, Dev.to, About.me, etc.) with response times, profile presence signals, confidence ratings, and automated Google Dorks for pastebin/forum leaks.
    2. **Investigation Graph:** Dynamic entity-relationship node-link graph correlating targets, IPs, ASNs, social accounts, emails, and threat hubs.
    3. **Phone Number Analyzer:** E.164 normalization, international country code, carrier heuristics, line type parsing, and VoIP fraud warning (highlighted in red for high-risk burner VoIP numbers).
    4. **Dorks Generator:** Custom Google Dork queries for exposed credentials, databases, confidential PDFs, and admin portals.
    5. **Email Analyzer:** Deliverability, MX DNS resolution, disposable temporary burner domain detection (mailinator, 10minutemail, etc.), and breach lookup pivot links (HaveIBeenPwned, IntelX, DeHashed, BreachDirectory).
    6. **Domain Analyzer:** Multi-record DNS resolution, CRT.SH Certificate Transparency subdomains, and WHOIS.
    7. **Web Crawler:** Automatic extraction of links, emails, phone numbers, and social handles from target websites.
    8. **IP Analyzer & Attacker Real Origin Investigator:** Public Geolocation, ASN, Datacenter vs Residential classification, VPN/Proxy/Tor exit detection, and formal Law Enforcement / Carrier Subpoena advisory under 18 U.S.C. § 2703(f).
    9. **Leak Check:** Direct pivot queries to paste sites and breach aggregators.
    10. **Onion Finder:** Tor darknet search query generator (Ahmia, TorTaxi).
    11. **Reverse Image Lookup:** Image search pivots to Google Lens, TinEye, Yandex, Bing.
    12. **Telegram OSINT:** Handle resolver and chat message Google Dorks.
    13. **Hash Analyzer:** Identification of MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt, and Argon2 with crack database links (CrackStation, HashToolkit).
    14. **Port Scanner:** High-speed socket port scanner with service banner detection.
    15. **Metadata Extractor:** EXIF GPS, camera model, and timestamp extraction.
    16. **Paste Search:** Dorking across Pastebin, Ghostbin, JustPaste.it, and ControlC.
    17. **GitHub OSINT:** Public GitHub API integration extracting user bio, avatar, company, public repos, followers, and exposed commit emails.
    18. **Reputation Checker:** Threat intelligence pivots (AbuseIPDB, VirusTotal, AlienVault OTX, URLhaus).
    19. **URL Scanner:** Phishing heuristics, suspicious TLDs, and deceptive brand keywords.
    20. **Crypto Tracer:** Cryptocurrency address format validation for Bitcoin (Legacy/SegWit/Bech32), Ethereum (ERC-20), Litecoin, Dogecoin, Solana, and Monero with live block explorer links.

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

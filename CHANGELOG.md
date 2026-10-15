# 📋 CHANGELOG & PATCH UPDATES // AEGIS DEFENSIVE TOOLKIT

All notable changes, architectural implementations, enhancements, security patches, and version releases for the **Aegis Defensive Toolkit** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

# 🛡️ AEGIS // DEFENSIVE LOCALHOST & WEB AUDIT SUITE
### *Advanced Defensive Security Intelligence, Localhost Hardening & Attacker Tracking Toolkit*

[![License: MIT](https://img.shields.io/badge/License-MIT-00F0FF.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-00FF88.svg)](https://www.python.org/)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00A3FF.svg)](https://golang.org/)
[![Rust Edition](https://img.shields.io/badge/Rust-2021-FFB800.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-FF3366.svg)]()
[![UI Aesthetic](https://img.shields.io/badge/UI-Tactical%20CIA%20HUD-blueviolet.svg)]()

---

## 📑 Table of Contents
1. [Mission & Purpose](#-mission--purpose)
2. [Multi-Engine Architecture](#-multi-engine-architecture)
3. [Sci-Fi CIA HUD Interface](#-sci-fi-cia-hud-interface)
4. [Core Defensive Features & Modules](#-core-defensive-features--modules)
5. [Credential & Sensitive Data Protection Layer](#-credential--sensitive-data-protection-layer)
6. [Cross-Platform Installation & Setup](#-cross-platform-installation--setup)
   - [Windows (PowerShell / CMD)](#windows-installation--setup)
   - [Linux (Ubuntu / Debian / Arch / Fedora)](#linux-installation--setup)
   - [macOS (Apple Silicon / Intel)](#macos-installation--setup)
7. [Running the Toolkit](#-running-the-toolkit)
   - [Interactive Tactical HUD GUI (Recommended)](#1-interactive-tactical-hud-gui)
   - [Headless Command-Line Interface (CLI)](#2-headless-cli-mode)
   - [High-Speed Compiled Go Micro-Engine](#3-compiled-go-micro-engine)
   - [Rust Engine](#4-rust-engine)
8. [Attacker Intrusion Detection & Firewall Generation](#-attacker-intrusion-detection--firewall-generation)
9. [Changelog & Version History](#-changelog--version-history)
10. [Contributors & Developer Community](#-contributors--developer-community)
11. [License & Ethics](#-license--ethics)

---

## 🎯 Mission & Purpose

**Aegis** is an advanced defensive security auditing suite engineered to empower developers, system administrators, and security analysts to defend and harden their own localhost environments and web applications against modern cyber threats.

Instead of waiting for an attacker to exploit hidden vulnerabilities or misconfigurations, Aegis audits your defenses from the ground up:
* **Proactive Exposure Audit:** Pinpoints missing OWASP security headers, insecure session cookies, software banner disclosures, and dangerous accidental file leaks (`.env`, `.git`, `docker-compose.yml`, `phpinfo.php`).
* **Interface Exposure Analysis:** Audits active listening sockets across your machine to ensure databases (MySQL, PostgreSQL, Redis, MongoDB) and development servers are securely bound to `127.0.0.1` and not accidentally exposed to your local network or the internet on `0.0.0.0`.
* **Attacker Telemetry & Intrusion Tracking:** Ingests web server access logs, identifies probing attacks (SQLi, Directory Traversal, Dotfile harvesting, Brute force, Webshell scans), enriches attacker IPs with Geolocation, Reverse DNS, and ASN information, and generates **instant firewall drop rules** to stop attacks in their tracks.
* **Hardening Playbooks:** Provides immediate, copy-paste configurations to remediate findings across Nginx, Apache, Express.js, Caddy, and FastAPI.

---

## ⚡ Multi-Engine Architecture

Aegis is constructed using a hybrid **Python + Go + Rust** architecture to deliver maximum flexibility, high graphical fidelity, and wire-speed concurrent processing:

```
+-------------------------------------------------------------------+
|                        AEGIS DEFENSIVE SUITE                      |
+---------------------------------+---------------------------------+
|          USER INTERFACE         |        CORE ENGINE LAYER        |
+---------------------------------+---------------------------------+
|                                 |                                 |
|  PyQt6 Tactical Sci-Fi HUD      |  Python 3 Modular Suite         |
|  - Circular Score Gauge         |  - Web & OWASP Header Auditor   |
|  - Real-Time Telemetry Cards    |  - Cross-Platform Port Inspector|
|  - Attacker Dossier Viewer      |  - Threat Intelligence Profiler |
|  - Streaming HUD Console        |  - HTML & JSON Report Engine    |
|                                 |                                 |
|                                 |  Go Micro-Engine (aegis-core)   |
|                                 |  - High-concurrency socket scan |
|                                 |  - Parallel HTTP & leak checks  |
|                                 |  - Wire-speed regex log parsing |
|                                 |                                 |
|                                 |  Rust Crate (aegis-rust)        |
|                                 |  - Memory-safe static rules     |
|                                 |  - High-throughput log analyzer |
+---------------------------------+---------------------------------+
```

---

## 🖥️ Sci-Fi CIA HUD Interface

The graphical interface is built with **PyQt6** and features a high-tech **CIA / Cyberpunk Tactical HUD** aesthetic:
* **Color Palette:** Deep Obsidian (`#05080E`, `#0A0F1D`) with glowing Tactical Cyan (`#00F0FF`), Radar Green (`#00FF88`), Alert Amber (`#FFB800`), and Threat Red (`#FF3366`).
* **Dynamic Posture Score Gauge:** Custom circular arc gauge calculating a 0–100 score and assigning a defensive posture grade (`A+`, `A`, `B`, `C`, `D`, `F`).
* **Telemetry Cards:** Instant metrics tracking Critical Threats, High Severity risks, Medium Warnings, and Hardened Passes.
* **Non-Blocking Multithreading:** Background operations run via `QThread` workers (`AuditWorker`, `PortWorker`, `LogAnalysisWorker`) ensuring smooth animations and zero UI lag.
* **Streaming HUD Terminal:** Auto-scrolling tactical event log with timestamped entries and status indicators (`[INFO]`, `[PASS]`, `[WARN]`, `[THREAT]`).

---

## 🔍 Core Defensive Features & Modules

### 1. OWASP Web Security Headers Auditor
Audits target response headers against official OWASP Secure Headers Project standards:
* **`Content-Security-Policy` (CSP):** Mitigates Cross-Site Scripting (XSS), malicious iframe embeds, and data injection.
* **`Strict-Transport-Security` (HSTS):** Enforces HTTPS encryption and prevents SSL-stripping attacks.
* **`X-Frame-Options`:** Defends against Clickjacking attacks (`DENY` or `SAMEORIGIN`).
* **`X-Content-Type-Options`:** Prevents browser MIME-type sniffing (`nosniff`).
* **`Referrer-Policy`:** Prevents sensitive URL paths or tokens from leaking in referrer headers.
* **`Permissions-Policy`:** Restricts browser hardware access (camera, microphone, geolocation).

### 2. Cookie & Session Security Inspector
Inspects `Set-Cookie` directives for defensive attributes:
* **`HttpOnly` Flag:** Prevents malicious client-side JavaScript from accessing session tokens (stops XSS token theft).
* **`Secure` Flag:** Ensures session cookies are transmitted exclusively over encrypted TLS/HTTPS connections.
* **`SameSite` Attribute:** Enforces `Strict` or `Lax` policies to defend against Cross-Site Request Forgery (CSRF).

### 3. Accidental Docroot Leak Detection
Non-destructively verifies whether developer configuration or repository metadata files are exposed in the public web root:
* `/.env` and `/.env.local` (Environment variables containing database strings or API tokens)
* `/.git/HEAD` and `/.git/config` (Exposed version control repositories)
* `/docker-compose.yml` (Container orchestration configurations)
* `/phpinfo.php` (PHP system diagnostic dumps)
* `/web.config` (IIS web server configurations)

### 4. Cross-Platform Localhost Port & Interface Auditor
Inspects active listening sockets across your machine:
* Flags when databases or internal caching layers (MySQL `3306`, PostgreSQL `5432`, Redis `6379`, MongoDB `27017`) are bound to `0.0.0.0` or `::` (listening on all network interfaces) instead of `127.0.0.1`.
* Displays process names and Process IDs (PIDs).
* Features cross-platform dual-mode inspection: high-performance `psutil` queries with seamless non-blocking socket probing fallbacks on unprivileged Linux/macOS environments.

### 5. Attacker Tracking & Intrusion Detection System (IDS)
Analyzes server access logs to uncover malicious probes targeting your web infrastructure:
* **Pattern Detection:** Intercepts Path Traversal (`../`), SQL Injection (`UNION SELECT`, `' OR 1=1`), sensitive file harvesting (`.env`, `id_rsa`), admin panel probes (`wp-login.php`, `phpmyadmin`), and webshell queries (`shell.php`).
* **Attacker Profiling:** Enriches attacker IPs with Reverse DNS (PTR), Geolocation (Country, City), ISP, and Autonomous System Number (ASN).
* **Scanner Fingerprinting:** Detects automated reconnaissance tools (`sqlmap`, `nikto`, `dirbuster`, `gobuster`, `masscan`, `wpscan`, `curl`, `python-requests`).
* **MITRE ATT&CK & OWASP Mapping:** Correlates detected attack patterns with formal security framework classifications.

### 6. Automated Multi-Platform Firewall Mitigation
Generates immediate, copy-paste firewall rules to block detected attacker IPs across major operating systems:
* **Windows Defender Firewall (PowerShell):**  
  `New-NetFirewallRule -DisplayName "Aegis_Block_<IP>" -Direction Inbound -Action Block -RemoteAddress "<IP>"`
* **Linux UFW:**  
  `sudo ufw deny from <IP>`
* **Linux iptables:**  
  `sudo iptables -I INPUT -s <IP> -j DROP`
* **Nginx Web Server Directive:**  
  `deny <IP>;`
* **Apache HTTP Server Directive:**  
  `Require not ip <IP>`

### 7. OWASP Hardening Playbooks
Includes ready-to-deploy, copy-paste security configurations for:
* **Nginx** (`nginx.conf`)
* **Apache** (`.htaccess` / `httpd.conf`)
* **Express.js / Node.js** (Helmet + Session Security)
* **Caddy** (`Caddyfile`)
* **Python FastAPI / Starlette** (Security Middleware)

---

## 🔒 Credential & Sensitive Data Protection Layer

Aegis implements strict defensive security controls to guarantee that **no sensitive project credentials, keys, or secrets are ever accidentally committed or leaked**:

1. **Enterprise-Grade `.gitignore`:**
   * **Environment Files:** `.env`, `.env.*`, `*.env`, `.env.local`
   * **Certificates & Private Keys:** `*.pem`, `*.key`, `*.cert`, `*.crt`, `*.pfx`, `*.p12`, `*.id_rsa`, `*.pub`
   * **Secrets & Tokens:** `credentials.json`, `secrets.json`, `secrets.yaml`, `*.secret`, `*.token`, `*.password`, `*serial_key*`, `*api_key*`
   * **Databases & Dumps:** `*.db`, `*.sqlite`, `*.sqlite3`, `*.sql`, `*.dump`, `dump.rdb`
   * **Binaries & Cache:** `*.exe`, `aegis-core.exe`, `__pycache__/`, `target/`
2. **Safe Template Model (`.env.example`):**
   * Projects should only commit `.env.example` containing non-sensitive placeholder configurations.
3. **100% Client-Side Auditing:**
   * All log parsing, socket checking, and security analysis executes completely locally on your host machine.

---

## 💻 Cross-Platform Installation & Setup

Aegis is engineered for seamless cross-platform operation on **Windows**, **Linux**, and **macOS**.

### Windows Installation & Setup
1. Open PowerShell or Command Prompt.
2. Clone the repository:
   ```powershell
   git clone https://github.com/unidentifiedcyberghost/AEGIS-DEFENSIVE-TOOLKITS.git
   cd AEGIS-DEFENSIVE-TOOLKITS
   ```
3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

### Linux Installation & Setup
1. Open your terminal (Ubuntu / Debian / Arch / Fedora):
   ```bash
   git clone https://github.com/unidentifiedcyberghost/AEGIS-DEFENSIVE-TOOLKITS.git
   cd AEGIS-DEFENSIVE-TOOLKITS
   ```
2. Set up a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. (Optional for GUI) Ensure Qt6 libraries are available:
   ```bash
   # Debian / Ubuntu:
   sudo apt-get install -y libxcb-cursor0 libxkbcommon-x11-0 libgl1
   ```

### macOS Installation & Setup
1. Open Terminal (Apple Silicon M1/M2/M3 or Intel):
   ```bash
   git clone https://github.com/unidentifiedcyberghost/AEGIS-DEFENSIVE-TOOLKITS.git
   cd AEGIS-DEFENSIVE-TOOLKITS
   ```
2. Set up a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

---

## 🚀 Running the Toolkit

### 1. Interactive Tactical HUD GUI
Launch the full desktop Sci-Fi HUD interface:
```bash
python main.py
```
*(Or explicitly `python main.py --gui`)*

### 2. Headless CLI Mode
For automated CI/CD pipelines, remote SSH sessions, or terminal workflows:

* **Audit a target website & export a styled HTML report:**
  ```bash
  python main.py --cli --target http://127.0.0.1:8000 --export-html security_audit.html
  ```

* **Inspect local listening ports & interface exposure:**
  ```bash
  python main.py --audit-ports
  ```

* **Analyze server access logs for attacker tracking:**
  ```bash
  # Analyze a live access log:
  python main.py --analyze-logs /var/log/nginx/access.log

  # Analyze representative attack telemetry:
  python main.py --sample-logs
  ```

### 3. Compiled Go Micro-Engine
The Go engine (`aegis-go/aegis-core.exe`) can be compiled and executed independently for high-speed audits:
```bash
# Build the Go binary (if needed):
cd aegis-go
go build -o aegis-core.exe main.go

# Run socket listener scan:
.\aegis-core.exe -ports

# Fast audit of headers & leaks:
.\aegis-core.exe -target http://localhost:8000 -json

# Fast streaming log parser:
.\aegis-core.exe -log access.log
```

### 4. Rust Engine
The Rust engine (`aegis-rust/`) can be compiled using Cargo:
```bash
cd aegis-rust
cargo run -- --parse-log access.log
```

---

## 🚨 Attacker Intrusion Detection & Firewall Generation

When suspicious activity is recorded in your web server logs, Aegis extracts the client IP, checks passive threat intelligence, and displays an **Attacker Intelligence Dossier**:

```text
=====================================================
ATTACKER INTELLIGENCE DOSSIER // IP: 203.0.113.88
=====================================================
[GEOLOCATION & NETWORK TELEMETRY]
  Country / City: United States (US), Ashburn
  ISP / Hosting:  Example Hosting LLC
  AS Number:      AS12345
  Reverse DNS:    scanner.example.com

[ATTACK ACTIVITY & VOLUME]
  Threat Severity: CRITICAL
  Malicious Probes: 14 / Total Requests: 18
  Attack Categories: SQL Injection Probe, Path Traversal

[MITRE ATT&CK & OWASP MAPPING]
  - SQL Injection Probe: A03:2021 - Injection | T1190
    Defensive Fix: Use Parameterized Queries / Prepared Statements; Enforce strict WAF SQLi filter.

[INSTANT DEFENSIVE FIREWALL MITIGATION RULES]
  Windows PowerShell: New-NetFirewallRule -DisplayName "Aegis_Block_203.0.113.88" -Direction Inbound -Action Block -RemoteAddress "203.0.113.88"
  Linux UFW:          sudo ufw deny from 203.0.113.88
  Linux iptables:     sudo iptables -I INPUT -s 203.0.113.88 -j DROP
  Nginx Directive:    deny 203.0.113.88;
```

---

## 📜 Changelog & Version History

See the complete version history, implementation details, and patch notes in [**`CHANGELOG.md`**](CHANGELOG.md).

* **v1.0.0 (2026-10-16):**
  * Initial public release with multi-engine architecture (Python, Go, Rust).
  * Tactical Sci-Fi CIA HUD GUI with circular posture score gauge and live console.
  * OWASP Security Headers, Cookie Hygiene, and Sensitive File Exposure Auditor.
  * Localhost Socket & Exposure Telemetry (detecting dangerous `0.0.0.0` bindings).
  * Attacker Tracking & Intrusion Detection System (IDS) with automated Geolocation, Reverse DNS, ASN lookup, scanner fingerprinting, and MITRE ATT&CK / OWASP mappings.
  * Multi-platform firewall rule generator (PowerShell, UFW, iptables, Nginx, Apache).
  * Full cross-platform support for Windows, Linux, and macOS.

---

## 👥 Contributors & Developer Community

Connect with the project creators, contributors, and the cybersecurity research community:

* **GitHub Organization & Core Profile:**
  * [**@unidentifiedcyberghost**](https://github.com/unidentifiedcyberghost) (Creator & Lead Maintainer)
  * [**@teamwhitehatdev**](https://github.com/teamwhitehatdev) (Core Security Research Team)
* **Social & Community Channels:**
  * [**X / Twitter (@TeamWhiteHatDev)**](https://x.com/TeamWhiteHatDev)
  * [**Instagram: @pinoyunknown**](https://instagram.com/pinoyunknown)
  * [**Instagram Post & Community Updates**](https://www.instagram.com/p/DbZKjkazUzR/)
  * [**Dev.to Articles & Publications**](https://dev.to/whitehatdev)
  * [**YouTube Video Showcase & Demos**](https://www.youtube.com/watch?v=zrF1EoEh1-w)
* **Official Browser Themes & Extensions:**
  * [**Cybersecurity Theme for Firefox**](https://addons.mozilla.org/en-US/firefox/addon/cybersecurity-theme-v1-0-1/)

---

## ⚖️ License & Ethics

This project is licensed under the **MIT License**.

> **Defensive Security Notice:** Aegis is designed strictly for defensive security auditing, educational purposes, vulnerability assessment of systems you own or have explicit authorization to audit, and incident response. Always obtain proper authorization before auditing network services.

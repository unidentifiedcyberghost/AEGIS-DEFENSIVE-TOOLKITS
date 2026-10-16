# 🛡️ AEGIS // DEFENSIVE LOCALHOST & WEB AUDIT SUITE
### *Next-Generation Cyber OSINT, Attack Surface Reconnaissance, Malware Path Scanner, Host Server Auditor, and OWASP Defense War Room*

[![License: MIT](https://img.shields.io/badge/License-MIT-00F0FF.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-00FF88.svg)](https://www.python.org/)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00A3FF.svg)](https://golang.org/)
[![Rust Edition](https://img.shields.io/badge/Rust-2021-FFB800.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-FF3366.svg)]()
[![Developed by](https://img.shields.io/badge/Team-White%20Hat-00FF88.svg)](https://x.com/TeamWhiteHatDev)

---

## 📑 Table of Contents
1. [Mission & Purpose](#-mission--purpose)
2. [Categorized Architecture & Holographic HUD](#-categorized-architecture)
3. [20-in-1 Cyber OSINT & Investigation Suite](#-20-in-1-cyber-osint--investigation-suite)
4. [CryptoTrace // On-Chain AML Money Flow Tracer](#-cryptotrace--on-chain-aml-money-flow-tracer)
5. [SpiderFoot // Scam Infrastructure Reconnaissance](#-spiderfoot--scam-infrastructure-reconnaissance)
6. [How to Run the Application](#-how-to-run-the-application)
   - [Desktop PyQt6 GUI Interface (`gui.py`)](#1-running-the-desktop-gui-interface-recommended)
   - [Interactive Web Tactical HUD (`web.py`)](#2-running-the-localhost-web-hud)
   - [Headless Command-Line Interface (`main.py`)](#3-running-via-command-line-cli)
7. [Target Connectivity & Connection Diagnostics](#-target-connectivity--connection-diagnostics)
8. [Infected Path & Malware Scanner](#-infected-path--malware-scanner)
9. [Host Server Machine Rootkit & Process Auditor](#-host-server-machine-rootkit--process-auditor)
10. [Comprehensive Attack Matrix & Fix Runbook](#-comprehensive-attack-matrix--fix-runbook)
11. [Attacker Tracking, VPN/Proxy Detection & Carrier Subpoena Protocol](#-attacker-tracking-vpnproxy-detection--carrier-subpoena-protocol)
12. [Real-Time Version-by-Version Changelog](#-real-time-version-by-version-changelog)
13. [Developers & Contributors (Team White Hat)](#-developers--contributors-team-white-hat)
14. [License & Ethics](#-license--ethics)

---

## 🎯 Mission & Purpose

**Aegis** is a modular, high-performance defensive cybersecurity toolkit developed by **Team White Hat** to help web developers, system administrators, and cybersecurity professionals proactively defend their localhost systems, cloud servers, and web applications.

Instead of waiting for an attacker to breach your systems, Aegis audits your defenses from the ground up:
* **Passive Cyber OSINT & Attack Surface Mapping:** Enumerates DNS records, Certificate Transparency subdomains, SSL/TLS cryptographic health, BGP routing/ASN, and RFC 9116 `security.txt` compliance without sending intrusive exploit probes.
* **Infected Path & Malware Scanner:** Deeply inspects website and server directories for backdoors, obfuscated PHP shells (`eval(base64_decode())`), JavaScript cryptominers, and double extensions. Detected infected paths are prominently highlighted in **bright red** with one-click **Quarantine** and **Permanent Delete** actions.
* **Host Server Machine Auditor:** Scans running OS processes for rogue cryptominers, reverse shells, backdoor ports (4444, 1337), hosts file hijacking, and dropped executable payloads in Temp directories, with one-click process termination (`kill PID`).
* **Interactive Cyber Attack Matrix:** A complete War Room dashboard cataloging all major web attack vectors (SQLi, XSS, Web Shells, RCE, Path Traversal, DDoS, Brute Force, .env leaks, CSRF, SSRF), detailing exact log symptoms, immediate containment actions, permanent architectural fixes, and ready-to-deploy code fixes for Nginx, Apache, Python, Node.js, and PHP.
* **Law Enforcement & Carrier Subpoena Dossier:** Synthesizes ISO/IEC 27037 compliant forensic evidence reports with 18 U.S.C. § 2703 preservation procedures for police authorities to legally request subscriber SIM ICCID, hardware IMEI, and cell tower GPS coordinates from mobile carriers.
* **On-Chain CryptoTrace & SpiderFoot Recon:** Institutional-grade cryptocurrency AML tracking linking scam wallets to exchanges, mixers, and cash-out off-ramps, paired with automated multi-sweep scam infrastructure reconnaissance.

---

## 🗂️ Categorized Architecture

Both the **PyQt6 Desktop GUI** and the **Localhost Web HUD** are structured into clean, intuitive categories:

| Category | Icon | Module Name | Primary Capabilities |
| :--- | :---: | :--- | :--- |
| **CAT 1** | 🛡️ | **Vulnerability Auditor & Compliance** | OWASP Security Headers (CSP, HSTS, X-Frame), Cookie security, and .env/Git/Credential leak checks. |
| **CAT 2** | 🕵️ | **Cyber OSINT & Attack Surface** | Passive multi-record DNS (A, AAAA, MX, NS, TXT), CRT.SH Subdomain Enumeration, SSL/TLS cryptanalysis, BGP/ASN, and threat pivots. |
| **CAT 3** | 🦠 | **Malware & Web Shell Scanner** | Path scanner detecting backdoors, PHP eval/base64 shells, JS cryptominers; displays infected paths in **bright red** with Quarantine and Delete. |
| **CAT 4** | 💉 | **Anti-XSS & Data Injection Shield** | Audits CSP, MIME sniffing, clickjacking; generates strict CSP policies, context-aware sanitization code, and ModSecurity WAF rules. |
| **CAT 5** | 📡 | **Localhost Ports & Server Rootkit Auditor** | Audits open sockets and 0.0.0.0 exposures; scans host computer for miners, reverse shells, backdoor ports, and dropped temp files with process kill. |
| **CAT 6** | 🚨 | **Attacker Tracker & Log IDS** | Ingests server access logs, identifies probing attacks, profiles attacker IPs, detects VPN/Proxy/Tor, and fingerprints mobile device models. |
| **CAT 7** | ⚔️ | **Attack Matrix & How to Fix Dashboard** | Catalog of all web attacks, symptoms, immediate emergency containment actions, permanent architectural fixes, and multi-language code snippets. |
| **CAT 8** | 📜 | **Carrier Subpoena Evidence Dossier** | Formal forensic evidence report formatted for police cybercrime units and carrier subpoenas (SIM/IMEI/GPS coordinates). |
| **CAT 9** | 🪙 | **CryptoTrace AML & Money Flow Tracer** | Real-time on-chain tracing across Bitcoin, Ethereum, USDT TRC-20, and Solana; links scam wallets to mixers and exchange off-ramps with AML risk scoring. |
| **CAT 10** | 🕷️ | **SpiderFoot Scam Infrastructure Recon** | Automated 8-module active sweep (DNS, WHOIS, CRT.SH subdomains, SSL/TLS, cloud buckets, dark web leaks, threat reputation) to expose scam infrastructure. |

---

## 🚀 How to Run the Application

Aegis provides multiple ways to launch the software depending on your workflow:

### 1. Running the Desktop GUI Interface (Recommended)
To run the high-tech Sci-Fi CIA-style PyQt6 desktop application with all 8 categorized tabs:

```bash
# Option A: Direct dedicated launcher
python gui.py

# Option B: Standard main launcher with --gui flag
python main.py --gui
```

### 2. Running the Localhost Web HUD
To run the interactive browser dashboard at `http://127.0.0.1:5000`:

```bash
# Option A: Direct dedicated web launcher
python web.py

# Option B: Standard main launcher (defaults to web)
python main.py
# or
python main.py --web
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

### 3. Running via Command-Line (CLI)
For automated pipelines, headless servers, or quick terminal audits:

```bash
# Run full OWASP web audit:
python main.py --cli --target http://localhost:8000 --export-html report.html

# Audit open listening ports:
python main.py --audit-ports

# Ingest and analyze server access logs for attackers:
python main.py --analyze-logs access.log
# Or run with built-in attack telemetry simulation:
python main.py --sample-logs
```

---

## 🌐 Target Connectivity & Connection Diagnostics

If you see the message:
> *"Could not connect to http://example.com. Ensure the web server or localhost service is running."*

Here is how to resolve it:
1. **Scanning Localhost:**
   Ensure your local web application (e.g., React, Vite, Express, Flask, Django, or Docker) is running on the specific port you entered (e.g. `http://localhost:3000` or `http://127.0.0.1:8000`).
2. **Scanning Public Websites:**
   Most modern public websites enforce HTTPS and block plain HTTP (port 80). **Ensure you include `https://`** when entering a public domain (e.g. `https://yourdomain.com`). Aegis now includes automatic HTTPS/HTTP fallback and multi-port probing to assist connection.
3. **Local IP Auto-Discovery:**
   Use the **"🎯 MY DETECTED LOCAL IPs"** button on the target bar to automatically detect and test your machine's LAN and loopback IP addresses.

---

## 🦠 Infected Path & Malware Scanner

The Category 3 Malware Scanner audits your project code and upload directories for unauthorized web shells and viruses:
* **Bright Red Highlighting:** Detected infected paths and files are styled in **bold bright red (`#FF3366`)** with a `🚨` warning indicator so they can be immediately recognized.
* **Malware Signatures Detected:**
  - Obfuscated PHP execution: `eval(base64_decode())`, `assert()`, `passthru()`, `shell_exec()`
  - Public web shells: c99, r57, WSO, b374k, FilesMan, Weevely, China Chopper
  - Cryptocurrency miners: Coinhive, CryptoLoot, Monero web miners
  - Upload vulnerabilities: Double-extensions (e.g. `image.php.jpg`, `shell.phtml`)
* **Instant Actions:**
  - **⚠️ Quarantine:** Moves the file into `.aegis_quarantine/` and sets permissions to read-only non-executable.
  - **🗑️ Remove:** Permanently deletes the infected file from disk.

---

## 💻 Host Server Machine Rootkit & Process Auditor

Located in **Category 5**, this tool inspects the host computer or server itself:
* **Cryptominer & Rogue Process Detection:** Checks running processes against known miners (`xmrig`, `minerd`, `kdevtmpfsi`) and reverse shells (`nc -e`, `powershell -enc`).
* **Backdoor Port Check:** Scans for rogue listeners on notorious hacker ports (`4444`, `1337`, `31337`).
* **Temp Directory Malware Drop:** Identifies executable files (`.exe`, `.bat`, `.vbs`, `.sh`) dropped into `%TEMP%` or `/tmp`.
* **Hosts File Integrity:** Verifies that security domains (e.g., Windows Update, VirusTotal) are not redirected.
* **1-Click Remediation:** Select any suspicious process row and click **"⚡ TERMINATE SELECTED ROGUE PROCESS (KILL PID)"** to terminate it immediately.

---

## ⚔️ Comprehensive Attack Matrix & Fix Runbook

Located in **Category 7**, this dashboard provides a complete defensive playbook for every major cyber attack:
1. **SQL Injection (SQLi)** (CWE-89)
2. **Cross-Site Scripting (XSS)** (CWE-79)
3. **Web Shell & Malicious File Upload** (CWE-434)
4. **Command Injection / Remote Code Execution (RCE)** (CWE-78)
5. **Path Traversal & Local File Inclusion (LFI)** (CWE-22)
6. **DDoS & HTTP Layer 7 Flood** (CWE-400)
7. **Brute Force & Credential Stuffing** (CWE-307)
8. **Sensitive File Exposure (.env / Git / Private Keys)** (CWE-552)
9. **Cross-Site Request Forgery (CSRF)** (CWE-352)
10. **Server-Side Request Forgery (SSRF)** (CWE-918)

For each attack vector, the dashboard displays:
- What the attack is & the attacker's objective
- Real-time indicator if your server is currently targeted
- Symptoms & how to tell if you are being attacked
- **Immediate Emergency Actions (What to do right now)**
- **Permanent Architectural Resolution (How to fix it)**
- Multi-framework code fixes for **Nginx**, **Apache**, **Python**, **Node.js**, and **PHP**
- 1-Click PowerShell / Bash firewall script generation

---

## 🕵️ Cyber OSINT & Attack Surface Engine

Located in **Category 2**, this engine conducts passive reconnaissance:
* **Multi-Record DNS:** Queries A, AAAA, MX, NS, PTR, and TXT records.
* **Certificate Transparency Subdomains:** Queries `crt.sh` logs and SSL Subject Alternative Names (SAN) to map all discovered subdomains, with a one-click **"📋 COPY ALL SUBDOMAINS"** button.
* **SSL/TLS Cryptanalysis:** Evaluates certificate validity, expiration, issuer, cipher suite, and TLS version.
* **BGP Routing & ASN:** Identifies target IP, Autonomous System, ISP, organization, and datacenter/proxy hosting flags.
* **RFC 9116 `security.txt`:** Checks for compliant security vulnerability disclosure files.
* **External Threat Pivots:** Generates deep search links for Shodan, Censys, VirusTotal, AlienVault OTX, and URLScan.

---

## 🚨 Attacker Tracking, VPN/Proxy Detection & Carrier Subpoena Protocol

Located in **Category 6 & Category 8**:
* **VPN / Proxy / Tor Detection:** Identifies whether the attacking IP belongs to a commercial VPN provider, public Tor exit node, or cloud datacenter hosting range.
* **Mobile Device Hardware Fingerprinting:** Decodes the attacker's HTTP `User-Agent` headers to identify specific physical hardware models (e.g. *Samsung Galaxy S23 Ultra [SM-S918B]*, *iPhone 15 Pro Max*, *Xiaomi 13 Pro*).
* **Law Enforcement & Carrier Subpoena Protocol (Category 8):**
  Because public internet packets do not carry physical device IMEI numbers, SIM card ICCIDs, or GPS coordinates directly over IP headers, Aegis generates a formal legal dossier conforming to **ISO/IEC 27037** and **18 U.S.C. § 2703 / Budapest Convention on Cybercrime**.
  This gives cybercrime police and legal authorities the exact UTC timestamp, source IP, source port, and hardware fingerprint needed to issue emergency preservation letters to mobile telecommunications carriers to legally unmask the suspect's registered SIM card and GPS tower locations.

---

## 🕵️ 20-in-1 Cyber OSINT & Investigation Suite

Aegis features a master intelligence engine in `aegis/osint_suite.py` providing 20 dedicated forensic investigation tools on one unified screen:

1. **Username OSINT Search & Correlator:** Parallel multi-threaded scanner checking handles across 35+ top social networks, forums, and developer platforms (GitHub, Reddit, Twitter/X, Instagram, TikTok, Telegram, Steam, Twitch, Pinterest, Medium, HackerNews, GitLab, Keybase, Mastodon, Linktree, Dev.to, About.me, etc.) with latency, profile links, confidence rating, and automated Google Dorks for paste/forum leaks.
2. **Investigation Graph:** Dynamic entity-relationship node-link graph correlating Target -> IPs -> ASNs -> Social Accounts -> Emails -> Threat Hubs.
3. **Phone Number Analyzer:** E.164 normalization, international country code, carrier heuristics, line type parsing, and VoIP fraud warning (highlighted in red for high-risk burner VoIP numbers).
4. **Dorks Generator:** High-powered Google Dork generator with 20+ specialized queries for passwords, SQL dumps, confidential PDFs, and exposed admin panels.
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

## 🪙 CryptoTrace // On-Chain AML Money Flow Tracer

**CryptoTrace** acts as an on-chain cryptocurrency and AML money flow tracer that traces fund movements across blockchains, linking scam wallets to exchanges, mixers, and cash-out off-ramps. For pig-butchering, investment scams, and ransomware, it turns a wallet address into an actionable money trail an AML compliance team or law enforcement investigator can act on.

* **Best For:** Cryptocurrency fraud investigations, pig-butchering scams, ransomware ransom tracing, and financial AML money tracking.
* **Sources:** On-chain live APIs across all major blockchains (Bitcoin, Ethereum, USDT ERC-20 / TRC-20, Solana).
* **Key Strengths:**
  - **Deep On-Chain Attribution:** Real-time query integration with `blockchain.info` (Bitcoin) and Ethereum JSON-RPC over Cloudflare.
  - **Sanctions & Threat Intelligence:** Built-in attribution database cross-referencing known mixer clusters (Tornado Cash, Wasabi, ChipMixer), state-sponsored threats (Lazarus Group Ronin Bridge exploit, WannaCry, DarkSide ransomware), industrial pig-butchering syndicates, and major centralized exchanges (Binance, Coinbase, Kraken, OKX, Bitfinex).
  - **Algorithmic AML Risk Scoring:** Calculates risk from 0 to 100 with categorical ratings (Minimal, Low, Elevated, High, Severe Risk).
  - **Multi-Stage Money Flow Analysis:** Traces victim deposit, intermediary mixing hops, and final off-ramp destinations.
  - **Law Enforcement & Bank Subpoena Dossier:** Formats formal subpoena and Suspicious Activity Report (SAR) dossiers under `18 U.S.C. § 2703(f)` and `31 U.S.C. § 5318(g)` for exchange KYC disclosure.

---

## 🕷️ SpiderFoot // Scam Infrastructure Reconnaissance

**SpiderFoot** automates data collection across modular reconnaissance sweeps, from DNS and WHOIS to Certificate Transparency logs, SSL/TLS handshakes, cloud bucket enumeration, breach databases, and threat intelligence feeds. It is designed for mapping out scam operations that utilize multiple domains, shell companies, or disposable infrastructure.

* **Best For:** Automated scam infrastructure mapping, attack surface discovery, and phishing network takedowns.
* **Price:** Fully open-source and built directly into Aegis without external subscription paywalls.
* **Sources:** 8 integrated tactical reconnaissance modules:
  - `sfp_dns`: A, AAAA, MX, NS, TXT, SOA record resolution via Cloudflare DNS-over-HTTPS.
  - `sfp_subdomains`: CRT.SH Certificate Transparency log extraction for hidden staging, admin, and API endpoints.
  - `sfp_whois`: Domain registrar, registration date, expiration, and name servers.
  - `sfp_ssl`: Direct SSL/TLS handshake for certificate subject, issuer, serial, and validity.
  - `sfp_threat_intel`: Real-time cross-referencing against AbuseIPDB, VirusTotal, AlienVault OTX, and URLhaus.
  - `sfp_cloud_buckets`: Heuristic enumeration of misconfigured AWS S3 and GCP storage buckets matching target brands.
  - `sfp_darkweb_leaks`: Tor darknet onion queries (Ahmia.fi, TorTaxi) and pastebin aggregators for credential exposure.
  - `sfp_tech_stack`: Web application server, framework, and security header fingerprinting.
* **Key Strengths:**
  - Automated correlation across disparate infrastructure points.
  - Finding classification across Critical, High, Medium, Low, and Info severities.
  - Overall composite infrastructure risk score with one-click JSON export.

---

## 📜 Real-Time Version-by-Version Changelog

All notable changes, architectural implementations, enhancements, security patches, and version releases are documented chronologically:

### 🌟 [2.6.0] - 2026-10-16
#### 🪙 CryptoTrace On-Chain AML Engine, 🕷️ SpiderFoot Scam Infra Recon & Verified Real-Time OSINT
* **CryptoTrace On-Chain AML Intelligence Engine (`aegis/crypto_tracer.py`):**
  - Live on-chain balance and transaction history lookup for Bitcoin (`blockchain.info`) and Ethereum JSON-RPC via Cloudflare, with format validation for TRON (TRC-20 USDT) and Solana.
  - Automated cross-referencing against mixers (Tornado Cash, Wasabi), ransomware (Lazarus Ronin Bridge, WannaCry, DarkSide), industrial pig-butchering syndicates, and centralized exchange off-ramps (Binance, Coinbase, Kraken, OKX).
  - Algorithmic AML Risk Scoring (0–100 scale: Minimal, Low, Elevated, High, Severe Risk).
  - Multi-stage money flow analysis tracing victim deposits, intermediary hops, and cash-out points.
  - Automated Law Enforcement & AML Subpoena Dossier generator conforming to `18 U.S.C. § 2703(f)` and FinCEN SAR guidelines.
  - Web HUD Tab `[☵] CRYPTOTRACE AML` with live tracing, risk gauges, multi-hop flow tables, and one-click dossier export.
* **SpiderFoot Automated Scam Infrastructure Reconnaissance Engine (`aegis/spiderfoot_recon.py`):**
  - 8 modular active sweeps: `sfp_dns`, `sfp_subdomains`, `sfp_whois`, `sfp_ssl`, `sfp_threat_intel`, `sfp_cloud_buckets`, `sfp_darkweb_leaks`, and `sfp_tech_stack`.
  - Severity classification (Critical, High, Medium, Low, Info) and overall composite infrastructure risk rating.
  - Web HUD Tab `[⌘] SPIDERFOOT RECON` with module selection checkboxes, live progress telemetry, severity metric cards, interactive filter pills, and JSON export.
* **Username OSINT Hunt Refinement (Verified Real-Time Data Only):**
  - Removed sample "Quick Presets" (`cyberghost`, `fraudster99`, `shadow_operative`, `octocat`) to eliminate UI clutter.
  - Integrated `[⚡] OSINT PIVOT SUITE` featuring Email Permutations, GitHub Deep Profiler, Wayback Archive Machine, Tor Darknet Leaks (Ahmia.fi), and PGP Keyring lookup.
  - Suppressed all speculative and "NOT FOUND" entries. Only confirmed profiles (`r.status === 'FOUND'`) with verified HTTP 200 OK responses and response latencies are rendered in the live footprint table.
  - If 0 profiles are found, renders a clean, focused amber notification banner stating zero confirmed footprints rather than 35+ red "NOT FOUND" rows.
* **20-in-1 Cyber OSINT Suite Real-Time Data Overhaul:**
  - Integrated `CryptoTraceEngine` into Tool 6 (Crypto Tracer) for live on-chain AML verification and mixer checks.
  - Enhanced Tool 5 (GitHub OSINT) to extract bio, company, avatar, public repos, and commit author email leaks.
  - Added dedicated holographic renderer `renderSuiteToolOutput()` in Web HUD generating structured, real-time cards and tables for all 10 primary tools, eliminating unconfirmed / speculative fields and displaying real-time actionable intelligence only.

---

### 🌟 [2.5.0] - 2026-10-16
#### 🔮 Minimal Holographical Sci-Fi HUD Transformation & 20-in-1 Cyber OSINT Suite
* **Minimal Holographical HUD Design System:** Removed clunky phone emojis across all banners, buttons, tabs, tables, and metric cards. Replaced with minimal, glowing holographic cyber vector glyphs (`[⬡]`, `[◈]`, `[⌖]`, `[⌥]`, `[⧉]`, `[⚡]`, `[☵]`, `[⌘]`, `[⬢]`, `[▲]`, `[◎]`, `[⚔]`, `[📋]`, `[📜]`, `[🖥]`). Added CRT holographic scanlines, rotating cyber radar sweep canvas, glowing borders (`box-shadow: 0 0 14px rgba(0, 240, 255, 0.35)`), and high-contrast typography (`Space Grotesk`, `JetBrains Mono`).
* **Real-Time Host Interface Detection & Live Canary Probing:**
  * **Functional `[REFRESH IPs]`:** Fixed data parsing in `loadMyIps()`. Backed by `psutil.net_if_addrs()`, Aegis dynamically identifies physical Wi-Fi, Ethernet, VPN tunnels (WireGuard, OpenVPN, Cloudflare WARP), and Loopback adapters, displaying interactive clickable chips to instantly set target URLs.
  * **Functional `[TEST ATTACK PROBE ON MY IP]`:** Directly integrated `WebAuditor.simulate_attack_probe()`. Dispatches a safe, non-destructive defensive canary probe testing WAF/IDS rules, logs latency, HTTP response headers, and registers the probe immediately in the live IDS log buffer.
* **Real-Time Live Access Logging & Intrusion Detection (Not Just Simulation):**
  * Implemented real-time in-memory request logger in Flask (`LIVE_ACCESS_LOGS`) capturing all real inbound localhost requests.
  * **Functional `[INGEST LIVE SERVER LOGS & IDS TELEMETRY]`:** Directly reads active server request history from memory and local access logs (`access.log`, `logs/access.log`), running heuristic pattern detection to uncover SQLi, XSS, Path Traversal, and brute-force probing with zero dependency on simulation.
* **Real-Time Live Traffic Sniffer & Connection Monitor:**
  * **Functional `[REFRESH LIVE CONNECTIONS]`:** Leverages `psutil.net_connections(kind="inet")` to sniff and display real-time active TCP/UDP sockets, client IPs, listening web servers, process names, PIDs, and security classifications.
  * **Auto-Sniff Radar Toggle:** Added a 2-second real-time live sniffing mode with an animated holographic pulsing radar indicator.
* **20-in-1 Cyber OSINT & Investigation Suite (`aegis/osint_suite.py`):**
  * Created a dedicated 20-tool intelligence suite featuring Username OSINT Search & Correlator across 35+ networks, Investigation Graph, Phone, Email, Domain, Darknet, Hashes, Crypto, and Metadata.

---

### [2.2.1] - 2026-10-16
#### 🎨 Symmetrical Centered Layout, Border Isolation & Cross-Architecture Synchronization
* **Symmetrical Centered Functional Toolbars:** Master defense toolbars (`.target-bar-actions`, `.presets`, `.host-interfaces-bar`, and `.hud-tabs`) updated with centered flex alignment. Added strict border isolation (`margin: 3px 6px !important;`) ensuring zero button border overlap and clean hitboxes across all display resolutions.
* **Category Banners:** Added `.category-header-banner-actions` containers across all tabs to center action buttons directly inside each category banner.
* **Attack Matrix & Playbooks Active Highlighting:** Added interactive active-state highlighting for Attack Matrix stack selection (`.stack-btn.active`) and Server Hardening Playbooks (`.playbook-btn.active`).
* **Go Core Engine 2.2 (`aegis-go`):** Added `-ip` command flag to synthesize Linux `iptables`, Ubuntu `ufw`, and Windows `netsh` firewall drop directives. Added `-route` command flag for instant network route telemetry. Recompiled high-speed binary `aegis-go/aegis-core.exe`.
* **Rust Engine 2.2 (`aegis-rust`):** Added `--iptables` and `--routes` commands to Rust CLI with structured JSON telemetry.
* **Warning Fixes:** Standardized schema keys between `findings_summary` and `summary` in `aegis/auditor.py` to ensure OWASP table findings always populate seamlessly. Globally suppressed `InsecureRequestWarning` across all HTTP client modules.

---

### [2.2.0] - 2026-10-16
#### 🛡️ Full Categorized Architecture & Cyber Defense War Room Release
* Restructured platform into 8 clearly defined, intuitive categories across both PyQt6 Desktop GUI and Localhost Web HUD:
  * **[CAT 1] Vulnerability Auditor & Compliance:** Automated OWASP header auditing, insecure cookie inspections, and credential leak checks (`.env`, `.git`).
  * **[CAT 2] Cyber OSINT & Attack Surface Intelligence:** Passive multi-record DNS resolution (A, AAAA, MX, NS, PTR, TXT), CRT.SH Subdomain Enumeration, SSL/TLS cryptanalysis, BGP/ASN, and RFC 9116 `security.txt` verification.
  * **[CAT 3] Malware, Web Shell & Infected Path Scanner:** Real-time scanner identifying backdoors, PHP `eval(base64_decode())` shells, and JS cryptominers with bright red path highlighting and 1-click Quarantine / Delete actions.
  * **[CAT 4] Anti-XSS & Data Injection Shield:** Strict CSP policy generator, context-aware input sanitization templates, and ModSecurity WAF blocking rules.
  * **[CAT 5] Localhost Ports & Host Server Rootkit Auditor:** Sockets inspector and OS process scanner for cryptominers, reverse shells, backdoor ports, and dropped temp files with process kill.
  * **[CAT 6] Attacker Tracker & Log IDS:** Access log parser identifying probing attacks, profiling attacker IPs, detecting VPN/Proxy/Tor, and fingerprinting mobile hardware models.
  * **[CAT 7] Cyber Attack Matrix & Remediation Dashboard:** Catalog of 10 major attack vectors, symptoms, immediate emergency actions, permanent fixes, and ready-to-deploy multi-framework code snippets.
  * **[CAT 8] Carrier Subpoena Evidence Dossier:** Formal forensic evidence report formatted for police cybercrime units and carrier subpoenas (SIM/IMEI/GPS coordinates).

---

### [1.0.1] - 2026-10-16
#### 🌐 Added Localhost Web Browser Tactical HUD & NPM Launcher
* Added `package.json` with `npm run dev`, `npm start`, and `npm run gui` shortcuts.
* Added `aegis/web_app.py` providing an interactive Tactical Sci-Fi CIA HUD web dashboard on `http://127.0.0.1:5000`.
* Integrated REST API endpoints (`/api/audit`, `/api/ports`, `/api/analyze-logs`, `/api/playbooks`).
* Added `--web`, `--port`, and `--host` CLI flags to `main.py`.

---

### [1.0.0] - 2026-10-16
#### 🚀 Initial Public Release & Multi-Engine Architecture
* Initial release of the **Aegis Defensive Localhost & Web Security Audit Suite** for **Windows, Linux, and macOS**.
* Multi-Engine Core: Python Core (`aegis/`), Go Micro-Engine (`aegis-go/`), and Rust Crate (`aegis-rust/`).
* PyQt6 Tactical Sci-Fi CIA HUD Interface (`aegis/gui/`).
* OWASP Web & Localhost Security Auditor (`aegis/auditor.py`).
* Listening Socket & Network Interface Auditor (`aegis/port_auditor.py`).
* Attacker Telemetry & Intrusion Detection System (`aegis/log_ids.py`, `aegis/threat_intel.py`).
* Multi-Platform Firewall Rule Generator (PowerShell, UFW, iptables, Nginx, Apache).
* OWASP Hardening Playbooks (`aegis/playbook.py`).

---

## 👥 Developers & Contributors (Team White Hat)

Aegis is developed and maintained by **TEAM WHITE HAT**:

* **GitHub:** [@unidentifiedcyberghost](https://github.com/unidentifiedcyberghost)
* **GitHub:** [@pinoyUnknown](https://github.com/pinoyUnknown)
* **X / Twitter:** [@TeamWhiteHatDev](https://x.com/TeamWhiteHatDev)

Repository: [https://github.com/unidentifiedcyberghost/AEGIS-DEFENSIVE-TOOLKITS](https://github.com/unidentifiedcyberghost/AEGIS-DEFENSIVE-TOOLKITS)

---

## 📄 License & Ethics

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

> [!IMPORTANT]
> **Defensive & Educational Use Only:**
> Aegis is designed exclusively for authorized defensive security audits, localhost testing, and incident response on systems you own or have explicit written permission to assess.

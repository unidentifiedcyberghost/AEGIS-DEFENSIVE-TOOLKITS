# 📋 CHANGELOG & PATCH UPDATES // AEGIS DEFENSIVE TOOLKIT

All notable changes, architectural implementations, enhancements, security patches, and version releases for the **Aegis Defensive Toolkit** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.8.0] - 2026-10-16

### ⌖ Collapsible Host Interfaces & Full 17-Module Operational Integrity
Major ergonomics and stability release making the host interfaces banner collapsible to reclaim valuable UI space, while hardening and standardizing all 17 cybersecurity analysis tabs and backend capabilities for zero-exception real-time execution.

### 🌟 New Features & Architectural Upgrades
- **⌖ Space-Saving Collapsible Host Interfaces Bar (`aegis/web_app.py`):**
  - Replaced the static full-width banner with an interactive `<details class="host-interfaces-accordion">` component with custom glowing neon border and hover animations.
  - Collapsed state displays a summary indicator (`#myIpsPreview`) showing detected IP addresses without consuming vertical screen space.
  - Displays dynamic adapter counter badge (`#hostInterfacesCountBadge`) and animated toggle chevron indicator.
  - Retains instant access to the "REFRESH IPs" and "TEST ATTACK PROBE" buttons.
- **🛠️ 17-Module Operational Integrity & Data Standardization:**
  - **[⬢] Server Rootkit Auditor (`aegis/server_auditor.py`):** Added unified `threats_identified` array consolidating rogue connections, hidden persistence keys, suspicious memory binaries, and hosts tampering; added instance aliases for automated audits.
  - **[⌥] Malware Scanner (`aegis/malware_scanner.py`):** Fixed directory path parameter resolution in `scan_directory(directory)` and added `total_scanned` metric.
  - **[⚡] Anti-XSS & Injection Defense (`aegis/injection_defense.py`):** Added structured `checks` array with standardized pass/fail status, current values, and recommended policies for the frontend table.
  - **[▲] Attacker IDS & Threat Intel (`aegis/threat_intel.py`):** Added RFC 5737 documentation subnet fast-path and bounded socket PTR lookups to eliminate 15-second hangs during attack log analysis.
  - **[⚓] Localhost & Ports (`aegis/port_auditor.py`):** Included bind address and security risk advisory details.
  - **[⌘] SpiderFoot Recon (`aegis/spiderfoot_recon.py`):** Parallelized web directory, database, and backdoor scans using `ThreadPoolExecutor` and optimized connection schemes for localhost.
  - **[📜] Carrier Subpoena Dossier (`aegis/web_app.py`):** Added interactive on-demand dossier generation button `[⚡] GENERATE EVIDENCE DOSSIER`.
  - **Comprehensive Verification Suite (`test_all_17_tabs.py`):** Automated test suite verifying 21/21 API and UI endpoints with 100% pass rate.

---

## [2.7.0] - 2026-10-16

### 🔐 Security Exposure & Secret-Leak Audit Center & Client-Side Execution Resilience
Major release introducing a full-spectrum defensive cybersecurity auditing suite to detect accidentally exposed credentials, misconfigured repositories, historical git leaks, exposed database dumps, and vulnerable dependencies, while resolving client-side script execution.

### 🌟 New Features & Architectural Upgrades
- **🔐 Security Exposure & Secret-Leak Audit Center (`aegis/secret_auditor.py`, `aegis/web_app.py`):**
  - **Secret & Credential Scanner:** High-entropy & regex detection for AWS IAM keys/secrets, GitHub PATs, Stripe keys, Slack tokens/webhooks, Private SSH/RSA keys, database URIs, JWTs, and passwords with mandatory `****[REDACTED]` masking.
  - **Git & .gitignore Security Auditor:** Analyzes `.gitignore` rules, identifies tracked sensitive files via `git ls-files`, flags staged secrets via `git diff --cached`, and provides safe `git rm --cached` remediation without local file deletion.
  - **Git History Secret Scanner:** Deep inspection of git commit diffs (`git log -p`) across history to uncover leaked credentials removed from HEAD but remaining in repository history.
  - **Sensitive File & Backup Hunter:** Filesystem scanner identifying raw SQL dumps, SQLite databases, cryptographic keys, logs, archives, and unprotected backup copies (`.bak`, `.old`).
  - **Dependency Vulnerability Scanner (OSV.dev):** Real-time vulnerability checking for `requirements.txt` (PyPI) and `package.json` (npm) against the official OSV.dev vulnerability database.
  - **Website Public File Exposure Scanner:** Conservative web assessment checking for publicly accessible `.env`, `.git/HEAD`, database dumps, and missing OWASP headers with custom 404 & SPA fallback detection.
  - **GitHub Repository Exposure Inspector:** Direct GitHub REST API query for public/private visibility, default branch, stars/forks, and sensitive file paths in repository trees.
  - **Pre-Commit Security Guard:** Generates and installs `.git/hooks/pre-commit` to prevent accidental credential commits.
  - **Report & Remediation Center:** Standalone holographic HTML security reports, formatted JSON exports, and CSV summaries with strictly redacted evidence.
- **⚡ Client-Side Execution Bugfix (`aegis/web_app.py`):**
  - **Resolved "Buttons Not Functioning":** Fixed an unclosed `if/else` block and unescaped quote in browser JavaScript that caused a client-side `SyntaxError` on page load, ensuring all dashboard buttons execute reactively.

---

## [2.6.1] - 2026-10-16

### 🛡️ Vulnerability Auditor Directory Sweeps, Target Connection Resilience & Strict OSINT Verification
Maintenance and intelligence upgrade resolving public domain connectivity, integrating comprehensive website directory and webshell auditing, eliminating all soft-404/challenge false positives in Username OSINT, expanding SpiderFoot with database/backdoor sweeps, and populating live SSL cryptanalysis.

### 🌟 New Features & Reliability Fixes
- **🌐 Vulnerability Auditor & OWASP Target Connectivity Resilience (`aegis/auditor.py`):**
  - **Resolved "Target Server Unreachable" for Public Domains:** Fixed connection dropouts for domains like `http://example.com` by adding automatic HTTP-to-HTTPS upgrade fallback, extended resilient socket timeout, and modern browser User-Agent headers (`Chrome/124`) to prevent edge WAF and bot drops.
  - **Detailed Connection Diagnostics:** Replaced generic unreachable notices with exact exception telemetry (`ConnectionTimeout`, `SSLError`, `NameResolutionError`) to inform security operators immediately.
- **📁 Vulnerable & Infected Directories / Webshell / Database Audit (`aegis/auditor.py`, `aegis/web_app.py`):**
  - **20 Comprehensive Sensitive Path Checks:** Audits database dumps (`/database.sql`, `/dump.sql`, `/backup.sql`, `/db.sqlite3`), sensitive directories (`/admin/`, `/administrator/`, `/phpmyadmin/`, `/wp-admin/`, `/backup/`, `/uploads/`), and common attacker webshell backdoors (`/shell.php`, `/c99.php`, `/r57.php`, `/wso.php`).
  - **Dedicated Web HUD Table (`[📁] VULNERABLE & INFECTED DIRECTORIES AUDIT`):** Added high-contrast inspection table in Tab 1 displaying exact path, category, severity, status (`INFECTED / EXPOSED` vs `SECURE / PROTECTED`), HTTP code, and direct remediation/removal guidance.
- **🎯 Username OSINT False-Positive Elimination (`aegis/osint_suite.py`):**
  - **Zero Unconfirmed Platforms Displayed:** Strictly filtered `analyze_username` to return ONLY confirmed accounts (`status == 'FOUND'`). Suppressed all non-existent or speculative entries.
  - **Anti-Bot & Soft-404 Filters:** Added strict rejection for Cloudflare challenges, reCAPTCHAs, and soft-404 signatures across Steam Community, PyPI, Kaggle, Twitch, Spotify, HackTheBox, TryHackMe, Instagram, and TikTok. Integrated official public profile APIs (e.g. TryHackMe `api/v2/public-profile`).
- **🕷️ SpiderFoot Scam Recon Engine Enhancements (`aegis/spiderfoot_recon.py`, `aegis/web_app.py`):**
  - **Updated Quick Presets:** Replaced outdated placeholders with `example.com` and `example@gmail.com`.
  - **3 New Active Modules:** Integrated `sfp_web_directories`, `sfp_database_exposure`, and `sfp_web_backdoors` to actively sweep target domains for exposed directories, SQL backups, and malicious webshell drops.
- **🔐 SSL/TLS Cryptanalysis Telemetry (`aegis/web_app.py`):**
  - Fully populated `tbodyOsintSsl` table with live certificate Common Name, Issuer Authority, validity dates, days remaining, signature algorithm, and SAN extensions.
- **📜 Forensic Incident Dossier Fix (`aegis/active_defense.py`):**
  - Added `ActiveDefenseManager.export_incident_report(report)` method generating SHA-256 sealed ISO/IEC 27037 and 18 U.S.C. § 2703(f) carrier subpoena dossiers.

---

## [2.6.0] - 2026-10-16

### 🪙 CryptoTrace On-Chain AML Engine, 🕷️ SpiderFoot Scam Infra Recon & Verified Real-Time OSINT
Major intelligence release introducing institutional-grade cryptocurrency AML tracking, automated multi-module scam infrastructure reconnaissance, and verified-only real-time OSINT rendering.

### 🌟 New Features & Architectural Upgrades
- **🪙 CryptoTrace On-Chain AML Intelligence Engine (`aegis/crypto_tracer.py`):**
  - **Live Blockchain Querying:** Real-time on-chain balance, transaction count, and history lookup for Bitcoin via `blockchain.info` API and Ethereum JSON-RPC via Cloudflare (`cloudflare-eth.com`), with format validation for TRON (TRC-20 USDT) and Solana.
  - **Attribution & Sanctions Database:** Automated cross-referencing against known high-risk clusters:
    - *Mixers & Laundering:* Tornado Cash, Wasabi Mixer, ChipMixer, Blender.io.
    - *State-Sponsored & Extortion:* Lazarus Group (Ronin Bridge exploit), WannaCry Ransomware, Colonial Pipeline DarkSide extortion.
    - *Scam Syndicates:* Southeast Asian industrial pig-butchering syndicates, PlusToken Ponzi ring.
    - *Exchanges & Off-Ramps:* Binance, Coinbase, Kraken, OKX, Bitfinex.
  - **Algorithmic AML Risk Scoring:** 0 to 100 risk score and rating (Minimal, Low, Elevated, High, Severe Risk) evaluating mixers, sanctioned origins, transaction frequency, and exchange off-ramps.
  - **Multi-Hop Flow Analysis:** Traces incoming victim funds, intermediary hopping, and final cash-out destinations.
  - **Law Enforcement & AML Subpoena Dossier:** Generates formal documentation conforming to `18 U.S.C. § 2703(f)` and FinCEN SAR standards for bank AML teams and law enforcement agencies.
  - **Web HUD Tab `[☵] CRYPTOTRACE AML`:** Interactive UI with live wallet tracing, risk meter gauges, attribution alerts, multi-hop flow tables, and one-click subpoena dossier generation and clipboard export.

- **🕷️ SpiderFoot Automated Scam Infrastructure Reconnaissance Engine (`aegis/spiderfoot_recon.py`):**
  - **8 Modular Active Sweeps:**
    - `sfp_dns`: A, AAAA, MX, NS, TXT, SOA record resolution via Cloudflare DNS-over-HTTPS.
    - `sfp_subdomains`: CRT.SH Certificate Transparency log extraction for hidden staging, admin, and API endpoints.
    - `sfp_whois`: Domain registrar, creation date, expiration, and name server detection.
    - `sfp_ssl`: Direct SSL/TLS handshake for certificate subject, issuer, serial, and validity period.
    - `sfp_threat_intel`: Real-time cross-referencing against AbuseIPDB, VirusTotal, AlienVault OTX, and URLhaus.
    - `sfp_cloud_buckets`: Heuristic enumeration of misconfigured AWS S3 and GCP storage buckets matching target naming conventions.
    - `sfp_darkweb_leaks`: Tor onion search queries (Ahmia.fi, TorTaxi) and pastebin aggregators for compromised credentials.
    - `sfp_tech_stack`: Web application server, framework, and security header fingerprinting.
  - **Severity Scoring & Risk Rating:** Classifies all discovered telemetry into Critical, High, Medium, Low, and Info categories, calculating an overall composite infrastructure risk rating.
  - **Web HUD Tab `[⌘] SPIDERFOOT RECON`:** Comprehensive tactical interface with module selection checkboxes, dynamic progress telemetry, severity metric cards, interactive filter pills, and JSON export.

- **🕵️ Username OSINT Hunt Refinement (Verified Real-Time Data Only):**
  - **Removed Sample "Quick Presets":** Eliminated static placeholder buttons (`cyberghost`, `fraudster99`, `shadow_operative`, `octocat`) to eliminate UI clutter.
  - **Integrated `[⚡] OSINT PIVOT SUITE`:**
    - `[✉] Email Permutations`: Instant generation of 12+ standard enterprise and scam email patterns for the handle.
    - `[⧉] GitHub Deep Profiler`: Direct API lookup of user bio, public repos, and commit author email leaks.
    - `[⌛] Wayback Archive`: One-click historical archive timeline search across target handles.
    - `[🧅] Tor Darknet Leaks`: Automated Ahmia.fi dark web search queries for breached handles.
    - `[🔑] PGP Keyring`: Verification of cryptographic keys and real-name associations via keys.openpgp.org.
  - **Strict Verified-Only Display Filtering:**
    - Suppressed all speculative and "NOT FOUND" entries. Only confirmed profiles (`r.status === 'FOUND'`) with verified HTTP 200 OK responses and response latencies are rendered in the live footprint table.
    - If 0 profiles are found, renders a clean, focused amber notification banner stating zero confirmed footprints rather than 35+ red "NOT FOUND" rows.

- **⌖ 20-in-1 Cyber OSINT Suite Real-Time Data Overhaul:**
  - **Tool 1: Investigation Graph:** Live Cloudflare DoH DNS (A, MX, NS) resolution, active socket service probing (ports 80, 443, 22, 53, 8080), live IP geolocation/ASN, and verified-only entity correlation rendered in a dynamic visual SVG node-link topology.
  - **Tool 2: Phone Analyzer:** 70+ international country prefix database, exact carrier parsing (Philippines Globe/Smart/TNT/DITO, North American NPA-NXX area codes, UK 07 mobile, India TRAI, Australia mobile), VoIP scam risk scoring, and one-click WhatsApp, Telegram, and Truecaller links.
  - **Tool 3: Email Analyzer:** Live Cloudflare DoH MX record validation, active SPF (`v=spf1`) and DMARC (`v=DMARC1`) anti-spoofing policy checks, 120+ disposable burner database checks, and HaveIBeenPwned/IntelX breach lookups.
  - **Tool 4: Dorks Generator:** Precision tactical search dorks synthesized for Google, Bing, and DuckDuckGo targeting credentials, `.env` configs, database dumps, and Telegram channels.
  - **Tool 5: GitHub OSINT:** Dual-tier architecture using GitHub API with automatic web-scraping fallback (immune to HTTP 403 rate limits), extracting public repositories, follower counts, and author email leaks from public commit patches.
  - **Tool 6: Crypto Tracer:** Powered by `CryptoTraceEngine` for live on-chain Bitcoin balance/tx queries (`blockchain.info`), Ethereum JSON-RPC balance queries, and mixer/sanction attribution (Tornado Cash, Lazarus, WannaCry, Pig-Butchering syndicates).
  - **Tool 7: Hash Analyzer:** Cryptographic bit-length algorithm detection (MD5, SHA-1/224/256/384/512, bcrypt, Argon2, Linux shadow hashes) with one-click crack lookups on CrackStation, HashToolkit, and CyberChef.
  - **Tool 8: Web Crawler:** Live HTTP crawl with intelligent false-positive filtering for verified emails (omitting `.png`, `.jpg`, schema.org), phone numbers, social media links, and server response headers.
  - **Tool 9: Reputation Checker:** Real-time DNSBL lookups on Spamhaus ZEN and SpamCop via socket DNS queries, live threat check against URLhaus API (`urlhaus-api.abuse.ch`), and AbuseIPDB/VirusTotal/AlienVault pivots.
  - **Tool 10: URL Scanner:** Live HTTP request probe testing online/offline status, full redirect chain inspection (identifying deceptive redirects), and heuristic phishing indicators (raw IP hosts, discount TLDs, brand spoofing keywords, Punycode IDN).
  - **Dedicated Holographic Renderers:** Upgraded `renderSuiteToolOutput()` in Web HUD generating dedicated metric cards and tables for all 10 tools, suppressing empty or speculative fields and displaying confirmed real data only.

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

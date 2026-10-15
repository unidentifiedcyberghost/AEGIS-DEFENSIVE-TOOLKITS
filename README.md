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
2. [Categorized Architecture (Cat 1 to Cat 8)](#-categorized-architecture)
3. [How to Run the Application](#-how-to-run-the-application)
   - [Desktop PyQt6 GUI Interface (`gui.py`)](#1-running-the-desktop-gui-interface-recommended)
   - [Interactive Web Tactical HUD (`web.py`)](#2-running-the-localhost-web-hud)
   - [Headless Command-Line Interface (`main.py`)](#3-running-via-command-line-cli)
4. [Target Connectivity & Connection Diagnostics](#-target-connectivity--connection-diagnostics)
5. [Infected Path & Malware Scanner (With Bright Red Highlighting)](#-infected-path--malware-scanner)
6. [Host Server Machine Rootkit & Process Auditor](#-host-server-machine-rootkit--process-auditor)
7. [Comprehensive Attack Matrix & Fix Runbook](#-comprehensive-attack-matrix--fix-runbook)
8. [Cyber OSINT & Attack Surface Engine](#-cyber-osint--attack-surface-engine)
9. [Attacker Tracking, VPN/Proxy Detection & Carrier Subpoena Protocol](#-attacker-tracking-vpnproxy-detection--carrier-subpoena-protocol)
10. [Developers & Contributors (Team White Hat)](#-developers--contributors-team-white-hat)
11. [License](#-license)

---

## 🎯 Mission & Purpose

**Aegis** is a modular, high-performance defensive cybersecurity toolkit developed by **Team White Hat** to help web developers, system administrators, and cybersecurity professionals proactively defend their localhost systems, cloud servers, and web applications.

Instead of waiting for an attacker to breach your systems, Aegis audits your defenses from the ground up:
* **Passive Cyber OSINT & Attack Surface Mapping:** Enumerates DNS records, Certificate Transparency subdomains, SSL/TLS cryptographic health, BGP routing/ASN, and RFC 9116 `security.txt` compliance without sending intrusive exploit probes.
* **Infected Path & Malware Scanner:** Deeply inspects website and server directories for backdoors, obfuscated PHP shells (`eval(base64_decode())`), JavaScript cryptominers, and double extensions. Detected infected paths are prominently highlighted in **bright red** with one-click **Quarantine** and **Permanent Delete** actions.
* **Host Server Machine Auditor:** Scans running OS processes for rogue cryptominers, reverse shells, backdoor ports (4444, 1337), hosts file hijacking, and dropped executable payloads in Temp directories, with one-click process termination (`kill PID`).
* **Interactive Cyber Attack Matrix:** A complete War Room dashboard cataloging all major web attack vectors (SQLi, XSS, Web Shells, RCE, Path Traversal, DDoS, Brute Force, .env leaks, CSRF, SSRF), detailing exact log symptoms, immediate containment actions, permanent architectural fixes, and ready-to-deploy code fixes for Nginx, Apache, Python, Node.js, and PHP.
* **Law Enforcement & Carrier Subpoena Dossier:** Synthesizes ISO/IEC 27037 compliant forensic evidence reports with 18 U.S.C. § 2703 preservation procedures for police authorities to legally request subscriber SIM ICCID, hardware IMEI, and cell tower GPS coordinates from mobile carriers.

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

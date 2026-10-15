"""
Aegis Localhost Web Dashboard
Serves an interactive Sci-Fi CIA-style Tactical HUD in the browser at http://127.0.0.1:5000.
Features:
- Full Category Separation (Cat 1 to Cat 8)
- [CAT 1] Vulnerability Auditor & Compliance
- [CAT 2] Cyber OSINT & Attack Surface Intelligence Engine (DNS, Subdomains, SSL/TLS, BGP/ASN, Tech Stack)
- [CAT 3] Malware, Web Shell & Infected Path Scanner (Bright RED paths, Quarantine & Permanent Delete)
- [CAT 4] Anti-XSS, Data Injection & Malicious Script Execution Shield (CSP, Sanitizers, ModSec WAF)
- [CAT 5] Localhost Ports, Sockets & Host Server Rootkit/Malware Auditor (Process Kill, Temp Drops)
- [CAT 6] Attacker Tracker & IDS (VPN/Proxy/Tor flags, Hardware Fingerprint, Hitting Freq)
- [CAT 7] Cyber Attack Matrix & Remediation Dashboard (All Attacks, Symptoms, Emergency Actions, Permanent Fixes, Multi-Language Code)
- [CAT 8] Law Enforcement Evidence & Carrier Subpoena Dossier (ISO/IEC 27037)
- Developed by Team White Hat
"""

import os
import warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message=".*Unverified HTTPS request.*")

from flask import Flask, request, jsonify, render_template_string
from aegis.auditor import WebAuditor
from aegis.port_auditor import PortAuditor
from aegis.log_ids import LogIntrusionDetector
from aegis.threat_intel import ThreatIntelAnalyzer
from aegis.active_defense import ActiveDefenseManager
from aegis.osint_engine import OsintEngine
from aegis.malware_scanner import MalwareScanner
from aegis.injection_defense import InjectionDefenseEngine
from aegis.server_auditor import ServerSystemAuditor
from aegis.attack_matrix import ATTACK_MATRIX
from aegis.playbook import PLAYBOOKS

app = Flask(__name__)

HUD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS // DEFENSIVE SECURITY HUD [TACTICAL WAR ROOM]</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-void: #04070D;
            --bg-panel: rgba(10, 15, 29, 0.94);
            --bg-card: rgba(15, 23, 42, 0.85);
            --border-dim: #182338;
            --border-glow: #00F0FF;
            --cyan: #00F0FF;
            --green: #00FF88;
            --amber: #FFB800;
            --red: #FF3366;
            --text-bright: #F8FAFC;
            --text-main: #CBD5E1;
            --text-muted: #64748B;
            --font-mono: 'JetBrains Mono', 'Consolas', monospace;
            --font-sans: 'Space Grotesk', sans-serif;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            scrollbar-width: none !important; /* Firefox */
            -ms-overflow-style: none !important; /* IE/Edge */
        }

        *::-webkit-scrollbar,
        body::-webkit-scrollbar,
        div::-webkit-scrollbar,
        pre::-webkit-scrollbar,
        table::-webkit-scrollbar,
        .table-container::-webkit-scrollbar,
        .matrix-list-box::-webkit-scrollbar,
        .matrix-detail-box::-webkit-scrollbar,
        .hud-console::-webkit-scrollbar {
            display: none !important;
            width: 0px !important;
            height: 0px !important;
        }

        body {
            background-color: var(--bg-void);
            color: var(--text-main);
            font-family: var(--font-mono);
            min-height: 100vh;
            padding: 16px 20px 40px 20px;
            line-height: 1.5;
            position: relative;
            overflow-x: hidden;
            scrollbar-width: none !important;
            -ms-overflow-style: none !important;
        }

        /* 60fps Animated HUD Canvas Background */
        #hudCanvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            pointer-events: none;
            z-index: 0;
            opacity: 0.45;
        }

        .hud-wrapper {
            position: relative;
            z-index: 1;
            max-width: 1540px;
            margin: 0 auto;
        }

        /* Top Header */
        .hud-header {
            background: var(--bg-panel);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-dim);
            border-left: 4px solid var(--cyan);
            border-radius: 6px;
            padding: 14px 22px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 0 35px rgba(0, 240, 255, 0.1);
            margin-bottom: 12px;
        }

        .hud-branding h1 {
            font-family: var(--font-sans);
            font-size: 19px;
            letter-spacing: 2px;
            color: var(--cyan);
            text-shadow: 0 0 12px rgba(0, 240, 255, 0.4);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .hud-branding p {
            color: var(--text-muted);
            font-size: 11px;
            margin-top: 2px;
        }

        .hud-badges {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background: var(--green);
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 10px var(--green);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(1.2); }
        }

        .badge-live {
            background: rgba(0, 255, 136, 0.1);
            color: var(--green);
            border: 1px solid var(--green);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            letter-spacing: 1px;
        }



        /* Automated Threat Alert Banner */
        .threat-alert-banner {
            display: none;
            background: rgba(255, 51, 102, 0.15);
            border: 1px solid var(--red);
            border-left: 6px solid var(--red);
            border-radius: 6px;
            padding: 12px 18px;
            margin-bottom: 14px;
            color: #FFF;
            box-shadow: 0 0 25px rgba(255, 51, 102, 0.25);
            animation: alertGlow 1.5s infinite alternate;
        }

        @keyframes alertGlow {
            from { box-shadow: 0 0 15px rgba(255, 51, 102, 0.2); }
            to { box-shadow: 0 0 30px rgba(255, 51, 102, 0.6); }
        }

        .threat-alert-banner h3 {
            font-size: 13px;
            color: var(--red);
            font-weight: 800;
            letter-spacing: 1px;
            margin-bottom: 4px;
        }

        .threat-alert-banner p {
            font-size: 11px;
            color: var(--text-main);
        }

        /* Target Control Bar - Organized Multi-Row Grid for Flawless Alignment */
        .target-bar {
            background: var(--bg-panel);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 14px 18px;
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-bottom: 14px;
        }

        .target-bar-top {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
            width: 100%;
        }

        .target-input-group {
            display: flex;
            flex: 1;
            min-width: 280px;
        }

        .target-input {
            width: 100%;
            background: #070B14;
            border: 1.5px solid var(--border-dim);
            color: var(--cyan);
            font-family: var(--font-mono);
            font-size: 12px;
            padding: 8px 14px;
            border-radius: 4px;
            outline: none;
            transition: all 0.2s;
        }

        .target-input:focus {
            border-color: var(--cyan);
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.25);
        }

        .presets {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .target-bar-actions {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
            width: 100%;
        }

        /* Global Button Sizing & Border Isolation (Zero Collision Guarantee) */
        .btn-preset, .btn-master, .btn-primary, .btn-danger, .btn-action, .hud-tab-btn {
            box-sizing: border-box !important;
            margin: 2px 4px !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            vertical-align: middle !important;
        }

        .btn-preset {
            background: #0B1736;
            border: 1.5px solid #38BDF8;
            color: #38BDF8;
            padding: 7px 14px;
            font-size: 11px;
            font-weight: 800;
            border-radius: 4px;
            cursor: pointer;
            font-family: var(--font-mono);
            box-shadow: 0 0 8px rgba(56, 189, 248, 0.2);
            transition: all 0.2s;
        }

        .btn-preset:hover {
            color: #FFFFFF;
            border-color: #00F0FF;
            background: rgba(0, 240, 255, 0.25);
            box-shadow: 0 0 14px rgba(0, 240, 255, 0.4);
        }

        .btn-master {
            background: linear-gradient(135deg, #00F0FF 0%, #00FF88 100%);
            border: 2px solid #FFFFFF;
            color: #05080E;
            font-family: var(--font-mono);
            font-size: 11.5px;
            font-weight: 900;
            padding: 9px 20px;
            border-radius: 4px;
            cursor: pointer;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.6);
            animation: pulseMaster 2s infinite alternate;
            transition: all 0.2s;
        }

        @keyframes pulseMaster {
            from { box-shadow: 0 0 14px rgba(0, 240, 255, 0.5); }
            to { box-shadow: 0 0 26px rgba(0, 255, 136, 0.9); }
        }

        .btn-master:hover {
            transform: translateY(-2px) scale(1.02);
            box-shadow: 0 0 35px rgba(0, 255, 136, 1);
        }

        .btn-primary {
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.3), rgba(0, 255, 136, 0.3));
            border: 2px solid #00F0FF;
            color: #00F0FF;
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 900;
            padding: 9px 18px;
            border-radius: 4px;
            cursor: pointer;
            letter-spacing: 1.2px;
            text-transform: uppercase;
            box-shadow: 0 0 14px rgba(0, 240, 255, 0.35);
            transition: all 0.2s;
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, #00F0FF, #00FF88);
            box-shadow: 0 0 24px rgba(0, 240, 255, 0.8);
            color: #05080E;
            border-color: #FFFFFF;
        }

        .btn-danger {
            background: linear-gradient(135deg, rgba(255, 51, 102, 0.35), rgba(255, 184, 0, 0.25));
            border: 2px solid #FF3366;
            color: #FF3366;
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 900;
            padding: 9px 18px;
            border-radius: 4px;
            cursor: pointer;
            letter-spacing: 1.2px;
            text-transform: uppercase;
            box-shadow: 0 0 14px rgba(255, 51, 102, 0.4);
            transition: all 0.2s;
        }

        .btn-danger:hover {
            background: linear-gradient(135deg, #FF3366, #FFB800);
            box-shadow: 0 0 24px rgba(255, 51, 102, 0.8);
            color: #05080E;
            border-color: #FFFFFF;
        }

        .btn-action {
            background: #0E1A38;
            border: 1.5px solid #00F0FF;
            color: #F8FAFC;
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 800;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.2);
            transition: all 0.2s;
        }

        .btn-action:hover {
            border-color: #00FF88;
            color: #00FF88;
            background: rgba(0, 255, 136, 0.15);
            box-shadow: 0 0 16px rgba(0, 255, 136, 0.4);
        }

        /* Metrics Row */
        .metrics-grid {
            display: grid;
            grid-template-columns: 180px repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 14px;
        }

        @media (max-width: 1050px) {
            .metrics-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        .gauge-card {
            background: var(--bg-card);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 12px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        .score-circle {
            position: relative;
            width: 80px;
            height: 80px;
        }

        .score-circle svg {
            width: 100%;
            height: 100%;
            transform: rotate(-90deg);
        }

        .circle-bg {
            fill: none;
            stroke: #182338;
            stroke-width: 8;
        }

        .circle-bar {
            fill: none;
            stroke: var(--green);
            stroke-width: 8;
            stroke-dasharray: 314;
            stroke-dashoffset: 0;
            stroke-linecap: round;
            transition: stroke-dashoffset 1s ease, stroke 0.5s ease;
        }

        .score-number {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 20px;
            font-weight: 800;
            color: var(--green);
            font-family: var(--font-sans);
        }

        .score-grade {
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1px;
            color: var(--green);
            margin-top: 6px;
        }

        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 14px 18px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }

        .metric-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 3px;
            height: 100%;
            background: var(--border-dim);
        }

        .metric-title {
            font-size: 10px;
            letter-spacing: 1.5px;
            color: var(--text-muted);
            margin-bottom: 4px;
        }

        .metric-value {
            font-family: var(--font-sans);
            font-size: 26px;
            font-weight: 800;
        }

        .metric-sub {
            font-size: 10.5px;
            color: var(--text-muted);
            margin-top: 2px;
        }

        /* Main Tabs Bar */
        /* Main Tabs Bar */
        .hud-tabs {
            display: flex;
            gap: 6px;
            border-bottom: 1.5px solid var(--border-dim);
            margin-bottom: 14px;
            overflow-x: auto;
            padding-bottom: 6px;
            scrollbar-width: none !important;
            -ms-overflow-style: none !important;
        }
        .hud-tabs::-webkit-scrollbar {
            display: none !important;
            width: 0px !important;
            height: 0px !important;
        }

        .hud-tab-btn {
            background: #0A1224;
            border: 1.5px solid #1E2E4E;
            color: #CBD5E1;
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 800;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
            box-shadow: 0 0 6px rgba(0, 0, 0, 0.4);
        }

        .hud-tab-btn:hover {
            color: #00F0FF;
            border-color: #00F0FF;
            background: rgba(0, 240, 255, 0.12);
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.3);
        }

        .hud-tab-btn.active {
            color: #00F0FF;
            border: 1.5px solid #00F0FF;
            background: rgba(0, 240, 255, 0.22);
            box-shadow: 0 0 16px rgba(0, 240, 255, 0.5), inset 0 0 8px rgba(0, 240, 255, 0.2);
        }

        /* Tab Content Panes */
        .tab-pane {
            display: none;
            background: var(--bg-panel);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 18px;
            min-height: 480px;
        }

        .tab-pane.active {
            display: block;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .category-header-banner {
            background: rgba(15, 23, 42, 0.6);
            border-left: 4px solid var(--cyan);
            padding: 10px 14px;
            border-radius: 4px;
            margin-bottom: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }

        .category-header-banner h2 {
            font-size: 13px;
            color: var(--cyan);
            letter-spacing: 1px;
        }

        .category-header-banner p {
            font-size: 11px;
            color: #94A3B8;
        }

        /* Tables */
        .table-container {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 11.5px;
        }

        th {
            background: #0B132B;
            color: #8899B5;
            padding: 10px 12px;
            text-align: left;
            font-size: 10px;
            letter-spacing: 1px;
            border-bottom: 1px solid var(--border-dim);
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid #0F172A;
        }

        tr:hover td {
            background: rgba(0, 240, 255, 0.03);
        }

        .badge-sev {
            padding: 2px 7px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 800;
            display: inline-block;
        }

        .badge-crit { background: rgba(255, 51, 102, 0.2); color: var(--red); border: 1px solid var(--red); }
        .badge-high { background: rgba(255, 184, 0, 0.2); color: var(--amber); border: 1px solid var(--amber); }
        .badge-med { background: rgba(0, 240, 255, 0.15); color: var(--cyan); border: 1px solid var(--cyan); }
        .badge-pass { background: rgba(0, 255, 136, 0.15); color: var(--green); border: 1px solid var(--green); }

        /* OSINT Grid */
        .osint-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 14px;
            margin-top: 14px;
        }

        @media (max-width: 900px) {
            .osint-grid {
                grid-template-columns: 1fr;
            }
        }

        .osint-card {
            background: #070B14;
            border: 1px solid var(--border-dim);
            border-radius: 5px;
            padding: 14px;
        }

        .osint-card h4 {
            font-size: 12px;
            color: var(--cyan);
            letter-spacing: 1px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        /* Attack Matrix Split Layout */
        .matrix-split {
            display: grid;
            grid-template-columns: 340px 1fr;
            gap: 14px;
            min-height: 520px;
        }

        @media (max-width: 950px) {
            .matrix-split {
                grid-template-columns: 1fr;
            }
        }

        .matrix-list-box {
            background: #070B14;
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 10px;
            overflow-y: auto;
            max-height: 600px;
        }

        .matrix-item {
            padding: 10px 12px;
            border-bottom: 1px solid #0F172A;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 4px;
            transition: all 0.2s;
        }

        .matrix-item:hover {
            background: rgba(0, 240, 255, 0.08);
            border-color: #38BDF8;
        }

        .matrix-item.active {
            background: rgba(0, 240, 255, 0.18);
            border: 1px solid var(--cyan);
            box-shadow: 0 0 10px rgba(0, 240, 255, 0.2);
        }

        .matrix-item h5 {
            font-size: 12px;
            color: var(--text-bright);
            margin-bottom: 2px;
        }

        .matrix-item p {
            font-size: 10px;
            color: var(--text-muted);
        }

        .matrix-detail-box {
            background: #070B14;
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 16px;
            overflow-y: auto;
            max-height: 600px;
        }

        /* Console */
        .hud-console {
            background: #020408;
            border: 1px solid var(--border-dim);
            border-radius: 4px;
            padding: 12px;
            font-size: 11px;
            height: 280px;
            overflow-y: auto;
            color: #8899B5;
        }

        .log-entry { margin-bottom: 3px; }
        .log-time { color: #475569; }

        pre {
            background: #020408;
            border: 1px solid var(--border-dim);
            padding: 12px;
            border-radius: 4px;
            overflow-x: auto;
            color: var(--cyan);
            font-size: 11.5px;
            line-height: 1.4;
        }

        /* Footer */
        .hud-footer {
            background: var(--bg-panel);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 24px;
            font-size: 11px;
            flex-wrap: wrap;
            gap: 10px;
        }

        .footer-links {
            display: flex;
            gap: 14px;
            align-items: center;
        }

        .footer-link {
            color: var(--green);
            text-decoration: none;
            padding: 3px 8px;
            border: 1px solid #1E293B;
            border-radius: 3px;
            transition: all 0.2s;
        }

        .footer-link:hover {
            color: var(--cyan);
            border-color: var(--cyan);
            background: rgba(0, 240, 255, 0.1);
        }
    </style>
</head>
<body>
    <canvas id="hudCanvas"></canvas>

    <div class="hud-wrapper">
        <!-- Top Header -->
        <header class="hud-header">
            <div class="hud-branding">
                <h1>AEGIS // DEFENSIVE WAR ROOM HUD</h1>
                <p>CATEGORIZED CYBER DEFENSE, OSINT RECON, MALWARE DETECTOR & INCIDENT RESPONSE MATRIX</p>
            </div>
            <div class="hud-badges">
                <span class="status-dot"></span>
                <span class="badge-live">DEFENSE SUITE: ONLINE (PORT 5000)</span>
            </div>
        </header>

        <!-- Automated Threat Alert Banner -->
        <div id="threatAlertBanner" class="threat-alert-banner">
            <h3>🚨 AUTOMATED DEFENSE ALERT: CRITICAL ATTACK PATTERNS DETECTED!</h3>
            <p id="threatAlertDesc">Malicious probes intercepted on target web server. Recommended Action: Engage Emergency Lockdown.</p>
        </div>

        <!-- Target Control Bar -->
        <div class="target-bar">
            <div class="target-bar-top">
                <div class="target-input-group">
                    <input type="text" id="targetUrl" class="target-input" value="http://127.0.0.1:8000" placeholder="Enter target website URL or IP address (e.g. http://localhost:3000, 127.0.0.1:8080, 192.168.1.1, https://yoursite.com)">
                </div>
                <div class="presets">
                    <button class="btn-preset" onclick="setTarget('http://localhost:3000')">localhost:3000</button>
                    <button class="btn-preset" onclick="setTarget('http://localhost:8000')">localhost:8000</button>
                    <button class="btn-preset" onclick="setTarget('http://127.0.0.1:8080')">127.0.0.1:8080</button>
                </div>
            </div>
            <div class="target-bar-actions">
                <button class="btn-master" onclick="runMasterScan()">🚀 RUN MASTER DEFENSE SCAN (ALL PANELS)</button>
                <button class="btn-primary" id="btnAudit" onclick="runAudit()">🛡️ RUN DEFENSIVE AUDIT</button>
                <button class="btn-action" onclick="exportAuditReport()">💾 EXPORT AUDIT REPORT (HTML)</button>
            </div>
            <div style="width: 100%; display: flex; gap: 8px; align-items: center; margin-top: 4px; flex-wrap: wrap;">
                <span style="color: var(--cyan); font-size: 11px; font-weight: bold;">🎯 DETECTED HOST INTERFACES & LOCAL IPs:</span>
                <div id="myIpsList" style="display: flex; gap: 6px; flex-wrap: wrap;"></div>
                <button class="btn-action" style="padding: 4px 10px; font-size: 10px;" onclick="loadMyIps()">🔄 REFRESH IPs</button>
                <button class="btn-action" style="padding: 4px 10px; font-size: 10px; border-color: var(--amber); color: var(--amber);" onclick="sendTestProbe()">🧪 TEST ATTACK PROBE ON MY IP</button>
            </div>
        </div>

        <!-- Top Metrics Cards -->
        <div class="metrics-grid">
            <div class="gauge-card">
                <div class="score-circle">
                    <svg viewBox="0 0 120 120">
                        <circle class="circle-bg" cx="60" cy="60" r="50"></circle>
                        <circle class="circle-bar" id="scoreBar" cx="60" cy="60" r="50"></circle>
                    </svg>
                    <div class="score-number" id="scoreNum">100</div>
                </div>
                <div class="score-grade" id="scoreGrade">GRADE: A+</div>
            </div>

            <div class="metric-card">
                <div class="metric-title">CRITICAL THREATS</div>
                <div class="metric-value" id="valCrit" style="color: var(--red);">0</div>
                <div class="metric-sub">Immediate Action Required</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">HIGH SEVERITY</div>
                <div class="metric-value" id="valHigh" style="color: var(--amber);">0</div>
                <div class="metric-sub">Missing Core OWASP Defenses</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">MEDIUM WARNINGS</div>
                <div class="metric-value" id="valMed" style="color: var(--cyan);">0</div>
                <div class="metric-sub">Information Leaks / Minor</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">HARDENED PASSES</div>
                <div class="metric-value" id="valPass" style="color: var(--green);">0</div>
                <div class="metric-sub">Verified Secure Controls</div>
            </div>
        </div>

        <!-- Tabs Navigation Bar -->
        <div class="hud-tabs">
            <button class="hud-tab-btn active" data-category="cat1" onclick="switchTab('tab-findings', this)">🌐 OWASP VULN AUDIT</button>
            <button class="hud-tab-btn" data-category="cat2" onclick="switchTab('tab-osint', this)">🕵️ CYBER OSINT, IP ROUTES & TABLES</button>
            <button class="hud-tab-btn" data-category="cat3" onclick="switchTab('tab-malware', this)">🦠 MALWARE & WEBSHELL SCANNER</button>
            <button class="hud-tab-btn" data-category="cat4" onclick="switchTab('tab-injection', this)">💉 ANTI-XSS & DATA INJECTION</button>
            <button class="hud-tab-btn" data-category="cat5" onclick="switchTab('tab-ports', this)">📡 LOCALHOST & PORTS</button>
            <button class="hud-tab-btn" data-category="cat5" onclick="switchTab('tab-server', this)">💻 SERVER ROOTKIT AUDITOR</button>
            <button class="hud-tab-btn" data-category="cat6" onclick="switchTab('tab-attackers', this)">🚨 ATTACKER IDS & LOGS</button>
            <button class="hud-tab-btn" data-category="cat6" onclick="switchTab('tab-live-traffic', this)">📡 LIVE TRAFFIC SNIFFER</button>
            <button class="hud-tab-btn" data-category="cat7" onclick="switchTab('tab-attack-matrix', this)">⚔️ ATTACK MATRIX & HOW TO FIX</button>
            <button class="hud-tab-btn" data-category="cat7" onclick="switchTab('tab-playbooks', this)">📋 SERVER PLAYBOOKS</button>
            <button class="hud-tab-btn" data-category="cat8" onclick="switchTab('tab-dossier', this)">📜 CARRIER SUBPOENA DOSSIER</button>
            <button class="hud-tab-btn" data-category="all" onclick="switchTab('tab-console', this)">🖥️ TACTICAL LOGS</button>
        </div>

        <!-- Tab 1: OWASP Vulnerability Findings -->
        <div id="tab-findings" class="tab-pane active">
            <div class="category-header-banner">
                <div>
                    <h2>🌐 VULNERABILITY AUDITOR & OWASP COMPLIANCE</h2>
                    <p>Scans target website/localhost for missing OWASP security headers (CSP, HSTS, X-Frame), .env/private credential leaks, and insecure cookies.</p>
                </div>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 100px;">SEVERITY</th>
                            <th style="width: 240px;">VULNERABILITY / CHECK</th>
                            <th>AUDIT DESCRIPTION & RISK</th>
                            <th style="width: 320px;">RECOMMENDED DEFENSIVE FIX</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyFindings">
                        <tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 30px;">Ready. Enter target URL or select a preset, then click 'RUN DEFENSIVE AUDIT'.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 2: Cyber OSINT Engine -->
        <div id="tab-osint" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2>🕵️ CYBER OSINT & ATTACK SURFACE INTELLIGENCE ENGINE</h2>
                    <p>Passive DNS enumeration, Certificate Transparency subdomains, SSL/TLS cryptanalysis, BGP routing/ASN, IP Tables, Routes, Details, and Origins.</p>
                </div>
                <div style="display: flex; gap: 8px;">
                    <button class="btn-action" id="btnRunOsint" onclick="runOsintRecon()">🕵️ RUN PASSIVE OSINT RECON</button>
                    <button class="btn-preset" onclick="copyDiscoveredSubdomains()">📋 COPY ALL SUBDOMAINS</button>
                </div>
            </div>

            <!-- OSINT Metric Cards -->
            <div class="metrics-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 12px;">
                <div class="metric-card">
                    <div class="metric-title">ATTACK SURFACE RISK</div>
                    <div class="metric-value" id="osintValRisk" style="color: var(--green);">LOW</div>
                    <div class="metric-sub" id="osintSubRisk">Passive Recon Score</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">DISCOVERED SUBDOMAINS</div>
                    <div class="metric-value" id="osintValSubs" style="color: var(--cyan);">0</div>
                    <div class="metric-sub">CRT.SH & SAN Certificates</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">SSL/TLS VALIDITY</div>
                    <div class="metric-value" id="osintValSsl" style="color: var(--green);">SECURE</div>
                    <div class="metric-sub" id="osintSubSsl">Certificate Telemetry</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">EMAIL SPOOF DEFENSE</div>
                    <div class="metric-value" id="osintValEmail" style="color: var(--amber);">SPF ONLY</div>
                    <div class="metric-sub" id="osintSubEmail">SPF / DMARC Status</div>
                </div>
            </div>

            <!-- Section: IP Infrastructure & Network Route Intelligence -->
            <div style="margin-top: 14px; margin-bottom: 8px;">
                <span style="color: var(--cyan); font-weight: 900; font-size: 12px; letter-spacing: 1px;">📡 TARGET IP INFRASTRUCTURE, ROUTES & FIREWALL IP TABLES:</span>
            </div>
            <div class="osint-grid">
                <!-- IP Details Card -->
                <div class="osint-card">
                    <h4>📌 IP DETAILS & SCOPE VERIFICATION</h4>
                    <div class="table-container" style="max-height: 220px;">
                        <table>
                            <thead><tr><th style="width: 140px;">PROPERTY</th><th>VALUE / VERIFICATION</th></tr></thead>
                            <tbody id="tbodyIpDetails">
                                <tr><td colspan="2" style="color: var(--text-muted); text-align: center;">Execute OSINT to inspect target IP details.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- IP Origins Card -->
                <div class="osint-card">
                    <h4>🌍 IP ORIGINS & GEOLOCATION TELEMETRY</h4>
                    <div class="table-container" style="max-height: 220px;">
                        <table>
                            <thead><tr><th style="width: 140px;">ORIGIN ATTRIBUTE</th><th>TELEMETRY DATA</th></tr></thead>
                            <tbody id="tbodyIpOrigins">
                                <tr><td colspan="2" style="color: var(--text-muted); text-align: center;">Execute OSINT to resolve IP origin gateway.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- IP Routes Card -->
                <div class="osint-card">
                    <h4>🛣️ IP ROUTES & BGP ROUTING INFRASTRUCTURE</h4>
                    <div class="table-container" style="max-height: 220px;">
                        <table>
                            <thead><tr><th style="width: 140px;">ROUTING LAYER</th><th>METRIC / PATHWAY</th></tr></thead>
                            <tbody id="tbodyIpRoutes">
                                <tr><td colspan="2" style="color: var(--text-muted); text-align: center;">Execute OSINT to trace BGP prefixes and default routes.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- IP Tables & Drop Rules Card -->
                <div class="osint-card">
                    <h4>🛡️ IP TABLES & DEFENSIVE FIREWALL ENFORCEMENT</h4>
                    <div class="table-container" style="max-height: 220px;">
                        <table>
                            <thead><tr><th style="width: 140px;">FIREWALL ENGINE</th><th>SYNTHESIZED DROP RULE</th></tr></thead>
                            <tbody id="tbodyIpTables">
                                <tr><td colspan="2" style="color: var(--text-muted); text-align: center;">Execute OSINT to generate IP table block directives.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Existing OSINT Recon Cards -->
            <div style="margin-top: 14px; margin-bottom: 8px;">
                <span style="color: var(--green); font-weight: 900; font-size: 12px; letter-spacing: 1px;">🌐 DOMAIN ATTACK SURFACE & PUBLIC TELEMETRY:</span>
            </div>
            <div class="osint-grid">
                <!-- Subdomains Card -->
                <div class="osint-card">
                    <h4>🌐 DISCOVERED SUBDOMAINS & SAN LOGS</h4>
                    <div class="table-container" style="max-height: 220px;">
                        <table>
                            <thead><tr><th>SUBDOMAIN</th><th>DISCOVERY SOURCE</th></tr></thead>
                            <tbody id="tbodyOsintSubs">
                                <tr><td colspan="2" style="color: var(--text-muted); text-align: center;">Click 'RUN PASSIVE OSINT RECON' to harvest subdomains.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- DNS Records Card -->
                <div class="osint-card">
                    <h4>📡 MULTI-RECORD DNS TELEMETRY</h4>
                    <div class="table-container" style="max-height: 220px;">
                        <table>
                            <thead><tr><th style="width: 100px;">TYPE</th><th>RECORD VALUE</th><th>FUNCTION</th></tr></thead>
                            <tbody id="tbodyOsintDns">
                                <tr><td colspan="3" style="color: var(--text-muted); text-align: center;">Ready for DNS query resolution.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- SSL Certificate Cryptanalysis -->
                <div class="osint-card">
                    <h4>🔒 SSL/TLS CRYPTOGRAPHIC SPECIFICATION</h4>
                    <div class="table-container" style="max-height: 220px;">
                        <table>
                            <thead><tr><th>PARAMETER</th><th>VALUE / STATUS</th></tr></thead>
                            <tbody id="tbodyOsintSsl">
                                <tr><td colspan="2" style="color: var(--text-muted); text-align: center;">Ready for TLS handshake audit.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- BGP Routing & Geolocation -->
                <div class="osint-card">
                    <h4>🗺️ BGP ROUTING, ASN & HOSTING FINGERPRINT</h4>
                    <div class="table-container" style="max-height: 220px;">
                        <table>
                            <thead><tr><th>ATTRIBUTE</th><th>DETAILS</th></tr></thead>
                            <tbody id="tbodyOsintBgp">
                                <tr><td colspan="2" style="color: var(--text-muted); text-align: center;">Ready for Autonomous System lookup.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Threat Pivots & Frameworks -->
            <div class="osint-card" style="margin-top: 14px;">
                <h4>🔍 EXTERNAL CYBER THREAT PIVOTS & INTELLIGENCE LINKS</h4>
                <div id="osintPivotsList" style="display: flex; gap: 8px; flex-wrap: wrap;">
                    <span style="color: var(--text-muted); font-size: 11px;">Execute OSINT recon to generate deep search pivots across Shodan, Censys, VirusTotal, and URLScan.</span>
                </div>
            </div>
        </div>

        <!-- Tab 3: Malware & Web Shell Scanner -->
        <div id="tab-malware" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2>🦠 MALWARE & WEB SHELL INFECTED PATH SCANNER</h2>
                    <p>Inspects website and server paths for malicious files, backdoors, obfuscated PHP eval/base64 shells, JS cryptominers, and double extensions.</p>
                </div>
                <div style="display: flex; gap: 8px; align-items: center;">
                    <input type="text" id="malwareDirInput" class="target-input" value="." style="width: 200px; padding: 4px 8px;" placeholder="Directory to scan (e.g. . or ./uploads)">
                    <button class="btn-danger" id="btnScanMalware" onclick="runMalwareScan()">🔍 SCAN PATHS FOR MALWARE</button>
                </div>
            </div>

            <div class="metrics-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 12px;">
                <div class="metric-card">
                    <div class="metric-title">INFECTION STATUS</div>
                    <div class="metric-value" id="malwareValStatus" style="color: var(--green);">CLEAN</div>
                    <div class="metric-sub" id="malwareSubStatus">Website Posture</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">INFECTED FILES IDENTIFIED</div>
                    <div class="metric-value" id="malwareValThreats" style="color: var(--red);">0</div>
                    <div class="metric-sub">Action Required Immediately</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">TOTAL FILES INSPECTED</div>
                    <div class="metric-value" id="malwareValScanned" style="color: var(--cyan);">0</div>
                    <div class="metric-sub">Scanned Paths</div>
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 90px;">SEVERITY</th>
                            <th style="width: 380px;">INFECTED FILE PATH / DIRECTORY [SUSPICIOUS]</th>
                            <th style="width: 220px;">THREAT CLASSIFICATION</th>
                            <th style="width: 70px;">LINE #</th>
                            <th>MATCHED MALICIOUS CODE / PARAMETER</th>
                            <th style="width: 180px;">DEFENSIVE ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyMalware">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">Click 'SCAN PATHS FOR MALWARE' to audit website directory for infected files and viruses.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 4: Anti-XSS & Data Injection Shield -->
        <div id="tab-injection" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2>💉 ANTI-XSS, DATA INJECTION & SCRIPT EXECUTION DEFENSE SHIELD</h2>
                    <p>Audits Content-Security-Policy (CSP), MIME sniffing, clickjacking, and generates context-aware input sanitization templates.</p>
                </div>
                <button class="btn-primary" onclick="runInjectionAudit()">💉 AUDIT ANTI-XSS DEFENSES</button>
            </div>

            <div class="metrics-grid" style="grid-template-columns: repeat(2, 1fr); margin-bottom: 12px;">
                <div class="metric-card">
                    <div class="metric-title">ANTI-INJECTION SCORE</div>
                    <div class="metric-value" id="injValScore" style="color: var(--green);">100/100</div>
                    <div class="metric-sub" id="injSubScore">Hardened Defense Posture</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">CSP DIRECTIVE INTEGRITY</div>
                    <div class="metric-value" id="injValCsp" style="color: var(--cyan);">READY</div>
                    <div class="metric-sub">Script Execution Shield</div>
                </div>
            </div>

            <div class="table-container" style="margin-bottom: 14px;">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 200px;">DEFENSE LAYER</th>
                            <th style="width: 120px;">AUDIT STATUS</th>
                            <th>DEFENSE FINDING & VULNERABILITY</th>
                            <th style="width: 320px;">RECOMMENDED HARDENING FIX</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyInjection">
                        <tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 20px;">Click 'AUDIT ANTI-XSS DEFENSES' to analyze CSP and script execution safeguards.</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="osint-grid">
                <div class="osint-card">
                    <h4>🔒 STRICT CONTENT-SECURITY-POLICY (CSP) GENERATOR</h4>
                    <pre id="boxCspPolicy" style="height: 180px;">Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self';</pre>
                </div>
                <div class="osint-card">
                    <h4>🛡️ MODSECURITY WAF SCRIPT EXECUTION RULES</h4>
                    <pre id="boxModSec" style="height: 180px;">SecRule REQUEST_URI|REQUEST_BODY "(<script|javascript:|onerror=|onload=)" "id:1001,phase:2,deny,status:403,log,msg:'Aegis WAF: Injected Script Blocked'"</pre>
                </div>
            </div>
        </div>

        <!-- Tab 5: Localhost Ports -->
        <div id="tab-ports" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2>📡 LOCALHOST OPEN PORTS & SOCKETS AUDITOR</h2>
                    <p>Scans system TCP listeners to identify dangerous wildcard (0.0.0.0) exposures, unauthenticated dev databases, and rogue services.</p>
                </div>
                <button class="btn-action" onclick="scanPorts()">🔄 REFRESH PORTS</button>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 80px;">PORT</th>
                            <th style="width: 160px;">INTERFACE BINDING</th>
                            <th style="width: 160px;">PROCESS NAME</th>
                            <th style="width: 80px;">PID</th>
                            <th style="width: 100px;">RISK LEVEL</th>
                            <th>SECURITY RECOMMENDATION & REMEDIATION</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyPorts">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">Loading listening sockets...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 6: Server Machine Rootkit Auditor -->
        <div id="tab-server" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2>💻 SERVER MACHINE & COMPUTER HOST ROOTKIT AUDITOR</h2>
                    <p>Deep host audit: scans running processes for cryptominers, reverse shells, backdoor ports, hosts file tampering, and dropped temp files.</p>
                </div>
                <button class="btn-danger" id="btnAuditServer" onclick="runServerAudit()">💻 RUN FULL SYSTEM INTEGRITY SCAN</button>
            </div>

            <div class="metrics-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 12px;">
                <div class="metric-card">
                    <div class="metric-title">SYSTEM HEALTH SCORE</div>
                    <div class="metric-value" id="srvValScore" style="color: var(--green);">100/100</div>
                    <div class="metric-sub" id="srvSubStatus">Host Posture: CLEAN</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">SUSPICIOUS PROCESSES / MINERS</div>
                    <div class="metric-value" id="srvValProcs" style="color: var(--red);">0</div>
                    <div class="metric-sub">Rogue PIDs Flagged</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">PROCESSES INSPECTED</div>
                    <div class="metric-value" id="srvValScanned" style="color: var(--cyan);">0</div>
                    <div class="metric-sub">Running Tasks</div>
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 90px;">SEVERITY</th>
                            <th style="width: 280px;">COMPONENT / INFECTED TARGET</th>
                            <th style="width: 180px;">THREAT CLASSIFICATION</th>
                            <th>DETECTION REASON & RISK</th>
                            <th style="width: 140px;">ACTION</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyServerThreats">
                        <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">Click 'RUN FULL SYSTEM INTEGRITY SCAN' to audit host computer for malware, reverse shells, and miners.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 7: Attacker Tracker & IDS -->
        <div id="tab-attackers" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2>🚨 LOG INTRUSION DETECTION & ATTACKER TRACKING ENGINE</h2>
                    <p>Detects automated attack probes (SQLi, XSS, Path Traversal), fingerprints attacker toolkits (SQLmap, Nikto), mobile hardware, and resolves VPN/Tor proxies.</p>
                </div>
                <div style="display: flex; gap: 8px;">
                    <button class="btn-action" onclick="analyzeLogs(true)">🧪 LOAD ATTACK LOGS (TELEMETRY SIMULATION)</button>
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 140px;">ATTACKER IP</th>
                            <th style="width: 150px;">GEOLOCATION / ISP</th>
                            <th style="width: 120px;">CONNECTION</th>
                            <th style="width: 160px;">DEVICE HARDWARE</th>
                            <th style="width: 60px;">HITS</th>
                            <th style="width: 100px;">SEVERITY</th>
                            <th>DETECTED ATTACK VECTORS & SCRIPT PROBES</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyAttackers">
                        <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">Ready. Click 'LOAD ATTACK LOGS' to parse access log telemetry and correlate attacker intelligence.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 8: Live Traffic Sniffer -->
        <div id="tab-live-traffic" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2>📡 LIVE TRAFFIC SNIFFER & CONNECTION MONITOR</h2>
                    <p>Real-time telemetry showing live network connections entering your localhost web server.</p>
                </div>
                <button class="btn-action" onclick="pollActiveTraffic()">🔄 REFRESH LIVE CONNECTIONS</button>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>LOCAL ADDRESS</th>
                            <th>REMOTE CLIENT IP</th>
                            <th>PROTOCOL STATE</th>
                            <th>ASSOCIATED PROCESS</th>
                            <th>PID</th>
                            <th>ATTACK CLASSIFICATION</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyLiveTraffic">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">Click 'REFRESH LIVE CONNECTIONS' to inspect incoming network sockets.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 9: Attack Matrix & How to Fix -->
        <div id="tab-attack-matrix" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2>⚔️ CYBER ATTACK MATRIX & DEFENSE REMEDIATION DASHBOARD</h2>
                    <p>Comprehensive interactive defense runbook: displays all known attacks, exact symptoms, immediate emergency actions, and multi-framework code fixes.</p>
                </div>
                <button class="btn-danger" onclick="triggerEmergencyLockdown()">⚡ ONE-CLICK EMERGENCY FIREWALL SCRIPT</button>
            </div>

            <div class="matrix-split">
                <!-- Left: List of all attacks -->
                <div class="matrix-list-box" id="matrixListContainer">
                    <!-- Populated dynamically via JS -->
                </div>

                <!-- Right: Detailed attack view and fix -->
                <div class="matrix-detail-box" id="matrixDetailContainer">
                    <h3 id="matTitle" style="color: var(--cyan); font-size: 16px; margin-bottom: 4px;">Select an Attack Vector</h3>
                    <p id="matMeta" style="color: var(--amber); font-size: 11px; font-weight: bold; margin-bottom: 10px;">OWASP / CWE CLASSIFICATION</p>
                    <div id="matStatusBox" style="background: rgba(0, 255, 136, 0.1); color: var(--green); border: 1px solid var(--green); padding: 6px 10px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-bottom: 12px;">🟢 STATUS: STANDBY // READY FOR MITIGATION DEPLOYMENT</div>

                    <h4 style="color: var(--cyan); font-size: 12px; margin-top: 10px; margin-bottom: 4px;">🎯 WHAT IS THIS ATTACK & ATTACKER OBJECTIVE:</h4>
                    <p id="matDesc" style="font-size: 11.5px; line-height: 1.6; color: var(--text-main); margin-bottom: 12px;"></p>

                    <h4 style="color: var(--amber); font-size: 12px; margin-top: 10px; margin-bottom: 4px;">🔍 SYMPTOMS (HOW TO TELL IF YOU ARE BEING ATTACKED):</h4>
                    <ul id="matSymptoms" style="font-size: 11.5px; line-height: 1.6; color: #CBD5E1; margin-left: 20px; margin-bottom: 12px;"></ul>

                    <h4 style="color: var(--red); font-size: 12px; margin-top: 10px; margin-bottom: 4px;">⚡ IMMEDIATE EMERGENCY ACTIONS (WHAT TO DO RIGHT NOW):</h4>
                    <div id="matImmediate" style="background: rgba(255, 51, 102, 0.08); border-left: 3px solid var(--red); padding: 10px; font-size: 11.5px; line-height: 1.6; margin-bottom: 12px;"></div>

                    <h4 style="color: var(--green); font-size: 12px; margin-top: 10px; margin-bottom: 4px;">🛠️ PERMANENT ARCHITECTURAL RESOLUTION (HOW TO FIX IT):</h4>
                    <div id="matPermanent" style="background: rgba(0, 255, 136, 0.08); border-left: 3px solid var(--green); padding: 10px; font-size: 11.5px; line-height: 1.6; margin-bottom: 12px;"></div>

                    <h4 style="color: var(--cyan); font-size: 12px; margin-top: 14px; margin-bottom: 6px;">💻 READY-TO-DEPLOY CODE FIX:</h4>
                    <div style="display: flex; gap: 6px; margin-bottom: 8px;">
                        <button class="btn-preset" onclick="switchMatrixStack('nginx')">Nginx</button>
                        <button class="btn-preset" onclick="switchMatrixStack('apache')">Apache</button>
                        <button class="btn-preset" onclick="switchMatrixStack('python')">Python</button>
                        <button class="btn-preset" onclick="switchMatrixStack('nodejs')">Node.js</button>
                        <button class="btn-preset" onclick="switchMatrixStack('php')">PHP</button>
                    </div>
                    <pre id="matCodeBox" style="height: 180px;"></pre>
                    <button class="btn-action" style="margin-top: 6px;" onclick="copyMatrixCode()">📋 COPY CODE FIX TO CLIPBOARD</button>
                </div>
            </div>
        </div>

        <!-- Tab 10: Server Playbooks -->
        <div id="tab-playbooks" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2>📋 SERVER HARDENING PLAYBOOKS</h2>
                    <p>Production-ready security configurations to instantly eliminate OWASP vulnerabilities across major web servers.</p>
                </div>
                <div style="display: flex; gap: 6px;">
                    <button class="btn-preset" onclick="loadPlaybook('nginx')">Nginx</button>
                    <button class="btn-preset" onclick="loadPlaybook('apache')">Apache</button>
                    <button class="btn-preset" onclick="loadPlaybook('express')">Express.js</button>
                    <button class="btn-preset" onclick="loadPlaybook('caddy')">Caddy</button>
                    <button class="btn-preset" onclick="loadPlaybook('python_fastapi')">FastAPI</button>
                </div>
            </div>
            <h3 id="playbookTitle" style="color: var(--cyan); font-size: 14px; margin-bottom: 4px;">Nginx Security Hardening</h3>
            <p id="playbookDesc" style="color: var(--text-muted); font-size: 11px; margin-bottom: 12px;">OWASP recommended headers, dotfile blocking, and version hiding.</p>
            <pre id="playbookCode" style="height: 380px;">Select a playbook above...</pre>
        </div>

        <!-- Tab 11: Carrier Subpoena Dossier -->
        <div id="tab-dossier" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2>📜 LAW ENFORCEMENT & MOBILE CARRIER SUBPOENA EVIDENCE DOSSIER</h2>
                    <p>Cryptographically hashed evidence report formatted for submission to Police Cybercrime Divisions, CERTs, and Mobile Carrier Subpoenas (SIM / IMEI / GPS).</p>
                </div>
                <button class="btn-action" onclick="exportForensicDossier()">💾 EXPORT FORMAL DOSSIER (.TXT)</button>
            </div>
            <pre id="formalDossierBox" style="height: 420px; overflow-y: auto;">Run an audit and load attack logs to synthesize the formal police & carrier subpoena evidence report...</pre>
        </div>

        <!-- Tab 12: Tactical Console -->
        <div id="tab-console" class="tab-pane">
            <h3 style="color: var(--green); font-size: 13px; margin-bottom: 12px; letter-spacing: 1px;">STREAMING TACTICAL HUD CONSOLE</h3>
            <div class="hud-console" id="hudConsole">
                <div class="log-entry"><span class="log-time">[00:00:00]</span> [INFO] Aegis Defensive Web HUD initialized on http://127.0.0.1:5000.</div>
            </div>
        </div>

        <!-- Developer Credits Footer -->
        <footer class="hud-footer">
            <div class="footer-brand">
                <span style="color: var(--cyan); font-weight: bold; letter-spacing: 1px;">🛡️ AEGIS DEFENSIVE SECURITY SUITE</span>
                <span style="color: var(--text-muted); margin: 0 8px;">|</span>
                <span style="color: var(--green); font-weight: bold;">DEVELOPED BY TEAM WHITE HAT</span>
            </div>
            <div class="footer-links">
                <a href="https://github.com/unidentifiedcyberghost" target="_blank" class="footer-link">GitHub: @unidentifiedcyberghost</a>
                <a href="https://github.com/pinoyUnknown" target="_blank" class="footer-link">GitHub: @pinoyUnknown</a>
                <a href="https://x.com/TeamWhiteHatDev" target="_blank" class="footer-link">X: @TeamWhiteHatDev</a>
            </div>
        </footer>
    </div>

    <!-- 60fps Radar Background Canvas Script -->
    <script>
        const canvas = document.getElementById('hudCanvas');
        const ctx = canvas.getContext('2d');

        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }
        window.addEventListener('resize', resizeCanvas);
        resizeCanvas();

        let angle = 0;
        const nodes = [];
        for (let i = 0; i < 35; i++) {
            nodes.push({
                x: Math.random() * window.innerWidth,
                y: Math.random() * window.innerHeight,
                vx: (Math.random() - 0.5) * 0.4,
                vy: (Math.random() - 0.5) * 0.4,
                size: Math.random() * 2 + 1
            });
        }

        function drawHudBackground() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            const cx = canvas.width / 2;
            const cy = canvas.height / 2;
            const maxR = Math.max(canvas.width, canvas.height) * 0.6;

            ctx.save();
            ctx.translate(cx, cy);
            ctx.rotate(angle);

            const gradient = ctx.createLinearGradient(0, 0, maxR, 0);
            gradient.addColorStop(0, 'rgba(0, 240, 255, 0.15)');
            gradient.addColorStop(1, 'rgba(0, 240, 255, 0)');

            ctx.fillStyle = gradient;
            ctx.beginPath();
            ctx.moveTo(0, 0);
            ctx.arc(0, 0, maxR, 0, Math.PI / 4);
            ctx.lineTo(0, 0);
            ctx.fill();
            ctx.restore();

            angle += 0.006;

            ctx.fillStyle = '#00F0FF';
            ctx.strokeStyle = 'rgba(0, 240, 255, 0.06)';

            nodes.forEach((n, idx) => {
                n.x += n.vx;
                n.y += n.vy;
                if (n.x < 0 || n.x > canvas.width) n.vx *= -1;
                if (n.y < 0 || n.y > canvas.height) n.vy *= -1;

                ctx.beginPath();
                ctx.arc(n.x, n.y, n.size, 0, Math.PI * 2);
                ctx.fill();

                for (let j = idx + 1; j < nodes.length; j++) {
                    const dist = Math.hypot(n.x - nodes[j].x, n.y - nodes[j].y);
                    if (dist < 130) {
                        ctx.beginPath();
                        ctx.moveTo(n.x, n.y);
                        ctx.lineTo(nodes[j].x, nodes[j].y);
                        ctx.stroke();
                    }
                }
            });

            requestAnimationFrame(drawHudBackground);
        }
        drawHudBackground();
    </script>

    <!-- Application Logic Script -->
    <script>
        let currentAttackers = [];
        let playbooksData = {};
        let currentTarget = "http://127.0.0.1:8000";
        let lastOsintData = null;
        let matrixData = {};
        let activeMatrixKey = "sqli";
        let activeMatrixStack = "nginx";

        function logToConsole(msg, level = 'INFO') {
            const box = document.getElementById('hudConsole');
            const now = new Date().toTimeString().split(' ')[0];
            const color = level === 'PASS' ? 'var(--green)' : (level === 'THREAT' ? 'var(--red)' : (level === 'WARN' ? 'var(--amber)' : 'var(--cyan)'));
            const row = document.createElement('div');
            row.className = 'log-entry';
            row.innerHTML = `<span class="log-time">[${now}]</span> <b style="color: ${color}">[${level}]</b> ${msg}`;
            box.appendChild(row);
            box.scrollTop = box.scrollHeight;
        }

        function setTarget(val) {
            document.getElementById('targetUrl').value = val;
            currentTarget = val;
        }

        let lastAuditReport = null;

        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.hud-tab-btn').forEach(el => el.classList.remove('active'));
            const targetPane = document.getElementById(tabId);
            if (targetPane) targetPane.classList.add('active');
            if (btn) btn.classList.add('active');
        }

        async function exportAuditReport() {
            if (!lastAuditReport) {
                logToConsole('Generating live audit report for export...', 'INFO');
                await runAudit();
            }
            if (!lastAuditReport) {
                return alert('Please enter a target URL and run an audit first.');
            }
            try {
                const res = await fetch('/api/export-report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ report: lastAuditReport })
                });
                const data = await res.json();
                if (data.html) {
                    const blob = new Blob([data.html], { type: 'text/html' });
                    const link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    link.download = `Aegis_Security_Audit_${new Date().toISOString().slice(0, 10)}.html`;
                    link.click();
                    logToConsole('Exported formal defensive audit report (HTML) to downloads.', 'PASS');
                }
            } catch (err) {
                logToConsole('Report export notice: ' + err, 'WARN');
            }
        }

        function updateScore(score, grade) {
            document.getElementById('scoreNum').innerText = score;
            const gradeEl = document.getElementById('scoreGrade');
            gradeEl.innerText = 'GRADE: ' + grade;

            const bar = document.getElementById('scoreBar');
            const circumference = 314;
            const offset = circumference - (score / 100) * circumference;
            bar.style.strokeDashoffset = offset;

            const col = score >= 85 ? 'var(--green)' : (score >= 65 ? 'var(--amber)' : 'var(--red)');
            bar.style.stroke = col;
            document.getElementById('scoreNum').style.color = col;
            gradeEl.style.color = col;
        }

        // ==========================================
        // Category 1: Vulnerability Auditor
        // ==========================================
        async function runAudit() {
            const url = document.getElementById('targetUrl').value.trim();
            if (!url) return alert('Please enter target URL.');
            currentTarget = url;

            const btn = document.getElementById('btnAudit');
            btn.innerText = '⏳ AUDITING...';
            btn.disabled = true;
            logToConsole('Initiating OWASP vulnerability audit on: ' + url, 'INFO');

            try {
                const res = await fetch('/api/audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: url })
                });
                const report = await res.json();
                lastAuditReport = report;

                updateScore(report.security_score, report.grade);
                document.getElementById('valCrit').innerText = report.findings_summary.critical;
                document.getElementById('valHigh').innerText = report.findings_summary.high;
                document.getElementById('valMed').innerText = report.findings_summary.medium;
                document.getElementById('valPass').innerText = report.findings_summary.pass;

                // Check automated alert
                if (report.findings_summary.critical > 0 || report.findings_summary.high > 0) {
                    const alertBanner = document.getElementById('threatAlertBanner');
                    alertBanner.style.display = 'block';
                    document.getElementById('threatAlertDesc').innerText =
                        `Detected ${report.findings_summary.critical} CRITICAL and ${report.findings_summary.high} HIGH OWASP vulnerabilities. Missing core defenses on target server!`;
                }

                const tbody = document.getElementById('tbodyFindings');
                tbody.innerHTML = '';

                report.findings.forEach(f => {
                    const tr = document.createElement('tr');
                    const sevClass = f.severity === 'Critical' ? 'badge-crit' : (f.severity === 'High' ? 'badge-high' : (f.severity === 'Medium' ? 'badge-med' : 'badge-pass'));
                    tr.innerHTML = `
                        <td><span class="badge-sev ${sevClass}">${f.severity.toUpperCase()}</span></td>
                        <td style="font-weight: bold; color: var(--cyan);">${f.check_name}</td>
                        <td>${f.description}</td>
                        <td style="color: var(--green);">${f.remediation}</td>
                    `;
                    tbody.appendChild(tr);
                });

                logToConsole(`Audit complete. Score: ${report.security_score}/100. Grade: ${report.grade}.`, report.security_score >= 80 ? 'PASS' : 'WARN');
            } catch (err) {
                logToConsole('Audit failed: ' + err, 'THREAT');
            } finally {
                btn.innerText = '🛡️ RUN DEFENSIVE AUDIT';
                btn.disabled = false;
            }
        }

        // ==========================================
        // Category 2: Cyber OSINT Engine
        // ==========================================
        async function runOsintRecon() {
            const url = document.getElementById('targetUrl').value.trim();
            let host = url.replace(/^https?:\\/\\//, '').split('/')[0].split(':')[0];
            if (!host) host = 'localhost';

            const btn = document.getElementById('btnRunOsint');
            btn.innerText = '⏳ RECONNAISSANCE IN PROGRESS...';
            btn.disabled = true;
            logToConsole('Starting Passive Cyber OSINT recon on target: ' + host, 'INFO');

            try {
                const res = await fetch('/api/osint', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: host })
                });
                const recon = await res.json();
                lastOsintData = recon;

                // 1. Update Metrics Cards
                const risk = recon.attack_surface_risk.toUpperCase();
                const riskEl = document.getElementById('osintValRisk');
                riskEl.innerText = risk;
                riskEl.style.color = risk === 'HIGH' ? 'var(--red)' : (risk === 'MEDIUM' ? 'var(--amber)' : 'var(--green)');
                document.getElementById('osintSubRisk').innerText = `Score: ${recon.risk_score}/100 Exposure`;

                const ssl = recon.ssl_certificate || {};
                const sslEl = document.getElementById('osintValSsl');
                if (ssl.valid) {
                    sslEl.innerText = `VALID (${ssl.expires_in_days}d left)`;
                    sslEl.style.color = 'var(--green)';
                    document.getElementById('osintSubSsl').innerText = ssl.cipher || 'TLS Active';
                } else {
                    sslEl.innerText = 'NO SSL / LOCAL';
                    sslEl.style.color = 'var(--text-muted)';
                    document.getElementById('osintSubSsl').innerText = 'Unencrypted or Localhost';
                }

                const email = recon.email_security || {};
                const emailEl = document.getElementById('osintValEmail');
                if (email.spf_present && email.dmarc_present) {
                    emailEl.innerText = 'PROTECTED';
                    emailEl.style.color = 'var(--green)';
                    document.getElementById('osintSubEmail').innerText = 'SPF & DMARC Enforced';
                } else if (email.spf_present) {
                    emailEl.innerText = 'PARTIAL';
                    emailEl.style.color = 'var(--amber)';
                    document.getElementById('osintSubEmail').innerText = 'SPF Only (No DMARC)';
                } else {
                    emailEl.innerText = 'VULNERABLE';
                    emailEl.style.color = 'var(--red)';
                    document.getElementById('osintSubEmail').innerText = 'High Spoofing Risk';
                }

                const subs = recon.subdomains_discovered || [];
                document.getElementById('osintValSubs').innerText = subs.length;

                // 2. Subdomains Table
                const tbodySubs = document.getElementById('tbodyOsintSubs');
                tbodySubs.innerHTML = '';
                if (subs.length > 0) {
                    subs.forEach(s => addTableRow(tbodySubs, [s, 'CRT.SH Certificate Transparency & SAN Logs']));
                } else {
                    tbodySubs.innerHTML = '<tr><td colspan="2" style="color: var(--text-muted); text-align: center;">No additional subdomains discovered via public CT logs.</td></tr>';
                }

                // 3. DNS Table
                const tbodyDns = document.getElementById('tbodyOsintDns');
                tbodyDns.innerHTML = '';
                const dns = recon.dns || {};
                (dns.ipv4_addresses || []).forEach(ip => addTableRow(tbodyDns, ['A (IPv4)', ip, 'Public Origin IP']));
                (dns.ipv6_addresses || []).forEach(ip => addTableRow(tbodyDns, ['AAAA (IPv6)', ip, 'Next-Gen IP']));
                if (dns.reverse_dns && dns.reverse_dns !== 'None') addTableRow(tbodyDns, ['PTR (rDNS)', dns.reverse_dns, 'Reverse DNS Validation']);
                (dns.mx_records || []).forEach(mx => addTableRow(tbodyDns, ['MX', mx, 'Mail Server Authority']));
                if (email.spf_record !== 'None') addTableRow(tbodyDns, ['TXT (SPF)', email.spf_record, 'Email Sender Policy']);
                if (email.dmarc_record !== 'None') addTableRow(tbodyDns, ['TXT (DMARC)', email.dmarc_record, 'Anti-Phishing Policy']);
                (dns.ns_records || []).forEach(ns => addTableRow(tbodyDns, ['NS', ns, 'Nameserver Authority']));

                // 4. SSL Table
                const tbodySsl = document.getElementById('tbodyOsintSsl');
                tbodySsl.innerHTML = '';
                if (ssl.valid) {
                    addTableRow(tbodySsl, ['Issuer Authority', (ssl.issuer.organizationName || ssl.issuer.commonName || 'Unknown')]);
                    addTableRow(tbodySsl, ['Subject CN', (ssl.subject.commonName || 'Unknown')]);
                    addTableRow(tbodySsl, ['Cipher Suite', ssl.cipher || 'Unknown']);
                    addTableRow(tbodySsl, ['TLS Protocol', ssl.tls_version || 'Unknown']);
                    addTableRow(tbodySsl, ['Valid Until', `${ssl.valid_until} (${ssl.expires_in_days} days remaining)`]);
                } else {
                    addTableRow(tbodySsl, ['Status', 'No active public SSL/TLS certificate detected on port 443']);
                }

                // 5. IP Infrastructure: Details, Origins, Routes, and Tables
                const details = recon.ip_details || {};
                const tbodyDetails = document.getElementById('tbodyIpDetails');
                if (tbodyDetails) {
                    tbodyDetails.innerHTML = '';
                    addTableRow(tbodyDetails, ['Target IP Address', details.target_ip || 'N/A']);
                    addTableRow(tbodyDetails, ['Target Hostname', details.hostname || 'N/A']);
                    addTableRow(tbodyDetails, ['Reverse DNS (PTR)', details.reverse_dns || 'N/A']);
                    addTableRow(tbodyDetails, ['Scope / Classification', details.ip_type || 'N/A']);
                    addTableRow(tbodyDetails, ['IP Version', details.ip_version || 'IPv4']);
                    addTableRow(tbodyDetails, ['Bogon Verification', details.bogon_status || 'Legitimate Routable']);
                }

                const origins = recon.ip_origins || {};
                const tbodyOrigins = document.getElementById('tbodyIpOrigins');
                if (tbodyOrigins) {
                    tbodyOrigins.innerHTML = '';
                    addTableRow(tbodyOrigins, ['Country', `${origins.country || 'Unknown'} (${origins.country_code || '--'})`]);
                    addTableRow(tbodyOrigins, ['Region / City', `${origins.city || 'Unknown'}, ${origins.region || ''}`]);
                    addTableRow(tbodyOrigins, ['GPS Coordinates', origins.coordinates || 'N/A']);
                    addTableRow(tbodyOrigins, ['Timezone', origins.timezone || 'UTC']);
                    addTableRow(tbodyOrigins, ['Internet Service Provider', origins.isp || 'N/A']);
                    addTableRow(tbodyOrigins, ['Organization', origins.org || 'N/A']);
                    addTableRow(tbodyOrigins, ['Public Origin IP', origins.public_origin_ip || origins.ip || 'N/A']);
                    addTableRow(tbodyOrigins, ['Hosting / VPN / Proxy', origins.is_vpn_or_hosting ? '⚠️ YES (Datacenter / Proxy IP)' : '🛡️ NO (Residential/Direct Origin)']);
                }

                const routes = recon.ip_routes || {};
                const tbodyRoutes = document.getElementById('tbodyIpRoutes');
                if (tbodyRoutes) {
                    tbodyRoutes.innerHTML = '';
                    addTableRow(tbodyRoutes, ['Autonomous System (ASN)', `${routes.asn || 'N/A'} (${routes.as_name || 'N/A'})`]);
                    addTableRow(tbodyRoutes, ['BGP Routing CIDR', routes.bgp_prefix || 'N/A']);
                    addTableRow(tbodyRoutes, ['Default Gateway', routes.default_gateway || '127.0.0.1']);
                    const sysRoutes = routes.active_system_routes || [];
                    if (sysRoutes.length > 0) {
                        const topRoute = sysRoutes[0];
                        addTableRow(tbodyRoutes, ['Active Host Route [0]', `Dest: ${topRoute.destination} | Mask: ${topRoute.netmask} | Gateway: ${topRoute.gateway} | Iface: ${topRoute.interface}`]);
                        if (sysRoutes.length > 1) {
                            const secondRoute = sysRoutes[1];
                            addTableRow(tbodyRoutes, ['Active Host Route [1]', `Dest: ${secondRoute.destination} | Mask: ${secondRoute.netmask} | Gateway: ${secondRoute.gateway} | Iface: ${secondRoute.interface}`]);
                        }
                    }
                }

                const tables = recon.ip_tables || {};
                const tbodyTables = document.getElementById('tbodyIpTables');
                if (tbodyTables) {
                    tbodyTables.innerHTML = '';
                    addTableRow(tbodyTables, ['Linux iptables Drop', tables.iptables_drop || `iptables -I INPUT -s ${details.target_ip || '127.0.0.1'} -j DROP`]);
                    addTableRow(tbodyTables, ['Linux nftables Drop', tables.nftables_drop || `nft add rule ip filter input ip saddr ${details.target_ip || '127.0.0.1'} drop`]);
                    addTableRow(tbodyTables, ['Windows PowerShell Block', tables.powershell_block || `New-NetFirewallRule -DisplayName 'Aegis-Drop' -RemoteAddress ${details.target_ip || '127.0.0.1'} -Action Block`]);
                    addTableRow(tbodyTables, ['Nginx Web Server Deny', tables.nginx_deny || `deny ${details.target_ip || '127.0.0.1'};`]);
                    addTableRow(tbodyTables, ['Apache .htaccess Deny', tables.apache_deny || `Require not ip ${details.target_ip || '127.0.0.1'}`]);
                    const ifaces = tables.active_interfaces || [];
                    if (ifaces.length > 0) {
                        addTableRow(tbodyTables, ['Host Network Adapter', `${ifaces[0].name}: ${ifaces[0].ip} (MAC: ${ifaces[0].mac})`]);
                    }
                }

                // 6. BGP & Routing Table
                const tbodyBgp = document.getElementById('tbodyOsintBgp');
                tbodyBgp.innerHTML = '';
                const bgp = recon.network_routing || {};
                addTableRow(tbodyBgp, ['Target IP', bgp.ip || 'N/A']);
                addTableRow(tbodyBgp, ['Autonomous System (ASN)', bgp.asn || 'N/A']);
                addTableRow(tbodyBgp, ['Internet Service Provider (ISP)', bgp.isp || 'N/A']);
                addTableRow(tbodyBgp, ['Organization', bgp.org || 'N/A']);
                addTableRow(tbodyBgp, ['Location', `${bgp.city || 'Unknown'}, ${bgp.country || 'Unknown'}`]);
                addTableRow(tbodyBgp, ['Hosting / Proxy Flag', bgp.is_vpn_or_hosting ? 'Yes (Datacenter / Cloud / Proxy)' : 'No (Residential/Origin)']);

                // 7. Threat Pivots
                const pivotsBox = document.getElementById('osintPivotsList');
                pivotsBox.innerHTML = '';
                for (const [name, pUrl] of Object.entries(recon.external_intelligence_links || {})) {
                    const a = document.createElement('a');
                    a.href = pUrl;
                    a.target = '_blank';
                    a.className = 'footer-link';
                    a.style.display = 'inline-block';
                    a.innerHTML = `🔍 ${name}: <span style="color: var(--cyan);">${pUrl}</span>`;
                    pivotsBox.appendChild(a);
                }

                logToConsole(`Passive OSINT recon completed for ${host}. Discovered ${subs.length} subdomains.`, 'PASS');
            } catch (err) {
                logToConsole('OSINT Recon failed: ' + err, 'THREAT');
            } finally {
                btn.innerText = '🕵️ RUN PASSIVE OSINT RECON';
                btn.disabled = false;
            }
        }

        async function runMasterScan() {
            logToConsole('🚀 MASTER DEFENSE SCAN ENGAGED: Executing all defensive domains across all panels...', 'INFO');
            const masterBtn = document.querySelector('.btn-master');
            if (masterBtn) {
                masterBtn.innerText = '⏳ SCANNING ALL PANELS...';
                masterBtn.disabled = true;
            }
            try {
                await Promise.allSettled([
                    runAudit(),
                    runOsintRecon(),
                    runMalwareScan(),
                    runInjectionAudit(),
                    scanPorts(),
                    runServerAudit(),
                    analyzeLogs(true)
                ]);
                logToConsole('✅ MASTER DEFENSE SCAN COMPLETE: All panels populated with live telemetry!', 'PASS');
            } catch (err) {
                logToConsole('Master scan notice: ' + err, 'WARN');
            } finally {
                if (masterBtn) {
                    masterBtn.innerText = '🚀 RUN MASTER DEFENSE SCAN (ALL PANELS)';
                    masterBtn.disabled = false;
                }
            }
        }

        function addTableRow(tbody, cells) {
            const tr = document.createElement('tr');
            cells.forEach(c => {
                const td = document.createElement('td');
                td.innerText = c;
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        }

        function copyDiscoveredSubdomains() {
            if (!lastOsintData || !lastOsintData.subdomains_discovered || lastOsintData.subdomains_discovered.length === 0) {
                return alert('No subdomains discovered yet. Run OSINT recon first.');
            }
            const text = lastOsintData.subdomains_discovered.join('\\n');
            navigator.clipboard.writeText(text);
            logToConsole('Copied all discovered subdomains to clipboard.', 'PASS');
            alert(`Copied ${lastOsintData.subdomains_discovered.length} subdomains to clipboard!`);
        }

        // ==========================================
        // Category 3: Malware & Webshell Scanner
        // ==========================================
        async function runMalwareScan() {
            const dir = document.getElementById('malwareDirInput').value.trim() || '.';
            const btn = document.getElementById('btnScanMalware');
            btn.innerText = '⏳ SCANNING PATHS...';
            btn.disabled = true;
            logToConsole(`Scanning directory path for viruses & webshells: ${dir}`, 'INFO');

            try {
                const res = await fetch('/api/scan-malware', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ directory: dir })
                });
                const result = await res.json();

                const infCount = result.infected_files_count || 0;
                const scannedCount = result.scanned_files_count || 0;

                document.getElementById('malwareValScanned').innerText = scannedCount;
                document.getElementById('malwareValThreats').innerText = infCount;
                const statusEl = document.getElementById('malwareValStatus');

                if (infCount > 0) {
                    statusEl.innerText = 'INFECTED';
                    statusEl.style.color = 'var(--red)';
                    document.getElementById('malwareSubStatus').innerText = 'Malicious Files Detected';
                } else {
                    statusEl.innerText = 'CLEAN';
                    statusEl.style.color = 'var(--green)';
                    document.getElementById('malwareSubStatus').innerText = 'No Backdoors Found';
                }

                const tbody = document.getElementById('tbodyMalware');
                tbody.innerHTML = '';

                if (infCount === 0) {
                    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--green); padding: 25px;">Verified Clean: All ${scannedCount} files inspected. No suspicious webshells or viruses detected.</td></tr>`;
                } else {
                    result.infected_files.forEach(inf => {
                        const tr = document.createElement('tr');
                        const sevClass = inf.severity === 'CRITICAL' ? 'badge-crit' : 'badge-high';
                        tr.innerHTML = `
                            <td><span class="badge-sev ${sevClass}">${inf.severity}</span></td>
                            <td style="color: #FF3366; font-weight: bold; font-family: monospace;">🚨 ${inf.file_path}</td>
                            <td style="color: var(--amber);">${inf.threat_type}</td>
                            <td>${inf.matched_line || 1}</td>
                            <td style="font-family: monospace; color: var(--cyan);">${escapeHtml(inf.code_snippet || 'Disguised Extension')}</td>
                            <td>
                                <button class="btn-preset" style="color: var(--amber); border-color: var(--amber);" onclick="quarantineFile('${escapeJs(inf.file_path)}')">⚠️ QUARANTINE</button>
                                <button class="btn-preset" style="color: var(--red); border-color: var(--red); margin-left: 4px;" onclick="removeFile('${escapeJs(inf.file_path)}')">🗑️ REMOVE</button>
                            </td>
                        `;
                        tbody.appendChild(tr);
                    });
                }

                logToConsole(`Malware scan finished: ${infCount} suspicious files identified out of ${scannedCount}.`, infCount > 0 ? 'THREAT' : 'PASS');
            } catch (err) {
                logToConsole('Malware scan failed: ' + err, 'THREAT');
            } finally {
                btn.innerText = '🔍 SCAN PATHS FOR MALWARE';
                btn.disabled = false;
            }
        }

        async function quarantineFile(fpath) {
            if (!confirm(`Quarantine infected file to .aegis_quarantine/?\\n${fpath}`)) return;
            try {
                const res = await fetch('/api/quarantine-file', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ file_path: fpath })
                });
                const data = await res.json();
                if (data.success) {
                    alert('Successfully quarantined: ' + fpath);
                    logToConsole('Quarantined malicious file: ' + fpath, 'PASS');
                    runMalwareScan();
                } else {
                    alert('Quarantine failed: ' + data.error);
                }
            } catch (e) {
                alert('Error: ' + e);
            }
        }

        async function removeFile(fpath) {
            if (!confirm(`PERMANENTLY DELETE malicious file?\\n${fpath}\\n\\nWARNING: This cannot be undone!`)) return;
            try {
                const res = await fetch('/api/remove-file', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ file_path: fpath })
                });
                const data = await res.json();
                if (data.success) {
                    alert('Permanently removed: ' + fpath);
                    logToConsole('Permanently removed malicious file: ' + fpath, 'PASS');
                    runMalwareScan();
                } else {
                    alert('Removal failed: ' + data.error);
                }
            } catch (e) {
                alert('Error: ' + e);
            }
        }

        // ==========================================
        // Category 4: Anti-XSS & Injection Shield
        // ==========================================
        async function runInjectionAudit() {
            const url = document.getElementById('targetUrl').value.trim() || 'http://127.0.0.1:8000';
            logToConsole('Auditing target for Anti-XSS, script injection & CSP: ' + url, 'INFO');

            try {
                const res = await fetch('/api/injection-audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: url })
                });
                const report = await res.json();

                const score = report.xss_defense_score;
                const scoreEl = document.getElementById('injValScore');
                scoreEl.innerText = `${score}/100`;
                scoreEl.style.color = score >= 80 ? 'var(--green)' : (score >= 60 ? 'var(--amber)' : 'var(--red)');

                document.getElementById('injValCsp').innerText = report.overall_status.toUpperCase();

                const tbody = document.getElementById('tbodyInjection');
                tbody.innerHTML = '';

                (report.findings || []).forEach(f => {
                    const tr = document.createElement('tr');
                    const sevClass = f.status.includes('CRITICAL') ? 'badge-crit' : (f.status.includes('WARNING') ? 'badge-high' : 'badge-pass');
                    tr.innerHTML = `
                        <td style="font-weight: bold; color: var(--cyan);">${f.defense}</td>
                        <td><span class="badge-sev ${sevClass}">${f.status}</span></td>
                        <td>${f.issue}</td>
                        <td style="color: var(--green);">${f.mitigation}</td>
                    `;
                    tbody.appendChild(tr);
                });

                if (report.generated_csp && report.generated_csp.strict_production) {
                    document.getElementById('boxCspPolicy').innerText = "Content-Security-Policy: " + report.generated_csp.strict_production;
                }

                logToConsole(`Anti-XSS & Injection audit complete. Score: ${score}/100.`, score >= 80 ? 'PASS' : 'WARN');
            } catch (err) {
                logToConsole('Injection audit failed: ' + err, 'THREAT');
            }
        }

        // ==========================================
        // Category 5: Localhost Ports & Server Machine Rootkit Auditor
        // ==========================================
        async function scanPorts() {
            logToConsole('Auditing local listening sockets...', 'INFO');
            try {
                const res = await fetch('/api/ports');
                const listeners = await res.json();
                const tbody = document.getElementById('tbodyPorts');
                tbody.innerHTML = '';

                listeners.forEach(l => {
                    const tr = document.createElement('tr');
                    const sevClass = l.risk_level === 'Critical' ? 'badge-crit' : (l.risk_level === 'Medium' ? 'badge-high' : 'badge-pass');
                    tr.innerHTML = `
                        <td style="font-weight: bold; color: var(--cyan);">${l.port}</td>
                        <td>${l.ip}:${l.port}</td>
                        <td>${l.process_name}</td>
                        <td>${l.pid || 'N/A'}</td>
                        <td><span class="badge-sev ${sevClass}">${l.risk_level.toUpperCase()}</span></td>
                        <td>${l.risk_message} &rarr; <b style="color: var(--green)">${l.remediation}</b></td>
                    `;
                    tbody.appendChild(tr);
                });

                logToConsole(`Audited ${listeners.length} local listening sockets.`, 'PASS');
            } catch (err) {
                logToConsole('Port scan failed: ' + err, 'THREAT');
            }
        }

        async function runServerAudit() {
            const btn = document.getElementById('btnAuditServer');
            btn.innerText = '⏳ SCANNING MACHINE...';
            btn.disabled = true;
            logToConsole('Auditing host machine for cryptominers, reverse shells, and rootkits...', 'INFO');

            try {
                const res = await fetch('/api/server-audit');
                const report = await res.json();

                const score = report.system_health_score;
                document.getElementById('srvValScore').innerText = `${score}/100`;
                document.getElementById('srvSubStatus').innerText = report.infection_status;
                document.getElementById('srvValProcs').innerText = report.suspicious_processes.length;
                document.getElementById('srvValScanned').innerText = report.summary.processes_scanned;

                const tbody = document.getElementById('tbodyServerThreats');
                tbody.innerHTML = '';

                const threats = [];
                (report.suspicious_processes || []).forEach(p => threats.push({
                    sev: p.severity,
                    comp: `PROCESS: ${p.name} (PID: ${p.pid})`,
                    type: p.threat_type,
                    reason: p.details,
                    pid: p.pid
                }));

                (report.rogue_connections || []).forEach(c => threats.push({
                    sev: c.severity,
                    comp: `SOCKET: Port ${c.local_port} / Remote ${c.remote_ip}:${c.remote_port}`,
                    type: 'BACKDOOR SOCKET',
                    reason: c.threat,
                    pid: c.pid
                }));

                (report.temp_infections || []).forEach(t => threats.push({
                    sev: t.severity,
                    comp: `FILE: ${t.filename}`,
                    type: 'DROPPED TEMP EXECUTABLE',
                    reason: t.threat,
                    fpath: t.file_path
                }));

                if (threats.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--green); padding: 25px;">Verified Clean: All ${report.summary.processes_scanned} running host processes and network sockets verified safe. No cryptominers or reverse shells detected.</td></tr>`;
                } else {
                    threats.forEach(t => {
                        const tr = document.createElement('tr');
                        const sevClass = t.sev === 'CRITICAL' ? 'badge-crit' : 'badge-high';
                        const actionBtn = t.pid ? `<button class="btn-danger" style="padding: 2px 8px; font-size: 10px;" onclick="killServerProc(${t.pid})">⚡ KILL PID ${t.pid}</button>` : '<span style="color: var(--text-muted)">N/A</span>';
                        tr.innerHTML = `
                            <td><span class="badge-sev ${sevClass}">${t.sev}</span></td>
                            <td style="color: #FF3366; font-weight: bold;">🚨 ${t.comp}</td>
                            <td style="color: var(--amber);">${t.type}</td>
                            <td>${t.reason}</td>
                            <td>${actionBtn}</td>
                        `;
                        tbody.appendChild(tr);
                    });
                }

                logToConsole(`Server machine audit completed. Status: ${report.infection_status}.`, score >= 80 ? 'PASS' : 'THREAT');
            } catch (err) {
                logToConsole('Server audit failed: ' + err, 'THREAT');
            } finally {
                btn.innerText = '💻 RUN FULL SYSTEM INTEGRITY SCAN';
                btn.disabled = false;
            }
        }

        async function killServerProc(pid) {
            if (!confirm(`Are you sure you want to terminate rogue process PID ${pid}?`)) return;
            try {
                const res = await fetch('/api/kill-process', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pid: pid })
                });
                const data = await res.json();
                if (data.success) {
                    alert('Successfully terminated process PID: ' + pid);
                    logToConsole('Terminated rogue process PID: ' + pid, 'PASS');
                    runServerAudit();
                } else {
                    alert('Termination failed: ' + data.error);
                }
            } catch (e) {
                alert('Error: ' + e);
            }
        }

        // ==========================================
        // Category 6: Attacker Tracker & IDS
        // ==========================================
        async function analyzeLogs(useSample = false) {
            logToConsole('Ingesting server access logs and running threat correlation...', 'INFO');
            try {
                const res = await fetch('/api/analyze-logs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ use_sample: useSample })
                });
                const attackers = await res.json();
                currentAttackers = attackers;

                const tbody = document.getElementById('tbodyAttackers');
                tbody.innerHTML = '';

                attackers.forEach(att => {
                    const tr = document.createElement('tr');
                    const tp = att.threat_profile || {};
                    const connType = tp.is_vpn_or_proxy ? '⚠️ VPN / PROXY' : 'Direct Origin';
                    const connColor = tp.is_vpn_or_proxy ? 'var(--amber)' : 'var(--green)';

                    const hw = att.device_hardware || {};
                    const hwStr = hw.device_model ? `${hw.platform} (${hw.device_model})` : (hw.platform || 'Desktop');

                    const sevClass = att.threat_level === 'CRITICAL' ? 'badge-crit' : (att.threat_level === 'HIGH' ? 'badge-high' : 'badge-med');

                    tr.innerHTML = `
                        <td style="font-weight: bold; color: var(--cyan);">${att.ip}</td>
                        <td>${tp.city || 'Unknown'}, ${tp.country || 'Unknown'} (${tp.isp || 'ISP'})</td>
                        <td style="color: ${connColor}; font-weight: bold;">${connType}</td>
                        <td style="color: var(--cyan);">${hwStr}</td>
                        <td>${att.hits}</td>
                        <td><span class="badge-sev ${sevClass}">${att.threat_level}</span></td>
                        <td>${att.attack_types.join(', ')}</td>
                    `;
                    tbody.appendChild(tr);
                });

                logToConsole(`IDS analysis complete: Profiled ${attackers.length} offending attacker IPs.`, 'PASS');
                updateFormalDossier();
            } catch (err) {
                logToConsole('Log analysis failed: ' + err, 'THREAT');
            }
        }

        async function pollActiveTraffic() {
            logToConsole('Inspecting live connections to localhost...', 'INFO');
            try {
                const res = await fetch('/api/active-traffic');
                const traffic = await res.json();
                const tbody = document.getElementById('tbodyLiveTraffic');
                tbody.innerHTML = '';

                if (traffic.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 25px;">No active external TCP connections currently established.</td></tr>';
                } else {
                    traffic.forEach(t => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td>${t.local_address}</td>
                            <td style="font-weight: bold; color: var(--cyan);">${t.remote_address}</td>
                            <td>${t.status}</td>
                            <td>${t.process_name}</td>
                            <td>${t.pid || 'N/A'}</td>
                            <td><span class="badge-sev badge-pass">${t.classification}</span></td>
                        `;
                        tbody.appendChild(tr);
                    });
                }
            } catch (e) {}
        }

        // ==========================================
        // Category 7: Attack Matrix & How to Fix
        // ==========================================
        async function loadAttackMatrix() {
            try {
                const res = await fetch('/api/attack-matrix');
                matrixData = await res.json();
                renderMatrixList();
                selectMatrixItem('sqli');
            } catch (e) {}
        }

        function renderMatrixList() {
            const container = document.getElementById('matrixListContainer');
            container.innerHTML = '';

            for (const [key, att] of Object.entries(matrixData)) {
                const div = document.createElement('div');
                div.className = `matrix-item ${key === activeMatrixKey ? 'active' : ''}`;
                div.id = `matrix-item-${key}`;
                div.onclick = () => selectMatrixItem(key);
                div.innerHTML = `
                    <h5>${att.icon} ${att.name}</h5>
                    <p>${att.owasp_cwe} | <b style="color: ${att.severity === 'CRITICAL' ? 'var(--red)' : 'var(--amber)'}">${att.severity}</b></p>
                `;
                container.appendChild(div);
            }
        }

        function selectMatrixItem(key) {
            activeMatrixKey = key;
            document.querySelectorAll('.matrix-item').forEach(el => el.classList.remove('active'));
            const el = document.getElementById(`matrix-item-${key}`);
            if (el) el.classList.add('active');

            const att = matrixData[key];
            if (!att) return;

            document.getElementById('matTitle').innerText = `${att.icon} ${att.name}`;
            document.getElementById('matMeta').innerText = `CATEGORY: ${att.category.toUpperCase()} | SEVERITY: ${att.severity} | CLASSIFICATION: ${att.owasp_cwe}`;
            document.getElementById('matDesc').innerText = att.description;

            const symList = document.getElementById('matSymptoms');
            symList.innerHTML = '';
            att.symptoms.forEach(s => {
                const li = document.createElement('li');
                li.innerText = s;
                symList.appendChild(li);
            });

            document.getElementById('matImmediate').innerHTML = att.immediate_actions.map(a => `<p style="margin-bottom: 4px;">${a}</p>`).join('');
            document.getElementById('matPermanent').innerHTML = att.permanent_fix.map(f => `<p style="margin-bottom: 4px;">${f}</p>`).join('');

            switchMatrixStack(activeMatrixStack);
        }

        function switchMatrixStack(stack) {
            activeMatrixStack = stack;
            const att = matrixData[activeMatrixKey];
            if (!att) return;
            const fixes = att.code_fixes || {};
            const snippet = fixes[stack] || Object.values(fixes)[0] || "# No specific code snippet available for this stack.";
            document.getElementById('matCodeBox').innerText = snippet;
        }

        function copyMatrixCode() {
            const code = document.getElementById('matCodeBox').innerText;
            navigator.clipboard.writeText(code);
            logToConsole('Copied code fix to clipboard.', 'PASS');
            alert('Code fix copied to clipboard!');
        }

        // ==========================================
        // Category 8: Carrier Subpoena Dossier & Lockdown
        // ==========================================
        async function triggerEmergencyLockdown() {
            let ips = currentAttackers.map(a => a.ip);
            if (ips.length === 0) {
                ips = ['198.51.100.45', '203.0.113.19', '185.220.101.5'];
            }

            const res = await fetch('/api/emergency-lockdown', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ips: ips })
            });
            const data = await res.json();

            const blob = new Blob([data.windows_script], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'aegis_emergency_block.ps1';
            a.click();

            logToConsole('Generated emergency firewall script aegis_emergency_block.ps1 for ' + ips.length + ' attacker IPs!', 'PASS');
            alert(`⚡ EMERGENCY DEFENSE ENGAGED!\n\nGenerated instant firewall drop rules for ${ips.length} attacker IPs.\nDownloaded: 'aegis_emergency_block.ps1'\n\nRight-click and Run with PowerShell as Administrator to drop all attackers immediately!`);
        }

        async function updateFormalDossier() {
            const res = await fetch('/api/export-dossier', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: currentTarget, attackers: currentAttackers })
            });
            const data = await res.json();
            document.getElementById('formalDossierBox').innerText = data.dossier;
        }

        async function exportForensicDossier() {
            const dossierText = document.getElementById('formalDossierBox').innerText;
            const blob = new Blob([dossierText], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `Aegis_Law_Enforcement_Dossier_${Date.now()}.txt`;
            a.click();
            logToConsole('Exported formal forensic dossier for law enforcement / carrier subpoena.', 'PASS');
        }

        async function loadMyIps() {
            try {
                const res = await fetch('/api/my-ips');
                const data = await res.json();
                const box = document.getElementById('myIpsList');
                box.innerHTML = '';
                (data.ips || []).forEach(ip => {
                    const btn = document.createElement('button');
                    btn.className = 'btn-preset';
                    btn.innerText = ip;
                    btn.onclick = () => setTarget(`http://${ip}:8000`);
                    box.appendChild(btn);
                });
            } catch (e) {}
        }

        async function sendTestProbe() {
            const url = document.getElementById('targetUrl').value.trim();
            logToConsole('Sending synthetic defensive test probe to: ' + url, 'WARN');
            try {
                const res = await fetch('/api/test-probe', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: url })
                });
                const data = await res.json();
                logToConsole(`Probe sent. Response code: ${data.status_code}. Interception logged in IDS.`, 'PASS');
                alert(`Defensive test probe transmitted to ${url}.\nStatus: ${data.status_code}\nNow load attack logs to see how IDS correlates the probe!`);
            } catch (err) {
                logToConsole('Probe error: ' + err, 'THREAT');
            }
        }

        async function loadPlaybooksInit() {
            try {
                const res = await fetch('/api/playbooks');
                playbooksData = await res.json();
                loadPlaybook('nginx');
            } catch (e) {}
        }

        function loadPlaybook(key) {
            const pb = playbooksData[key];
            if (!pb) return;
            document.getElementById('playbookTitle').innerText = pb.title;
            document.getElementById('playbookDesc').innerText = pb.description;
            document.getElementById('playbookCode').innerText = pb.snippet;
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        function escapeJs(str) {
            if (!str) return '';
            return str.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'");
        }

        window.addEventListener('DOMContentLoaded', () => {
            loadMyIps();
            scanPorts();
            loadPlaybooksInit();
            loadAttackMatrix();
        });
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HUD_HTML)


@app.route("/api/audit", methods=["POST"])
def api_audit():
    data = request.get_json() or {}
    target = data.get("target", "http://127.0.0.1:8000")
    auditor = WebAuditor(target)
    report = auditor.run_full_audit()
    return jsonify(report)


@app.route("/api/osint", methods=["POST"])
def api_osint():
    data = request.get_json() or {}
    target = data.get("target", "localhost")
    engine = OsintEngine(target)
    recon = engine.run_full_recon()
    return jsonify(recon)


@app.route("/api/ports", methods=["GET"])
def api_ports():
    listeners = PortAuditor.audit_listeners()
    return jsonify(listeners)


@app.route("/api/my-ips", methods=["GET"])
def api_my_ips():
    ips = WebAuditor.get_local_system_ips()
    return jsonify({"ips": ips})


@app.route("/api/active-traffic", methods=["GET"])
def api_active_traffic():
    traffic = WebAuditor.sniff_active_connections()
    return jsonify(traffic)


@app.route("/api/test-probe", methods=["POST"])
def api_test_probe():
    data = request.get_json() or {}
    target = data.get("target", "http://127.0.0.1:8000")
    res = WebAuditor.simulate_attack_probe(target)
    return jsonify(res)


@app.route("/api/analyze-logs", methods=["POST"])
def api_analyze_logs():
    data = request.get_json() or {}
    use_sample = data.get("use_sample", False)
    content = data.get("log_content", "")

    if use_sample or not content:
        content = LogIntrusionDetector.generate_sample_attack_log()

    detector = LogIntrusionDetector()
    attackers = detector.parse_log_text(content)
    intel = ThreatIntelAnalyzer()

    enriched = []
    for att in attackers:
        geo = intel.enrich_attacker_ip(att["ip"])
        tools = intel.fingerprint_user_agents(att["user_agents"])
        hw = intel.fingerprint_device_hardware(att["user_agents"])
        mitre = intel.map_to_mitre_and_owasp(att["attack_types"])
        att["threat_profile"] = geo
        att["identified_tools"] = tools
        att["device_hardware"] = hw
        att["mitre_mappings"] = mitre
        enriched.append(att)

    return jsonify(enriched)


@app.route("/api/emergency-lockdown", methods=["POST"])
def api_emergency_lockdown():
    data = request.get_json() or {}
    ips = data.get("ips", [])
    ps_script = ActiveDefenseManager.generate_batch_firewall_script(ips, os_type="windows")
    linux_script = ActiveDefenseManager.generate_batch_firewall_script(ips, os_type="linux")
    waf_filters = ActiveDefenseManager.generate_emergency_waf_filter()

    return jsonify({
        "windows_script": ps_script,
        "linux_script": linux_script,
        "waf_filters": waf_filters
    })


@app.route("/api/export-dossier", methods=["POST"])
def api_export_dossier():
    data = request.get_json() or {}
    target = data.get("target", "http://127.0.0.1:8000")
    attackers = data.get("attackers", [])
    dossier = ActiveDefenseManager.generate_law_enforcement_dossier(target, attackers)
    return jsonify({"dossier": dossier})


@app.route("/api/export-report", methods=["POST"])
def api_export_report():
    data = request.get_json() or {}
    report = data.get("report", {})
    from aegis.reporter import ReportGenerator
    html = ReportGenerator.to_html(report)
    return jsonify({"status": "success", "html": html})


@app.route("/api/scan-malware", methods=["POST"])
def api_scan_malware():
    data = request.get_json() or {}
    directory = data.get("directory", ".")
    scanner = MalwareScanner()
    result = scanner.scan_directory(directory)
    return jsonify(result)


@app.route("/api/quarantine-file", methods=["POST"])
def api_quarantine_file():
    data = request.get_json() or {}
    file_path = data.get("file_path", "")
    scanner = MalwareScanner()
    result = scanner.quarantine_file(file_path)
    return jsonify(result)


@app.route("/api/remove-file", methods=["POST"])
def api_remove_file():
    data = request.get_json() or {}
    file_path = data.get("file_path", "")
    scanner = MalwareScanner()
    result = scanner.remove_file(file_path)
    return jsonify(result)


@app.route("/api/injection-audit", methods=["POST"])
def api_injection_audit():
    data = request.get_json() or {}
    target = data.get("target", "http://127.0.0.1:8000")
    shield = InjectionDefenseEngine(target)
    result = shield.audit_target_defenses()
    return jsonify(result)


@app.route("/api/attack-matrix", methods=["GET"])
def api_attack_matrix():
    return jsonify(ATTACK_MATRIX)


@app.route("/api/server-audit", methods=["GET"])
def api_server_audit():
    result = ServerSystemAuditor.audit_full_system()
    return jsonify(result)


@app.route("/api/kill-process", methods=["POST"])
def api_kill_process():
    data = request.get_json() or {}
    pid = data.get("pid")
    if not pid:
        return jsonify({"success": False, "error": "PID required"}), 400
    res = ServerSystemAuditor.kill_process(int(pid))
    return jsonify(res)


@app.route("/api/playbooks", methods=["GET"])
def api_playbooks():
    return jsonify(PLAYBOOKS)


def run_web(host="127.0.0.1", port=5000):
    print(f"\n[+] AEGIS Tactical Sci-Fi HUD Web Dashboard online:")
    print(f"    --> http://{host}:{port} or http://localhost:{port}\n")
    print(f"    Developed by Team White Hat (Defensive Cyber Research)\n")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run_web()

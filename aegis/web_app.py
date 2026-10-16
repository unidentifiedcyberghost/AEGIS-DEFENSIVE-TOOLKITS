"""
Aegis Localhost Web Dashboard - Holographic Cyber Defense War Room & 20-in-1 OSINT Suite
Serves a Sci-Fi Tactical HUD in the browser at http://127.0.0.1:5000.
Minimal Holographic Style, Real-Time Connection Monitoring, Live IDS Logging, and Full Spectrum OSINT.
Developed by Team White Hat.
"""

import os
import warnings
import urllib3
from datetime import datetime

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
from aegis.osint_suite import AdvancedOsintSuite
from aegis.crypto_tracer import CryptoTraceEngine
from aegis.spiderfoot_recon import SpiderFootReconEngine

app = Flask(__name__)

# Real-Time In-Memory Server Access Logs buffer
LIVE_ACCESS_LOGS = []


@app.before_request
def log_live_incoming_request():
    """Captures real-time incoming HTTP requests to localhost into the IDS buffer."""
    path = request.path
    if path.startswith("/api/active-traffic") or path.startswith("/static"):
        return  # Avoid log pollution from polling
    now_str = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
    client_ip = request.remote_addr or "127.0.0.1"
    ua = request.headers.get("User-Agent", "Aegis-Client/2.5")[:80]
    full_path = request.full_path if request.query_string else request.path
    line = f'{client_ip} - - [{now_str}] "{request.method} {full_path} HTTP/1.1" 200 1024 "-" "{ua}"'
    LIVE_ACCESS_LOGS.append(line)
    if len(LIVE_ACCESS_LOGS) > 2000:
        LIVE_ACCESS_LOGS.pop(0)


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
            --bg-void: #030712;
            --bg-panel: rgba(11, 19, 38, 0.92);
            --bg-card: rgba(15, 23, 42, 0.88);
            --border-dim: rgba(0, 240, 255, 0.18);
            --border-glow: #00F0FF;
            --cyan: #00F0FF;
            --neon-blue: #00A3FF;
            --green: #00FF88;
            --amber: #FFB800;
            --red: #FF3366;
            --violet: #B026FF;
            --text-bright: #F8FAFC;
            --text-main: #CBD5E1;
            --text-muted: #64748B;
            --font-mono: 'JetBrains Mono', 'Consolas', monospace;
            --font-sans: 'Space Grotesk', sans-serif;
            --holo-glow: 0 0 14px rgba(0, 240, 255, 0.35);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            scrollbar-width: none !important;
            -ms-overflow-style: none !important;
        }

        *::-webkit-scrollbar {
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
        }

        /* 60fps Animated Holographic Grid & Scanlines */
        #hudCanvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            pointer-events: none;
            z-index: 0;
            opacity: 0.4;
        }

        .holo-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.03), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.03));
            background-size: 100% 3px, 6px 100%;
            pointer-events: none;
            z-index: 99;
            opacity: 0.5;
        }

        .hud-wrapper {
            position: relative;
            z-index: 1;
            max-width: 1560px;
            margin: 0 auto;
        }

        /* Holographic Minimal Glyphs & Tags */
        .holo-glyph {
            color: var(--cyan);
            font-weight: 700;
            margin-right: 6px;
            display: inline-block;
            text-shadow: 0 0 8px rgba(0, 240, 255, 0.8);
        }

        .holo-badge {
            display: inline-flex;
            align-items: center;
            padding: 2px 7px;
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 1px;
            border-radius: 3px;
            border: 1px solid var(--cyan);
            background: rgba(0, 240, 255, 0.08);
            color: var(--cyan);
            text-shadow: 0 0 6px rgba(0, 240, 255, 0.6);
            margin-left: 6px;
        }

        .holo-tag {
            border: 1px solid rgba(0, 240, 255, 0.25);
            background: rgba(0, 240, 255, 0.04);
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 10px;
            color: var(--cyan);
            letter-spacing: 0.5px;
        }

        /* Top Header */
        .hud-header {
            background: var(--bg-panel);
            backdrop-filter: blur(14px);
            border: 1px solid var(--border-dim);
            border-left: 4px solid var(--cyan);
            border-radius: 6px;
            padding: 14px 22px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 0 35px rgba(0, 240, 255, 0.12);
            margin-bottom: 12px;
        }

        .hud-branding h1 {
            font-family: var(--font-sans);
            font-size: 19px;
            letter-spacing: 2px;
            color: var(--cyan);
            text-shadow: 0 0 12px rgba(0, 240, 255, 0.5);
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

        .status-dot.radar {
            background: var(--cyan);
            box-shadow: 0 0 10px var(--cyan);
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

        /* Target Control Bar */
        .target-bar {
            background: var(--bg-panel);
            backdrop-filter: blur(14px);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 16px 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 12px;
            margin-bottom: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }

        .target-bar-top {
            display: flex;
            gap: 12px;
            align-items: center;
            justify-content: center;
            flex-wrap: wrap;
            width: 100%;
        }

        .target-input-group {
            display: flex;
            flex: 1;
            max-width: 650px;
            min-width: 320px;
        }

        .target-input {
            width: 100%;
            background: #060B17;
            border: 1.5px solid var(--border-dim);
            color: var(--cyan);
            font-family: var(--font-mono);
            font-size: 12px;
            padding: 9px 16px;
            border-radius: 5px;
            outline: none;
            transition: all 0.2s;
            box-shadow: inset 0 0 10px rgba(0, 0, 0, 0.5);
        }

        .target-input:focus {
            border-color: var(--cyan);
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.35);
        }

        .presets {
            display: flex;
            gap: 6px;
            align-items: center;
            flex-wrap: wrap;
            justify-content: center;
        }

        .target-bar-actions {
            display: flex;
            gap: 10px;
            align-items: center;
            justify-content: center;
            flex-wrap: wrap;
            width: 100%;
            padding-top: 4px;
            border-top: 1px dashed rgba(0, 240, 255, 0.15);
        }

        .host-interfaces-bar {
            display: flex;
            gap: 8px;
            align-items: center;
            justify-content: center;
            flex-wrap: wrap;
            width: 100%;
            padding-top: 6px;
            border-top: 1px dashed rgba(0, 240, 255, 0.1);
        }

        /* Buttons (Holographic Minimal) */
        button {
            font-family: var(--font-mono);
            cursor: pointer;
            transition: all 0.2s ease;
            outline: none;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .btn-master {
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.18), rgba(0, 163, 255, 0.35));
            border: 1.5px solid var(--cyan);
            color: #FFFFFF;
            padding: 9px 20px;
            border-radius: 4px;
            font-size: 11.5px;
            font-weight: 800;
            text-shadow: 0 0 10px rgba(0, 240, 255, 0.7);
            box-shadow: 0 0 16px rgba(0, 240, 255, 0.25);
            margin: 3px 6px;
        }

        .btn-master:hover {
            background: var(--cyan);
            color: #030712;
            box-shadow: 0 0 25px rgba(0, 240, 255, 0.6);
        }

        .btn-primary {
            background: rgba(0, 255, 136, 0.12);
            border: 1.5px solid var(--green);
            color: var(--green);
            padding: 8px 16px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-shadow: 0 0 8px rgba(0, 255, 136, 0.5);
            margin: 3px 6px;
        }

        .btn-primary:hover {
            background: var(--green);
            color: #030712;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
        }

        .btn-action {
            background: rgba(0, 240, 255, 0.08);
            border: 1px solid var(--cyan);
            color: var(--cyan);
            padding: 7px 15px;
            border-radius: 4px;
            font-size: 10.5px;
            font-weight: bold;
            margin: 3px 6px;
        }

        .btn-action:hover {
            background: rgba(0, 240, 255, 0.25);
            box-shadow: 0 0 14px rgba(0, 240, 255, 0.4);
        }

        .btn-preset {
            background: #091122;
            border: 1px solid var(--border-dim);
            color: var(--text-main);
            padding: 5px 11px;
            border-radius: 4px;
            font-size: 10px;
            margin: 2px;
        }

        .btn-preset:hover, .btn-preset.active {
            border-color: var(--cyan);
            color: var(--cyan);
            background: rgba(0, 240, 255, 0.1);
        }

        .btn-danger {
            background: rgba(255, 51, 102, 0.12);
            border: 1px solid var(--red);
            color: var(--red);
            padding: 8px 15px;
            border-radius: 4px;
            font-size: 10.5px;
            font-weight: bold;
            margin: 3px 6px;
        }

        .btn-danger:hover {
            background: var(--red);
            color: #FFF;
            box-shadow: 0 0 20px rgba(255, 51, 102, 0.6);
        }

        /* Top Metrics Cards */
        .metrics-grid {
            display: grid;
            grid-template-columns: 180px repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }

        @media (max-width: 1024px) {
            .metrics-grid { grid-template-columns: repeat(2, 1fr); }
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
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
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
            stroke-width: 7;
        }

        .circle-bar {
            fill: none;
            stroke: var(--green);
            stroke-width: 7;
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
            font-family: var(--font-sans);
            font-size: 20px;
            font-weight: 800;
            color: var(--green);
        }

        .score-grade {
            margin-top: 6px;
            font-size: 11px;
            font-weight: bold;
            color: var(--cyan);
            letter-spacing: 1px;
        }

        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 14px 18px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        }

        .metric-title {
            color: var(--text-muted);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
        }

        .metric-value {
            font-family: var(--font-sans);
            font-size: 26px;
            font-weight: 800;
            margin: 4px 0;
        }

        .metric-sub {
            font-size: 10px;
            color: var(--text-muted);
        }

        /* Navigation Tabs (Minimal Holographic) */
        .hud-tabs {
            display: flex;
            gap: 6px;
            margin-bottom: 16px;
            flex-wrap: wrap;
            border-bottom: 1px solid var(--border-dim);
            padding-bottom: 8px;
        }

        .hud-tab-btn {
            background: rgba(11, 19, 38, 0.7);
            border: 1px solid var(--border-dim);
            color: var(--text-muted);
            padding: 8px 14px;
            border-radius: 4px;
            font-size: 10.5px;
            font-weight: 700;
            letter-spacing: 0.5px;
            transition: all 0.2s;
            position: relative;
        }

        .hud-tab-btn:hover {
            color: var(--cyan);
            border-color: rgba(0, 240, 255, 0.4);
            background: rgba(0, 240, 255, 0.05);
        }

        .hud-tab-btn.active {
            color: #FFF;
            background: rgba(0, 240, 255, 0.14);
            border-color: var(--cyan);
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.3);
        }

        .hud-tab-btn.active::after {
            content: '';
            position: absolute;
            bottom: -9px;
            left: 20%;
            width: 60%;
            height: 2px;
            background: var(--cyan);
            box-shadow: 0 0 8px var(--cyan);
        }

        /* Tab Content Panes */
        .tab-pane {
            display: none;
            animation: fadeIn 0.3s ease;
        }

        .tab-pane.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .category-header-banner {
            background: linear-gradient(90deg, rgba(11, 19, 38, 0.95), rgba(7, 12, 24, 0.85));
            border: 1px solid var(--border-dim);
            border-left: 3px solid var(--cyan);
            border-radius: 6px;
            padding: 14px 20px;
            margin-bottom: 14px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }

        .category-header-banner h2 {
            font-family: var(--font-sans);
            font-size: 14.5px;
            color: var(--cyan);
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .category-header-banner p {
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 3px;
        }

        .category-header-banner-actions {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }

        /* Tables & Cards */
        .table-container {
            background: var(--bg-card);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            overflow: hidden;
            margin-bottom: 16px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 11.5px;
            text-align: left;
        }

        thead {
            background: #080D1A;
            border-bottom: 1px solid var(--border-dim);
        }

        th {
            padding: 11px 14px;
            color: var(--cyan);
            font-weight: 700;
            letter-spacing: 0.5px;
            font-size: 10px;
            text-transform: uppercase;
        }

        td {
            padding: 10px 14px;
            border-bottom: 1px solid rgba(24, 35, 56, 0.6);
            color: var(--text-main);
            vertical-align: middle;
        }

        tbody tr:hover {
            background: rgba(0, 240, 255, 0.03);
        }

        .badge-sev {
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 9.5px;
            font-weight: 800;
            letter-spacing: 0.5px;
            display: inline-block;
        }

        .badge-crit { background: rgba(255, 51, 102, 0.15); color: var(--red); border: 1px solid var(--red); }
        .badge-high { background: rgba(255, 184, 0, 0.15); color: var(--amber); border: 1px solid var(--amber); }
        .badge-med { background: rgba(0, 240, 255, 0.15); color: var(--cyan); border: 1px solid var(--cyan); }
        .badge-pass { background: rgba(0, 255, 136, 0.15); color: var(--green); border: 1px solid var(--green); }

        /* Tactical Console */
        .hud-console {
            background: #040812;
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 14px 18px;
            font-family: var(--font-mono);
            font-size: 11px;
            height: 380px;
            overflow-y: auto;
            color: #A0AEC0;
            line-height: 1.6;
            box-shadow: inset 0 0 15px rgba(0, 0, 0, 0.6);
        }

        .log-entry { margin-bottom: 3px; }
        .log-time { color: var(--text-muted); margin-right: 8px; }
        .log-pass { color: var(--green); }
        .log-threat { color: var(--red); font-weight: bold; }
        .log-warn { color: var(--amber); }
        .log-info { color: var(--cyan); }

        /* OSINT Suite & Tool Grid */
        .osint-tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }

        .osint-tool-card {
            background: var(--bg-card);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 14px;
            cursor: pointer;
            transition: all 0.2s;
            position: relative;
        }

        .osint-tool-card:hover, .osint-tool-card.active {
            border-color: var(--cyan);
            background: rgba(0, 240, 255, 0.05);
            box-shadow: 0 0 16px rgba(0, 240, 255, 0.2);
        }

        .osint-tool-card h4 {
            color: var(--cyan);
            font-size: 12px;
            margin-bottom: 5px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .osint-tool-card p {
            color: var(--text-muted);
            font-size: 10px;
            line-height: 1.4;
        }

        /* Matrix Split Pane */
        .matrix-split {
            display: grid;
            grid-template-columns: 360px 1fr;
            gap: 16px;
        }

        @media (max-width: 1024px) {
            .matrix-split { grid-template-columns: 1fr; }
        }

        .matrix-list-box {
            background: var(--bg-card);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 12px;
            height: 600px;
            overflow-y: auto;
        }

        .matrix-item {
            padding: 10px 12px;
            border-radius: 4px;
            border: 1px solid rgba(24, 35, 56, 0.6);
            margin-bottom: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .matrix-item:hover, .matrix-item.active {
            border-color: var(--cyan);
            background: rgba(0, 240, 255, 0.08);
        }

        .matrix-item h5 {
            color: var(--text-bright);
            font-size: 11px;
            margin-bottom: 3px;
        }

        .matrix-item p {
            color: var(--text-muted);
            font-size: 9.5px;
        }

        .matrix-detail-box {
            background: var(--bg-card);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 20px;
            height: 600px;
            overflow-y: auto;
        }

        pre {
            background: #040812;
            border: 1px solid var(--border-dim);
            border-radius: 4px;
            padding: 12px;
            color: var(--green);
            font-size: 11px;
            overflow-x: auto;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="holo-overlay"></div>
    <canvas id="hudCanvas"></canvas>

    <div class="hud-wrapper">
        <!-- Top Header -->
        <header class="hud-header">
            <div class="hud-branding">
                <h1>
                    <span class="holo-glyph">[⬡]</span> AEGIS // DEFENSIVE WAR ROOM
                    <span class="holo-badge">HOLO // SPEC 2.5</span>
                </h1>
                <p>AUTONOMOUS DEFENSIVE LOCALHOST AUDIT, REAL-TIME INTRUSION MONITORING &amp; 20-IN-1 CYBER OSINT ENGINE</p>
            </div>
            <div class="hud-badges">
                <span class="badge-live"><span class="status-dot"></span> LIVE TELEMETRY: ACTIVE</span>
                <span class="holo-tag" id="hudClock">UTC 00:00:00</span>
            </div>
        </header>

        <!-- Target Control Bar -->
        <div class="target-bar">
            <div class="target-bar-top">
                <span style="color: var(--cyan); font-size: 11px; font-weight: bold;"><span class="holo-glyph">[⌖]</span> DEFENSIVE TARGET:</span>
                <div class="target-input-group">
                    <input type="text" id="targetUrl" class="target-input" value="http://127.0.0.1:5000" placeholder="http://127.0.0.1:5000 or http://localhost:8000">
                </div>
                <div class="presets">
                    <button class="btn-preset active" onclick="setTarget('http://127.0.0.1:5000')">127.0.0.1:5000 (Aegis)</button>
                    <button class="btn-preset" onclick="setTarget('http://localhost:3000')">localhost:3000</button>
                    <button class="btn-preset" onclick="setTarget('http://localhost:8000')">localhost:8000</button>
                    <button class="btn-preset" onclick="setTarget('http://127.0.0.1:8080')">127.0.0.1:8080</button>
                </div>
            </div>
            <div class="target-bar-actions">
                <button class="btn-master" onclick="runMasterScan()"><span class="holo-glyph">[⬡]</span> RUN MASTER DEFENSE SCAN (ALL PANELS)</button>
                <button class="btn-primary" id="btnAudit" onclick="runAudit()"><span class="holo-glyph">[◈]</span> RUN DEFENSIVE AUDIT</button>
                <button class="btn-action" onclick="exportAuditReport()"><span class="holo-glyph">[⧉]</span> EXPORT AUDIT REPORT (HTML)</button>
            </div>
            <div class="host-interfaces-bar">
                <span style="color: var(--cyan); font-size: 11px; font-weight: bold;"><span class="holo-glyph">[⌖]</span> DETECTED HOST INTERFACES &amp; LOCAL IPs:</span>
                <div id="myIpsList" style="display: flex; gap: 6px; align-items: center; justify-content: center; flex-wrap: wrap;"></div>
                <button class="btn-action" style="padding: 5px 12px; font-size: 10px;" onclick="loadMyIps()"><span class="holo-glyph">[◈]</span> REFRESH IPs</button>
                <button class="btn-action" style="padding: 5px 12px; font-size: 10px; border-color: var(--amber); color: var(--amber);" onclick="sendTestProbe()"><span class="holo-glyph">[⚡]</span> TEST ATTACK PROBE ON MY IP</button>
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

        <!-- Tabs Navigation Bar (Minimal Holographic) -->
        <div class="hud-tabs">
            <button class="hud-tab-btn active" data-category="cat1" onclick="switchTab('tab-findings', this)">[⬡] OWASP AUDIT</button>
            <button class="hud-tab-btn" data-category="osint_user" onclick="switchTab('tab-username-osint', this)">[◈] USERNAME OSINT HUNT</button>
            <button class="hud-tab-btn" data-category="osint_suite" onclick="switchTab('tab-osint-suite', this)">[⌖] 20-IN-1 OSINT SUITE</button>
            <button class="hud-tab-btn" data-category="cryptotrace" onclick="switchTab('tab-cryptotrace', this)">[☵] CRYPTOTRACE AML</button>
            <button class="hud-tab-btn" data-category="spiderfoot" onclick="switchTab('tab-spiderfoot', this)">[⌘] SPIDERFOOT RECON</button>
            <button class="hud-tab-btn" data-category="cat2" onclick="switchTab('tab-osint', this)">[⧉] CYBER OSINT &amp; IP TABLES</button>
            <button class="hud-tab-btn" data-category="cat3" onclick="switchTab('tab-malware', this)">[⌥] MALWARE SCANNER</button>
            <button class="hud-tab-btn" data-category="cat4" onclick="switchTab('tab-injection', this)">[⚡] ANTI-XSS &amp; INJECTION</button>
            <button class="hud-tab-btn" data-category="cat5" onclick="switchTab('tab-ports', this)">[⚓] LOCALHOST &amp; PORTS</button>
            <button class="hud-tab-btn" data-category="cat5" onclick="switchTab('tab-server', this)">[⬢] SERVER ROOTKIT AUDITOR</button>
            <button class="hud-tab-btn" data-category="cat6" onclick="switchTab('tab-attackers', this)">[▲] ATTACKER IDS &amp; LOGS</button>
            <button class="hud-tab-btn" data-category="cat6" onclick="switchTab('tab-live-traffic', this)">[◎] LIVE TRAFFIC SNIFFER</button>
            <button class="hud-tab-btn" data-category="cat7" onclick="switchTab('tab-attack-matrix', this)">[⚔] ATTACK MATRIX</button>
            <button class="hud-tab-btn" data-category="cat7" onclick="switchTab('tab-playbooks', this)">[📋] SERVER PLAYBOOKS</button>
            <button class="hud-tab-btn" data-category="cat8" onclick="switchTab('tab-dossier', this)">[📜] CARRIER SUBPOENA DOSSIER</button>
            <button class="hud-tab-btn" data-category="all" onclick="switchTab('tab-console', this)">[🖥] TACTICAL LOGS</button>
        </div>

        <!-- ========================================== -->
        <!-- TAB 1: OWASP VULNERABILITY FINDINGS       -->
        <!-- ========================================== -->
        <div id="tab-findings" class="tab-pane active">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[⬡]</span> VULNERABILITY AUDITOR &amp; OWASP COMPLIANCE</h2>
                    <p>Scans target website/localhost for missing OWASP security headers (CSP, HSTS, X-Frame), .env/private credential leaks, and insecure cookies.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-primary" onclick="runAudit()"><span class="holo-glyph">[◈]</span> RUN DEFENSIVE AUDIT</button>
                    <button class="btn-action" onclick="exportAuditReport()"><span class="holo-glyph">[⧉]</span> EXPORT AUDIT REPORT</button>
                </div>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 100px;">SEVERITY</th>
                            <th style="width: 240px;">VULNERABILITY / CHECK</th>
                            <th>AUDIT DESCRIPTION &amp; RISK</th>
                            <th style="width: 320px;">RECOMMENDED DEFENSIVE FIX</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyFindings">
                        <tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 30px;">Ready. Enter target URL or select a preset, then click 'RUN DEFENSIVE AUDIT'.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 2: USERNAME OSINT SEARCH & CORRELATOR -->
        <!-- ========================================== -->
        <div id="tab-username-osint" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[◈]</span> USERNAME OSINT SEARCH &amp; PROFILE CORRELATOR // LIVE INVESTIGATION</h2>
                    <p>Scans 35+ major social networks, developer hubs, forums, and darknet paste aggregators in parallel to reveal where an attacker, scammer, or fraudster has a digital footprint.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-action" onclick="exportUsernameReport()"><span class="holo-glyph">[⧉]</span> EXPORT FORENSIC REPORT</button>
                </div>
            </div>

            <div class="target-bar" style="margin-bottom: 14px;">
                <div class="target-bar-top">
                    <span style="color: var(--cyan); font-size: 11px; font-weight: bold;"><span class="holo-glyph">[⌖]</span> TARGET ALIAS / USERNAME:</span>
                    <div class="target-input-group">
                        <input type="text" id="usernameInput" class="target-input" value="cyberghost" placeholder="Enter target username or handle (e.g. fraudster99, cyberghost, darkphantom)...">
                    </div>
                    <button class="btn-master" id="btnHuntUser" onclick="huntUsername()"><span class="holo-glyph">[◈]</span> HUNT USERNAME ACROSS ALL SERVICES</button>
                </div>
                <div class="presets" style="padding-top: 4px;">
                    <span style="font-size: 10px; color: var(--cyan); font-weight: bold;"><span class="holo-glyph">[⚡]</span> OSINT PIVOT SUITE:</span>
                    <button class="btn-preset" onclick="pivotEmailPermutations()"><span class="holo-glyph">[⬡]</span> EMAIL PERMUTATION ENGINE</button>
                    <button class="btn-preset" onclick="pivotGithubDeepSearch()"><span class="holo-glyph">[◈]</span> GITHUB DEEP PROFILER</button>
                    <button class="btn-preset" onclick="pivotWaybackLookup()"><span class="holo-glyph">[⌖]</span> WAYBACK ARCHIVE SEARCH</button>
                    <button class="btn-preset" onclick="pivotAhmiaDarknet()"><span class="holo-glyph">[⌥]</span> TOR DARKNET LEAKS</button>
                    <button class="btn-preset" onclick="pivotPgpKeyring()"><span class="holo-glyph">[⧉]</span> PGP KEYRING SEARCH</button>
                </div>
            </div>

            <!-- Username Metrics -->
            <div class="metrics-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 14px;">
                <div class="metric-card">
                    <div class="metric-title">PLATFORMS QUERIED</div>
                    <div class="metric-value" id="valUserTotal" style="color: var(--cyan);">0</div>
                    <div class="metric-sub">Parallel Multi-Threaded Checks</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">ACCOUNTS DISCOVERED</div>
                    <div class="metric-value" id="valUserFound" style="color: var(--green);">0</div>
                    <div class="metric-sub">Active Confirmed Profiles</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">FOOTPRINT RATING</div>
                    <div class="metric-value" id="valUserRating" style="color: var(--amber); font-size: 16px;">STANDBY</div>
                    <div class="metric-sub">Digital Exposure Level</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">CATEGORIES ACTIVE</div>
                    <div class="metric-value" id="valUserCats" style="color: var(--violet); font-size: 18px;">None</div>
                    <div class="metric-sub">Social / Dev / Gaming / Dumps</div>
                </div>
            </div>

            <!-- Discovered Profiles Table -->
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 140px;">PLATFORM</th>
                            <th style="width: 110px;">CATEGORY</th>
                            <th style="width: 120px;">STATUS</th>
                            <th style="width: 80px;">LATENCY</th>
                            <th>PROFILE URL &amp; PIVOT LINK</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyUsernameProfiles">
                        <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">Enter a handle above and click 'HUNT USERNAME' to initiate live multi-platform reconnaissance.</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Google Dorks & Leak Pivots for Username -->
            <div class="category-header-banner" style="margin-top: 16px;">
                <div>
                    <h2><span class="holo-glyph">[⬡]</span> AUTOMATED GOOGLE DORKS &amp; DEEP LEAK PIVOTS FOR THIS ALIAS</h2>
                    <p>Instant search queries indexing pastebin dumps, forum mentions, leaked database files, and underground chats.</p>
                </div>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 180px;">INTEL CATEGORY</th>
                            <th>CUSTOM GOOGLE DORK QUERY</th>
                            <th style="width: 140px;">ACTION</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyUsernameDorks">
                        <tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 20px;">Dorks will populate automatically upon running a username search.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 3: 20-IN-1 CYBER OSINT INVESTIGATION SUITE -->
        <!-- ========================================== -->
        <div id="tab-osint-suite" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[⌖]</span> 20-IN-1 CYBER OSINT INVESTIGATION SUITE</h2>
                    <p>Full suite of tactical intelligence tools: Investigation Graph, Phone, Email, Domain, Darknet, Hashes, Crypto, and Metadata.</p>
                </div>
            </div>

            <!-- Tool Selection Grid -->
            <div class="osint-tools-grid" id="osintToolsGrid">
                <div class="osint-tool-card active" onclick="selectOsintTool('graph')">
                    <h4><span class="holo-glyph">[⬡]</span> 1. Investigation Graph</h4>
                    <p>Correlates entities into an interactive visual node-link chart.</p>
                </div>
                <div class="osint-tool-card" onclick="selectOsintTool('phone')">
                    <h4><span class="holo-glyph">[◈]</span> 2. Phone Analyzer</h4>
                    <p>E.164 normalization, carrier lookup, and VoIP scammer risk.</p>
                </div>
                <div class="osint-tool-card" onclick="selectOsintTool('email')">
                    <h4><span class="holo-glyph">[⌖]</span> 3. Email Analyzer</h4>
                    <p>MX validation, disposable burner check, and breach lookups.</p>
                </div>
                <div class="osint-tool-card" onclick="selectOsintTool('dorks')">
                    <h4><span class="holo-glyph">[⌥]</span> 4. Dorks Generator</h4>
                    <p>Generates advanced Google Dorks for credentials and paste leaks.</p>
                </div>
                <div class="osint-tool-card" onclick="selectOsintTool('github')">
                    <h4><span class="holo-glyph">[⧉]</span> 5. GitHub OSINT</h4>
                    <p>Queries GitHub API: profile, public repos, and commit email leaks.</p>
                </div>
                <div class="osint-tool-card" onclick="selectOsintTool('crypto')">
                    <h4><span class="holo-glyph">[☵]</span> 6. Crypto Tracer</h4>
                    <p>Validates BTC, ETH, LTC, DOGE, SOL addresses with explorer links.</p>
                </div>
                <div class="osint-tool-card" onclick="selectOsintTool('hash')">
                    <h4><span class="holo-glyph">[⌘]</span> 7. Hash Analyzer</h4>
                    <p>Identifies MD5, SHA, bcrypt, NTLM algorithms &amp; crack lookups.</p>
                </div>
                <div class="osint-tool-card" onclick="selectOsintTool('crawler')">
                    <h4><span class="holo-glyph">[⬢]</span> 8. Web Crawler</h4>
                    <p>Extracts pages, emails, social profiles, and phone numbers.</p>
                </div>
                <div class="osint-tool-card" onclick="selectOsintTool('reputation')">
                    <h4><span class="holo-glyph">[▲]</span> 9. Reputation Checker</h4>
                    <p>Queries AbuseIPDB, VirusTotal, AlienVault OTX, GreyNoise.</p>
                </div>
                <div class="osint-tool-card" onclick="selectOsintTool('url')">
                    <h4><span class="holo-glyph">[◎]</span> 10. URL Scanner</h4>
                    <p>Heuristics for phishing, suspicious TLDs, and fake brands.</p>
                </div>
            </div>

            <!-- Active Tool Execution Box -->
            <div class="target-bar" style="margin-bottom: 14px;">
                <div class="target-bar-top">
                    <span id="activeToolLabel" style="color: var(--cyan); font-size: 11px; font-weight: bold;"><span class="holo-glyph">[⌖]</span> TARGET INPUT:</span>
                    <div class="target-input-group">
                        <input type="text" id="suiteTargetInput" class="target-input" value="cyberghost" placeholder="Enter target query...">
                    </div>
                    <button class="btn-master" onclick="executeSuiteTool()"><span class="holo-glyph">[⚡]</span> EXECUTE OSINT TOOL</button>
                </div>
            </div>

            <!-- Active Tool Output Display -->
            <div class="table-container" style="padding: 16px;">
                <h3 id="suiteToolTitle" style="color: var(--cyan); font-size: 13px; margin-bottom: 10px;">[⬡] Investigation Graph Output</h3>
                <div id="suiteToolOutput">
                    <pre style="height: 320px;">Select a tool from the grid above and click 'EXECUTE OSINT TOOL' to view structured intelligence output.</pre>
                </div>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB: CRYPTOTRACE ON-CHAIN AML & FLOW TRACER -->
        <!-- ========================================== -->
        <div id="tab-cryptotrace" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[☵]</span> CRYPTOTRACE // ON-CHAIN FLOW TRACER &amp; AML INVESTIGATOR</h2>
                    <p>Traces cryptocurrency flows across blockchains (Bitcoin, Ethereum, USDT ERC-20/TRC-20, Solana). Links scam wallets, pig-butchering syndicates, and ransomware to exchanges, mixers, and cash-out points for bank compliance and law enforcement subpoena action.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-primary" id="btnCryptoTrace" onclick="traceCryptoWallet()"><span class="holo-glyph">[☵]</span> TRACE ON-CHAIN FLOW</button>
                    <button class="btn-action" id="btnCryptoSubpoena" onclick="exportCryptoDossier()"><span class="holo-glyph">[📜]</span> DRAFT AML SUBPOENA</button>
                </div>
            </div>

            <!-- Target Wallet Input Bar -->
            <div class="target-bar" style="margin-bottom: 14px;">
                <div class="target-bar-top">
                    <span style="color: var(--cyan); font-size: 11px; font-weight: bold;"><span class="holo-glyph">[⌖]</span> SUSPECT WALLET ADDRESS:</span>
                    <div class="target-input-group">
                        <input type="text" id="cryptoAddressInput" class="target-input" value="0x098b716b8aaf21512996dc57eb0615e2383e2f96" placeholder="Enter BTC (1..., 3..., bc1...), ETH (0x...), USDT, or SOL wallet address...">
                    </div>
                    <button class="btn-master" onclick="traceCryptoWallet()"><span class="holo-glyph">[◈]</span> RUN FORENSIC ON-CHAIN TRACE</button>
                </div>
                <div class="presets" style="padding-top: 4px;">
                    <span style="font-size: 10px; color: var(--text-muted);">Investigative Presets:</span>
                    <button class="btn-preset" onclick="setCryptoAddressAndTrace('0x098b716b8aaf21512996dc57eb0615e2383e2f96')">Lazarus / Ronin Heist (ETH)</button>
                    <button class="btn-preset" onclick="setCryptoAddressAndTrace('1ScamVictimPool7777777777777777777')">Pig-Butchering Pool (BTC)</button>
                    <button class="btn-preset" onclick="setCryptoAddressAndTrace('13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94')">WannaCry Ransomware (BTC)</button>
                    <button class="btn-preset" onclick="setCryptoAddressAndTrace('0xd90e2f925da726b50c4ed8d0fb90ad053324f31b')">Tornado Cash Router (ETH)</button>
                    <button class="btn-preset" onclick="setCryptoAddressAndTrace('34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo')">Binance Cold Vault (BTC)</button>
                    <button class="btn-preset" onclick="setCryptoAddressAndTrace('0xd8da6bf26964af9d7eed9e03e53415d37aa96045')">vitalik.eth (Clean Benchmark)</button>
                </div>
            </div>

            <!-- Crypto Metrics Grid -->
            <div class="metrics-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 14px;">
                <div class="metric-card">
                    <div class="metric-title">AML RISK SCORE</div>
                    <div class="metric-value" id="valCryptoRisk" style="color: var(--cyan);">--</div>
                    <div class="metric-sub" id="valCryptoRiskLabel">Awaiting Trace</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">DETECTED BLOCKCHAIN</div>
                    <div class="metric-value" id="valCryptoChain" style="color: var(--neon-blue); font-size: 18px;">STANDBY</div>
                    <div class="metric-sub" id="valCryptoFormat">Format &amp; Standard</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">ON-CHAIN BALANCE / TXS</div>
                    <div class="metric-value" id="valCryptoBalance" style="color: var(--green); font-size: 18px;">0.00</div>
                    <div class="metric-sub" id="valCryptoTxCount">0 Transactions</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">ATTRIBUTION ENTITY</div>
                    <div class="metric-value" id="valCryptoEntity" style="color: var(--amber); font-size: 15px;">Unattributed</div>
                    <div class="metric-sub" id="valCryptoCategory">Scam / Mixer / Exchange</div>
                </div>
            </div>

            <!-- Attribution Banner & Off-Ramp Identification -->
            <div id="cryptoAttributionBox" class="table-container" style="padding: 16px; margin-bottom: 14px; display: none;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
                    <div>
                        <div style="font-size: 10px; color: var(--text-muted); font-weight: bold; letter-spacing: 1px;">ON-CHAIN ENTITY IDENTIFIED:</div>
                        <h3 id="cryptoEntityTitle" style="color: var(--cyan); font-size: 16px; margin-top: 3px;">--</h3>
                        <p id="cryptoEntityDesc" style="color: var(--text-main); font-size: 12px; margin-top: 4px;">--</p>
                    </div>
                    <div id="cryptoSanctionBadgeContainer"></div>
                </div>
                <div id="cryptoAlertNotice" style="margin-top: 10px; padding: 10px 14px; background: rgba(255, 51, 102, 0.12); border-left: 3px solid var(--red); color: var(--red); font-size: 11.5px; border-radius: 4px; display: none;"></div>
                <div id="cryptoExplorerLinks" style="margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap;"></div>
            </div>

            <!-- Transaction Flow Table -->
            <div class="table-container">
                <div style="padding: 12px 16px; background: #080D1A; border-bottom: 1px solid var(--border-dim); display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: var(--cyan); font-weight: bold; font-size: 11px;"><span class="holo-glyph">[⬡]</span> ON-CHAIN MONEY TRAIL &amp; OFF-RAMP ATTRIBUTION TIMELINE</span>
                    <span id="cryptoHopBadge" class="badge-sev badge-med">0 HOPS RECORDED</span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th style="width: 70px;">HOP</th>
                            <th style="width: 90px;">DIRECTION</th>
                            <th style="width: 170px;">TX HASH / IDENTIFIER</th>
                            <th>COUNTERPARTY ENTITY &amp; WALLET</th>
                            <th style="width: 140px;">AMOUNT / ASSET</th>
                            <th style="width: 130px;">AML FLAG / STATUS</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyCryptoFlow">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">Ready. Enter a cryptocurrency wallet address or pick a preset, then click 'TRACE ON-CHAIN FLOW'.</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Subpoena Dossier Viewer -->
            <div id="cryptoSubpoenaDossierBox" class="table-container" style="padding: 16px; display: none; margin-top: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h3 style="color: var(--cyan); font-size: 13px;"><span class="holo-glyph">[📜]</span> FORMAL AML SUBPOENA &amp; LAW ENFORCEMENT SEIZURE DOSSIER</h3>
                    <div>
                        <button class="btn-preset" onclick="copyCryptoDossier()"><span class="holo-glyph">[⧉]</span> COPY DOSSIER TEXT</button>
                        <button class="btn-action" onclick="downloadCryptoDossierFile()"><span class="holo-glyph">[⚡]</span> DOWNLOAD .TXT DOSSIER</button>
                    </div>
                </div>
                <pre id="cryptoSubpoenaText" style="height: 280px; overflow-y: auto; background: #050914; border: 1px solid var(--border-dim); padding: 12px; font-size: 11px; color: var(--text-main); line-height: 1.5;"></pre>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB: SPIDERFOOT AUTOMATED SCAM INFRA RECON -->
        <!-- ========================================== -->
        <div id="tab-spiderfoot" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[⌘]</span> SPIDERFOOT // AUTOMATED SCAM INFRASTRUCTURE RECONNAISSANCE ENGINE</h2>
                    <p>Automates comprehensive multi-module data collection across 200+ recon sources: DNS, Certificate Transparency subdomains, WHOIS, SSL/TLS, cloud storage buckets, dark web/paste leaks, email spoofing (SPF/DMARC), and threat reputation feeds.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-primary" id="btnSpiderFootRun" onclick="runSpiderFootRecon()"><span class="holo-glyph">[⌘]</span> LAUNCH SPIDERFOOT RECON</button>
                    <button class="btn-action" onclick="exportSpiderFootReport()"><span class="holo-glyph">[⧉]</span> EXPORT INFRA DOSSIER</button>
                </div>
            </div>

            <!-- Target Input Bar -->
            <div class="target-bar" style="margin-bottom: 14px;">
                <div class="target-bar-top">
                    <span style="color: var(--cyan); font-size: 11px; font-weight: bold;"><span class="holo-glyph">[⌖]</span> SCAM DOMAIN / IP / EMAIL:</span>
                    <div class="target-input-group">
                        <input type="text" id="spiderfootTargetInput" class="target-input" value="localhost" placeholder="Enter scam domain (scam-bank-login.com), IP (185.220.101.5), or email...">
                    </div>
                    <button class="btn-master" onclick="runSpiderFootRecon()"><span class="holo-glyph">[◈]</span> RUN MODULAR SWEEP</button>
                </div>
                <div class="presets" style="padding-top: 4px;">
                    <span style="font-size: 10px; color: var(--text-muted);">Quick Targets:</span>
                    <button class="btn-preset" onclick="setSpiderFootTargetAndRun('localhost')">localhost (Self-Audit)</button>
                    <button class="btn-preset" onclick="setSpiderFootTargetAndRun('1.1.1.1')">1.1.1.1 (Cloudflare Clean)</button>
                    <button class="btn-preset" onclick="setSpiderFootTargetAndRun('185.220.101.5')">185.220.101.5 (Known Tor Exit)</button>
                    <button class="btn-preset" onclick="setSpiderFootTargetAndRun('scam-crypto-wallet.org')">scam-crypto-wallet.org</button>
                    <button class="btn-preset" onclick="setSpiderFootTargetAndRun('fraudster@darkmail.onion')">fraudster@darkmail.onion</button>
                </div>
            </div>

            <!-- SpiderFoot Metrics Grid -->
            <div class="metrics-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 14px;">
                <div class="metric-card">
                    <div class="metric-title">TOTAL OSINT FINDINGS</div>
                    <div class="metric-value" id="valSfTotal" style="color: var(--cyan);">0</div>
                    <div class="metric-sub" id="valSfModules">0 Modules Swept</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">HIGH / CRITICAL THREATS</div>
                    <div class="metric-value" id="valSfCritHigh" style="color: var(--red);">0</div>
                    <div class="metric-sub">Malicious Signals Identified</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">INFRASTRUCTURE RISK</div>
                    <div class="metric-value" id="valSfRisk" style="color: var(--green); font-size: 18px;">STANDBY</div>
                    <div class="metric-sub" id="valSfScanDuration">Scan Latency: 0s</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">TARGET CLASSIFICATION</div>
                    <div class="metric-value" id="valSfTargetType" style="color: var(--violet); font-size: 16px;">DOMAIN / HOST</div>
                    <div class="metric-sub">Entity Type Detected</div>
                </div>
            </div>

            <!-- Filter Bar for Findings -->
            <div style="display: flex; gap: 8px; margin-bottom: 10px; align-items: center; flex-wrap: wrap;">
                <span style="font-size: 10px; color: var(--text-muted); font-weight: bold;">FILTER SEVERITY:</span>
                <button class="btn-preset active" onclick="filterSpiderFootFindings('ALL', this)">ALL (<span id="countSfAll">0</span>)</button>
                <button class="btn-preset" onclick="filterSpiderFootFindings('CRITICAL', this)">CRITICAL (<span id="countSfCrit">0</span>)</button>
                <button class="btn-preset" onclick="filterSpiderFootFindings('HIGH', this)">HIGH (<span id="countSfHigh">0</span>)</button>
                <button class="btn-preset" onclick="filterSpiderFootFindings('MEDIUM', this)">MEDIUM (<span id="countSfMed">0</span>)</button>
                <button class="btn-preset" onclick="filterSpiderFootFindings('LOW', this)">LOW (<span id="countSfLow">0</span>)</button>
                <button class="btn-preset" onclick="filterSpiderFootFindings('INFO', this)">INFO (<span id="countSfInfo">0</span>)</button>
            </div>

            <!-- SpiderFoot Discovered Findings Table -->
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 100px;">SEVERITY</th>
                            <th style="width: 140px;">MODULE</th>
                            <th style="width: 200px;">FINDING TYPE</th>
                            <th>EVIDENCE / INFRASTRUCTURE DETAIL</th>
                            <th style="width: 140px;">SOURCE</th>
                        </tr>
                    </thead>
                    <tbody id="tbodySpiderFoot">
                        <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">Enter scam target above and click 'LAUNCH SPIDERFOOT RECON' to execute automated infrastructure sweeps.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 4: CYBER OSINT, IP ROUTES & TABLES    -->
        <!-- ========================================== -->
        <div id="tab-osint" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[⧉]</span> CYBER OSINT, IP ROUTES, TABLES &amp; ATTACK SURFACE INTELLIGENCE</h2>
                    <p>Passive DNS enumeration, Certificate Transparency subdomains, SSL/TLS cryptanalysis, BGP routing/ASN, IP Tables, Routes, Details, and Origins.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-action" id="btnRunOsint" onclick="runOsintRecon()"><span class="holo-glyph">[◈]</span> RUN PASSIVE OSINT RECON</button>
                    <button class="btn-preset" onclick="copyDiscoveredSubdomains()"><span class="holo-glyph">[⧉]</span> COPY ALL SUBDOMAINS</button>
                </div>
            </div>

            <!-- OSINT Metric Cards -->
            <div class="metrics-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 16px;">
                <div class="metric-card">
                    <div class="metric-title">SUBDOMAINS FOUND</div>
                    <div class="metric-value" id="valOsintSubs" style="color: var(--cyan);">0</div>
                    <div class="metric-sub">Passive CRT.SH &amp; SAN Logs</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">EMAIL SPOOF RISK</div>
                    <div class="metric-value" id="valOsintDmarc" style="color: var(--green); font-size: 18px;">PASS</div>
                    <div class="metric-sub">DMARC &amp; SPF Enforcement</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">ROUTING / ASN</div>
                    <div class="metric-value" id="valOsintAsn" style="color: var(--amber); font-size: 15px;">Localhost</div>
                    <div class="metric-sub">BGP Autonomous System</div>
                </div>
                <div class="metric-card">
                    <div class="metric-title">EDGE PERIMETER</div>
                    <div class="metric-value" id="valOsintCdn" style="color: var(--violet); font-size: 16px;">Direct Origin</div>
                    <div class="metric-sub">WAF / Cloud Proxy Detection</div>
                </div>
            </div>

            <!-- Subdomains Table -->
            <div class="table-container">
                <div style="padding: 12px 16px; background: #080D1A; border-bottom: 1px solid var(--border-dim); display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: var(--cyan); font-weight: bold; font-size: 11px;"><span class="holo-glyph">[⬡]</span> DISCOVERED SUBDOMAINS VIA CERTIFICATE TRANSPARENCY (CRT.SH) &amp; SAN</span>
                    <span id="subdomainCountBadge" class="badge-sev badge-med">0 SUBDOMAINS</span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th style="width: 60px;">INDEX</th>
                            <th>SUBDOMAIN HOSTNAME</th>
                            <th style="width: 140px;">STATUS</th>
                        </tr>
                    </thead>
                    <tbody id="tbodySubdomains">
                        <tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 20px;">Click 'RUN PASSIVE OSINT RECON' to query Certificate Transparency logs.</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- DNS & SSL Split -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
                <div class="table-container">
                    <div style="padding: 10px 14px; background: #080D1A; border-bottom: 1px solid var(--border-dim); color: var(--cyan); font-weight: bold; font-size: 11px;">
                        <span class="holo-glyph">[◈]</span> DNS TELEMETRY RECORDS
                    </div>
                    <table>
                        <thead>
                            <tr><th style="width: 110px;">RECORD</th><th>VALUE</th><th style="width: 140px;">TYPE</th></tr>
                        </thead>
                        <tbody id="tbodyOsintDns">
                            <tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 15px;">No records loaded.</td></tr>
                        </tbody>
                    </table>
                </div>

                <div class="table-container">
                    <div style="padding: 10px 14px; background: #080D1A; border-bottom: 1px solid var(--border-dim); color: var(--cyan); font-weight: bold; font-size: 11px;">
                        <span class="holo-glyph">[⬡]</span> SSL/TLS CERTIFICATE CRYPTANALYSIS
                    </div>
                    <table>
                        <thead>
                            <tr><th style="width: 130px;">PROPERTY</th><th>VALUE</th></tr>
                        </thead>
                        <tbody id="tbodyOsintSsl">
                            <tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 15px;">No SSL certificate loaded.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- IP Infrastructure: Details, Origins, Routes & Tables -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
                <div class="table-container">
                    <div style="padding: 10px 14px; background: #080D1A; border-bottom: 1px solid var(--border-dim); color: var(--cyan); font-weight: bold; font-size: 11px;">
                        <span class="holo-glyph">[⌖]</span> IP DETAILS &amp; BOGON VALIDATION
                    </div>
                    <table>
                        <thead>
                            <tr><th style="width: 140px;">FIELD</th><th>VALUE</th></tr>
                        </thead>
                        <tbody id="tbodyIpDetails">
                            <tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 15px;">No IP details loaded.</td></tr>
                        </tbody>
                    </table>
                </div>

                <div class="table-container">
                    <div style="padding: 10px 14px; background: #080D1A; border-bottom: 1px solid var(--border-dim); color: var(--cyan); font-weight: bold; font-size: 11px;">
                        <span class="holo-glyph">[◈]</span> IP ORIGINS, ISP &amp; GEOLOCATION
                    </div>
                    <table>
                        <thead>
                            <tr><th style="width: 140px;">PROPERTY</th><th>VALUE</th></tr>
                        </thead>
                        <tbody id="tbodyIpOrigins">
                            <tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 15px;">No origin data loaded.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
                <div class="table-container">
                    <div style="padding: 10px 14px; background: #080D1A; border-bottom: 1px solid var(--border-dim); color: var(--cyan); font-weight: bold; font-size: 11px;">
                        <span class="holo-glyph">[⬡]</span> IP ROUTES &amp; BGP ASN
                    </div>
                    <table>
                        <thead>
                            <tr><th style="width: 140px;">PARAMETER</th><th>VALUE</th></tr>
                        </thead>
                        <tbody id="tbodyIpRoutes">
                            <tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 15px;">No routing data loaded.</td></tr>
                        </tbody>
                    </table>
                </div>

                <div class="table-container">
                    <div style="padding: 10px 14px; background: #080D1A; border-bottom: 1px solid var(--border-dim); color: var(--cyan); font-weight: bold; font-size: 11px;">
                        <span class="holo-glyph">[⚡]</span> DEFENSIVE FIREWALL DROP RULES (IPTABLES / NFTABLES / POWERSHELL)
                    </div>
                    <table>
                        <thead>
                            <tr><th style="width: 150px;">PLATFORM</th><th>SYNTHESIZED FIREWALL DROP DIRECTIVE</th></tr>
                        </thead>
                        <tbody id="tbodyIpTables">
                            <tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 15px;">Run OSINT recon to synthesize firewall rules.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 5: MALWARE & WEB SHELL SCANNER         -->
        <!-- ========================================== -->
        <div id="tab-malware" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[⌥]</span> MALWARE, WEB SHELL &amp; INFECTED PATH SCANNER</h2>
                    <p>Deep file inspector detecting obfuscated web shells, backdoors, PHP eval(base64_decode()) droppers, and cryptominers.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-primary" id="btnScanMalware" onclick="runMalwareScan()"><span class="holo-glyph">[◈]</span> SCAN PATHS FOR MALWARE</button>
                </div>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 100px;">SEVERITY</th>
                            <th>INFECTED FILE PATH</th>
                            <th style="width: 160px;">THREAT SIGNATURE</th>
                            <th style="width: 60px;">LINE</th>
                            <th>CODE SNIPPET / DISGUISED EXTENSION</th>
                            <th style="width: 160px;">ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyMalware">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">Click 'SCAN PATHS FOR MALWARE' to inspect directory tree.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 6: ANTI-XSS & DATA INJECTION           -->
        <!-- ========================================== -->
        <div id="tab-injection" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[☵]</span> ANTI-XSS, DATA INJECTION &amp; MALICIOUS SCRIPT SHIELD</h2>
                    <p>Audits Content-Security-Policy (CSP) headers, input sanitization handlers, and delivers ModSecurity WAF rules.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-action" onclick="runInjectionAudit()"><span class="holo-glyph">[◈]</span> AUDIT INJECTION CONTROLS</button>
                </div>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 100px;">STATUS</th>
                            <th style="width: 220px;">DEFENSIVE CONTROL</th>
                            <th>CURRENT CONFIGURATION</th>
                            <th>SECURE SPECIFICATION</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyInjection">
                        <tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 30px;">Click 'AUDIT INJECTION CONTROLS' to evaluate WAF &amp; sanitization headers.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 7: LOCALHOST & PORTS                   -->
        <!-- ========================================== -->
        <div id="tab-ports" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[⌘]</span> LOCALHOST PORTS &amp; SOCKET AUDITOR</h2>
                    <p>Scans localhost for open network sockets, listening web/database services, and flags dangerous 0.0.0.0 wildcard exposures.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-action" onclick="scanPorts()"><span class="holo-glyph">[◈]</span> RE-SCAN OPEN PORTS</button>
                </div>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 90px;">PORT</th>
                            <th style="width: 140px;">SERVICE</th>
                            <th style="width: 140px;">BIND INTERFACE</th>
                            <th style="width: 120px;">EXPOSURE</th>
                            <th>DEFENSIVE ADVISORY &amp; RISK</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyPorts">
                        <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">Loading listening sockets...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 8: SERVER ROOTKIT AUDITOR              -->
        <!-- ========================================== -->
        <div id="tab-server" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[⬢]</span> HOST SERVER MACHINE ROOTKIT &amp; PROCESS AUDITOR</h2>
                    <p>Scans running operating system processes for cryptominers, reverse shells, backdoor ports, hosts file hijacking, and dropped payloads in Temp directories.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-primary" id="btnServerAudit" onclick="runServerAudit()"><span class="holo-glyph">[◈]</span> RUN HOST SERVER AUDIT</button>
                </div>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 100px;">SEVERITY</th>
                            <th style="width: 200px;">THREAT CATEGORY</th>
                            <th>DETAILS &amp; CORRELATED ARTIFACTS</th>
                            <th style="width: 160px;">DEFENSIVE ACTION</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyServer">
                        <tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 30px;">Click 'RUN HOST SERVER AUDIT' to inspect OS processes and rootkit artifacts.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 9: ATTACKER IDS & LOG TELEMETRY        -->
        <!-- ========================================== -->
        <div id="tab-attackers" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[▲]</span> LOG INTRUSION DETECTION &amp; ATTACKER TRACKING ENGINE</h2>
                    <p>Detects automated attack probes (SQLi, XSS, Path Traversal), fingerprints attacker toolkits (SQLmap, Nikto), mobile hardware, and resolves VPN/Tor proxies.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-action" onclick="analyzeLogs(false)"><span class="holo-glyph">[⬡]</span> INGEST LIVE SERVER LOGS &amp; IDS TELEMETRY</button>
                    <button class="btn-preset" onclick="analyzeLogs(true)"><span class="holo-glyph">[◈]</span> LOAD SAMPLE FORENSIC LOGS</button>
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 140px;">ATTACKER IP</th>
                            <th style="width: 170px;">GEOLOCATION / ISP</th>
                            <th style="width: 130px;">CONNECTION</th>
                            <th style="width: 160px;">DEVICE HARDWARE</th>
                            <th style="width: 60px;">HITS</th>
                            <th style="width: 100px;">SEVERITY</th>
                            <th>DETECTED ATTACK VECTORS &amp; SCRIPT PROBES</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyAttackers">
                        <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">Ready. Click 'INGEST LIVE SERVER LOGS' to parse access log telemetry and correlate attacker intelligence.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 10: LIVE TRAFFIC SNIFFER               -->
        <!-- ========================================== -->
        <div id="tab-live-traffic" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[◎]</span> LIVE TRAFFIC SNIFFER &amp; REAL-TIME CONNECTION MONITOR</h2>
                    <p>Real-time telemetry showing live network connections entering your localhost web server and active system sockets.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-action" id="btnAutoSniff" onclick="toggleAutoSniff()"><span class="status-dot radar" style="margin-right: 6px;"></span> AUTO-SNIFF REAL-TIME: OFF</button>
                    <button class="btn-action" onclick="pollActiveTraffic()"><span class="holo-glyph">[◈]</span> REFRESH LIVE CONNECTIONS</button>
                </div>
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

        <!-- ========================================== -->
        <!-- TAB 11: ATTACK MATRIX                      -->
        <!-- ========================================== -->
        <div id="tab-attack-matrix" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[⚔]</span> CYBER ATTACK MATRIX &amp; DEFENSE REMEDIATION DASHBOARD</h2>
                    <p>Comprehensive interactive defense runbook: displays all known attacks, exact symptoms, immediate emergency actions, and multi-framework code fixes.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-danger" onclick="triggerEmergencyLockdown()"><span class="holo-glyph">[⚡]</span> EMERGENCY FIREWALL SCRIPT</button>
                </div>
            </div>

            <div class="matrix-split">
                <div class="matrix-list-box" id="matrixListContainer"></div>

                <div class="matrix-detail-box" id="matrixDetailContainer">
                    <h3 id="matTitle" style="color: var(--cyan); font-size: 16px; margin-bottom: 4px;">Select an Attack Vector</h3>
                    <p id="matMeta" style="color: var(--amber); font-size: 11px; font-weight: bold; margin-bottom: 10px;">OWASP / CWE CLASSIFICATION</p>
                    <div id="matStatusBox" style="background: rgba(0, 255, 136, 0.1); color: var(--green); border: 1px solid var(--green); padding: 6px 10px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-bottom: 12px;"><span class="holo-glyph">[⬡]</span> STATUS: STANDBY // READY FOR MITIGATION DEPLOYMENT</div>

                    <h4 style="color: var(--cyan); font-size: 12px; margin-top: 10px; margin-bottom: 4px;"><span class="holo-glyph">[⌖]</span> WHAT IS THIS ATTACK &amp; ATTACKER OBJECTIVE:</h4>
                    <p id="matDesc" style="font-size: 11.5px; line-height: 1.6; color: var(--text-main); margin-bottom: 12px;"></p>

                    <h4 style="color: var(--amber); font-size: 12px; margin-top: 10px; margin-bottom: 4px;"><span class="holo-glyph">[◈]</span> SYMPTOMS (HOW TO TELL IF YOU ARE BEING ATTACKED):</h4>
                    <ul id="matSymptoms" style="font-size: 11.5px; line-height: 1.6; color: #CBD5E1; margin-left: 20px; margin-bottom: 12px;"></ul>

                    <h4 style="color: var(--red); font-size: 12px; margin-top: 10px; margin-bottom: 4px;"><span class="holo-glyph">[⚡]</span> IMMEDIATE EMERGENCY ACTIONS (WHAT TO DO RIGHT NOW):</h4>
                    <div id="matImmediate" style="background: rgba(255, 51, 102, 0.08); border-left: 3px solid var(--red); padding: 10px; font-size: 11.5px; line-height: 1.6; margin-bottom: 12px;"></div>

                    <h4 style="color: var(--green); font-size: 12px; margin-top: 10px; margin-bottom: 4px;"><span class="holo-glyph">[🛠]</span> PERMANENT ARCHITECTURAL RESOLUTION (HOW TO FIX IT):</h4>
                    <div id="matPermanent" style="background: rgba(0, 255, 136, 0.08); border-left: 3px solid var(--green); padding: 10px; font-size: 11.5px; line-height: 1.6; margin-bottom: 12px;"></div>

                    <h4 style="color: var(--cyan); font-size: 12px; margin-top: 14px; margin-bottom: 6px;"><span class="holo-glyph">[⌘]</span> READY-TO-DEPLOY CODE FIX:</h4>
                    <div class="category-header-banner-actions" style="justify-content: flex-start; margin-bottom: 8px;">
                        <button class="btn-preset stack-btn active" id="btnStack-nginx" onclick="switchMatrixStack('nginx', this)">Nginx</button>
                        <button class="btn-preset stack-btn" id="btnStack-apache" onclick="switchMatrixStack('apache', this)">Apache</button>
                        <button class="btn-preset stack-btn" id="btnStack-python" onclick="switchMatrixStack('python', this)">Python</button>
                        <button class="btn-preset stack-btn" id="btnStack-nodejs" onclick="switchMatrixStack('nodejs', this)">Node.js</button>
                        <button class="btn-preset stack-btn" id="btnStack-php" onclick="switchMatrixStack('php', this)">PHP</button>
                    </div>
                    <pre id="matCodeBox" style="height: 180px;"></pre>
                    <button class="btn-action" style="margin-top: 6px;" onclick="copyMatrixCode()"><span class="holo-glyph">[📋]</span> COPY CODE FIX TO CLIPBOARD</button>
                </div>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 12: SERVER PLAYBOOKS                   -->
        <!-- ========================================== -->
        <div id="tab-playbooks" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[📋]</span> PRODUCTION SERVER SECURITY PLAYBOOKS</h2>
                    <p>Ready-to-deploy, battle-tested configuration hardening scripts for Nginx, Apache, Caddy, Node.js, and Python web services.</p>
                </div>
            </div>

            <div class="category-header-banner-actions" style="justify-content: flex-start; margin-bottom: 14px;">
                <button class="btn-preset playbook-btn active" id="pb-nginx" onclick="loadPlaybook('nginx', this)">Nginx Security Conf</button>
                <button class="btn-preset playbook-btn" id="pb-apache" onclick="loadPlaybook('apache', this)">Apache .htaccess Hardening</button>
                <button class="btn-preset playbook-btn" id="pb-fastapi" onclick="loadPlaybook('fastapi', this)">Python FastAPI Middleware</button>
                <button class="btn-preset playbook-btn" id="pb-express" onclick="loadPlaybook('express', this)">Node.js Express / Helmet</button>
                <button class="btn-preset playbook-btn" id="pb-docker" onclick="loadPlaybook('docker', this)">Hardened Dockerfile</button>
                <button class="btn-preset playbook-btn" id="pb-firewall" onclick="loadPlaybook('firewall', this)">Linux UFW / iptables Script</button>
            </div>

            <div class="table-container" style="padding: 20px;">
                <h3 id="playbookTitle" style="color: var(--cyan); font-size: 15px; margin-bottom: 6px;">Nginx Production Hardening Configuration</h3>
                <p id="playbookDesc" style="color: var(--text-muted); font-size: 11.5px; margin-bottom: 14px;">Full configuration template enforcing HSTS, CSP, and blocking common exploit paths.</p>
                <pre id="playbookCode" style="height: 380px; overflow-y: auto;"></pre>
                <button class="btn-action" style="margin-top: 10px;" onclick="copyPlaybookCode()"><span class="holo-glyph">[📋]</span> COPY PLAYBOOK TO CLIPBOARD</button>
            </div>
        </div>

        <!-- ========================================== -->
        <!-- TAB 13: CARRIER SUBPOENA DOSSIER           -->
        <!-- ========================================== -->
        <div id="tab-dossier" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[📜]</span> LAW ENFORCEMENT &amp; CARRIER SUBPOENA EVIDENCE DOSSIER</h2>
                    <p>Formal ISO/IEC 27037 forensic evidence dossier designed for submission to police cybercrime divisions and mobile network carrier subpoenas.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-action" onclick="exportFormalDossier()"><span class="holo-glyph">[💾]</span> EXPORT FORMAL DOSSIER (.TXT)</button>
                </div>
            </div>
            <pre id="formalDossierBox" style="height: 440px; overflow-y: auto;">Run an audit and load attack logs to synthesize the formal police &amp; carrier subpoena evidence report...</pre>
        </div>

        <!-- ========================================== -->
        <!-- TAB 14: TACTICAL LOGS                      -->
        <!-- ========================================== -->
        <div id="tab-console" class="tab-pane">
            <div class="category-header-banner">
                <div>
                    <h2><span class="holo-glyph">[🖥]</span> TACTICAL SYSTEM CONSOLE // REAL-TIME EVENT STREAM</h2>
                    <p>Live event bus tracking security audit steps, IDS interceptions, telemetry queries, and active defense directives.</p>
                </div>
                <div class="category-header-banner-actions">
                    <button class="btn-preset" onclick="clearConsole()"><span class="holo-glyph">[◈]</span> CLEAR CONSOLE</button>
                </div>
            </div>
            <div class="hud-console" id="hudConsoleBox">
                <div class="log-entry"><span class="log-time">[00:00:00 UTC]</span> <span class="log-info">[INIT] Aegis Defensive Cyber HUD 2.5 initialized.</span></div>
                <div class="log-entry"><span class="log-time">[00:00:00 UTC]</span> <span class="log-pass">[READY] Real-time intrusion detection and OSINT engine online.</span></div>
            </div>
        </div>

    </div>

    <!-- Master Scripts -->
    <script>
        let currentFindings = [];
        let currentOsint = null;
        let currentAttackers = [];
        let matrixData = {};
        let activeMatrixKey = 'sqli';
        let activeMatrixStack = 'nginx';
        let playbooksData = {};
        let autoSniffInterval = null;
        let activeSuiteTool = 'graph';
        let lastUsernameReport = null;

        // Clock
        function updateClock() {
            const now = new Date();
            document.getElementById('hudClock').innerText = 'UTC ' + now.toUTCString().split(' ')[4];
        }
        setInterval(updateClock, 1000);
        updateClock();

        // Canvas Cyber Radar Background
        const canvas = document.getElementById('hudCanvas');
        const ctx = canvas.getContext('2d');
        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }
        window.addEventListener('resize', resizeCanvas);
        resizeCanvas();

        let angle = 0;
        function drawCanvas() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.strokeStyle = 'rgba(0, 240, 255, 0.04)';
            ctx.lineWidth = 1;

            // Grid
            const step = 45;
            for (let x = 0; x < canvas.width; x += step) {
                ctx.beginPath();
                ctx.moveTo(x, 0);
                ctx.lineTo(x, canvas.height);
                ctx.stroke();
            }
            for (let y = 0; y < canvas.height; y += step) {
                ctx.beginPath();
                ctx.moveTo(0, y);
                ctx.lineTo(canvas.width, y);
                ctx.stroke();
            }

            // Radar sweep in top right
            const cx = canvas.width - 120;
            const cy = 120;
            const r = 80;

            ctx.strokeStyle = 'rgba(0, 240, 255, 0.15)';
            ctx.beginPath();
            ctx.arc(cx, cy, r, 0, Math.PI * 2);
            ctx.stroke();
            ctx.beginPath();
            ctx.arc(cx, cy, r / 2, 0, Math.PI * 2);
            ctx.stroke();

            const sx = cx + Math.cos(angle) * r;
            const sy = cy + Math.sin(angle) * r;
            ctx.strokeStyle = 'rgba(0, 255, 136, 0.35)';
            ctx.beginPath();
            ctx.moveTo(cx, cy);
            ctx.lineTo(sx, sy);
            ctx.stroke();

            angle += 0.02;
            requestAnimationFrame(drawCanvas);
        }
        requestAnimationFrame(drawCanvas);

        // Console Logging
        function logToConsole(msg, type = 'INFO') {
            const box = document.getElementById('hudConsoleBox');
            const d = new Date();
            const timeStr = d.toTimeString().split(' ')[0] + ' UTC';
            const div = document.createElement('div');
            div.className = 'log-entry';
            let cls = 'log-info';
            if (type === 'PASS') cls = 'log-pass';
            if (type === 'WARN') cls = 'log-warn';
            if (type === 'THREAT') cls = 'log-threat';
            div.innerHTML = `<span class="log-time">[${timeStr}]</span> <span class="${cls}">[${type}] ${escapeHtml(msg)}</span>`;
            box.appendChild(div);
            box.scrollTop = box.scrollHeight;
        }

        function clearConsole() {
            document.getElementById('hudConsoleBox').innerHTML = '';
        }

        function setTarget(url) {
            document.getElementById('targetUrl').value = url;
            document.querySelectorAll('.presets .btn-preset').forEach(b => b.classList.remove('active'));
            if (event && event.target) event.target.classList.add('active');
            logToConsole(`Defensive target updated: ${url}`, 'INFO');
        }

        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.hud-tab-btn').forEach(b => b.classList.remove('active'));
            const el = document.getElementById(tabId);
            if (el) el.classList.add('active');
            if (btn) btn.classList.add('active');
        }

        // ==========================================
        // HOST INTERFACES & LOCAL IPs (WORKING)
        // ==========================================
        async function loadMyIps() {
            try {
                const res = await fetch('/api/my-ips');
                const data = await res.json();
                const box = document.getElementById('myIpsList');
                box.innerHTML = '';

                // Handle both data.ips as array or data.ips.ips object
                const list = (data.ips && Array.isArray(data.ips)) ? data.ips : ((data.ips && data.ips.ips) ? data.ips.ips : []);

                if (list.length === 0) {
                    box.innerHTML = '<span style="font-size: 10px; color: var(--text-muted);">127.0.0.1 (Loopback)</span>';
                    return;
                }

                list.forEach(item => {
                    const ipStr = typeof item === 'string' ? item : item.ip;
                    const label = typeof item === 'string' ? item : (item.iface ? `${item.iface}: ${item.ip}` : item.ip);
                    const btn = document.createElement('button');
                    btn.className = 'btn-preset';
                    btn.innerHTML = `<span class="holo-glyph">[⬡]</span> ${escapeHtml(label)}`;
                    btn.title = `Click to set defensive target to http://${ipStr}:5000`;
                    btn.onclick = () => {
                        setTarget(`http://${ipStr}:5000`);
                        logToConsole(`Selected Host Interface: ${ipStr}`, 'PASS');
                    };
                    box.appendChild(btn);
                });
                logToConsole(`Host interfaces discovered: ${list.length} network adapters active.`, 'INFO');
            } catch (e) {
                logToConsole('Failed loading host interfaces: ' + e, 'WARN');
            }
        }

        async function sendTestProbe() {
            const url = document.getElementById('targetUrl').value.trim();
            logToConsole(`Transmitting safe defensive canary probe to: ${url}`, 'WARN');
            try {
                const res = await fetch('/api/test-probe', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: url })
                });
                const data = await res.json();
                logToConsole(`Canary Probe dispatched: Status ${data.status_code || 0} (${data.latency_ms}ms). IDS registered: ${data.ids_intercepted}`, 'PASS');
                alert(`Defensive Canary Probe Dispatched to ${url}\n\nStatus: ${data.status_code}\nPayload Tested: ${data.payload_tested}\n\nNotice: ${data.notice}\n\nNow open the 'ATTACKER IDS & LOGS' tab to view the live interception!`);
            } catch (err) {
                logToConsole('Defensive probe error: ' + err, 'THREAT');
            }
        }

        // ==========================================
        // TAB 1: RUN DEFENSIVE AUDIT (OWASP)
        // ==========================================
        async function runAudit() {
            const target = document.getElementById('targetUrl').value.trim();
            const btn = document.getElementById('btnAudit');
            btn.innerText = 'AUDITING...';
            btn.disabled = true;
            logToConsole(`Starting OWASP defense audit on: ${target}`, 'INFO');

            try {
                const res = await fetch('/api/audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                });
                const report = await res.json();
                currentFindings = report.findings || [];

                // Update gauges
                updateGauge(report.security_score || report.score || 100, report.score_grade || report.grade || 'A+');
                const summ = report.findings_summary || report.summary || {};
                document.getElementById('valCrit').innerText = summ.critical || 0;
                document.getElementById('valHigh').innerText = summ.high || 0;
                document.getElementById('valMed').innerText = summ.medium || 0;
                document.getElementById('valPass').innerText = summ.pass || 0;

                // Render table
                const tbody = document.getElementById('tbodyFindings');
                tbody.innerHTML = '';
                if (currentFindings.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--green); padding: 30px;">Hardened: Zero OWASP vulnerabilities identified!</td></tr>';
                } else {
                    currentFindings.forEach(f => {
                        const tr = document.createElement('tr');
                        let sevCls = 'badge-pass';
                        const sev = (f.severity || 'Pass').toUpperCase();
                        if (sev === 'CRITICAL') sevCls = 'badge-crit';
                        if (sev === 'HIGH') sevCls = 'badge-high';
                        if (sev === 'MEDIUM') sevCls = 'badge-med';

                        tr.innerHTML = `
                            <td><span class="badge-sev ${sevCls}">${f.severity}</span></td>
                            <td style="font-weight: bold; color: var(--text-bright);">${escapeHtml(f.title || f.check_name)}</td>
                            <td>${escapeHtml(f.description)}</td>
                            <td style="color: var(--cyan);">${escapeHtml(f.remediation || 'Maintain configuration.')}</td>
                        `;
                        tbody.appendChild(tr);
                    });
                }
                logToConsole(`Audit complete: Score ${report.security_score || 100} (${report.score_grade || 'A+'}).`, 'PASS');
            } catch (err) {
                logToConsole('Audit execution failed: ' + err, 'THREAT');
            } finally {
                btn.innerText = '[◈] RUN DEFENSIVE AUDIT';
                btn.disabled = false;
            }
        }

        function updateGauge(score, grade) {
            const circle = document.getElementById('scoreBar');
            const num = document.getElementById('scoreNum');
            const gr = document.getElementById('scoreGrade');
            num.innerText = score;
            gr.innerText = 'GRADE: ' + grade;

            const circumference = 314;
            const offset = circumference - (score / 100) * circumference;
            circle.style.strokeDashoffset = offset;

            if (score >= 90) circle.style.stroke = 'var(--green)';
            else if (score >= 75) circle.style.stroke = 'var(--cyan)';
            else if (score >= 60) circle.style.stroke = 'var(--amber)';
            else circle.style.stroke = 'var(--red)';
        }

        // ==========================================
        // TAB 2: USERNAME OSINT HUNT (NEW FEATURE)
        // ==========================================
        async function huntUsername() {
            const user = document.getElementById('usernameInput').value.trim();
            if (!user) return alert('Please enter a username or handle to investigate.');

            const btn = document.getElementById('btnHuntUser');
            btn.innerText = 'HUNTING ACROSS 35+ SERVICES...';
            btn.disabled = true;
            logToConsole(`Initiating multi-platform OSINT search for username: @${user}`, 'WARN');

            try {
                const res = await fetch('/api/osint/username', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: user })
                });
                const data = await res.json();
                lastUsernameReport = data;

                // Update Metrics
                document.getElementById('valUserTotal').innerText = data.total_searched || 35;
                document.getElementById('valUserFound').innerText = data.found_count || 0;
                document.getElementById('valUserRating').innerText = data.footprint_rating || 'Completed';
                document.getElementById('valUserCats').innerText = (data.categories_found || []).slice(0, 3).join(', ') || 'None';

                // Render Results Table - ONLY confirmed real profiles (No unverified or not-found clutter)
                const tbody = document.getElementById('tbodyUsernameProfiles');
                tbody.innerHTML = '';
                const confirmed = (data.results || []).filter(r => r.status === 'FOUND');

                if (confirmed.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--amber); padding: 30px;"><span class="holo-glyph">[⬡]</span> Zero active public profiles confirmed for '@${escapeHtml(user)}' across ${data.total_searched || 35} indexed services. No unverified or speculative entries displayed.</td></tr>`;
                } else {
                    confirmed.forEach(r => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td style="font-weight: bold; color: var(--text-bright);">${escapeHtml(r.name)}</td>
                            <td><span class="holo-tag">${escapeHtml(r.category)}</span></td>
                            <td><span class="badge-sev badge-pass"><span class="status-dot"></span> CONFIRMED ACTIVE</span></td>
                            <td style="color: var(--text-muted); font-size: 10px;">${r.response_ms}ms</td>
                            <td><a href="${r.url}" target="_blank" style="color: var(--cyan); text-decoration: none; font-weight: bold;"><span class="holo-glyph">[⧉]</span> ${escapeHtml(r.url)}</a></td>
                        `;
                        tbody.appendChild(tr);
                    });
                }

                // Render Dorks Table
                const tbodyDorks = document.getElementById('tbodyUsernameDorks');
                tbodyDorks.innerHTML = '';
                (data.google_dorks || []).forEach(d => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td style="font-weight: bold; color: var(--amber);">${escapeHtml(d.category)}</td>
                        <td style="font-family: monospace; color: var(--cyan);">${escapeHtml(d.query)}</td>
                        <td><a href="${d.search_url}" target="_blank" class="btn-preset" style="color: var(--green); text-decoration: none; display: inline-block;"><span class="holo-glyph">[⌖]</span> SEARCH GOOGLE</a></td>
                    `;
                    tbodyDorks.appendChild(tr);
                });

                logToConsole(`Username Hunt complete for @${user}: Discovered ${confirmed.length} confirmed profiles.`, 'PASS');
            } catch (err) {
                logToConsole('Username Hunt failed: ' + err, 'THREAT');
            } finally {
                btn.innerText = '[◈] HUNT USERNAME ACROSS ALL SERVICES';
                btn.disabled = false;
            }
        }

        function pivotEmailPermutations() {
            const user = document.getElementById('usernameInput').value.trim();
            if (!user) return alert('Enter a username first.');
            switchTab('tab-osint-suite', document.querySelector('[data-category="osint_suite"]'));
            selectOsintTool('email');
            document.getElementById('suiteTargetInput').value = `${user}@gmail.com`;
            executeSuiteTool();
            logToConsole(`Pivoting username @${user} into Email Permutations Analyzer.`, 'INFO');
        }

        function pivotGithubDeepSearch() {
            const user = document.getElementById('usernameInput').value.trim();
            if (!user) return alert('Enter a username first.');
            switchTab('tab-osint-suite', document.querySelector('[data-category="osint_suite"]'));
            selectOsintTool('github');
            document.getElementById('suiteTargetInput').value = user;
            executeSuiteTool();
            logToConsole(`Pivoting username @${user} into GitHub Deep Profiler.`, 'INFO');
        }

        function pivotWaybackLookup() {
            const user = document.getElementById('usernameInput').value.trim();
            if (!user) return alert('Enter a username first.');
            const url = `https://web.archive.org/web/*/${encodeURIComponent(user)}`;
            window.open(url, '_blank');
            logToConsole(`Wayback Archive lookup opened for: ${user}`, 'PASS');
        }

        function pivotAhmiaDarknet() {
            const user = document.getElementById('usernameInput').value.trim();
            if (!user) return alert('Enter a username first.');
            const url = `https://ahmia.fi/search/?q=${encodeURIComponent(user)}`;
            window.open(url, '_blank');
            logToConsole(`Ahmia Tor darknet leak search initiated for: ${user}`, 'PASS');
        }

        function pivotPgpKeyring() {
            const user = document.getElementById('usernameInput').value.trim();
            if (!user) return alert('Enter a username first.');
            const url = `http://keyserver.ubuntu.com/pks/lookup?search=${encodeURIComponent(user)}&op=vindex`;
            window.open(url, '_blank');
            logToConsole(`PGP Keyring query opened for: ${user}`, 'PASS');
        }

        function exportUsernameReport() {
            if (!lastUsernameReport) return alert('Run a username hunt first to generate a report.');
            const blob = new Blob([JSON.stringify(lastUsernameReport, null, 2)], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `Aegis_Username_OSINT_${lastUsernameReport.username}_${Date.now()}.json`;
            a.click();
            logToConsole('Exported OSINT username investigation dossier.', 'PASS');
        }

        // ==========================================
        // TAB 3: 20-IN-1 CYBER OSINT SUITE (NEW FEATURE)
        // ==========================================
        function selectOsintTool(toolKey) {
            activeSuiteTool = toolKey;
            document.querySelectorAll('.osint-tool-card').forEach(c => c.classList.remove('active'));
            if (event && event.currentTarget) event.currentTarget.classList.add('active');

            const placeholders = {
                'graph': 'Enter Target Handle, IP, or Domain (e.g. cyberghost, 1.1.1.1)...',
                'phone': 'Enter International Phone Number (e.g. +1-555-0199 or +639171234567)...',
                'email': 'Enter Target Email Address (e.g. suspect@proton.me)...',
                'dorks': 'Enter Target Name, Handle, or Domain for Dork synthesis...',
                'github': 'Enter Target GitHub Username (e.g. octocat, torvalds)...',
                'crypto': 'Enter Bitcoin, Ethereum, or Crypto Wallet Address...',
                'hash': 'Enter MD5, SHA-256, or bcrypt Hash String...',
                'crawler': 'Enter Target Website URL to crawl (e.g. http://localhost:5000)...',
                'reputation': 'Enter Target IP or Domain for multi-threat pivot...',
                'url': 'Enter Suspicious or Phishing URL to scan...'
            };
            document.getElementById('suiteTargetInput').placeholder = placeholders[toolKey] || 'Enter target...';
            document.getElementById('suiteToolTitle').innerHTML = `<span class="holo-glyph">[⬡]</span> Active Tool: ${toolKey.toUpperCase()}`;
        }

        async function executeSuiteTool() {
            const target = document.getElementById('suiteTargetInput').value.trim();
            if (!target) return alert('Please enter a target query.');
            logToConsole(`Executing OSINT tool [${activeSuiteTool}] against target: ${target}`, 'INFO');

            try {
                const res = await fetch('/api/osint/suite', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tool: activeSuiteTool, target })
                });
                const data = await res.json();
                renderSuiteToolOutput(activeSuiteTool, data);
                logToConsole(`Tool [${activeSuiteTool}] execution successful.`, 'PASS');
            } catch (err) {
                logToConsole(`Tool execution failed: ${err}`, 'THREAT');
            }
        }

        function renderSuiteToolOutput(tool, data) {
            const container = document.getElementById('suiteToolOutput');
            if (!data || data.error) {
                container.innerHTML = `<div style="padding: 24px; text-align: center; color: var(--red);"><span class="holo-glyph">[⚠️]</span> ${escapeHtml(data ? data.error : 'Execution failed or returned no response.')}</div>`;
                return;
            }

            if (tool === 'graph') {
                const nodes = data.nodes || [];
                const links = data.links || [];
                if (nodes.length <= 1) {
                    container.innerHTML = `<div style="padding: 24px; text-align: center; color: var(--amber);"><span class="holo-glyph">[⬡]</span> Zero correlated external entities confirmed for target '${escapeHtml(data.target || '')}'. Digital footprint minimal.</div>`;
                    return;
                }
                let html = `<div style="display: flex; gap: 10px; margin-bottom: 12px; flex-wrap: wrap;">`;
                nodes.forEach(n => {
                    html += `<div style="padding: 6px 12px; background: rgba(15,23,42,0.9); border: 1px solid ${n.color || 'var(--border-dim)'}; border-radius: 4px; font-size: 11px;">
                        <span style="color: ${n.color || 'var(--cyan)'}; font-weight: bold;">[${escapeHtml(n.type || 'NODE')}]</span> ${escapeHtml(n.label)}
                    </div>`;
                });
                html += `</div>`;
                html += `<table><thead><tr><th>SOURCE ENTITY</th><th>RELATIONSHIP</th><th>CORRELATED TARGET ENTITY</th></tr></thead><tbody>`;
                links.forEach(l => {
                    html += `<tr>
                        <td style="color: var(--cyan); font-weight: bold;">${escapeHtml(l.source)}</td>
                        <td><span class="holo-tag">${escapeHtml(l.relation)}</span></td>
                        <td style="color: var(--text-bright);">${escapeHtml(l.target)}</td>
                    </tr>`;
                });
                html += `</tbody></table>`;
                container.innerHTML = html;
            } else if (tool === 'phone') {
                if (!data.formatted_e164) {
                    container.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--amber);">No valid international phone metadata identified.</div>`;
                    return;
                }
                const isVoip = data.is_voip_risk;
                container.innerHTML = `
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 14px;">
                        <div class="metric-card"><div class="metric-title">E.164 NUMBER</div><div class="metric-value" style="color: var(--cyan); font-size: 16px;">${escapeHtml(data.formatted_e164)}</div><div class="metric-sub">${escapeHtml(data.country || '')}</div></div>
                        <div class="metric-card"><div class="metric-title">CARRIER / LINE</div><div class="metric-value" style="color: ${isVoip ? 'var(--red)' : 'var(--green)'}; font-size: 15px;">${isVoip ? 'VOIP / VIRTUAL' : 'CELLULAR / FIXED'}</div><div class="metric-sub">${escapeHtml(data.regulator || 'Standard')}</div></div>
                        <div class="metric-card"><div class="metric-title">FRAUD RISK</div><div class="metric-value" style="color: ${isVoip ? 'var(--red)' : 'var(--green)'}; font-size: 18px;">${data.fraud_risk_score || 0}/100</div><div class="metric-sub">${isVoip ? 'HIGH SUSPICION' : 'NORMAL'}</div></div>
                    </div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        <a href="${data.whatsapp_link}" target="_blank" class="btn-preset" style="color: var(--green); text-decoration: none;"><span class="holo-glyph">[⧉]</span> OPEN IN WHATSAPP</a>
                        <a href="${data.telegram_link}" target="_blank" class="btn-preset" style="color: var(--neon-blue); text-decoration: none;"><span class="holo-glyph">[⧉]</span> OPEN IN TELEGRAM</a>
                    </div>
                `;
            } else if (tool === 'email') {
                const mx = data.mx_records || [];
                const isBurner = data.is_disposable;
                container.innerHTML = `
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 14px;">
                        <div class="metric-card"><div class="metric-title">TARGET EMAIL</div><div class="metric-value" style="color: var(--cyan); font-size: 15px;">${escapeHtml(data.email)}</div><div class="metric-sub">${escapeHtml(data.domain)}</div></div>
                        <div class="metric-card"><div class="metric-title">PROVIDER INFRASTRUCTURE</div><div class="metric-value" style="color: var(--text-bright); font-size: 14px;">${escapeHtml(data.provider || 'Custom MX')}</div><div class="metric-sub">${mx.length} MX Records Found</div></div>
                        <div class="metric-card"><div class="metric-title">DISPOSABLE BURNER</div><div class="metric-value" style="color: ${isBurner ? 'var(--red)' : 'var(--green)'}; font-size: 16px;">${isBurner ? '⚠️ DISPOSABLE' : 'VERIFIED PERMANENT'}</div><div class="metric-sub">Fraud Risk: ${data.fraud_risk_score || 5}/100</div></div>
                    </div>
                    ${mx.length > 0 ? `<div style="font-size: 11px; color: var(--text-muted); margin-bottom: 6px; font-weight: bold;">CONFIRMED MX EXCHANGES:</div><div style="font-family: monospace; font-size: 11px; color: var(--cyan); margin-bottom: 12px;">${mx.map(m => escapeHtml(m)).join('<br>')}</div>` : ''}
                `;
            } else if (tool === 'dorks') {
                const dorks = Array.isArray(data) ? data : (data.dorks || []);
                if (dorks.length === 0) {
                    container.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted);">No dorks generated.</div>`;
                    return;
                }
                let html = `<table><thead><tr><th style="width: 180px;">INTEL CATEGORY</th><th>CUSTOM GOOGLE DORK</th><th style="width: 140px;">ACTION</th></tr></thead><tbody>`;
                dorks.forEach(d => {
                    html += `<tr>
                        <td style="font-weight: bold; color: var(--amber);">${escapeHtml(d.category || 'Leak')}</td>
                        <td style="font-family: monospace; color: var(--cyan); font-size: 11px;">${escapeHtml(d.query)}</td>
                        <td><a href="${d.search_url}" target="_blank" class="btn-preset" style="color: var(--green); text-decoration: none; display: inline-block;"><span class="holo-glyph">[⌖]</span> SEARCH GOOGLE</a></td>
                    </tr>`;
                });
                html += `</tbody></table>`;
                container.innerHTML = html;
            } else if (tool === 'github') {
                if (data.found === false) {
                    container.innerHTML = `<div style="padding: 24px; text-align: center; color: var(--amber);"><span class="holo-glyph">[⬡]</span> Zero public GitHub activity confirmed for '@${escapeHtml(data.username || '')}'. No unverified data displayed.</div>`;
                    return;
                }
                const emails = data.discovered_emails || [];
                container.innerHTML = `
                    <div style="display: flex; gap: 16px; align-items: flex-start; margin-bottom: 14px; background: rgba(8,13,26,0.6); padding: 14px; border: 1px solid var(--border-dim); border-radius: 6px;">
                        ${data.avatar_url ? `<img src="${data.avatar_url}" style="width: 64px; height: 64px; border-radius: 50%; border: 2px solid var(--cyan);" />` : ''}
                        <div style="flex: 1;">
                            <h3 style="color: var(--cyan); font-size: 16px;">${escapeHtml(data.name || data.username)} <span style="font-size: 12px; color: var(--text-muted);">(@${escapeHtml(data.username)})</span></h3>
                            <p style="color: var(--text-main); font-size: 12px; margin: 4px 0;">${escapeHtml(data.bio || 'No public bio.')}</p>
                            <div style="display: flex; gap: 12px; font-size: 11px; color: var(--text-muted); flex-wrap: wrap;">
                                <span>Company: <b style="color: var(--text-bright);">${escapeHtml(data.company || 'None')}</b></span>
                                <span>Location: <b style="color: var(--text-bright);">${escapeHtml(data.location || 'Unknown')}</b></span>
                                <span>Public Repos: <b style="color: var(--green);">${data.public_repos || 0}</b></span>
                                <span>Followers: <b style="color: var(--cyan);">${data.followers || 0}</b></span>
                            </div>
                        </div>
                        <a href="${data.profile_url}" target="_blank" class="btn-action" style="text-decoration: none;"><span class="holo-glyph">[⧉]</span> VIEW PROFILE</a>
                    </div>
                    ${emails.length > 0 ? `<div style="padding: 10px 14px; background: rgba(0, 255, 136, 0.08); border-left: 3px solid var(--green); margin-top: 10px; border-radius: 4px;">
                        <span style="color: var(--green); font-weight: bold; font-size: 11px;"><span class="holo-glyph">[⚡]</span> EXPOSED GIT COMMIT AUTHOR EMAILS:</span>
                        <div style="font-family: monospace; color: var(--cyan); font-size: 12px; margin-top: 4px;">${emails.map(e => escapeHtml(e)).join(' | ')}</div>
                    </div>` : '<div style="font-size: 11px; color: var(--text-muted);">No commit author emails publicly exposed in recent push events.</div>'}
                `;
            } else if (tool === 'crypto') {
                const chain = (data.network || data.currency || data.blockchain || 'Crypto').toUpperCase();
                const bal = data.balance || data.balance_str || '0.00';
                const txCount = data.transaction_count !== undefined ? data.transaction_count : 0;
                const risk = (data.aml_risk && data.aml_risk.score !== undefined) ? data.aml_risk.score : 0;
                const att = data.attribution || {};
                container.innerHTML = `
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 14px;">
                        <div class="metric-card"><div class="metric-title">BLOCKCHAIN</div><div class="metric-value" style="color: var(--cyan); font-size: 16px;">${escapeHtml(chain)}</div><div class="metric-sub">${escapeHtml(data.address || '')}</div></div>
                        <div class="metric-card"><div class="metric-title">CONFIRMED BALANCE</div><div class="metric-value" style="color: var(--green); font-size: 16px;">${escapeHtml(bal)}</div><div class="metric-sub">${txCount} Total Transactions</div></div>
                        <div class="metric-card"><div class="metric-title">AML RISK SCORE</div><div class="metric-value" style="color: ${risk >= 70 ? 'var(--red)' : (risk >= 40 ? 'var(--amber)' : 'var(--green)')}; font-size: 18px;">${risk}/100</div><div class="metric-sub">${escapeHtml((data.aml_risk && data.aml_risk.rating) || 'Evaluated')}</div></div>
                        <div class="metric-card"><div class="metric-title">IDENTIFIED ENTITY</div><div class="metric-value" style="color: var(--amber); font-size: 14px;">${escapeHtml(att.entity || att.identified_entity || 'Unattributed')}</div><div class="metric-sub">${escapeHtml(att.category || 'General')}</div></div>
                    </div>
                `;
            } else if (tool === 'hash') {
                const algos = data.possible_algorithms || [];
                const links = data.crack_lookup_links || {};
                container.innerHTML = `
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 14px;">
                        <div class="metric-card"><div class="metric-title">HASH STRING</div><div class="metric-value" style="color: var(--cyan); font-size: 13px; word-break: break-all;">${escapeHtml(data.hash)}</div><div class="metric-sub">Length: ${data.length || 0} characters</div></div>
                        <div class="metric-card"><div class="metric-title">CANDIDATE ALGORITHMS</div><div class="metric-value" style="color: var(--green); font-size: 15px;">${escapeHtml(algos.slice(0, 2).join(', '))}</div><div class="metric-sub">${algos.length} possible hash types</div></div>
                        <div class="metric-card"><div class="metric-title">ENCODING</div><div class="metric-value" style="color: var(--text-bright); font-size: 15px;">${data.is_hex ? 'Hexadecimal String' : 'Salted Crypt Format'}</div><div class="metric-sub">Standard Format</div></div>
                    </div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        ${Object.entries(links).map(([k, v]) => `<a href="${v}" target="_blank" class="btn-preset" style="color: var(--cyan); text-decoration: none;"><span class="holo-glyph">[⧉]</span> CRACK ON ${escapeHtml(k.toUpperCase())}</a>`).join('')}
                    </div>
                `;
            } else if (tool === 'crawler') {
                const emails = data.emails_extracted || [];
                const phones = data.phones_extracted || [];
                const socials = data.social_profiles || [];
                if (emails.length === 0 && phones.length === 0 && socials.length === 0) {
                    container.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--amber);"><span class="holo-glyph">[⬡]</span> Web crawl completed on '${escapeHtml(data.target || '')}'. Zero emails, phones, or social profiles exposed on landing page.</div>`;
                    return;
                }
                container.innerHTML = `
                    <div style="margin-bottom: 12px; font-size: 12px; color: var(--text-bright);">Target: <b style="color: var(--cyan);">${escapeHtml(data.target || '')}</b> | Page Title: <i>${escapeHtml(data.page_title || '')}</i></div>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;">
                        <div class="table-container" style="padding: 10px;"><b style="color: var(--green);">EXTRACTED EMAILS (${emails.length}):</b><div style="font-family: monospace; font-size: 11px; margin-top: 6px; color: var(--cyan);">${emails.map(e => escapeHtml(e)).join('<br>') || 'None'}</div></div>
                        <div class="table-container" style="padding: 10px;"><b style="color: var(--cyan);">PHONE NUMBERS (${phones.length}):</b><div style="font-family: monospace; font-size: 11px; margin-top: 6px; color: var(--text-bright);">${phones.map(p => escapeHtml(p)).join('<br>') || 'None'}</div></div>
                        <div class="table-container" style="padding: 10px;"><b style="color: var(--amber);">SOCIAL PROFILES (${socials.length}):</b><div style="font-size: 11px; margin-top: 6px;">${socials.map(s => `<a href="${s}" target="_blank" style="color: var(--neon-blue); text-decoration: none; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(s)}</a>`).join('') || 'None'}</div></div>
                    </div>
                `;
            } else if (tool === 'reputation') {
                const sources = data.reputation_sources || {};
                container.innerHTML = `
                    <div style="font-size: 12px; color: var(--text-bright); margin-bottom: 12px;">Target Entity: <b style="color: var(--cyan);">${escapeHtml(data.target || '')}</b></div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        ${Object.entries(sources).map(([k, v]) => `<a href="${v}" target="_blank" class="btn-preset" style="color: var(--amber); text-decoration: none;"><span class="holo-glyph">[⌖]</span> QUERY ${escapeHtml(k.toUpperCase())}</a>`).join('')}
                    </div>
                `;
            } else if (tool === 'url') {
                const flags = data.heuristic_flags || [];
                const risk = data.risk_score || 0;
                container.innerHTML = `
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 14px;">
                        <div class="metric-card"><div class="metric-title">TARGET URL</div><div class="metric-value" style="color: var(--cyan); font-size: 14px; word-break: break-all;">${escapeHtml(data.url)}</div><div class="metric-sub">Host: ${escapeHtml(data.hostname || '')}</div></div>
                        <div class="metric-card"><div class="metric-title">PHISHING RISK</div><div class="metric-value" style="color: ${risk >= 50 ? 'var(--red)' : (risk >= 25 ? 'var(--amber)' : 'var(--green)')}; font-size: 18px;">${risk}/100</div><div class="metric-sub">${escapeHtml(data.threat_rating || 'Clean')}</div></div>
                        <div class="metric-card"><div class="metric-title">FLAGS TRIGGERED</div><div class="metric-value" style="color: var(--text-bright); font-size: 18px;">${flags.length}</div><div class="metric-sub">Verified Heuristics</div></div>
                    </div>
                    ${flags.length > 0 ? `<div class="table-container" style="padding: 12px;"><b style="color: var(--red);">TRIGGERED SUSPICIOUS SIGNALS:</b><ul style="margin-left: 20px; font-size: 11.5px; color: var(--text-main); margin-top: 6px;">${flags.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul></div>` : '<div style="color: var(--green); font-size: 12px;"><span class="holo-glyph">[✔]</span> Zero phishing indicators or brand spoofing detected in URL hostname.</div>'}
                `;
            } else {
                container.innerHTML = `<pre style="height: 380px; overflow-y: auto;">${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
            }
        }

        // ==========================================
        // TAB: CRYPTOTRACE ON-CHAIN AML TRACER
        // ==========================================
        let currentCryptoTrace = null;

        function setCryptoAddressAndTrace(addr) {
            document.getElementById('cryptoAddressInput').value = addr;
            traceCryptoWallet();
        }

        async function traceCryptoWallet() {
            const addr = document.getElementById('cryptoAddressInput').value.trim();
            if (!addr) return alert('Please enter a cryptocurrency wallet address.');

            const btn = document.getElementById('btnCryptoTrace');
            if (btn) { btn.innerText = 'TRACING FLOWS ON-CHAIN...'; btn.disabled = true; }
            logToConsole(`Querying on-chain blockchain ledger and AML attribution for wallet: ${addr}`, 'WARN');

            try {
                const res = await fetch('/api/cryptotrace/trace', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ address: addr })
                });
                const data = await res.json();
                currentCryptoTrace = data;

                // Update metrics
                const amlRisk = data.aml_risk || {};
                const risk = (amlRisk.score !== undefined) ? amlRisk.score : (data.aml_risk_score !== undefined ? data.aml_risk_score : 50);
                const riskEl = document.getElementById('valCryptoRisk');
                riskEl.innerText = `${risk}/100`;
                if (risk >= 80) {
                    riskEl.style.color = 'var(--red)';
                    document.getElementById('valCryptoRiskLabel').innerText = amlRisk.rating || 'CRITICAL / OFAC SANCTION';
                    document.getElementById('valCryptoRiskLabel').style.color = 'var(--red)';
                } else if (risk >= 50) {
                    riskEl.style.color = 'var(--amber)';
                    document.getElementById('valCryptoRiskLabel').innerText = amlRisk.rating || 'HIGH SUSPICION / UNVERIFIED';
                    document.getElementById('valCryptoRiskLabel').style.color = 'var(--amber)';
                } else {
                    riskEl.style.color = 'var(--green)';
                    document.getElementById('valCryptoRiskLabel').innerText = amlRisk.rating || 'LOW / BENCHMARK CLEAN';
                    document.getElementById('valCryptoRiskLabel').style.color = 'var(--green)';
                }

                const chainStr = (data.network || data.currency || data.blockchain || 'UNKNOWN').toUpperCase();
                document.getElementById('valCryptoChain').innerText = chainStr;
                document.getElementById('valCryptoFormat').innerText = data.format || data.address_format || 'Standard Wallet';

                const balStr = data.balance || data.balance_str || `${data.balance_native || 0} ${data.currency || data.asset_symbol || ''}`;
                document.getElementById('valCryptoBalance').innerText = balStr;
                document.getElementById('valCryptoTxCount').innerText = `${data.transaction_count || 0} Transactions`;

                const att = data.attribution || {};
                const entityName = att.entity || att.name || att.identified_entity || 'Unattributed Counterparty';
                const entityCat = att.category || 'General Transfer';
                const entityTag = att.tag || att.description || '';

                document.getElementById('valCryptoEntity').innerText = entityName;
                document.getElementById('valCryptoCategory').innerText = entityCat;

                // Attribution Banner
                const attBox = document.getElementById('cryptoAttributionBox');
                attBox.style.display = 'block';
                document.getElementById('cryptoEntityTitle').innerText = `${entityName} (${data.address})`;
                document.getElementById('cryptoEntityDesc').innerText = entityTag || 'No direct mixer or law enforcement sanctions flag in primary database. Flow tracing active.';

                const sanctionCont = document.getElementById('cryptoSanctionBadgeContainer');
                sanctionCont.innerHTML = '';
                if (att.is_sanctioned || att.is_mixer || att.is_known_scam) {
                    const badge = document.createElement('span');
                    badge.className = 'badge-sev badge-crit';
                    badge.innerText = att.is_sanctioned ? '🚨 OFAC SDN SANCTIONED' : (att.is_mixer ? '⚠️ PRIVACY MIXER HOP' : '⚠️ CONFIRMED SCAM SYNDICATE');
                    sanctionCont.appendChild(badge);
                } else {
                    const badge = document.createElement('span');
                    badge.className = 'badge-sev badge-pass';
                    badge.innerText = 'VERIFIED LEDGER ENTRY';
                    sanctionCont.appendChild(badge);
                }

                const alertNotice = document.getElementById('cryptoAlertNotice');
                const flags = (amlRisk.flags && amlRisk.flags.length) ? amlRisk.flags.join('; ') : (data.aml_alert || att.aml_alert || '');
                if (flags) {
                    alertNotice.style.display = 'block';
                    alertNotice.innerText = `FinCEN / AML ALERT: ${flags}`;
                } else {
                    alertNotice.style.display = 'none';
                }

                // Explorer Links
                const expBox = document.getElementById('cryptoExplorerLinks');
                expBox.innerHTML = '';
                let expList = [];
                if (Array.isArray(data.explorers)) expList = data.explorers;
                else if (typeof data.explorers === 'object' && data.explorers !== null) {
                    expList = Object.entries(data.explorers).map(([k, v]) => ({ label: k, url: v }));
                } else if (Array.isArray(data.explorer_links)) {
                    expList = data.explorer_links;
                }
                expList.forEach(l => {
                    const a = document.createElement('a');
                    a.href = l.url;
                    a.target = '_blank';
                    a.className = 'btn-preset';
                    a.style.color = 'var(--cyan)';
                    a.style.textDecoration = 'none';
                    a.innerHTML = `<span class="holo-glyph">[⧉]</span> ${escapeHtml(l.label || 'Explorer')}`;
                    expBox.appendChild(a);
                });

                // Transaction Flow Table
                const tbody = document.getElementById('tbodyCryptoFlow');
                tbody.innerHTML = '';
                const flows = data.transaction_flow || [];
                const recentTxs = data.recent_transactions || [];
                const totalHops = flows.length + recentTxs.length;
                document.getElementById('cryptoHopBadge').innerText = `${totalHops} HOPS / TXS RECORDED`;

                if (totalHops === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 25px;">No confirmed transaction history recorded on this address.</td></tr>';
                } else {
                    // Render investigative forensic flow steps
                    flows.forEach((flow, idx) => {
                        const tr = document.createElement('tr');
                        const stage = flow.stage || `HOP ${flow.step || (idx + 1)}`;
                        const isOffRamp = stage.includes('OFF-RAMP') || stage.includes('CASH-OUT') || stage.includes('LIQUIDATION');
                        const isScam = stage.includes('SCAM') || stage.includes('INGESTION');
                        const dirBadge = isOffRamp
                            ? '<span class="badge-sev badge-crit">CASH-OUT</span>'
                            : (isScam ? '<span class="badge-sev badge-high">INFLOW</span>' : '<span class="badge-sev badge-med">LAYERING</span>');

                        tr.innerHTML = `
                            <td style="font-weight: bold; color: var(--cyan);">${flow.step || (idx + 1)}</td>
                            <td>${dirBadge}</td>
                            <td style="font-family: monospace; font-size: 10.5px; color: var(--amber);">${escapeHtml(flow.type || 'On-Chain Hop')}</td>
                            <td><span style="color: var(--text-bright); font-weight: bold;">${escapeHtml(flow.entity || '')}</span><br><span style="font-size: 10px; color: var(--text-muted);">${escapeHtml(flow.stage || '')}</span></td>
                            <td style="color: var(--green); font-weight: bold;">${escapeHtml(balStr)}</td>
                            <td><span class="badge-sev ${isOffRamp ? 'badge-crit' : 'badge-med'}">${escapeHtml(flow.aml_action || 'Monitored')}</span></td>
                        `;
                        tbody.appendChild(tr);
                    });

                    // Render confirmed on-chain recent ledger transactions if available
                    recentTxs.forEach((tx, idx) => {
                        const tr = document.createElement('tr');
                        const shortHash = tx.hash ? tx.hash.substring(0, 16) + '...' : `tx-${idx+1}`;
                        tr.innerHTML = `
                            <td style="font-weight: bold; color: var(--cyan);">TX ${idx + 1}</td>
                            <td><span class="badge-sev badge-pass">LEDGER TX</span></td>
                            <td style="font-family: monospace; font-size: 10.5px;"><a href="${expList[0] ? expList[0].url : '#'}" target="_blank" style="color: var(--cyan); text-decoration: none;">${escapeHtml(shortHash)}</a></td>
                            <td><span style="color: var(--text-muted); font-size: 11px;">Confirmed Block: ${escapeHtml(String(tx.block_height || 'On-chain'))} (${escapeHtml(tx.time || '')})</span></td>
                            <td style="color: var(--green); font-weight: bold;">${escapeHtml(tx.value || '0.00')}</td>
                            <td><span class="badge-sev badge-pass">CONFIRMED</span></td>
                        `;
                        tbody.appendChild(tr);
                    });
                }

                // If subpoena text is present in response, update preview
                const subpoenaTxt = data.law_enforcement_subpoena || data.subpoena_dossier || '';
                if (subpoenaTxt) {
                    document.getElementById('cryptoSubpoenaDossierBox').style.display = 'block';
                    document.getElementById('cryptoSubpoenaText').innerText = subpoenaTxt;
                }

                logToConsole(`CryptoTrace complete for ${addr}: Risk Score ${risk}/100, Network ${chainStr}, Entity: ${entityName}`, 'PASS');
            } catch (err) {
                logToConsole('CryptoTrace request failed: ' + err, 'THREAT');
            } finally {
                if (btn) { btn.innerText = '[☵] TRACE ON-CHAIN FLOW'; btn.disabled = false; }
            }
        }

        async function exportCryptoDossier() {
            if (!currentCryptoTrace) return alert('Run a CryptoTrace on a suspect wallet first.');
            try {
                const res = await fetch('/api/cryptotrace/subpoena', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ trace_result: currentCryptoTrace })
                });
                const data = await res.json();
                const txt = data.dossier_text || currentCryptoTrace.law_enforcement_subpoena || '';

                document.getElementById('cryptoSubpoenaDossierBox').style.display = 'block';
                document.getElementById('cryptoSubpoenaText').innerText = txt;

                // Download text file
                const blob = new Blob([txt], { type: 'text/plain' });
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = `Aegis_CryptoTrace_Subpoena_${currentCryptoTrace.address || 'wallet'}_${Date.now()}.txt`;
                a.click();
                logToConsole('Exported AML Law Enforcement Subpoena Dossier.', 'PASS');
            } catch (e) {
                logToConsole('Failed generating subpoena dossier: ' + e, 'THREAT');
            }
        }

        function copyCryptoDossier() {
            const txt = document.getElementById('cryptoSubpoenaText').innerText;
            if (!txt) return alert('No dossier generated yet.');
            navigator.clipboard.writeText(txt);
            logToConsole('Copied AML Subpoena Dossier to clipboard.', 'PASS');
            alert('AML Subpoena Dossier copied to clipboard!');
        }

        function downloadCryptoDossierFile() {
            const txt = document.getElementById('cryptoSubpoenaText').innerText;
            if (!txt) return alert('No dossier generated yet.');
            const blob = new Blob([txt], { type: 'text/plain' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `Aegis_CryptoTrace_AML_Subpoena_${Date.now()}.txt`;
            a.click();
        }

        // ==========================================
        // TAB: SPIDERFOOT SCAM INFRASTRUCTURE RECON
        // ==========================================
        let currentSpiderFootReport = null;
        let sfActiveFilter = 'ALL';

        function setSpiderFootTargetAndRun(t) {
            document.getElementById('spiderfootTargetInput').value = t;
            runSpiderFootRecon();
        }

        async function runSpiderFootRecon() {
            const target = document.getElementById('spiderfootTargetInput').value.trim();
            if (!target) return alert('Please enter a target domain, IP, or email to profile.');

            const btn = document.getElementById('btnSpiderFootRun');
            if (btn) { btn.innerText = 'EXECUTING 8 RECON MODULES...'; btn.disabled = true; }
            logToConsole(`Launching SpiderFoot automated infrastructure recon on: ${target}`, 'WARN');

            try {
                const res = await fetch('/api/spiderfoot/recon', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: target, profile: 'all' })
                });
                const data = await res.json();
                currentSpiderFootReport = data;

                // Update Metrics
                const totalFindings = data.total_findings || 0;
                document.getElementById('valSfTotal').innerText = totalFindings;

                const modCount = typeof data.modules_executed === 'number' ? data.modules_executed : ((data.modules_executed && data.modules_executed.length) || (data.modules_list && data.modules_list.length) || 8);
                document.getElementById('valSfModules').innerText = `${modCount} Modules Swept`;

                const s = data.severity_counts || data.severity_summary || {};
                const critHigh = (s.CRITICAL || 0) + (s.HIGH || 0);
                const critHighEl = document.getElementById('valSfCritHigh');
                critHighEl.innerText = critHigh;
                critHighEl.style.color = critHigh > 0 ? 'var(--red)' : 'var(--green)';

                const overallRisk = data.overall_infrastructure_risk || data.risk_rating || 'LOW';
                const riskEl = document.getElementById('valSfRisk');
                riskEl.innerText = overallRisk;
                if (overallRisk === 'CRITICAL') riskEl.style.color = 'var(--red)';
                else if (overallRisk === 'HIGH') riskEl.style.color = 'var(--amber)';
                else riskEl.style.color = 'var(--green)';

                const elapsed = data.elapsed_seconds || data.scan_duration_sec || 0;
                document.getElementById('valSfScanDuration').innerText = `Scan Latency: ${elapsed}s`;
                document.getElementById('valSfTargetType').innerText = data.target_type || 'DOMAIN / HOST';

                // Severity Counts for Filter buttons
                document.getElementById('countSfAll').innerText = totalFindings;
                document.getElementById('countSfCrit').innerText = s.CRITICAL || 0;
                document.getElementById('countSfHigh').innerText = s.HIGH || 0;
                document.getElementById('countSfMed').innerText = s.MEDIUM || 0;
                document.getElementById('countSfLow').innerText = s.LOW || 0;
                document.getElementById('countSfInfo').innerText = s.INFO || 0;

                renderSpiderFootTable();
                logToConsole(`SpiderFoot sweep complete for ${target}: ${totalFindings} findings discovered across ${modCount} modules.`, 'PASS');
            } catch (err) {
                logToConsole('SpiderFoot reconnaissance failed: ' + err, 'THREAT');
            } finally {
                if (btn) { btn.innerText = '[⌘] LAUNCH SPIDERFOOT RECON'; btn.disabled = false; }
            }
        }

        function filterSpiderFootFindings(sev, btn) {
            sfActiveFilter = sev;
            document.querySelectorAll('#tab-spiderfoot .presets .btn-preset').forEach(b => b.classList.remove('active'));
            if (btn) btn.classList.add('active');
            renderSpiderFootTable();
        }

        function renderSpiderFootTable() {
            if (!currentSpiderFootReport) return;
            const findings = currentSpiderFootReport.findings || [];
            const tbody = document.getElementById('tbodySpiderFoot');
            tbody.innerHTML = '';

            const filtered = sfActiveFilter === 'ALL' 
                ? findings 
                : findings.filter(f => (f.severity || 'INFO').toUpperCase() === sfActiveFilter);

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 25px;">No findings matching severity [${sfActiveFilter}].</td></tr>`;
                return;
            }

            filtered.forEach(f => {
                const tr = document.createElement('tr');
                const sev = (f.severity || 'INFO').toUpperCase();
                let badgeClass = 'badge-pass';
                if (sev === 'CRITICAL') badgeClass = 'badge-crit';
                else if (sev === 'HIGH') badgeClass = 'badge-high';
                else if (sev === 'MEDIUM') badgeClass = 'badge-med';

                tr.innerHTML = `
                    <td><span class="badge-sev ${badgeClass}">${sev}</span></td>
                    <td style="color: var(--cyan); font-family: monospace; font-size: 11px;">${escapeHtml(f.module || '')}</td>
                    <td style="font-weight: bold; color: var(--text-bright);">${escapeHtml(f.type || '')}</td>
                    <td style="color: var(--text-main); font-size: 11.5px; line-height: 1.4;">${escapeHtml(f.data || '')}</td>
                    <td style="color: var(--text-muted); font-size: 10.5px;">${escapeHtml(f.source || f.confidence || '')}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        function exportSpiderFootReport() {
            if (!currentSpiderFootReport) return alert('Execute SpiderFoot recon first to generate an infrastructure dossier.');
            const blob = new Blob([JSON.stringify(currentSpiderFootReport, null, 2)], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `Aegis_SpiderFoot_Recon_${currentSpiderFootReport.target || 'target'}_${Date.now()}.json`;
            a.click();
            logToConsole('Exported SpiderFoot Scam Infrastructure JSON dossier.', 'PASS');
        }

        // ==========================================
        // TAB 4: CYBER OSINT ENGINE (IP & DOMAIN)
        // ==========================================
        async function runOsintRecon() {
            const target = document.getElementById('targetUrl').value.trim();
            const btn = document.getElementById('btnRunOsint');
            btn.innerText = 'ENUMERATING...';
            btn.disabled = true;
            logToConsole(`Querying OSINT DNS, CRT.SH, and IP tables for: ${target}`, 'INFO');

            try {
                const res = await fetch('/api/osint', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                });
                const recon = await res.json();
                currentOsint = recon;

                // Subdomains
                const subs = recon.subdomains_discovered || [];
                document.getElementById('valOsintSubs').innerText = subs.length;
                document.getElementById('subdomainCountBadge').innerText = `${subs.length} SUBDOMAINS`;
                const tbodySubs = document.getElementById('tbodySubdomains');
                tbodySubs.innerHTML = '';
                if (subs.length === 0) {
                    tbodySubs.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 15px;">No public subdomains recorded in CRT.SH logs.</td></tr>';
                } else {
                    subs.forEach((sub, i) => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td>${i + 1}</td>
                            <td style="color: var(--cyan); font-weight: bold;">${escapeHtml(sub)}</td>
                            <td><span class="badge-sev badge-pass">CERT LOGGED</span></td>
                        `;
                        tbodySubs.appendChild(tr);
                    });
                }

                // DNS
                const dns = recon.dns || {};
                const tbodyDns = document.getElementById('tbodyOsintDns');
                tbodyDns.innerHTML = '';
                (dns.ipv4_addresses || []).forEach(ip => addTableRow(tbodyDns, ['A (IPv4)', ip, 'Host IPv4 Address']));
                (dns.ipv6_addresses || []).forEach(ip => addTableRow(tbodyDns, ['AAAA (IPv6)', ip, 'Next-Gen IP']));
                if (dns.reverse_dns && dns.reverse_dns !== 'None') addTableRow(tbodyDns, ['PTR (rDNS)', dns.reverse_dns, 'Reverse DNS Validation']);
                (dns.mx_records || []).forEach(mx => addTableRow(tbodyDns, ['MX', mx, 'Mail Exchange Authority']));

                // IP Details, Origins, Routes, Tables
                const details = recon.ip_details || {};
                const tbodyDetails = document.getElementById('tbodyIpDetails');
                tbodyDetails.innerHTML = '';
                addTableRow(tbodyDetails, ['Target IP Address', details.target_ip || '127.0.0.1']);
                addTableRow(tbodyDetails, ['Hostname', details.hostname || 'localhost']);
                addTableRow(tbodyDetails, ['Reverse DNS (PTR)', details.reverse_dns || 'None']);
                addTableRow(tbodyDetails, ['Classification', details.ip_type || 'Localhost / Loopback']);

                const origins = recon.ip_origins || {};
                const tbodyOrigins = document.getElementById('tbodyIpOrigins');
                tbodyOrigins.innerHTML = '';
                addTableRow(tbodyOrigins, ['Country', `${origins.country || 'Unknown'} (${origins.country_code || '--'})`]);
                addTableRow(tbodyOrigins, ['ISP', origins.isp || 'Internal Network']);
                addTableRow(tbodyOrigins, ['Connection Type', origins.is_vpn_or_hosting ? '⚠️ VPN / PROXY' : 'Direct Origin']);

                const routes = recon.ip_routes || {};
                const tbodyRoutes = document.getElementById('tbodyIpRoutes');
                tbodyRoutes.innerHTML = '';
                addTableRow(tbodyRoutes, ['Autonomous System (ASN)', `${routes.asn || 'N/A'} (${routes.as_name || 'N/A'})`]);
                addTableRow(tbodyRoutes, ['Default Gateway', routes.default_gateway || '127.0.0.1']);

                const tables = recon.ip_tables || {};
                const tbodyTables = document.getElementById('tbodyIpTables');
                tbodyTables.innerHTML = '';
                addTableRow(tbodyTables, ['Linux iptables', tables.iptables_drop || `iptables -I INPUT -s ${details.target_ip || '127.0.0.1'} -j DROP`]);
                addTableRow(tbodyTables, ['Windows PowerShell', tables.powershell_block || `New-NetFirewallRule -DisplayName 'Aegis-Drop' -RemoteAddress ${details.target_ip || '127.0.0.1'} -Action Block`]);

                logToConsole('Passive Cyber OSINT reconnaissance complete.', 'PASS');
            } catch (err) {
                logToConsole('OSINT recon error: ' + err, 'THREAT');
            } finally {
                btn.innerText = '[◈] RUN PASSIVE OSINT RECON';
                btn.disabled = false;
            }
        }

        function addTableRow(tbody, cols) {
            const tr = document.createElement('tr');
            cols.forEach(c => {
                const td = document.createElement('td');
                td.innerText = c;
                tr.appendChild(td);
            });
            tbody.appendChild(tr);
        }

        function copyDiscoveredSubdomains() {
            if (!currentOsint || !currentOsint.subdomains_discovered) return alert('Run OSINT recon first.');
            navigator.clipboard.writeText(currentOsint.subdomains_discovered.join('\\n'));
            logToConsole('Copied subdomains to clipboard.', 'PASS');
            alert('Copied all subdomains to clipboard!');
        }

        // ==========================================
        // TAB 9: ATTACKER IDS & LOGS (WORKING)
        // ==========================================
        async function analyzeLogs(useSample = false) {
            logToConsole(useSample ? 'Loading forensic sample attack logs...' : 'Ingesting live server access logs from memory buffer...', 'INFO');
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

                if (attackers.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--green); padding: 30px;">Zero malicious hits logged on the live server. Transmit a test probe or load sample logs to test IDS telemetry!</td></tr>';
                    return;
                }

                attackers.forEach(att => {
                    const tr = document.createElement('tr');
                    const tp = att.threat_profile || {};
                    const connType = tp.is_vpn_proxy ? '⚠️ VPN / PROXY' : 'Direct Origin';
                    const connColor = tp.is_vpn_proxy ? 'var(--amber)' : 'var(--green)';
                    const hw = att.device_hardware || {};
                    const hwStr = hw.device_model ? `${hw.platform} (${hw.device_model})` : (hw.platform || 'Desktop');
                    const sev = (att.highest_severity || 'Medium').toUpperCase();
                    const sevClass = sev === 'CRITICAL' ? 'badge-crit' : (sev === 'HIGH' ? 'badge-high' : 'badge-med');

                    tr.innerHTML = `
                        <td style="font-weight: bold; color: var(--cyan);">${att.ip}</td>
                        <td>${tp.city || 'Localhost'}, ${tp.country || 'LAN'} (${tp.isp || 'Localhost'})</td>
                        <td style="color: ${connColor}; font-weight: bold;">${connType}</td>
                        <td style="color: var(--cyan);">${hwStr}</td>
                        <td>${att.malicious_hits || att.total_requests || 1}</td>
                        <td><span class="badge-sev ${sevClass}">${att.highest_severity || 'High'}</span></td>
                        <td>${(att.attack_types || []).join(', ') || 'Script Probe'}</td>
                    `;
                    tbody.appendChild(tr);
                });

                logToConsole(`IDS analysis complete: Profiled ${attackers.length} offending attacker IPs.`, 'PASS');
                updateFormalDossier();
            } catch (err) {
                logToConsole('Log analysis failed: ' + err, 'THREAT');
            }
        }

        // ==========================================
        // TAB 10: LIVE TRAFFIC SNIFFER (WORKING & REAL-TIME)
        // ==========================================
        async function pollActiveTraffic() {
            logToConsole('Sniffing real-time network sockets hitting host web services...', 'INFO');
            try {
                const res = await fetch('/api/active-traffic');
                const traffic = await res.json();
                const tbody = document.getElementById('tbodyLiveTraffic');
                tbody.innerHTML = '';

                if (!traffic || traffic.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 25px;">No active sockets currently intercepted.</td></tr>';
                } else {
                    traffic.forEach(t => {
                        const tr = document.createElement('tr');
                        const isExt = t.classification === 'INBOUND WEB CLIENT';
                        tr.innerHTML = `
                            <td>${t.local_address}</td>
                            <td style="font-weight: bold; color: ${isExt ? 'var(--red)' : 'var(--cyan)'};">${t.remote_address}</td>
                            <td>${t.status}</td>
                            <td>${t.process_name}</td>
                            <td>${t.pid || 'N/A'}</td>
                            <td><span class="badge-sev ${isExt ? 'badge-crit' : 'badge-pass'}">${t.classification}</span></td>
                        `;
                        tbody.appendChild(tr);
                    });
                }
            } catch (e) {
                logToConsole('Error polling live connections: ' + e, 'WARN');
            }
        }

        function toggleAutoSniff() {
            const btn = document.getElementById('btnAutoSniff');
            if (autoSniffInterval) {
                clearInterval(autoSniffInterval);
                autoSniffInterval = null;
                btn.innerHTML = '<span class="status-dot radar" style="margin-right: 6px;"></span> AUTO-SNIFF REAL-TIME: OFF';
                logToConsole('Auto-sniff deactivated.', 'INFO');
            } else {
                pollActiveTraffic();
                autoSniffInterval = setInterval(pollActiveTraffic, 2000);
                btn.innerHTML = '<span class="status-dot" style="margin-right: 6px;"></span> AUTO-SNIFF REAL-TIME: ON (2s)';
                logToConsole('Auto-sniff activated: Live telemetry streaming every 2 seconds.', 'PASS');
            }
        }

        // ==========================================
        // OTHER CATEGORIES: MALWARE, PORTS, SERVER, MATRIX
        // ==========================================
        async function runMalwareScan() {
            const btn = document.getElementById('btnScanMalware');
            btn.innerText = 'SCANNING DIRECTORIES...';
            btn.disabled = true;
            logToConsole('Scanning filesystem paths for webshells and droppers...', 'INFO');

            try {
                const res = await fetch('/api/scan-malware', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ directory: '.' })
                });
                const result = await res.json();
                const tbody = document.getElementById('tbodyMalware');
                tbody.innerHTML = '';

                if (!result.infected_files || result.infected_files.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--green); padding: 25px;">Verified Clean: All ${result.total_scanned || 0} files inspected. Zero webshells detected.</td></tr>`;
                } else {
                    result.infected_files.forEach(inf => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td><span class="badge-sev badge-crit">${inf.severity}</span></td>
                            <td style="color: #FF3366; font-weight: bold; font-family: monospace;">🚨 ${inf.file_path}</td>
                            <td style="color: var(--amber);">${inf.threat_type}</td>
                            <td>${inf.matched_line || 1}</td>
                            <td style="font-family: monospace; color: var(--cyan);">${escapeHtml(inf.code_snippet || '')}</td>
                            <td>
                                <button class="btn-preset" style="color: var(--amber); border-color: var(--amber);" onclick="quarantineFile('${escapeJs(inf.file_path)}')">QUARANTINE</button>
                            </td>
                        `;
                        tbody.appendChild(tr);
                    });
                }
                logToConsole(`Malware scan finished: ${result.infected_files ? result.infected_files.length : 0} suspicious files flagged.`, 'PASS');
            } catch (e) {
                logToConsole('Malware scan failed: ' + e, 'THREAT');
            } finally {
                btn.innerText = '[◈] SCAN PATHS FOR MALWARE';
                btn.disabled = false;
            }
        }

        async function scanPorts() {
            try {
                const res = await fetch('/api/ports');
                const ports = await res.json();
                const tbody = document.getElementById('tbodyPorts');
                tbody.innerHTML = '';
                (ports || []).forEach(p => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td style="font-weight: bold; color: var(--cyan);">${p.port}</td>
                        <td>${p.service || 'Unknown'}</td>
                        <td style="color: ${p.is_wildcard ? 'var(--red)' : 'var(--green)'};">${p.bind_address || '127.0.0.1'}</td>
                        <td><span class="badge-sev ${p.is_wildcard ? 'badge-crit' : 'badge-pass'}">${p.is_wildcard ? 'WILDCARD (0.0.0.0)' : 'SECURE LOCAL'}</span></td>
                        <td>${escapeHtml(p.advisory || 'Normal socket.')}</td>
                    `;
                    tbody.appendChild(tr);
                });
            } catch (e) {}
        }

        async function runServerAudit() {
            logToConsole('Auditing operating system processes and rootkit signatures...', 'INFO');
            try {
                const res = await fetch('/api/server-audit');
                const data = await res.json();
                const tbody = document.getElementById('tbodyServer');
                tbody.innerHTML = '';

                const threats = data.threats_identified || [];
                if (threats.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--green); padding: 25px;">Verified Clean: Zero rogue cryptominers, reverse shells, or backdoor processes running.</td></tr>';
                } else {
                    threats.forEach(t => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td><span class="badge-sev badge-crit">${t.severity}</span></td>
                            <td style="color: var(--amber); font-weight: bold;">${t.title}</td>
                            <td>${escapeHtml(t.details)}</td>
                            <td><button class="btn-danger" style="padding: 4px 10px; font-size: 10px;" onclick="killProcess(${t.pid})">TERMINATE PID ${t.pid}</button></td>
                        `;
                        tbody.appendChild(tr);
                    });
                }
                logToConsole(`Host server audit completed: ${threats.length} issues identified.`, 'PASS');
            } catch (e) {
                logToConsole('Host server audit error: ' + e, 'THREAT');
            }
        }

        async function runInjectionAudit() {
            const target = document.getElementById('targetUrl').value.trim();
            logToConsole('Auditing anti-XSS and data injection controls...', 'INFO');
            try {
                const res = await fetch('/api/injection-audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                });
                const data = await res.json();
                const tbody = document.getElementById('tbodyInjection');
                tbody.innerHTML = '';
                (data.checks || []).forEach(c => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><span class="badge-sev ${c.passed ? 'badge-pass' : 'badge-high'}">${c.passed ? 'PASS' : 'WARNING'}</span></td>
                        <td style="font-weight: bold; color: var(--text-bright);">${c.name}</td>
                        <td style="font-family: monospace; color: var(--cyan);">${escapeHtml(c.current_value || 'None')}</td>
                        <td style="color: var(--green);">${escapeHtml(c.recommended)}</td>
                    `;
                    tbody.appendChild(tr);
                });
                logToConsole('Anti-XSS injection shield audit complete.', 'PASS');
            } catch (e) {
                logToConsole('Injection audit failed: ' + e, 'THREAT');
            }
        }

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
                div.onclick = () => selectMatrixItem(key);
                div.innerHTML = `
                    <h5><span class="holo-glyph">[⬡]</span> ${att.name}</h5>
                    <p>${att.owasp_cwe} | <b style="color: ${att.severity === 'CRITICAL' ? 'var(--red)' : 'var(--amber)'}">${att.severity}</b></p>
                `;
                container.appendChild(div);
            }
        }

        function selectMatrixItem(key) {
            activeMatrixKey = key;
            renderMatrixList();
            const att = matrixData[key];
            if (!att) return;
            document.getElementById('matTitle').innerHTML = `<span class="holo-glyph">[⬡]</span> ${att.name}`;
            document.getElementById('matMeta').innerText = `${att.owasp_cwe} // SEVERITY: ${att.severity}`;
            document.getElementById('matDesc').innerText = att.description;
            const ul = document.getElementById('matSymptoms');
            ul.innerHTML = '';
            (att.symptoms || []).forEach(s => {
                const li = document.createElement('li');
                li.innerText = s;
                ul.appendChild(li);
            });
            document.getElementById('matImmediate').innerText = att.immediate_actions || '';
            document.getElementById('matPermanent').innerText = att.permanent_fix || '';
            renderMatrixCode();
        }

        function switchMatrixStack(stack, btn) {
            activeMatrixStack = stack;
            document.querySelectorAll('.stack-btn').forEach(b => b.classList.remove('active'));
            if (btn) btn.classList.add('active');
            renderMatrixCode();
        }

        function renderMatrixCode() {
            const att = matrixData[activeMatrixKey];
            if (!att || !att.code_fixes) return;
            const code = att.code_fixes[activeMatrixStack] || '# No snippet available for this stack.';
            document.getElementById('matCodeBox').innerText = code;
        }

        function copyMatrixCode() {
            const code = document.getElementById('matCodeBox').innerText;
            navigator.clipboard.writeText(code);
            alert('Copied code fix to clipboard!');
        }

        async function triggerEmergencyLockdown() {
            if (!confirm('Deploy emergency firewall isolation rules?')) return;
            const ips = currentAttackers.map(a => a.ip);
            try {
                const res = await fetch('/api/emergency-lockdown', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips })
                });
                const data = await res.json();
                navigator.clipboard.writeText(data.windows_script || '');
                alert('Copied emergency firewall drop rules to clipboard!');
            } catch (e) {}
        }

        async function loadPlaybooksInit() {
            try {
                const res = await fetch('/api/playbooks');
                playbooksData = await res.json();
                loadPlaybook('nginx');
            } catch (e) {}
        }

        function loadPlaybook(key, btn) {
            document.querySelectorAll('.playbook-btn').forEach(b => b.classList.remove('active'));
            if (btn) btn.classList.add('active');
            const pb = playbooksData[key];
            if (!pb) return;
            document.getElementById('playbookTitle').innerHTML = `<span class="holo-glyph">[📋]</span> ${pb.title}`;
            document.getElementById('playbookDesc').innerText = pb.description;
            document.getElementById('playbookCode').innerText = pb.snippet;
        }

        function copyPlaybookCode() {
            const code = document.getElementById('playbookCode').innerText;
            navigator.clipboard.writeText(code);
            alert('Copied playbook code to clipboard!');
        }

        function updateFormalDossier() {
            const box = document.getElementById('formalDossierBox');
            if (currentAttackers.length === 0) {
                box.innerText = 'Run an audit and load attack logs to synthesize the formal police & carrier subpoena evidence report...';
                return;
            }
            let dossier = `================================================================================\\n`;
            dossier += `AEGIS FORMAL FORENSIC INCIDENT REPORT // CARRIER & LAW ENFORCEMENT SUBPOENA\\n`;
            dossier += `STANDARD: ISO/IEC 27037 FORENSIC EVIDENCE PRESERVATION\\n`;
            dossier += `TIMESTAMP: ${new Date().toUTCString()}\\n`;
            dossier += `================================================================================\\n\\n`;

            currentAttackers.forEach((att, idx) => {
                const tp = att.threat_profile || {};
                dossier += `[INCIDENT CASE #${idx + 1}]\\n`;
                dossier += `ATTACKER IP: ${att.ip}\\n`;
                dossier += `GEOLOCATION: ${tp.city || 'Unknown'}, ${tp.country || 'Unknown'}\\n`;
                dossier += `ISP / HOSTING: ${tp.isp || 'Unknown'} (ASN: ${tp.as_number || 'N/A'})\\n`;
                dossier += `CONNECTION TYPE: ${tp.is_vpn_proxy ? 'VPN / PROXY / DATACENTER' : 'DIRECT RESIDENTIAL ORIGIN'}\\n`;
                dossier += `IDENTIFIED TOOLS: ${(att.identified_tools || []).join(', ') || 'Custom Script'}\\n`;
                dossier += `MALICIOUS REQUESTS: ${att.malicious_hits || 1}\\n`;
                dossier += `PROBE PATHS: ${(att.sample_payloads || []).join(' | ')}\\n\\n`;
            });
            box.innerText = dossier;
        }

        function exportFormalDossier() {
            const content = document.getElementById('formalDossierBox').innerText;
            const blob = new Blob([content], { type: 'text/plain' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `Aegis_Law_Enforcement_Dossier_${Date.now()}.txt`;
            a.click();
            logToConsole('Exported formal forensic carrier subpoena dossier.', 'PASS');
        }

        function exportAuditReport() {
            const content = document.documentElement.outerHTML;
            const blob = new Blob([content], { type: 'text/html' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `Aegis_Security_Audit_${Date.now()}.html`;
            a.click();
            logToConsole('Exported complete security audit report (HTML).', 'PASS');
        }

        async function runMasterScan() {
            logToConsole('Initiating MASTER DEFENSE SCAN across all categories...', 'WARN');
            await runAudit();
            await runOsintRecon();
            await scanPorts();
            await analyzeLogs(false);
            await pollActiveTraffic();
            logToConsole('MASTER SCAN COMPLETE: All telemetry synchronized.', 'PASS');
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        function escapeJs(str) {
            if (!str) return '';
            return String(str).replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'");
        }

        window.addEventListener('DOMContentLoaded', () => {
            loadMyIps();
            scanPorts();
            loadPlaybooksInit();
            loadAttackMatrix();
            pollActiveTraffic();
        });
    </script>
</body>
</html>
"""


# ==============================================================================
# FLASK BACKEND API ROUTES
# ==============================================================================

@app.route("/")
def index():
    return render_template_string(HUD_HTML)


@app.route("/api/audit", methods=["POST"])
def api_audit():
    data = request.get_json() or {}
    target = data.get("target", "http://127.0.0.1:5000")
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
    target = data.get("target", "http://127.0.0.1:5000")
    res = WebAuditor.simulate_attack_probe(target)
    if res.get("log_line"):
        LIVE_ACCESS_LOGS.append(res["log_line"])
    return jsonify(res)


@app.route("/api/analyze-logs", methods=["POST"])
def api_analyze_logs():
    data = request.get_json() or {}
    use_sample = data.get("use_sample", False)
    content = data.get("log_content", "").strip()

    if use_sample:
        content = LogIntrusionDetector.generate_sample_attack_log()
    elif not content:
        if LIVE_ACCESS_LOGS:
            content = "\\n".join(LIVE_ACCESS_LOGS)
        else:
            found_log = None
            for p in ["access.log", "logs/access.log", "server.log"]:
                if os.path.exists(p):
                    try:
                        with open(p, "r", encoding="utf-8", errors="ignore") as f:
                            found_log = f.read()
                            break
                    except Exception:
                        pass
            if found_log:
                content = found_log
            else:
                now_str = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
                client_ip = request.remote_addr or "127.0.0.1"
                canary = f'{client_ip} - - [{now_str}] "GET /?aegis_probe=1&sqli=union_select_1-- HTTP/1.1" 403 512 "-" "Aegis-Canary-Probe/1.0"'
                LIVE_ACCESS_LOGS.append(canary)
                content = canary

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


@app.route("/api/osint/username", methods=["POST"])
def api_osint_username():
    data = request.get_json() or {}
    username = data.get("username", "")
    suite = AdvancedOsintSuite()
    res = suite.analyze_username(username)
    return jsonify(res)


@app.route("/api/osint/suite", methods=["POST"])
def api_osint_suite():
    data = request.get_json() or {}
    tool = data.get("tool", "graph")
    target = data.get("target", "localhost")
    suite = AdvancedOsintSuite()

    if tool == "phone":
        return jsonify(suite.analyze_phone(target))
    elif tool == "email":
        return jsonify(suite.analyze_email(target))
    elif tool == "github":
        return jsonify(suite.analyze_github(target))
    elif tool == "crypto":
        return jsonify(suite.trace_crypto(target))
    elif tool == "hash":
        return jsonify(suite.identify_hash(target))
    elif tool == "dorks":
        return jsonify(suite.generate_dorks(target))
    elif tool == "graph":
        return jsonify(suite.build_investigation_graph(target))
    elif tool == "crawler":
        return jsonify(suite.crawl_target(target))
    elif tool == "ip":
        return jsonify(suite.analyze_ip(target))
    elif tool == "reputation":
        return jsonify(suite.check_reputation(target))
    elif tool == "url":
        return jsonify(suite.scan_url(target))
    else:
        return jsonify({"error": f"Unknown tool: {tool}"})


@app.route("/api/cryptotrace/trace", methods=["POST"])
def api_cryptotrace_trace():
    data = request.get_json() or {}
    address = data.get("address", "").strip()
    tracer = CryptoTraceEngine()
    result = tracer.trace_wallet(address)
    return jsonify(result)


@app.route("/api/cryptotrace/subpoena", methods=["POST"])
def api_cryptotrace_subpoena():
    data = request.get_json() or {}
    trace_result = data.get("trace_result", {})
    tracer = CryptoTraceEngine()
    dossier = tracer.generate_subpoena_dossier(trace_result)
    return jsonify({"dossier_text": dossier})


@app.route("/api/spiderfoot/recon", methods=["POST"])
def api_spiderfoot_recon():
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    profile = data.get("profile", "all")
    recon = SpiderFootReconEngine()
    result = recon.run_recon(target, scan_profile=profile)
    return jsonify(result)


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
    report = data.get("report", {})
    txt = ActiveDefenseManager.export_incident_report(report)
    return jsonify({"dossier_text": txt})


@app.route("/api/export-report", methods=["POST"])
def api_export_report():
    data = request.get_json() or {}
    report = data.get("report", {})
    from aegis.reporter import SecurityReporter
    html = SecurityReporter.generate_html_report(report)
    return jsonify({"html_report": html})


@app.route("/api/scan-malware", methods=["POST"])
def api_scan_malware():
    data = request.get_json() or {}
    directory = data.get("directory", ".")
    scanner = MalwareScanner(directory)
    result = scanner.scan_directory()
    return jsonify(result)


@app.route("/api/quarantine-file", methods=["POST"])
def api_quarantine_file():
    data = request.get_json() or {}
    file_path = data.get("file_path", "")
    scanner = MalwareScanner(".")
    success = scanner.quarantine_file(file_path)
    return jsonify({"success": success})


@app.route("/api/remove-file", methods=["POST"])
def api_remove_file():
    data = request.get_json() or {}
    file_path = data.get("file_path", "")
    scanner = MalwareScanner(".")
    success = scanner.permanent_delete(file_path)
    return jsonify({"success": success})


@app.route("/api/injection-audit", methods=["POST"])
def api_injection_audit():
    data = request.get_json() or {}
    target = data.get("target", "http://127.0.0.1:5000")
    engine = InjectionDefenseEngine(target)
    result = engine.audit_injection_defense()
    return jsonify(result)


@app.route("/api/attack-matrix", methods=["GET"])
def api_attack_matrix():
    return jsonify(ATTACK_MATRIX)


@app.route("/api/server-audit", methods=["GET"])
def api_server_audit():
    auditor = ServerSystemAuditor()
    report = auditor.run_full_system_audit()
    return jsonify(report)


@app.route("/api/kill-process", methods=["POST"])
def api_kill_process():
    data = request.get_json() or {}
    pid = data.get("pid", 0)
    auditor = ServerSystemAuditor()
    res = auditor.kill_rogue_process(pid)
    return jsonify(res)


@app.route("/api/playbooks", methods=["GET"])
def api_playbooks():
    return jsonify(PLAYBOOKS)


def run_web(host: str = "127.0.0.1", port: int = 5000):
    """Launches the Flask Web HUD Server."""
    print(f"[*] Launching Aegis Holographic Web HUD on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run_web()

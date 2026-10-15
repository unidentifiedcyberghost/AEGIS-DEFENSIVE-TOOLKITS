"""
Aegis Localhost Web Dashboard
Serves an interactive Sci-Fi CIA-style Tactical HUD in the browser at http://127.0.0.1:5000.
"""

from flask import Flask, request, jsonify, render_template_string
from aegis.auditor import WebAuditor
from aegis.port_auditor import PortAuditor
from aegis.log_ids import LogIntrusionDetector
from aegis.threat_intel import ThreatIntelAnalyzer
from aegis.playbook import PLAYBOOKS

app = Flask(__name__)

HUD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS // DEFENSIVE SECURITY HUD [LOCALHOST]</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-void: #04070D;
            --bg-panel: #0A0F1D;
            --bg-card: #0F172A;
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

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            background-color: var(--bg-void);
            background-image: 
                radial-gradient(circle at 50% 0%, rgba(0, 240, 255, 0.08) 0%, transparent 60%),
                linear-gradient(rgba(24, 35, 56, 0.25) 1px, transparent 1px),
                linear-gradient(90deg, rgba(24, 35, 56, 0.25) 1px, transparent 1px);
            background-size: 100% 100%, 30px 30px, 30px 30px;
            color: var(--text-main);
            font-family: var(--font-mono);
            min-height: 100vh;
            padding: 20px;
            line-height: 1.5;
        }

        .hud-wrapper {
            max-width: 1400px;
            margin: 0 auto;
        }

        /* Top Bar */
        .hud-header {
            background: var(--bg-panel);
            border: 1px solid var(--border-dim);
            border-left: 4px solid var(--cyan);
            border-radius: 6px;
            padding: 18px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 0 30px rgba(0, 240, 255, 0.08);
            margin-bottom: 20px;
        }

        .hud-branding h1 {
            font-family: var(--font-sans);
            font-size: 20px;
            letter-spacing: 2px;
            color: var(--cyan);
            text-shadow: 0 0 10px rgba(0, 240, 255, 0.4);
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
            gap: 12px;
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
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 1px;
        }

        /* Target Control Bar */
        .target-bar {
            background: var(--bg-panel);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 16px 20px;
            margin-bottom: 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
        }

        .target-input-group {
            flex: 1;
            min-width: 280px;
            position: relative;
        }

        .target-input {
            width: 100%;
            background: #070B14;
            border: 1px solid var(--border-dim);
            color: var(--cyan);
            padding: 10px 14px;
            font-family: var(--font-mono);
            font-size: 13px;
            border-radius: 4px;
            outline: none;
            transition: all 0.2s ease;
        }

        .target-input:focus {
            border-color: var(--cyan);
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.25);
        }

        .presets {
            display: flex;
            gap: 8px;
        }

        .btn-preset {
            background: rgba(14, 22, 40, 0.8);
            border: 1px solid var(--border-dim);
            color: var(--text-muted);
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            font-family: var(--font-mono);
            transition: all 0.2s;
        }

        .btn-preset:hover {
            border-color: var(--cyan);
            color: var(--cyan);
        }

        .btn-primary {
            background: var(--cyan);
            color: #04070D;
            border: none;
            padding: 10px 20px;
            font-family: var(--font-mono);
            font-weight: 800;
            font-size: 12px;
            letter-spacing: 1px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 0 15px rgba(0, 240, 255, 0.3);
        }

        .btn-primary:hover {
            background: #46F5FF;
            box-shadow: 0 0 25px rgba(0, 240, 255, 0.6);
        }

        .btn-action {
            background: transparent;
            color: var(--cyan);
            border: 1px solid var(--cyan);
            padding: 9px 16px;
            font-family: var(--font-mono);
            font-size: 12px;
            font-weight: bold;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-action:hover {
            background: rgba(0, 240, 255, 0.15);
        }

        /* Metric Cards Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: 240px repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }

        @media (max-width: 1024px) {
            .metrics-grid { grid-template-columns: 1fr 1fr; }
        }

        .gauge-card {
            background: var(--bg-panel);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 16px;
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            position: relative;
        }

        .score-circle {
            position: relative;
            width: 120px;
            height: 120px;
        }

        .score-circle svg {
            width: 120px;
            height: 120px;
            transform: rotate(-90deg);
        }

        .score-circle circle {
            fill: none;
            stroke-width: 8;
        }

        .circle-bg { stroke: #121A2C; }
        .circle-bar {
            stroke: var(--green);
            stroke-linecap: round;
            stroke-dasharray: 314;
            stroke-dashoffset: 0;
            transition: stroke-dashoffset 1s ease, stroke 0.5s ease;
        }

        .score-number {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 26px;
            font-weight: 800;
            color: var(--text-bright);
        }

        .score-grade {
            margin-top: 10px;
            font-weight: bold;
            font-size: 13px;
            color: var(--green);
            letter-spacing: 1px;
        }

        .metric-card {
            background: var(--bg-panel);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 16px 20px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        .metric-title {
            color: var(--text-muted);
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 1px;
        }

        .metric-value {
            font-size: 32px;
            font-weight: 800;
            margin: 6px 0;
        }

        .metric-sub {
            color: var(--text-muted);
            font-size: 11px;
        }

        /* Navigation Tabs */
        .hud-tabs {
            display: flex;
            gap: 4px;
            border-bottom: 1px solid var(--border-dim);
            margin-bottom: 20px;
        }

        .hud-tab-btn {
            background: #070B14;
            border: 1px solid var(--border-dim);
            border-bottom: none;
            color: var(--text-muted);
            padding: 10px 20px;
            cursor: pointer;
            font-family: var(--font-mono);
            font-size: 12px;
            font-weight: bold;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            transition: all 0.2s;
        }

        .hud-tab-btn:hover {
            color: var(--text-bright);
            border-color: #334155;
        }

        .hud-tab-btn.active {
            background: var(--bg-panel);
            color: var(--cyan);
            border-color: var(--cyan);
            border-bottom: 2px solid var(--bg-panel);
            margin-bottom: -1px;
        }

        /* Tab Content Panes */
        .tab-pane {
            display: none;
            background: var(--bg-panel);
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 20px;
        }

        .tab-pane.active {
            display: block;
        }

        /* Tables */
        .table-container {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }

        th {
            background: #070B14;
            color: var(--cyan);
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border-dim);
            font-weight: bold;
            letter-spacing: 1px;
        }

        td {
            padding: 12px 14px;
            border-bottom: 1px solid #10172A;
            vertical-align: top;
        }

        tr:hover td {
            background: rgba(0, 240, 255, 0.02);
        }

        .badge-sev {
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 10px;
            letter-spacing: 1px;
            display: inline-block;
        }

        .badge-crit { background: rgba(255, 51, 102, 0.15); color: var(--red); border: 1px solid var(--red); }
        .badge-high { background: rgba(255, 184, 0, 0.15); color: var(--amber); border: 1px solid var(--amber); }
        .badge-med { background: rgba(0, 240, 255, 0.15); color: var(--cyan); border: 1px solid var(--cyan); }
        .badge-pass { background: rgba(0, 255, 136, 0.15); color: var(--green); border: 1px solid var(--green); }

        /* Attacker Dossier Splitter */
        .dossier-layout {
            display: grid;
            grid-template-columns: 1fr 420px;
            gap: 20px;
        }

        @media (max-width: 900px) {
            .dossier-layout { grid-template-columns: 1fr; }
        }

        .dossier-box {
            background: #070B14;
            border: 1px solid var(--border-dim);
            border-radius: 6px;
            padding: 16px;
            font-size: 12px;
            white-space: pre-wrap;
            max-height: 520px;
            overflow-y: auto;
            color: #94A3B8;
        }

        /* Console Output */
        .hud-console {
            background: #03060B;
            border: 1px solid var(--border-dim);
            border-radius: 4px;
            padding: 14px;
            font-family: var(--font-mono);
            font-size: 12px;
            height: 380px;
            overflow-y: auto;
            color: var(--green);
        }

        .log-entry { margin-bottom: 4px; }
        .log-time { color: var(--text-muted); }

        /* Code Blocks */
        pre {
            background: #070B14;
            border: 1px solid var(--border-dim);
            padding: 14px;
            border-radius: 4px;
            overflow-x: auto;
            color: var(--cyan);
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="hud-wrapper">
        <!-- Header -->
        <header class="hud-header">
            <div class="hud-branding">
                <h1>AEGIS // DEFENSIVE LOCALHOST HUD</h1>
                <p>AUTONOMOUS DEFENSIVE POSTURE AUDITOR & REAL-TIME ATTACKER TRACKER</p>
            </div>
            <div class="hud-badges">
                <span class="status-dot"></span>
                <span class="badge-live">LOCAL SERVER: ONLINE (5000)</span>
            </div>
        </header>

        <!-- Target Input Bar -->
        <div class="target-bar">
            <div class="target-input-group">
                <input type="text" id="targetUrl" class="target-input" value="http://127.0.0.1:8000" placeholder="Enter localhost URL (e.g. http://localhost:3000, http://127.0.0.1:8080)">
            </div>
            <div class="presets">
                <button class="btn-preset" onclick="setTarget('http://localhost:3000')">localhost:3000</button>
                <button class="btn-preset" onclick="setTarget('http://localhost:8000')">localhost:8000</button>
                <button class="btn-preset" onclick="setTarget('http://127.0.0.1:8080')">127.0.0.1:8080</button>
            </div>
            <button class="btn-primary" id="btnAudit" onclick="runAudit()">🛡️ RUN DEFENSIVE AUDIT</button>
            <button class="btn-action" onclick="scanPorts()">📡 SCAN PORTS</button>
            <button class="btn-action" onclick="loadSampleLogs()">⚡ LOAD ATTACK LOGS</button>
        </div>

        <!-- Metrics Cards -->
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

        <!-- Tabs Navigation -->
        <div class="hud-tabs">
            <button class="hud-tab-btn active" onclick="switchTab('tab-findings', this)">🌐 WEB & OWASP AUDIT</button>
            <button class="hud-tab-btn" onclick="switchTab('tab-attackers', this)">🚨 ATTACKER TRACKER & IDS</button>
            <button class="hud-tab-btn" onclick="switchTab('tab-ports', this)">📡 LOCALHOST PORTS</button>
            <button class="hud-tab-btn" onclick="switchTab('tab-playbooks', this)">📋 HARDENING PLAYBOOKS</button>
            <button class="hud-tab-btn" onclick="switchTab('tab-console', this)">🖥️ TACTICAL LOGS</button>
        </div>

        <!-- Tab 1: Findings -->
        <div id="tab-findings" class="tab-pane active">
            <h3 style="color: var(--cyan); font-size: 14px; margin-bottom: 12px; letter-spacing: 1px;">WEB POSTURE AUDIT FINDINGS</h3>
            <div class="table-container">
                <table id="tableFindings">
                    <thead>
                        <tr>
                            <th style="width: 110px;">SEVERITY</th>
                            <th style="width: 250px;">SECURITY CHECK</th>
                            <th>FINDING DESCRIPTION</th>
                            <th>DEFENSIVE REMEDIATION</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyFindings">
                        <tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 30px;">Click 'RUN DEFENSIVE AUDIT' above to inspect your target web server.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 2: Attacker Tracking & IDS -->
        <div id="tab-attackers" class="tab-pane">
            <div class="dossier-layout">
                <div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <h3 style="color: var(--red); font-size: 14px; letter-spacing: 1px;">DETECTED ATTACKERS & PROBING TRAFFIC</h3>
                        <button class="btn-action" style="padding: 4px 10px; font-size: 11px;" onclick="loadSampleLogs()">⚡ LOAD SAMPLE ATTACK LOGS</button>
                    </div>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr>
                                    <th>ATTACKER IP</th>
                                    <th>GEO / COUNTRY</th>
                                    <th>HITS</th>
                                    <th>SEVERITY</th>
                                    <th>ATTACK CATEGORIES</th>
                                </tr>
                            </thead>
                            <tbody id="tbodyAttackers">
                                <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">No attacker logs analyzed yet. Click 'LOAD ATTACK LOGS' to test intrusion telemetry.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div>
                    <h3 style="color: var(--cyan); font-size: 14px; margin-bottom: 12px; letter-spacing: 1px;">ATTACKER DOSSIER & FIREWALL BLOCK</h3>
                    <div class="dossier-box" id="dossierBox">Select an attacker IP from the table to view intelligence dossier, reverse DNS, and generated firewall drop rules.</div>
                </div>
            </div>
        </div>

        <!-- Tab 3: Local Ports -->
        <div id="tab-ports" class="tab-pane">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <h3 style="color: var(--cyan); font-size: 14px; letter-spacing: 1px;">ACTIVE LISTENING SOCKETS & INTERFACE EXPOSURE</h3>
                <button class="btn-action" style="padding: 4px 10px; font-size: 11px;" onclick="scanPorts()">🔄 REFRESH SOCKETS</button>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>PORT</th>
                            <th>BINDING</th>
                            <th>PROCESS</th>
                            <th>PID</th>
                            <th>RISK</th>
                            <th>SECURITY RECOMMENDATION</th>
                        </tr>
                    </thead>
                    <tbody id="tbodyPorts">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">Loading listening sockets...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tab 4: Playbooks -->
        <div id="tab-playbooks" class="tab-pane">
            <h3 style="color: var(--cyan); font-size: 14px; margin-bottom: 12px; letter-spacing: 1px;">OWASP DEFENSIVE HARDENING PLAYBOOKS</h3>
            <div style="display: flex; gap: 8px; margin-bottom: 15px;">
                <button class="btn-preset" onclick="loadPlaybook('nginx')">Nginx</button>
                <button class="btn-preset" onclick="loadPlaybook('apache')">Apache</button>
                <button class="btn-preset" onclick="loadPlaybook('express')">Express.js</button>
                <button class="btn-preset" onclick="loadPlaybook('caddy')">Caddy</button>
                <button class="btn-preset" onclick="loadPlaybook('python_fastapi')">FastAPI</button>
            </div>
            <h4 id="playbookTitle" style="color: var(--text-bright); margin-bottom: 6px;">Nginx Security Hardening</h4>
            <p id="playbookDesc" style="color: var(--text-muted); font-size: 12px; margin-bottom: 12px;"></p>
            <pre id="playbookCode"></pre>
        </div>

        <!-- Tab 5: Console -->
        <div id="tab-console" class="tab-pane">
            <h3 style="color: var(--green); font-size: 14px; margin-bottom: 12px; letter-spacing: 1px;">STREAMING TACTICAL HUD CONSOLE</h3>
            <div class="hud-console" id="hudConsole">
                <div class="log-entry"><span class="log-time">[00:00:00]</span> [INFO] Aegis Defensive Web HUD initialized on http://127.0.0.1:5000.</div>
            </div>
        </div>
    </div>

    <script>
        let currentAttackers = [];
        let playbooksData = {};

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
        }

        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.hud-tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
        }

        function updateScore(score, grade) {
            document.getElementById('scoreNum').innerText = score;
            const gradeEl = document.getElementById('scoreGrade');
            gradeEl.innerText = 'GRADE: ' + grade;

            const bar = document.getElementById('scoreBar');
            const circumference = 314;
            const offset = circumference - (score / 100) * circumference;
            bar.style.strokeDashoffset = offset;

            let color = 'var(--red)';
            if (score >= 90) color = 'var(--green)';
            else if (score >= 80) color = 'var(--cyan)';
            else if (score >= 70) color = 'var(--amber)';

            bar.style.stroke = color;
            gradeEl.style.color = color;
        }

        async function runAudit() {
            const target = document.getElementById('targetUrl').value.trim();
            if (!target) return alert('Please enter a target URL.');

            const btn = document.getElementById('btnAudit');
            btn.innerText = 'AUDITING...';
            btn.disabled = true;
            logToConsole('Initiating defensive audit against: ' + target, 'INFO');

            try {
                const res = await fetch('/api/audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: target })
                });
                const data = await res.json();

                updateScore(data.score, data.grade);
                document.getElementById('valCrit').innerText = data.summary.critical;
                document.getElementById('valHigh').innerText = data.summary.high;
                document.getElementById('valMed').innerText = data.summary.medium;
                document.getElementById('valPass').innerText = data.summary.pass;

                const tbody = document.getElementById('tbodyFindings');
                tbody.innerHTML = '';

                data.findings.forEach(f => {
                    const row = document.createElement('tr');
                    const sev = f.severity.toUpperCase();
                    let badgeClass = 'badge-med';
                    if (sev === 'CRITICAL') badgeClass = 'badge-crit';
                    else if (sev === 'HIGH') badgeClass = 'badge-high';
                    else if (sev === 'PASS') badgeClass = 'badge-pass';

                    row.innerHTML = `
                        <td><span class="badge-sev ${badgeClass}">${sev}</span></td>
                        <td style="font-weight: bold; color: #FFF;">${f.title}</td>
                        <td style="color: #94A3B8;">${f.description}</td>
                        <td style="color: var(--cyan);">${f.remediation}</td>
                    `;
                    tbody.appendChild(row);
                });

                logToConsole(`Audit complete for ${target}. Score: ${data.score}/100 [Grade: ${data.grade}]`, data.score >= 80 ? 'PASS' : 'WARN');
            } catch (err) {
                logToConsole('Audit failed: ' + err, 'THREAT');
            } finally {
                btn.innerText = '🛡️ RUN DEFENSIVE AUDIT';
                btn.disabled = false;
            }
        }

        async function scanPorts() {
            logToConsole('Scanning local listening ports and interface bindings...', 'INFO');
            try {
                const res = await fetch('/api/ports');
                const listeners = await res.json();
                const tbody = document.getElementById('tbodyPorts');
                tbody.innerHTML = '';

                listeners.forEach(l => {
                    const row = document.createElement('tr');
                    const risk = l.risk_level.toUpperCase();
                    let badgeClass = 'badge-pass';
                    if (risk === 'CRITICAL') badgeClass = 'badge-crit';
                    else if (risk === 'MEDIUM') badgeClass = 'badge-high';

                    row.innerHTML = `
                        <td style="font-weight: bold; color: #FFF;">${l.port}</td>
                        <td style="color: var(--cyan);">${l.ip}:${l.port}</td>
                        <td>${l.process_name}</td>
                        <td style="color: var(--text-muted);">${l.pid || 'N/A'}</td>
                        <td><span class="badge-sev ${badgeClass}">${risk}</span></td>
                        <td>${l.risk_message} <br><span style="color: var(--cyan);">Fix: ${l.remediation}</span></td>
                    `;
                    tbody.appendChild(row);
                });
                logToConsole(`Found ${listeners.length} active listening ports.`, 'PASS');
            } catch (err) {
                logToConsole('Port scan error: ' + err, 'THREAT');
            }
        }

        async function loadSampleLogs() {
            logToConsole('Loading representative attack telemetry...', 'INFO');
            try {
                const res = await fetch('/api/analyze-logs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ use_sample: true })
                });
                const attackers = await res.json();
                currentAttackers = attackers;

                const tbody = document.getElementById('tbodyAttackers');
                tbody.innerHTML = '';

                attackers.forEach((att, idx) => {
                    const row = document.createElement('tr');
                    row.style.cursor = 'pointer';
                    row.onclick = () => selectAttacker(idx);

                    const geo = att.threat_profile || {};
                    const sev = att.highest_severity.toUpperCase();
                    let badgeClass = sev === 'CRITICAL' ? 'badge-crit' : (sev === 'HIGH' ? 'badge-high' : 'badge-med');

                    row.innerHTML = `
                        <td style="color: #FFF; font-weight: bold;">${att.ip}</td>
                        <td>${geo.country_code || 'XX'} - ${geo.country || 'Unknown'}</td>
                        <td style="color: var(--red); font-weight: bold;">${att.malicious_hits}</td>
                        <td><span class="badge-sev ${badgeClass}">${sev}</span></td>
                        <td style="color: #94A3B8;">${att.attack_types.join(', ')}</td>
                    `;
                    tbody.appendChild(row);
                });

                if (attackers.length > 0) {
                    selectAttacker(0);
                    switchTab('tab-attackers', document.querySelectorAll('.hud-tab-btn')[1]);
                    logToConsole(`Detected ${attackers.length} malicious attacker IPs hitting your server!`, 'THREAT');
                }
            } catch (err) {
                logToConsole('Log analysis error: ' + err, 'THREAT');
            }
        }

        function selectAttacker(idx) {
            const att = currentAttackers[idx];
            if (!att) return;
            const geo = att.threat_profile || {};
            const fw = att.firewall_rules || {};

            const mitre = (att.mitre_mappings || []).map(m => `  - ${m.category}: ${m.owasp} | ${m.mitre}\n    Fix: ${m.defensive_control}`).join('\\n');
            const payloads = (att.sample_payloads || []).map(p => `  * ${p}`).join('\\n');

            const dossier = `=====================================================
ATTACKER DOSSIER // IP: ${att.ip}
=====================================================
[GEOLOCATION & NETWORK PROFILE]
  Location:    ${geo.country || 'Unknown'} (${geo.country_code || 'XX'}), ${geo.city || 'Unknown'}
  ISP / Host:  ${geo.isp || 'Unknown'}
  Reverse DNS: ${geo.reverse_dns || 'Unknown'}
  AS Number:   ${geo.as_number || 'N/A'}

[PROBING ACTIVITY]
  Severity:    ${att.highest_severity.toUpperCase()}
  Attacks:     ${att.malicious_hits} malicious / ${att.total_requests} total requests
  Categories:  ${att.attack_types.join(', ')}

[MITRE ATT&CK & OWASP]
${mitre || '  None'}

[CAPTURED ATTACK PROBES]
${payloads || '  None'}

=====================================================
INSTANT DEFENSIVE FIREWALL MITIGATION RULES:
=====================================================
[Windows Defender Firewall (PowerShell)]
${fw.powershell || ''}

[Linux UFW]
${fw.ufw || ''}

[Nginx Block Directive]
${fw.nginx || ''}
`;
            document.getElementById('dossierBox').innerText = dossier;
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

        // On Load
        window.addEventListener('DOMContentLoaded', () => {
            scanPorts();
            loadPlaybooksInit();
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


@app.route("/api/ports", methods=["GET"])
def api_ports():
    listeners = PortAuditor.audit_listeners()
    return jsonify(listeners)


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
        mitre = intel.map_to_mitre_and_owasp(att["attack_types"])
        att["threat_profile"] = geo
        att["identified_tools"] = tools
        att["mitre_mappings"] = mitre
        enriched.append(att)

    return jsonify(enriched)


@app.route("/api/playbooks", methods=["GET"])
def api_playbooks():
    return jsonify(PLAYBOOKS)


def run_web(host="127.0.0.1", port=5000):
    print(f"\n[+] AEGIS Tactical Sci-Fi HUD Web Dashboard online:")
    print(f"    --> http://{host}:{port} or http://localhost:{port}\n")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run_web()

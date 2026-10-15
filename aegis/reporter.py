"""
Aegis Defensive Report Generator
Produces structured JSON reports and standalone Sci-Fi HUD styled HTML security audit summaries.
"""

import json
from datetime import datetime
from typing import Dict, Any


class ReportGenerator:
    """Exports defensive audit findings to JSON or styled HTML."""

    @staticmethod
    def to_json(report_data: Dict[str, Any], indent: int = 2) -> str:
        return json.dumps(report_data, indent=indent, default=str)

    @staticmethod
    def to_html(report: Dict[str, Any]) -> str:
        target = report.get("target", "Unknown")
        score = report.get("score", 0)
        grade = report.get("grade", "F")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        summary = report.get("summary", {})
        findings = report.get("findings", [])

        grade_color = "#00FF88" if score >= 90 else ("#00F0FF" if score >= 80 else ("#FFB800" if score >= 70 else "#FF3366"))

        findings_html = ""
        for f in findings:
            sev = f.get("severity", "Info")
            sev_class = sev.lower()
            findings_html += f"""
            <div class="finding-card {sev_class}">
                <div class="finding-header">
                    <span class="badge badge-{sev_class}">{sev.upper()}</span>
                    <span class="finding-title">{f.get('title', '')}</span>
                </div>
                <div class="finding-body">
                    <p class="finding-desc">{f.get('description', '')}</p>
                    <div class="remediation-box">
                        <strong>Defensive Remediation:</strong> {f.get('remediation', '')}
                    </div>
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS DEFENSIVE AUDIT // {target}</title>
    <style>
        :root {{
            --bg-deep: #070B12;
            --bg-panel: #0D131F;
            --bg-card: #121A2C;
            --border-glow: #1E2D4A;
            --cyan-glow: #00F0FF;
            --green-glow: #00FF88;
            --amber-glow: #FFB800;
            --red-glow: #FF3366;
            --text-main: #E2E8F0;
            --text-muted: #8899B5;
            --font-mono: 'Consolas', 'Courier New', monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-deep);
            color: var(--text-main);
            font-family: var(--font-mono);
            padding: 30px;
            line-height: 1.6;
        }}
        .hud-container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .hud-header {{
            border: 1px solid var(--border-glow);
            background: var(--bg-panel);
            padding: 24px;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 0 25px rgba(0, 240, 255, 0.1);
            margin-bottom: 25px;
            border-left: 5px solid var(--cyan-glow);
        }}
        .hud-title h1 {{
            color: var(--cyan-glow);
            font-size: 22px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }}
        .hud-title p {{
            color: var(--text-muted);
            font-size: 13px;
        }}
        .score-box {{
            text-align: right;
            padding: 10px 20px;
            border: 1px solid {grade_color};
            border-radius: 6px;
            background: rgba(0,0,0,0.4);
        }}
        .score-val {{
            font-size: 32px;
            font-weight: bold;
            color: {grade_color};
        }}
        .score-grade {{
            font-size: 16px;
            color: var(--text-muted);
        }}
        .telemetry-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .stat-card {{
            background: var(--bg-panel);
            border: 1px solid var(--border-glow);
            padding: 16px;
            border-radius: 6px;
            text-align: center;
        }}
        .stat-num {{
            font-size: 24px;
            font-weight: bold;
            margin-top: 5px;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 1px;
        }}
        .badge-critical {{ background: rgba(255, 51, 102, 0.2); color: var(--red-glow); border: 1px solid var(--red-glow); }}
        .badge-high {{ background: rgba(255, 184, 0, 0.2); color: var(--amber-glow); border: 1px solid var(--amber-glow); }}
        .badge-medium {{ background: rgba(0, 240, 255, 0.2); color: var(--cyan-glow); border: 1px solid var(--cyan-glow); }}
        .badge-low {{ background: rgba(136, 153, 181, 0.2); color: var(--text-muted); border: 1px solid var(--text-muted); }}
        .badge-pass {{ background: rgba(0, 255, 136, 0.2); color: var(--green-glow); border: 1px solid var(--green-glow); }}
        .finding-card {{
            background: var(--bg-panel);
            border: 1px solid var(--border-glow);
            border-radius: 6px;
            margin-bottom: 15px;
            padding: 18px;
            border-left: 4px solid var(--text-muted);
        }}
        .finding-card.critical {{ border-left-color: var(--red-glow); }}
        .finding-card.high {{ border-left-color: var(--amber-glow); }}
        .finding-card.medium {{ border-left-color: var(--cyan-glow); }}
        .finding-card.pass {{ border-left-color: var(--green-glow); }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-size: 15px;
            font-weight: bold;
            color: #FFFFFF;
        }}
        .finding-desc {{
            color: var(--text-muted);
            font-size: 13px;
            margin-bottom: 12px;
        }}
        .remediation-box {{
            background: rgba(0, 0, 0, 0.35);
            border-left: 3px solid var(--cyan-glow);
            padding: 10px 14px;
            font-size: 12px;
            color: #94A3B8;
        }}
        .remediation-box strong {{
            color: var(--cyan-glow);
        }}
    </style>
</head>
<body>
    <div class="hud-container">
        <div class="hud-header">
            <div class="hud-title">
                <h1>AEGIS // DEFENSIVE SECURITY AUDIT</h1>
                <p>TARGET: {target} | AUDIT TIMESTAMP: {timestamp}</p>
            </div>
            <div class="score-box">
                <div class="score-val">{score}/100</div>
                <div class="score-grade">POSTURE GRADE: {grade}</div>
            </div>
        </div>

        <div class="telemetry-grid">
            <div class="stat-card">
                <div>CRITICAL THREATS</div>
                <div class="stat-num" style="color: var(--red-glow);">{summary.get('critical', 0)}</div>
            </div>
            <div class="stat-card">
                <div>HIGH SEVERITY</div>
                <div class="stat-num" style="color: var(--amber-glow);">{summary.get('high', 0)}</div>
            </div>
            <div class="stat-card">
                <div>MEDIUM WARNINGS</div>
                <div class="stat-num" style="color: var(--cyan-glow);">{summary.get('medium', 0)}</div>
            </div>
            <div class="stat-card">
                <div>HARDENED PASSES</div>
                <div class="stat-num" style="color: var(--green-glow);">{summary.get('pass', 0)}</div>
            </div>
        </div>

        <h2 style="color: var(--cyan-glow); font-size: 16px; margin-bottom: 15px; letter-spacing: 1px;">AUDIT FINDINGS & DEFENSIVE PLAYBOOKS</h2>
        {findings_html}
    </div>
</body>
</html>"""
        return html

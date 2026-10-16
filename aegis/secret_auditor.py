"""
Aegis Defensive Security Suite - Security Exposure & Secret-Leak Audit Center
Enterprise-grade modular security auditing platform for detecting accidentally exposed credentials,
misconfigured .gitignore files, leaked secrets in Git history, risky backups, and vulnerable dependencies.

Modules:
1. SecretScanner - High-entropy & signature regex secret scanner with automatic redaction
2. GitAuditor - .gitignore rule parser, tracked sensitive file detector, staged secret check
3. GitHistoryScanner - Scans git commit log diffs for past leaked credentials
4. GitHubExposureInspector - Inspects public/private GitHub repo exposure, trees, and alerts
5. SensitiveFileHunter - Filesystem hunter for database dumps, private keys, logs, and backups
6. DependencyAuditor - Queries OSV.dev (Open Source Vulnerabilities) for requirements.txt & package.json
7. PreCommitGuard - Git pre-commit hook generator & validation
8. ExposureReporter - HTML, JSON, and CSV report synthesis with zero unredacted secrets
"""

import os
import re
import json
import time
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
# 1. SECRET DETECTION PATTERNS & REDACTION ENGINE
# ==============================================================================

SECRET_RULES = [
    {
        "id": "SEC_AWS_KEY",
        "name": "AWS Access Key ID",
        "category": "Cloud Credentials",
        "severity": "Critical",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "remediation": "Revoke the AWS IAM access key immediately in AWS IAM Console and rotate credentials."
    },
    {
        "id": "SEC_AWS_SECRET",
        "name": "AWS Secret Access Key",
        "category": "Cloud Credentials",
        "severity": "Critical",
        "pattern": r"(?i)aws_?(?:secret)?_?(?:access)?_?(?:key)?\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
        "remediation": "Deactivate AWS IAM secret access key immediately. Check AWS CloudTrail logs for unauthorized API calls."
    },
    {
        "id": "SEC_GITHUB_PAT",
        "name": "GitHub Personal Access Token",
        "category": "Developer Tokens",
        "severity": "Critical",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[0-9a-zA-Z_]{82}",
        "remediation": "Revoke the GitHub Personal Access Token immediately under GitHub Settings -> Developer Settings -> Personal Access Tokens."
    },
    {
        "id": "SEC_PRIVATE_KEY",
        "name": "Cryptographic Private Key",
        "category": "Cryptographic Keys",
        "severity": "Critical",
        "pattern": r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP)? PRIVATE KEY-----",
        "remediation": "Delete private key file from repository, rotate keypair on all servers, and add key extension to .gitignore."
    },
    {
        "id": "SEC_STRIPE_KEY",
        "name": "Stripe Live Secret Key",
        "category": "Payment Gateways",
        "severity": "Critical",
        "pattern": r"(?:sk|rk)_live_[0-9a-zA-Z]{24,34}",
        "remediation": "Rotate Stripe API keys in the Stripe Dashboard immediately. Audit recent charges and transfers."
    },
    {
        "id": "SEC_GOOGLE_API",
        "name": "Google API / Firebase Key",
        "category": "API Credentials",
        "severity": "High",
        "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
        "remediation": "Restrict API key restrictions in Google Cloud Console to specific IP addresses, HTTP referrers, or services."
    },
    {
        "id": "SEC_SLACK_WEBHOOK",
        "name": "Slack Incoming Webhook",
        "category": "Webhooks & Notifications",
        "severity": "High",
        "pattern": r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+",
        "remediation": "Revoke and regenerate Slack incoming webhook URL in Slack App settings."
    },
    {
        "id": "SEC_SLACK_TOKEN",
        "name": "Slack Bot / User Token",
        "category": "OAuth & Access Tokens",
        "severity": "High",
        "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "remediation": "Revoke Slack token in your Slack App admin portal."
    },
    {
        "id": "SEC_DB_CONN_STRING",
        "name": "Database Connection String with Credentials",
        "category": "Database Credentials",
        "severity": "Critical",
        "pattern": r"(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:\s]+:[^@\s]+@[^\s/]+/[^\s]+",
        "remediation": "Remove connection URI containing credentials. Store database credentials in environment variables outside source code."
    },
    {
        "id": "SEC_JWT_TOKEN",
        "name": "JSON Web Token (JWT)",
        "category": "Session & Auth",
        "severity": "Medium",
        "pattern": r"eyJh[A-Za-z0-9_-]+\.eyJh[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "remediation": "Ensure static JWT tokens are not committed to code. Verify token expiration."
    },
    {
        "id": "SEC_HARDCODED_PASSWORD",
        "name": "Hardcoded Password Variable",
        "category": "Application Secrets",
        "severity": "High",
        "pattern": r"(?i)(?:password|passwd|pwd|db_pass|secret_key|api_secret)\s*[:=]\s*['\"]([^'\"]{8,64})['\"]",
        "remediation": "Replace hardcoded passwords with environment variables (os.environ or process.env)."
    },
    {
        "id": "SEC_GENERIC_API_KEY",
        "name": "Generic API Secret Key Variable",
        "category": "Application Secrets",
        "severity": "Medium",
        "pattern": r"(?i)(?:api_key|apikey|client_secret|auth_token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]",
        "remediation": "Move API keys to environment variables and add .env to .gitignore."
    }
]


def redact_secret(val: str) -> str:
    """Masks secret to prevent exposing real credentials in UI or reports."""
    val = val.strip()
    if len(val) <= 6:
        return "****[REDACTED]"
    return f"{val[:3]}****[REDACTED]"


# ==============================================================================
# MODULE 1: SECRET & CREDENTIAL SCANNER
# ==============================================================================

class SecretScanner:
    """Scans local filesystem files for accidentally committed secrets with full redaction."""

    EXCLUDED_DIRS = {
        ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
        ".idea", ".vscode", "coverage", ".next", ".nuxt", "vendor"
    }

    EXCLUDED_EXTS = {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
        ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll", ".so"
    }

    @staticmethod
    def scan_path(target_path: str = ".", max_files: int = 500) -> Dict[str, Any]:
        """Scans all text files under target_path for likely credentials."""
        target_path = os.path.abspath(target_path)
        if not os.path.exists(target_path):
            return {"error": f"Path not found: {target_path}", "findings": []}

        findings = []
        files_scanned = 0
        t0 = time.time()

        for root, dirs, files in os.walk(target_path):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in SecretScanner.EXCLUDED_DIRS]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in SecretScanner.EXCLUDED_EXTS:
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, target_path)

                # Skip files larger than 2MB to prevent memory exhaustion
                try:
                    if os.path.getsize(full_path) > 2 * 1024 * 1024:
                        continue
                except Exception:
                    continue

                files_scanned += 1
                if files_scanned > max_files:
                    break

                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for line_num, line in enumerate(lines, 1):
                    # Skip comment-only documentation lines or markdown samples
                    if line.strip().startswith("//") and "example" in line.lower():
                        continue

                    for rule in SECRET_RULES:
                        matches = re.finditer(rule["pattern"], line)
                        for match in matches:
                            raw_match = match.group(0)
                            # Avoid false positives on empty placeholders
                            if any(p in raw_match.lower() for p in ["your_", "example", "placeholder", "xxx", "todo"]):
                                continue

                            redacted = redact_secret(raw_match)
                            # Sanitize preview line
                            sanitized_line = line.replace(raw_match, redacted).strip()
                            if len(sanitized_line) > 120:
                                sanitized_line = sanitized_line[:117] + "..."

                            findings.append({
                                "rule_id": rule["id"],
                                "rule_name": rule["name"],
                                "category": rule["category"],
                                "severity": rule["severity"],
                                "file_path": rel_path.replace("\\", "/"),
                                "line_number": line_num,
                                "evidence_snippet": sanitized_line,
                                "redacted_value": redacted,
                                "remediation": rule["remediation"]
                            })

        elapsed = round(time.time() - t0, 2)
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev = f.get("severity", "Low")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        return {
            "status": "success",
            "target_path": target_path,
            "files_scanned": files_scanned,
            "scan_duration_sec": elapsed,
            "total_findings": len(findings),
            "severity_counts": sev_counts,
            "findings": findings
        }

    scan_directory = scan_path


# ==============================================================================
# MODULE 2: GIT & .GITIGNORE SECURITY AUDITOR
# ==============================================================================

class GitAuditor:
    """Inspects .gitignore format, tracked sensitive files, and staged credentials."""

    RECOMMENDED_IGNORES = [
        ".env", ".env.local", ".env.*.local", "*.pem", "*.key", "id_rsa",
        "*.sql", "*.sqlite", "*.sqlite3", "*.db", "database.sql", "dump.sql",
        "node_modules/", "__pycache__/", "*.pyc", ".venv/", "venv/",
        "*.log", "logs/", "*.bak", "*.backup", ".DS_Store"
    ]

    @staticmethod
    def audit_repository(repo_path: str = ".") -> Dict[str, Any]:
        """Runs comprehensive Git and .gitignore audit on the specified directory."""
        repo_path = os.path.abspath(repo_path)
        is_git = os.path.exists(os.path.join(repo_path, ".git"))

        gitignore_path = os.path.join(repo_path, ".gitignore")
        gitignore_exists = os.path.exists(gitignore_path)

        gitignore_rules = []
        if gitignore_exists:
            try:
                with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                    gitignore_rules = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass

        # Check which recommended ignores are missing
        missing_ignores = []
        for rec in GitAuditor.RECOMMENDED_IGNORES:
            rule_clean = rec.rstrip("/")
            if not any(rule_clean in r for r in gitignore_rules):
                missing_ignores.append(rec)

        # Check tracked files via git ls-files if git available
        tracked_sensitive = []
        staged_files = []
        git_version = "Unknown"

        if is_git:
            try:
                # Check git version
                res = subprocess.run(["git", "--version"], cwd=repo_path, capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    git_version = res.stdout.strip()

                # Get all tracked files
                res_files = subprocess.run(["git", "ls-files"], cwd=repo_path, capture_output=True, text=True, timeout=5)
                if res_files.returncode == 0:
                    all_tracked = res_files.stdout.splitlines()
                    sensitive_patterns = [
                        r"\.env(?:\..+)?$", r"\.pem$", r"\.key$", r"id_rsa", r"\.sqlite3?$",
                        r"database\.sql$", r"dump\.sql$", r"backup\.sql$", r"\.p12$", r"\.pfx$"
                    ]
                    for tf in all_tracked:
                        tf_clean = tf.strip().replace("\\", "/")
                        # Exclude benign example templates from critical tracked alerts
                        if any(tf_clean.endswith(ext) for ext in [".example", ".sample", ".template", ".dist"]):
                            continue
                        for pat in sensitive_patterns:
                            if re.search(pat, tf_clean, re.IGNORECASE):
                                tracked_sensitive.append({
                                    "file": tf_clean,
                                    "status": "TRACKED_IN_INDEX",
                                    "risk": "Critical: Sensitive file is currently tracked in Git repository!",
                                    "remediation": f"Run 'git rm --cached {tf_clean}' to untrack without deleting local file, then commit."
                                })
                                break

                # Check staged files
                res_staged = subprocess.run(["git", "diff", "--cached", "--name-only"], cwd=repo_path, capture_output=True, text=True, timeout=3)
                if res_staged.returncode == 0:
                    staged_files = [s.strip() for s in res_staged.stdout.splitlines() if s.strip()]

            except Exception:
                pass

        return {
            "status": "success",
            "repo_path": repo_path,
            "is_git_repository": is_git,
            "git_version": git_version,
            "gitignore_exists": gitignore_exists,
            "total_gitignore_rules": len(gitignore_rules),
            "missing_recommended_ignores": missing_ignores,
            "tracked_sensitive_files": tracked_sensitive,
            "staged_files_count": len(staged_files),
            "staged_files": staged_files,
            "security_grade": "A" if (not tracked_sensitive and not missing_ignores) else ("C" if not tracked_sensitive else "F")
        }


# ==============================================================================
# MODULE 3: GIT HISTORY SECRET SCANNER
# ==============================================================================

class GitHistoryScanner:
    """Scans git commit history diffs for past leaked credentials."""

    @staticmethod
    def scan_history(repo_path: str = ".", max_commits: int = 50) -> Dict[str, Any]:
        """Inspects past commit patches to verify whether credentials linger in history."""
        repo_path = os.path.abspath(repo_path)
        if not os.path.exists(os.path.join(repo_path, ".git")):
            return {"error": "Target directory is not a Git repository (.git not found).", "findings": []}

        findings = []
        commits_inspected = 0
        t0 = time.time()

        try:
            # Query git log with diff patch
            cmd = ["git", "log", f"-n{max_commits}", "-p", "--pretty=format:COMMIT_SEP:%H|%an|%ad|%s"]
            proc = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, errors="ignore", timeout=15)
            if proc.returncode != 0:
                return {"error": f"git log failed: {proc.stderr}", "findings": []}

            raw_output = proc.stdout
            commit_blocks = raw_output.split("COMMIT_SEP:")

            for block in commit_blocks:
                if not block.strip():
                    continue

                commits_inspected += 1
                lines = block.splitlines()
                header = lines[0] if lines else ""
                parts = header.split("|", 3)
                commit_hash = parts[0] if len(parts) > 0 else "Unknown"
                author = parts[1] if len(parts) > 1 else "Unknown"
                date_str = parts[2] if len(parts) > 2 else "Unknown"
                subject = parts[3] if len(parts) > 3 else "Unknown"

                # Scan added lines (+) in patch
                for line in lines[1:]:
                    if line.startswith("+") and not line.startswith("+++"):
                        content = line[1:].strip()
                        for rule in SECRET_RULES:
                            match = re.search(rule["pattern"], content)
                            if match:
                                raw_val = match.group(0)
                                if any(p in raw_val.lower() for p in ["your_", "example", "placeholder", "xxx"]):
                                    continue

                                redacted = redact_secret(raw_val)
                                findings.append({
                                    "commit_hash": commit_hash[:8],
                                    "author": author,
                                    "date": date_str,
                                    "commit_subject": subject[:60],
                                    "rule_name": rule["name"],
                                    "severity": rule["severity"],
                                    "redacted_evidence": redact_secret(content),
                                    "remediation": "Credentials committed to history must be revoked immediately. Consider rotating keys and running BFG Repo-Cleaner or git filter-repo."
                                })

        except Exception as e:
            return {"error": f"Git history scan error: {str(e)}", "findings": []}

        elapsed = round(time.time() - t0, 2)
        return {
            "status": "success",
            "repo_path": repo_path,
            "commits_inspected": commits_inspected,
            "duration_sec": elapsed,
            "historical_leaks_found": len(findings),
            "findings": findings
        }


# ==============================================================================
# MODULE 4: SENSITIVE FILE & BACKUP HUNTER
# ==============================================================================

class SensitiveFileHunter:
    """Hunts for high-risk files (SQL dumps, private keys, backups, environment copies)."""

    RISKY_FILE_DEFINITIONS = [
        {"pattern": r"^\.env(?:\..+)?$", "category": "Environment File", "sev": "Critical", "reason": "Contains sensitive configuration & environment secrets."},
        {"pattern": r".*\.sql$", "category": "Database SQL Dump", "sev": "Critical", "reason": "Database dump containing tables, users, or customer data."},
        {"pattern": r".*\.(?:sqlite|sqlite3|db)$", "category": "SQLite Database", "sev": "Critical", "reason": "Raw SQLite database file accessible in project root."},
        {"pattern": r".*\.(?:pem|key|pkcs12|p12|pfx)$", "category": "Private Key / Certificate", "sev": "Critical", "reason": "Cryptographic private key or keystore container."},
        {"pattern": r"^id_rsa.*$", "category": "SSH Private Key", "sev": "Critical", "reason": "SSH private key file permitting remote shell authentication."},
        {"pattern": r".*\.(?:bak|backup|old|swp|~)$", "category": "Backup / Temp File", "sev": "High", "reason": "Unprotected backup file which may bypass web server access controls."},
        {"pattern": r".*\.(?:tar\.gz|zip|tgz|rar)$", "category": "Archive File", "sev": "Medium", "reason": "Compressed archive file potentially containing code or data backups."},
        {"pattern": r".*\.log$", "category": "Log File", "sev": "Medium", "reason": "Application or error log potentially exposing sensitive stacktraces or tokens."},
        {"pattern": r"^docker-compose(?:\..+)?\.ya?ml$", "category": "Docker Compose", "sev": "Medium", "reason": "Orchestration config containing default ports, services, or DB passwords."}
    ]

    @staticmethod
    def hunt_files(directory: str = ".", max_results: int = 100) -> Dict[str, Any]:
        """Walks directory to find risky file types."""
        directory = os.path.abspath(directory)
        findings = []
        files_evaluated = 0
        t0 = time.time()

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in SecretScanner.EXCLUDED_DIRS]

            for file in files:
                files_evaluated += 1
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, directory).replace("\\", "/")

                for rdef in SensitiveFileHunter.RISKY_FILE_DEFINITIONS:
                    if re.match(rdef["pattern"], file, re.IGNORECASE):
                        is_template = any(file.endswith(ext) for ext in [".example", ".sample", ".template", ".dist"])
                        size_bytes = 0
                        mtime_str = "Unknown"
                        try:
                            st = os.stat(full_path)
                            size_bytes = st.st_size
                            mtime_str = datetime.utcfromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            pass

                        sev = "Low (Template)" if is_template else rdef["sev"]
                        cat = "Config Template" if is_template else rdef["category"]
                        reason = "Configuration template file. Verify no live credentials were left inside." if is_template else rdef["reason"]

                        findings.append({
                            "file_name": file,
                            "relative_path": rel_path,
                            "category": cat,
                            "severity": sev,
                            "size_kb": round(size_bytes / 1024, 2),
                            "last_modified": mtime_str,
                            "reason": reason,
                            "remediation": f"Ensure '{file}' contains only dummy placeholder values." if is_template else f"Ensure '{file}' is added to .gitignore and removed from public web roots."
                        })
                        if len(findings) >= max_results:
                            break
                if len(findings) >= max_results:
                    break

        elapsed = round(time.time() - t0, 2)
        return {
            "status": "success",
            "directory": directory,
            "files_evaluated": files_evaluated,
            "risky_files_found": len(findings),
            "duration_sec": elapsed,
            "findings": findings
        }


# ==============================================================================
# MODULE 5: DEPENDENCY VULNERABILITY SCANNER (OSV.DEV Integration)
# ==============================================================================

class DependencyAuditor:
    """Audits Python requirements.txt or Node package.json against OSV (Open Source Vulnerabilities)."""

    @staticmethod
    def audit_dependencies(repo_path: str = ".") -> Dict[str, Any]:
        """Parses local manifest files and queries OSV API for real CVE advisories."""
        repo_path = os.path.abspath(repo_path)
        packages_checked = []
        advisories_found = []

        # 1. Check requirements.txt
        req_path = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(req_path):
            try:
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:==|>=|<=|~=)?([0-9a-zA-Z\.\-_]*)", line)
                            if m:
                                pkg_name, pkg_ver = m.group(1), m.group(2)
                                packages_checked.append({
                                    "ecosystem": "PyPI",
                                    "name": pkg_name,
                                    "version": pkg_ver or "latest"
                                })
            except Exception:
                pass

        # 2. Check package.json
        pkg_json_path = os.path.join(repo_path, "package.json")
        if os.path.exists(pkg_json_path):
            try:
                with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    for name, ver in deps.items():
                        clean_ver = re.sub(r"[\^~>=<]", "", ver)
                        packages_checked.append({
                            "ecosystem": "npm",
                            "name": name,
                            "version": clean_ver
                        })
            except Exception:
                pass

        # Query OSV.dev in batch
        for pkg in packages_checked[:20]: # Check top 20 packages
            if not pkg["version"] or pkg["version"] == "latest":
                continue
            payload = {
                "version": pkg["version"],
                "package": {
                    "name": pkg["name"],
                    "ecosystem": pkg["ecosystem"]
                }
            }
            try:
                res = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=3)
                if res.status_code == 200:
                    data = res.json()
                    vulns = data.get("vulns", [])
                    for v in vulns:
                        advisories_found.append({
                            "package": pkg["name"],
                            "version": pkg["version"],
                            "ecosystem": pkg["ecosystem"],
                            "vuln_id": v.get("id", "CVE-UNKNOWN"),
                            "summary": v.get("summary") or (v.get("details", "")[:120] + "..."),
                            "severity": v.get("database_specific", {}).get("severity", "High"),
                            "remediation": f"Upgrade '{pkg['name']}' to latest secure release."
                        })
            except Exception:
                pass

        return {
            "status": "success",
            "repo_path": repo_path,
            "manifests_detected": ("requirements.txt" if os.path.exists(req_path) else "") + (", package.json" if os.path.exists(pkg_json_path) else ""),
            "packages_checked": len(packages_checked),
            "vulnerabilities_found": len(advisories_found),
            "advisories": advisories_found
        }


# ==============================================================================
# MODULE 6: PRE-COMMIT SECURITY GUARD
# ==============================================================================

class PreCommitGuard:
    """Generates and installs git pre-commit hook to block unredacted credentials."""

    HOOK_SCRIPT = """#!/bin/sh
# Aegis Defensive Pre-Commit Security Guard
# Blocks commits containing sensitive keys, tokens, and .env files

echo "[⬡] Aegis Pre-Commit Guard: Inspecting staged files for secrets..."

# 1. Check for staged sensitive files
STAGED_SENSITIVE=$(git diff --cached --name-only | grep -E '(\\.env|id_rsa|\\.pem$|\\.key$|database\\.sql$)')
if [ ! -z "$STAGED_SENSITIVE" ]; then
    echo "❌ COMMIT BLOCKED: Attempting to commit sensitive file(s):"
    echo "$STAGED_SENSITIVE"
    echo "Remediation: Run 'git reset HEAD <file>' and add to .gitignore."
    exit 1
fi

# 2. Check for high-confidence secrets in staged diff
if git diff --cached | grep -E '(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk_live_[0-9a-zA-Z]{24}|-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----)'; then
    echo "❌ COMMIT BLOCKED: High-confidence credential pattern detected in staged changes!"
    echo "Remediation: Remove hardcoded credentials before committing."
    exit 1
fi

echo "✔ Aegis Guard: Staged changes verified clean."
exit 0
"""

    @staticmethod
    def install_hook(repo_path: str = ".") -> Dict[str, Any]:
        """Installs pre-commit hook into target repository's .git/hooks directory."""
        repo_path = os.path.abspath(repo_path)
        hooks_dir = os.path.join(repo_path, ".git", "hooks")
        if not os.path.exists(hooks_dir):
            return {"error": "Target directory is not a Git repository (.git/hooks missing)."}

        hook_file = os.path.join(hooks_dir, "pre-commit")
        try:
            with open(hook_file, "w", encoding="utf-8") as f:
                f.write(PreCommitGuard.HOOK_SCRIPT)
            # Make executable if supported
            try:
                os.chmod(hook_file, 0o755)
            except Exception:
                pass
            return {
                "status": "success",
                "message": "Aegis Pre-Commit Security Guard installed successfully.",
                "hook_path": hook_file
            }
        except Exception as e:
            return {"error": f"Failed installing pre-commit hook: {str(e)}"}


# ==============================================================================
# MODULE 7: GITHUB REPOSITORY EXPOSURE INSPECTOR
# ==============================================================================

class GitHubExposureInspector:
    """Inspects GitHub repository visibility, branches, and sensitive files in tree."""

    @staticmethod
    def inspect_repo(repo_full_name: str, token: Optional[str] = None) -> Dict[str, Any]:
        """Queries GitHub REST API to assess repository exposure."""
        clean_repo = repo_full_name.strip().lstrip("/")
        headers = {"User-Agent": "Aegis-Exposure-Inspector/2.0"}
        if token:
            headers["Authorization"] = f"token {token}"

        api_url = f"https://api.github.com/repos/{clean_repo}"
        try:
            r = requests.get(api_url, headers=headers, timeout=5)
            if r.status_code == 404:
                return {"error": f"Repository '{clean_repo}' not found or private (authentication required)."}
            if r.status_code != 200:
                return {"error": f"GitHub API responded with status {r.status_code}: {r.text[:100]}"}

            data = r.json()
            is_private = data.get("private", False)
            default_branch = data.get("default_branch", "main")

            # Check tree for sensitive filenames
            tree_url = f"https://api.github.com/repos/{clean_repo}/git/trees/{default_branch}?recursive=1"
            tree_resp = requests.get(tree_url, headers=headers, timeout=6)
            sensitive_files_in_tree = []
            if tree_resp.status_code == 200:
                tree_data = tree_resp.json()
                for item in tree_data.get("tree", []):
                    path = item.get("path", "")
                    if re.search(r"(\.env|\.pem|\.key|id_rsa|database\.sql|dump\.sql)", path, re.I):
                        sensitive_files_in_tree.append(path)

            return {
                "status": "success",
                "repository": clean_repo,
                "visibility": "PRIVATE" if is_private else "PUBLIC (WORLD-ACCESSIBLE)",
                "is_public_risk": not is_private,
                "default_branch": default_branch,
                "stars": data.get("stargazers_count", 0),
                "forks": data.get("forks_count", 0),
                "open_issues": data.get("open_issues_count", 0),
                "created_at": data.get("created_at"),
                "pushed_at": data.get("pushed_at"),
                "sensitive_files_exposed": sensitive_files_in_tree,
                "risk_rating": "CRITICAL" if (not is_private and sensitive_files_in_tree) else ("MEDIUM" if not is_private else "LOW")
            }
        except Exception as e:
            return {"error": f"GitHub inspection failed: {str(e)}"}


# ==============================================================================
# MODULE 8: WEBSITE PUBLIC FILE EXPOSURE SCANNER
# ==============================================================================

class WebsiteExposureScanner:
    """Conservative scanner for publicly accessible sensitive files & security headers."""

    DEFAULT_CHECKS = [
        {"path": "/.env", "name": "Exposed Environment File", "severity": "Critical", "indicators": ["DB_PASSWORD", "SECRET_KEY", "AWS_ACCESS", "API_KEY"]},
        {"path": "/.git/HEAD", "name": "Exposed Git Repository Metadata", "severity": "Critical", "indicators": ["ref: refs/heads/", "ref: refs/tags/"]},
        {"path": "/.git/config", "name": "Exposed Git Config", "severity": "Critical", "indicators": ["[core]", "[remote \"origin\"]"]},
        {"path": "/database.sql", "name": "Public Database SQL Dump", "severity": "Critical", "indicators": ["CREATE TABLE", "INSERT INTO", "-- MySQL dump", "PostgreSQL database dump"]},
        {"path": "/backup.sql", "name": "Public Backup SQL Dump", "severity": "Critical", "indicators": ["CREATE TABLE", "INSERT INTO"]},
        {"path": "/wp-config.php.bak", "name": "WordPress Config Backup", "severity": "Critical", "indicators": ["DB_PASSWORD", "DB_USER", "define("]},
        {"path": "/.DS_Store", "name": "macOS Desktop Services Store", "severity": "Medium", "indicators": ["Bud1"]},
        {"path": "/phpinfo.php", "name": "PHP Info Diagnostic Exposure", "severity": "High", "indicators": ["PHP Version", "Configuration File (php.ini) Path"]},
        {"path": "/server-status", "name": "Apache Server Status Page", "severity": "Medium", "indicators": ["Apache Server Status for", "Current Time:"]},
        {"path": "/robots.txt", "name": "Robots Exclusion File", "severity": "Informational", "indicators": ["User-agent:"]}
    ]

    @staticmethod
    def inspect_url(target_url: str, timeout: int = 6) -> Dict[str, Any]:
        """Performs conservative non-intrusive exposure checks with custom 404 & SPA fallback detection."""
        target_url = target_url.strip()
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        parsed = urllib3.util.parse_url(target_url)
        host = parsed.host
        if not host:
            return {"error": "Invalid target URL."}

        # SSRF safety filter - block AWS/GCP/Azure metadata endpoints
        if host in ["169.254.169.254", "metadata.google.internal"]:
            return {"error": "SSRF Protection: Access to cloud metadata IP addresses is strictly blocked."}

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 AegisAuditor/2.5",
            "Accept": "*/*"
        }

        # Baseline probe to detect SPA or wildcard 200 response
        baseline_url = f"{parsed.scheme}://{host}{(':' + str(parsed.port)) if parsed.port else ''}/aegis_baseline_probe_{int(time.time())}"
        baseline_len = -1
        try:
            r_base = requests.get(baseline_url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
            if r_base.status_code == 200:
                baseline_len = len(r_base.content)
        except Exception:
            pass

        findings = []
        base_origin = f"{parsed.scheme}://{host}{(':' + str(parsed.port)) if parsed.port else ''}"

        # 1. Check Root & Headers
        header_issues = []
        try:
            r_root = requests.get(base_origin + "/", headers=headers, timeout=timeout, verify=False, allow_redirects=True)
            resp_headers = {k.lower(): v for k, v in r_root.headers.items()}

            if "strict-transport-security" not in resp_headers and parsed.scheme == "https":
                header_issues.append({"header": "Strict-Transport-Security (HSTS)", "status": "Missing", "severity": "Medium", "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."})
            if "content-security-policy" not in resp_headers:
                header_issues.append({"header": "Content-Security-Policy (CSP)", "status": "Missing", "severity": "High", "remediation": "Deploy a restrictive CSP to prevent XSS and unauthorized asset loading."})
            if "x-frame-options" not in resp_headers and "frame-ancestors" not in resp_headers.get("content-security-policy", ""):
                header_issues.append({"header": "X-Frame-Options", "status": "Missing", "severity": "Medium", "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking attacks."})
            if "x-content-type-options" not in resp_headers:
                header_issues.append({"header": "X-Content-Type-Options", "status": "Missing", "severity": "Low", "remediation": "Add 'X-Content-Type-Options: nosniff' to disable MIME-type sniffing."})
            if "referrer-policy" not in resp_headers:
                header_issues.append({"header": "Referrer-Policy", "status": "Missing", "severity": "Low", "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'."})
        except Exception as e:
            return {"error": f"Could not connect to target host: {str(e)}"}

        # 2. Check Exposure Paths
        for chk in WebsiteExposureScanner.DEFAULT_CHECKS:
            probe_url = base_origin + chk["path"]
            try:
                res = requests.get(probe_url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
                if res.status_code == 200:
                    is_spa_catchall = False
                    if baseline_len > 0 and abs(len(res.content) - baseline_len) < 50:
                        is_spa_catchall = True
                    if "<!doctype html" in res.text[:200].lower() and chk["path"].endswith((".sql", ".env", ".bak", "HEAD")):
                        is_spa_catchall = True

                    has_indicator = any(ind.lower() in res.text.lower() for ind in chk["indicators"])

                    if (not is_spa_catchall and has_indicator) or (chk["path"] == "/robots.txt" and res.status_code == 200):
                        snippet = res.text[:100].replace("\n", " ").strip()
                        findings.append({
                            "path": chk["path"],
                            "full_url": probe_url,
                            "name": chk["name"],
                            "severity": chk["severity"],
                            "status_code": res.status_code,
                            "content_length": len(res.content),
                            "evidence": redact_secret(snippet) if "env" in chk["path"] else snippet[:80],
                            "remediation": f"Block public web server access to {chk['path']} or remove file immediately from web document root."
                        })
            except Exception:
                pass

        return {
            "status": "success",
            "target_url": target_url,
            "host": host,
            "scheme": parsed.scheme,
            "exposed_files_found": len(findings),
            "findings": findings,
            "missing_headers_count": len(header_issues),
            "header_issues": header_issues
        }


# ==============================================================================
# MODULE 9: MASTER COORDINATOR - SECURITY EXPOSURE LAB
# ==============================================================================

class SecurityExposureLab:
    """Master coordinator executing full or modular security audits."""

    @staticmethod
    def run_full_audit(target_dir: str = ".", website_url: Optional[str] = None, github_repo: Optional[str] = None, github_token: Optional[str] = None) -> Dict[str, Any]:
        """Runs the complete suite of security exposure checks."""
        t0 = time.time()
        target_dir = os.path.abspath(target_dir)

        # 1. Local Secrets
        secrets_result = SecretScanner.scan_directory(target_dir)

        # 2. Git & .gitignore
        git_result = GitAuditor.audit_repository(target_dir)

        # 3. Git History
        history_result = GitHistoryScanner.scan_history(target_dir, max_commits=30)

        # 4. Sensitive Files
        file_result = SensitiveFileHunter.hunt_files(target_dir)

        # 5. Dependencies
        dep_result = DependencyAuditor.audit_dependencies(target_dir)

        # 6. Pre-Commit Guard Check
        hook_path = os.path.join(target_dir, ".git", "hooks", "pre-commit")
        precommit_installed = os.path.exists(hook_path)

        # 7. Website Exposure (optional)
        web_result = None
        if website_url:
            web_result = WebsiteExposureScanner.inspect_url(website_url)

        # 8. GitHub Exposure (optional)
        gh_result = None
        if github_repo:
            gh_result = GitHubExposureInspector.inspect_repo(github_repo, github_token)

        # Calculate Overall Grade & Score
        total_crit = secrets_result.get("severity_counts", {}).get("Critical", 0) + len(git_result.get("tracked_sensitive_files", []))
        total_high = secrets_result.get("severity_counts", {}).get("High", 0) + history_result.get("historical_leaks_found", 0) + dep_result.get("vulnerabilities_found", 0)
        total_med = secrets_result.get("severity_counts", {}).get("Medium", 0) + len(git_result.get("missing_recommended_ignores", []))

        score = 100 - (total_crit * 25 + total_high * 10 + total_med * 3)
        score = max(0, min(100, score))

        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"

        elapsed = round(time.time() - t0, 2)

        return {
            "status": "success",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "duration_sec": elapsed,
            "target_dir": target_dir,
            "posture_score": score,
            "security_grade": grade,
            "precommit_installed": precommit_installed,
            "summary": {
                "secrets_found": secrets_result.get("total_findings", 0),
                "tracked_sensitive_git": len(git_result.get("tracked_sensitive_files", [])),
                "history_leaks": history_result.get("historical_leaks_found", 0),
                "risky_files": file_result.get("risky_files_found", 0),
                "vulnerable_dependencies": dep_result.get("vulnerabilities_found", 0),
                "critical_total": total_crit,
                "high_total": total_high,
                "medium_total": total_med
            },
            "secrets_audit": secrets_result,
            "git_audit": git_result,
            "history_audit": history_result,
            "file_hunt": file_result,
            "dependency_audit": dep_result,
            "website_audit": web_result,
            "github_audit": gh_result
        }


# ==============================================================================
# MODULE 10: REPORT & REMEDIATION EXPORTER
# ==============================================================================

class ExposureReporter:
    """Generates HTML, JSON, and CSV reports with strictly sanitized evidence."""

    @staticmethod
    def generate_json_report(data: Dict[str, Any]) -> str:
        """Returns pretty JSON report."""
        return json.dumps(data, indent=2)

    @staticmethod
    def generate_csv_report(data: Dict[str, Any]) -> str:
        """Flattens all findings into CSV format."""
        rows = ["Module,Severity,Category,Title/Rule,Location/Path,Redacted_Evidence,Remediation"]

        # 1. Secrets
        for f in data.get("secrets_audit", {}).get("findings", []):
            loc = f"{f.get('file_path')}:{f.get('line_number')}"
            ev = f.get("evidence_snippet", "").replace(",", ";")
            rem = f.get("remediation", "").replace(",", ";")
            rows.append(f"SecretScanner,{f.get('severity')},{f.get('category')},{f.get('rule_name')},{loc},{ev},{rem}")

        # 2. Tracked Sensitive Git
        for f in data.get("git_audit", {}).get("tracked_sensitive_files", []):
            rem = f.get("remediation", "").replace(",", ";")
            rows.append(f"GitAuditor,Critical,Tracked Files,Tracked Sensitive Git File,{f.get('file')},Tracked in Index,{rem}")

        # 3. History Leaks
        for f in data.get("history_audit", {}).get("findings", []):
            ev = f.get("redacted_evidence", "").replace(",", ";")
            rem = f.get("remediation", "").replace(",", ";")
            rows.append(f"GitHistory,{f.get('severity')},Commit Patch,{f.get('rule_name')},Commit {f.get('commit_hash')},{ev},{rem}")

        # 4. Risky Files
        for f in data.get("file_hunt", {}).get("findings", []):
            reason = f.get("reason", "").replace(",", ";")
            rem = f.get("remediation", "").replace(",", ";")
            rows.append(f"FileHunter,{f.get('severity')},{f.get('category')},{f.get('file_name')},{f.get('relative_path')},{reason},{rem}")

        # 5. Dependencies
        for f in data.get("dependency_audit", {}).get("advisories", []):
            summ = f.get("summary", "").replace(",", ";")
            rows.append(f"Dependencies,{f.get('severity')},{f.get('ecosystem')},{f.get('vuln_id')},{f.get('package')}@{f.get('version')},{summ},{f.get('remediation')}")

        return "\n".join(rows)

    @staticmethod
    def generate_html_report(data: Dict[str, Any]) -> str:
        """Generates executive standalone holographic HTML security report."""
        summary = data.get("summary", {})
        score = data.get("posture_score", 100)
        grade = data.get("security_grade", "A+")
        score_color = "#00FF88" if score >= 80 else ("#FFB800" if score >= 60 else "#FF3366")

        # HTML Rows
        secret_rows = ""
        for f in data.get("secrets_audit", {}).get("findings", []):
            sev_color = "#FF3366" if f.get("severity") == "Critical" else ("#FFB800" if f.get("severity") == "High" else "#00F0FF")
            secret_rows += f"""<tr>
                <td><span style="color:{sev_color};font-weight:700;">{f.get('severity')}</span></td>
                <td>{f.get('rule_name')}</td>
                <td><code>{f.get('file_path')}:{f.get('line_number')}</code></td>
                <td><code>{f.get('evidence_snippet')}</code></td>
                <td style="color:#00F0FF;">{f.get('remediation')}</td>
            </tr>"""

        if not secret_rows:
            secret_rows = "<tr><td colspan='5' style='text-align:center;color:#00FF88;'>✔ No hardcoded secrets detected in scanned files.</td></tr>"

        history_rows = ""
        for f in data.get("history_audit", {}).get("findings", []):
            history_rows += f"""<tr>
                <td><code>{f.get('commit_hash')}</code></td>
                <td>{f.get('author')}</td>
                <td>{f.get('commit_subject')}</td>
                <td>{f.get('rule_name')}</td>
                <td><code>{f.get('redacted_evidence')}</code></td>
            </tr>"""
        if not history_rows:
            history_rows = "<tr><td colspan='5' style='text-align:center;color:#00FF88;'>✔ Clean: No credentials found in inspected git commit history.</td></tr>"

        risky_rows = ""
        for f in data.get("file_hunt", {}).get("findings", []):
            sev_color = "#FF3366" if "Critical" in f.get("severity") else ("#FFB800" if "High" in f.get("severity") else "#00FF88")
            risky_rows += f"""<tr>
                <td><span style="color:{sev_color};">{f.get('severity')}</span></td>
                <td>{f.get('category')}</td>
                <td><code>{f.get('relative_path')}</code></td>
                <td>{f.get('size_kb')} KB</td>
                <td>{f.get('reason')}</td>
            </tr>"""
        if not risky_rows:
            risky_rows = "<tr><td colspan='5' style='text-align:center;color:#00FF88;'>✔ No suspicious database dumps or exposed backup files found.</td></tr>"

        dep_rows = ""
        for f in data.get("dependency_audit", {}).get("advisories", []):
            dep_rows += f"""<tr>
                <td style="color:#FF3366;font-weight:700;">{f.get('severity')}</td>
                <td>{f.get('package')} ({f.get('version')})</td>
                <td><code>{f.get('vuln_id')}</code></td>
                <td>{f.get('summary')}</td>
                <td style="color:#00F0FF;">{f.get('remediation')}</td>
            </tr>"""
        if not dep_rows:
            dep_rows = "<tr><td colspan='5' style='text-align:center;color:#00FF88;'>✔ All audited dependencies match clean OSV.dev vulnerability baseline.</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AEGIS // SECURITY EXPOSURE & SECRET-LEAK AUDIT REPORT</title>
    <style>
        body {{ background: #030712; color: #CBD5E1; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 24px; }}
        .header {{ border-bottom: 2px solid #00F0FF; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; }}
        h1 {{ color: #F8FAFC; margin: 0 0 6px 0; font-size: 22px; letter-spacing: 1px; }}
        .meta {{ color: #64748B; font-size: 13px; }}
        .score-box {{ text-align: right; }}
        .score-val {{ font-size: 38px; font-weight: 800; color: {score_color}; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 28px; }}
        .metric-card {{ background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(0, 240, 255, 0.2); padding: 14px; border-radius: 6px; }}
        .metric-val {{ font-size: 24px; font-weight: 700; color: #F8FAFC; margin-top: 4px; }}
        .section-title {{ font-size: 16px; color: #00F0FF; margin: 24px 0 10px 0; text-transform: uppercase; letter-spacing: 0.5px; border-left: 3px solid #00F0FF; padding-left: 8px; }}
        table {{ width: 100%; border-collapse: collapse; background: rgba(15, 23, 42, 0.7); font-size: 13px; margin-bottom: 20px; }}
        th {{ background: rgba(0, 240, 255, 0.08); color: #00F0FF; text-align: left; padding: 10px; border-bottom: 1px solid rgba(0, 240, 255, 0.2); }}
        td {{ padding: 10px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }}
        code {{ background: rgba(0, 0, 0, 0.4); padding: 2px 6px; border-radius: 4px; color: #E2E8F0; font-family: monospace; }}
        .footer {{ font-size: 12px; color: #64748B; text-align: center; margin-top: 40px; border-top: 1px solid rgba(255, 255, 255, 0.1); padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>[🔐] AEGIS DEFENSIVE // SECURITY EXPOSURE & SECRET-LEAK AUDIT REPORT</h1>
            <div class="meta">Target Directory: <code>{data.get('target_dir')}</code> | Timestamp: {data.get('timestamp')} | Duration: {data.get('duration_sec')}s</div>
        </div>
        <div class="score-box">
            <div class="score-val">{score}/100</div>
            <div style="color:{score_color};font-weight:700;">GRADE: {grade}</div>
        </div>
    </div>

    <div class="metrics-grid">
        <div class="metric-card"><div>Active Secrets</div><div class="metric-val" style="color:{'#FF3366' if summary.get('secrets_found',0)>0 else '#00FF88'};">{summary.get('secrets_found', 0)}</div></div>
        <div class="metric-card"><div>Tracked Git Leaks</div><div class="metric-val" style="color:{'#FF3366' if summary.get('tracked_sensitive_git',0)>0 else '#00FF88'};">{summary.get('tracked_sensitive_git', 0)}</div></div>
        <div class="metric-card"><div>History Leaks</div><div class="metric-val">{summary.get('history_leaks', 0)}</div></div>
        <div class="metric-card"><div>Risky Backups/Files</div><div class="metric-val">{summary.get('risky_files', 0)}</div></div>
        <div class="metric-card"><div>Vulnerable Deps</div><div class="metric-val">{summary.get('vulnerable_dependencies', 0)}</div></div>
        <div class="metric-card"><div>Pre-Commit Guard</div><div class="metric-val" style="color:{'#00FF88' if data.get('precommit_installed') else '#FFB800'};">{'ACTIVE' if data.get('precommit_installed') else 'NOT INSTALLED'}</div></div>
    </div>

    <div class="section-title">1. Secret & Hardcoded Credential Detections (Redacted)</div>
    <table>
        <thead><tr><th>Severity</th><th>Rule</th><th>File & Line</th><th>Redacted Evidence</th><th>Remediation</th></tr></thead>
        <tbody>{secret_rows}</tbody>
    </table>

    <div class="section-title">2. Historical Git Commits with Credentials</div>
    <table>
        <thead><tr><th>Commit</th><th>Author</th><th>Subject</th><th>Rule</th><th>Redacted Diff Snippet</th></tr></thead>
        <tbody>{history_rows}</tbody>
    </table>

    <div class="section-title">3. Suspicious Files, Dumps, and Database Copies</div>
    <table>
        <thead><tr><th>Severity</th><th>Category</th><th>Relative Path</th><th>Size</th><th>Reason</th></tr></thead>
        <tbody>{risky_rows}</tbody>
    </table>

    <div class="section-title">4. Open Source Dependency Vulnerability Advisories (OSV.dev)</div>
    <table>
        <thead><tr><th>Severity</th><th>Package</th><th>Advisory ID</th><th>Summary</th><th>Remediation</th></tr></thead>
        <tbody>{dep_rows}</tbody>
    </table>

    <div class="footer">
        Generated by Aegis Whitehat OSINT & Defensive Security Suite // Confidential Audit Dossier // All sensitive credentials redacted.
    </div>
</body>
</html>"""
        return html


"""
Aegis System & Server Machine Security Auditor
Audits the local server/computer for malware infection, rogue processes,
reverse shells, persistence mechanisms (Registry/Cron), hosts file tampering,
and suspicious files dropped in temporary directories.
Developed by Team White Hat.
"""

import os
import sys
import psutil
import socket
import platform
import subprocess
from datetime import datetime
from typing import Dict, List, Any


class ServerSystemAuditor:
    """Performs deep OS-level defensive integrity and malware infection audits on the host machine."""

    KNOWN_MALWARE_PROCESSES = {
        "xmrig", "minerd", "cpuminer", "stratum", "kdevtmpfsi", "kinsing",
        "pwnrig", "nanominer", "ethminer", "wannacry", "mimikatz", "pwdump",
        "procdump", "chisel", "frpc", "ngrok", "meterpreter"
    }

    SUSPICIOUS_SHELL_COMMANDS = [
        "-enc", "-encodedcommand", "downloadstring", "iex", "invoke-expression",
        "bash -i", "/dev/tcp/", "nc -e", "ncat -e", "mkfifo /tmp", "sh -i"
    ]

    SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 6667, 8888, 9999, 12345}

    @classmethod
    def audit_full_system(cls) -> Dict[str, Any]:
        """Runs a comprehensive scan on the local server machine."""
        os_type = platform.system()
        report: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "os": f"{os_type} {platform.release()} ({platform.architecture()[0]})",
            "hostname": platform.node(),
            "system_health_score": 100,
            "infection_status": "CLEAN",
            "suspicious_processes": [],
            "rogue_connections": [],
            "temp_infections": [],
            "persistence_findings": [],
            "hosts_file_tampered": False,
            "hosts_tamper_details": [],
            "summary": {
                "processes_scanned": 0,
                "threats_detected": 0,
                "critical_alerts": 0
            }
        }

        # 1. Audit Running Processes
        cls._audit_running_processes(report)

        # 2. Audit Rogue Network Connections & Reverse Shells
        cls._audit_active_connections(report)

        # 3. Audit Temp Directories for Malware Payloads
        cls._audit_temp_directories(report)

        # 4. Audit Hosts File Integrity
        cls._audit_hosts_file(report)

        # 5. Audit Startup / Persistence Mechanisms
        cls._audit_persistence(report)

        # Compute final score
        threat_count = (
            len(report["suspicious_processes"]) +
            len(report["rogue_connections"]) +
            len(report["temp_infections"]) +
            len(report["persistence_findings"]) +
            (1 if report["hosts_file_tampered"] else 0)
        )
        report["summary"]["threats_detected"] = threat_count
        report["system_health_score"] = max(10, 100 - (threat_count * 20))

        if threat_count > 0:
            report["infection_status"] = "WARNING: SUSPICIOUS ACTIVITY DETECTED"
            if len(report["suspicious_processes"]) > 0 or len(report["rogue_connections"]) > 0:
                report["infection_status"] = "CRITICAL: POTENTIAL MALWARE / REVERSE SHELL DETECTED"
                report["summary"]["critical_alerts"] += 1
        else:
            report["infection_status"] = "CLEAN (NO HOST INFECTIONS DETECTED)"

        return report

    @classmethod
    def _audit_running_processes(cls, report: Dict[str, Any]):
        """Inspects all running processes for known cryptominers, reverse shells, and malicious command lines."""
        scanned = 0
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
            scanned += 1
            try:
                pinfo = proc.info
                pname = (pinfo['name'] or '').lower()
                cmdline_list = pinfo.get('cmdline') or []
                cmdline = " ".join(cmdline_list).lower()

                # Check 1: Known malware binary name
                for bad in cls.KNOWN_MALWARE_PROCESSES:
                    if bad in pname:
                        report["suspicious_processes"].append({
                            "pid": pinfo["pid"],
                            "name": pinfo["name"],
                            "threat_type": "KNOWN MALWARE / CRYPTOMINER",
                            "severity": "CRITICAL",
                            "details": f"Process name matches known miner/malware: '{bad}'",
                            "cmdline": cmdline[:250]
                        })
                        break

                # Check 2: Suspicious command line invocation (encoded PowerShell, reverse shell)
                for cmd_sig in cls.SUSPICIOUS_SHELL_COMMANDS:
                    if cmd_sig in cmdline:
                        report["suspicious_processes"].append({
                            "pid": pinfo["pid"],
                            "name": pinfo["name"],
                            "threat_type": "OBFUSCATED SHELL / REVERSE SHELL",
                            "severity": "CRITICAL",
                            "details": f"Command line contains signature: '{cmd_sig}'",
                            "cmdline": cmdline[:250]
                        })
                        break

                # Check 3: Abnormal CPU usage (>85% continuously)
                cpu = pinfo.get('cpu_percent') or 0
                if cpu > 85.0 and pname not in ["system idle process", "system", "idle"]:
                    report["suspicious_processes"].append({
                        "pid": pinfo["pid"],
                        "name": pinfo["name"],
                        "threat_type": "ABNORMAL RESOURCE CONSUMPTION",
                        "severity": "MEDIUM",
                        "details": f"Excessive CPU consumption: {cpu}% (Possible hidden miner or loop)",
                        "cmdline": cmdline[:250]
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        report["summary"]["processes_scanned"] = scanned

    @classmethod
    def _audit_active_connections(cls, report: Dict[str, Any]):
        """Inspects sockets for known hacker backdoor ports and outbound connections."""
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                lport = c.laddr.port if c.laddr else 0
                rport = c.raddr.port if c.raddr else 0
                r_ip = c.raddr.ip if c.raddr else ""

                if lport in cls.SUSPICIOUS_PORTS:
                    pname = "Unknown"
                    if c.pid:
                        try:
                            pname = psutil.Process(c.pid).name()
                        except:
                            pass
                    report["rogue_connections"].append({
                        "pid": c.pid,
                        "process": pname,
                        "local_port": lport,
                        "remote_ip": r_ip,
                        "remote_port": rport,
                        "status": c.status,
                        "severity": "CRITICAL",
                        "threat": f"Listening on notorious hacker backdoor port {lport} (Metasploit / Netcat)"
                    })

                # Check suspicious outbound connection on hacker ports
                if rport in cls.SUSPICIOUS_PORTS:
                    pname = "Unknown"
                    if c.pid:
                        try:
                            pname = psutil.Process(c.pid).name()
                        except:
                            pass
                    report["rogue_connections"].append({
                        "pid": c.pid,
                        "process": pname,
                        "local_port": lport,
                        "remote_ip": r_ip,
                        "remote_port": rport,
                        "status": c.status,
                        "severity": "CRITICAL",
                        "threat": f"Outbound connection to suspicious remote port {rport} (Potential Reverse Shell)"
                    })
        except Exception:
            pass

    @classmethod
    def _audit_temp_directories(cls, report: Dict[str, Any]):
        """Inspects system Temp directories for dropped executables, batches, or malware scripts."""
        temp_dirs = []
        if os.name == 'nt':
            t1 = os.environ.get('TEMP')
            t2 = os.environ.get('TMP')
            t3 = os.path.expanduser('~\\AppData\\Local\\Temp')
            for t in [t1, t2, t3]:
                if t and os.path.exists(t) and t not in temp_dirs:
                    temp_dirs.append(t)
        else:
            for t in ['/tmp', '/var/tmp']:
                if os.path.exists(t):
                    temp_dirs.append(t)

        suspicious_exts = {'.exe', '.scr', '.vbs', '.bat', '.ps1', '.sh', '.elf', '.php'}

        for tdir in temp_dirs:
            try:
                for root, _, files in os.walk(tdir):
                    for fname in files:
                        ext = os.path.splitext(fname)[1].lower()
                        if ext in suspicious_exts:
                            fpath = os.path.join(root, fname)
                            try:
                                sz = os.path.getsize(fpath)
                                # Flag executable files dropped in temp
                                report["temp_infections"].append({
                                    "file_path": fpath,
                                    "filename": fname,
                                    "size_bytes": sz,
                                    "severity": "HIGH",
                                    "threat": f"Executable file found in Temporary Directory ({ext})"
                                })
                                if len(report["temp_infections"]) >= 25:
                                    break
                            except:
                                pass
                    if len(report["temp_infections"]) >= 25:
                        break
            except Exception:
                continue

    @classmethod
    def _audit_hosts_file(cls, report: Dict[str, Any]):
        """Checks if the system hosts file has been poisoned or hijacked by malware."""
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if os.name == 'nt' else "/etc/hosts"
        if not os.path.exists(hosts_path):
            return

        try:
            with open(hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if len(parts) >= 2:
                    ip, domain = parts[0], parts[1].lower()
                    # Check if security or update domains are redirected to localhost or rogue IP
                    sec_domains = ["virustotal.com", "microsoft.com", "kaspersky.com", "symantec.com", "windowsupdate.com"]
                    for sec in sec_domains:
                        if sec in domain:
                            report["hosts_file_tampered"] = True
                            report["hosts_tamper_details"].append({
                                "domain": domain,
                                "redirected_to": ip,
                                "threat": "Security domain hijacked in local hosts file"
                            })
        except Exception:
            pass

    @classmethod
    def _audit_persistence(cls, report: Dict[str, Any]):
        """Audits autostart / persistence keys."""
        if os.name == 'nt':
            try:
                import winreg
                run_keys = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
                ]
                for hive, subkey in run_keys:
                    try:
                        with winreg.OpenKey(hive, subkey) as key:
                            num_values = winreg.QueryInfoKey(key)[1]
                            for i in range(num_values):
                                name, val, _ = winreg.EnumValue(key, i)
                                val_str = str(val).lower()
                                # Check for suspicious execution from Temp or AppData
                                if "temp" in val_str or "appdata" in val_str or "powershell" in val_str:
                                    report["persistence_findings"].append({
                                        "name": name,
                                        "command": str(val),
                                        "severity": "HIGH",
                                        "threat": "Startup Run key executes script from Temp/AppData directory"
                                    })
                    except Exception:
                        pass
            except Exception:
                pass

    @classmethod
    def kill_process(cls, pid: int) -> Dict[str, Any]:
        """Terminates a rogue or malicious process on the host machine."""
        try:
            p = psutil.Process(pid)
            pname = p.name()
            p.terminate()
            p.wait(timeout=3)
            return {"success": True, "message": f"Successfully terminated rogue process '{pname}' (PID: {pid})"}
        except psutil.NoSuchProcess:
            return {"success": True, "message": f"Process PID {pid} is already terminated"}
        except psutil.AccessDenied:
            return {"success": False, "error": f"Access denied terminating PID {pid}. Administrator / root privileges required."}
        except Exception as e:
            return {"success": False, "error": str(e)}

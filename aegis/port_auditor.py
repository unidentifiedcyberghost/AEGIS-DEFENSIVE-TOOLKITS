"""
Aegis Localhost Port & Service Listener Auditor
Cross-Platform network listening socket inspector (Windows, Linux, macOS)
Detects accidental external exposure of sensitive local services.
"""

import socket
from typing import List, Dict, Any
import psutil

COMMON_SERVICES = {
    80: ("HTTP", "Standard Web Server", "Medium"),
    443: ("HTTPS", "Secure Web Server", "Low"),
    3000: ("Node/React Dev", "Frontend Development Server", "Medium"),
    3306: ("MySQL/MariaDB", "Relational Database", "High"),
    5432: ("PostgreSQL", "Relational Database", "High"),
    6379: ("Redis", "In-Memory Cache (Often Unauthenticated)", "Critical"),
    8000: ("HTTP Dev", "Django/FastAPI/Python Dev Server", "Medium"),
    8080: ("HTTP Alt", "Tomcat/Spring/Proxy Web Server", "Medium"),
    8443: ("HTTPS Alt", "Secondary SSL Web Server", "Low"),
    9200: ("Elasticsearch", "Search Index / Data Store", "High"),
    27017: ("MongoDB", "NoSQL Database", "Critical"),
    5173: ("Vite Dev", "Frontend Bundler Server", "Low"),
}


class PortAuditor:
    """Audits local network listeners and flags risky network bindings."""

    @staticmethod
    def audit_listeners() -> List[Dict[str, Any]]:
        listeners = []
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            connections = []

        if connections:
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN:
                    laddr = conn.laddr
                    ip = laddr.ip
                    port = laddr.port

                    pid = conn.pid
                    pname = "Unknown"
                    if pid:
                        try:
                            pname = psutil.Process(pid).name()
                        except Exception:
                            pname = "System/Protected"

                    is_all_interfaces = (ip in ("0.0.0.0", "::", "*", ""))
                    service_info = COMMON_SERVICES.get(port, ("Custom Service", "Application Port", "Low"))
                    service_name, desc, base_sev = service_info

                    if is_all_interfaces and base_sev in ("High", "Critical"):
                        risk_level = "Critical"
                        risk_msg = f"Database/Cache '{service_name}' on port {port} is bound to 0.0.0.0 (exposed to LAN/WAN)!"
                        remediation = "Change service config to bind strictly to '127.0.0.1' instead of '0.0.0.0'."
                    elif is_all_interfaces:
                        risk_level = "Medium"
                        risk_msg = f"Service '{service_name}' on port {port} listens on all interfaces (0.0.0.0)."
                        remediation = "If this is a local development server, bind to 127.0.0.1 to avoid exposing it to your local network."
                    else:
                        risk_level = "Pass"
                        risk_msg = f"Service '{service_name}' on port {port} is securely restricted to localhost ({ip})."
                        remediation = "Properly restricted to local loopback interface."

                    listeners.append({
                        "port": port,
                        "ip": ip,
                        "bind_address": ip,
                        "pid": pid,
                        "process_name": pname,
                        "service": service_name,
                        "description": desc,
                        "risk_level": risk_level,
                        "risk_message": risk_msg,
                        "advisory": risk_msg,
                        "remediation": remediation,
                        "is_all_interfaces": is_all_interfaces,
                        "is_wildcard": is_all_interfaces
                    })
        else:
            # Cross-Platform Fallback: Direct Socket Probing (Linux/macOS unprivileged mode)
            for port, (sname, desc, base_sev) in COMMON_SERVICES.items():
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.15)
                res = s.connect_ex(("127.0.0.1", port))
                s.close()
                if res == 0:
                    listeners.append({
                        "port": port,
                        "ip": "127.0.0.1",
                        "bind_address": "127.0.0.1",
                        "pid": None,
                        "process_name": sname,
                        "service": sname,
                        "description": desc,
                        "risk_level": "Pass",
                        "risk_message": f"Active service detected on localhost ({sname}) via socket check.",
                        "advisory": f"Active service detected on localhost ({sname}) via socket check.",
                        "remediation": "Loopback service active.",
                        "is_all_interfaces": False,
                        "is_wildcard": False
                    })

        listeners.sort(key=lambda x: x["port"])
        return listeners

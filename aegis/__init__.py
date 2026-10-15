"""
AegisHUD - Defensive Localhost & Web Security Audit Suite
Version: 1.0.0
Architecture: Python + PyQt6 HUD GUI + Go Core Engine + Rust Engine
"""

__version__ = "1.0.0"
__author__ = "Defensive Security Engineering Team"

# Global Defensive Security: Suppress unverified HTTPS warnings for self-signed & test environments
import warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message=".*Unverified HTTPS request.*")


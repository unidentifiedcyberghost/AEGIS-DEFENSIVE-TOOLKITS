"""
Aegis Defensive Security Suite - Web HUD Launcher
Launches the Localhost Web Dashboard on http://127.0.0.1:5000.
Developed by Team White Hat.
"""

from aegis.web_app import run_web

if __name__ == "__main__":
    run_web(host="127.0.0.1", port=5000)

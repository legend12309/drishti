"""
DRISHTI — Standalone Desktop Executable Entrypoint
Launches the local air-gap security monolith and opens the native application window.
"""

import os
import sys
import time
import subprocess
import threading
import webbrowser
from pathlib import Path

# Set working directory to the script or executable's directory
if getattr(sys, 'frozen', False):
    APP_DIR = Path(sys.executable).parent
else:
    APP_DIR = Path(__file__).resolve().parent

os.chdir(APP_DIR)
sys.path.insert(0, str(APP_DIR))

# Load .env
from dotenv import load_dotenv
load_dotenv(APP_DIR / ".env")
load_dotenv()

import uvicorn
from backend.main import app

def run_server():
    """Runs uvicorn in a dedicated worker thread."""
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    server.run()

def open_desktop_window():
    """Launches DRISHTI in a standalone borderless desktop window."""
    time.sleep(1.5)
    url = "http://127.0.0.1:8000"

    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]

    for ep in edge_paths:
        if os.path.exists(ep):
            try:
                subprocess.Popen([ep, f"--app={url}", "--window-size=1440,920"])
                return
            except Exception:
                pass

    for cp in chrome_paths:
        if os.path.exists(cp):
            try:
                subprocess.Popen([cp, f"--app={url}", "--window-size=1440,920"])
                return
            except Exception:
                pass

    webbrowser.open(url)

if __name__ == "__main__":
    print("=" * 80)
    print("      DRISHTI // SOVEREIGN CYBER DEFENSE PLATFORM")
    print("      Air-Gap Monolith Desktop Suite v1.0.0")
    print("=" * 80)
    print("[+] Initializing local enclave storage...")
    print("[+] Serving cockit at http://127.0.0.1:8000")
    
    # Start browser / desktop window launcher in background thread
    launcher_thread = threading.Thread(target=open_desktop_window, daemon=True)
    launcher_thread.start()

    # Run uvicorn on main thread
    run_server()

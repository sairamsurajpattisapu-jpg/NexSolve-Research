"""Unified One-Command Startup & Demo Launcher for NexSolve.

SIH 2026 Problem Statement ID: 26153
"AI-based Network Attack Forecasting from Network Traffic Data"

Usage:
    python scripts/start_demo.py [--headless] [--port 8000] [--frontend-port 5173]
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV_PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
PYTHON_BIN = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable


def banner() -> None:
    print(r"""
======================================================================
  _   _           ____        _            
 | \ | | _____  _/ ___|  ___ | |_   _____  
 |  \| |/ _ \ \/ \___ \ / _ \| \ \ / / _ \ 
 | |\  |  __/>  < ___) | (_) | |\ V /  __/ 
 |_| \_|\___/_/\_\____/ \___/|_| \_/ \___| 
                                           
 AI-Powered Network Attack Forecasting & Early-Warning Platform
 SIH 2026 Problem Statement ID: 26153
 Unified Startup Orchestrator (Backend + Frontend)
======================================================================
""")


def main() -> int:
    parser = argparse.ArgumentParser(description="NexSolve Unified Startup Orchestrator")
    parser.add_argument("--headless", action="store_true", help="Do not launch web browser automatically")
    parser.add_argument("--backend-port", type=int, default=8000, help="Backend port (default: 8000)")
    parser.add_argument("--frontend-port", type=int, default=5173, help="Frontend port (default: 5173)")
    args = parser.parse_args()

    banner()
    print(f"[*] Workspace Root: {ROOT}")
    print(f"[*] Python Binary:  {PYTHON_BIN}")

    # 1. Start Backend Process
    print("\n[1/3] Launching FastAPI Backend Service...")
    backend_cmd = [
        PYTHON_BIN,
        "-m",
        "uvicorn",
        "model_service.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(args.backend_port),
    ]
    backend_proc = subprocess.Popen(
        backend_cmd,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"      [+] Backend running at http://127.0.0.1:{args.backend_port} (PID: {backend_proc.pid})")

    # 2. Start Frontend Process
    frontend_dir = ROOT / "frontend"
    print("\n[2/3] Launching Frontend SOC Command Center...")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    frontend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev", "--", "--port", str(args.frontend_port)],
        cwd=str(frontend_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"      [+] Frontend running at http://localhost:{args.frontend_port} (PID: {frontend_proc.pid})")

    # 3. Open Browser
    time.sleep(2.0)
    target_url = f"http://localhost:{args.frontend_port}/demo"
    print(f"\n[3/3] Ready! Open {target_url} to explore the SIH Live Demo.")
    if not args.headless:
        try:
            webbrowser.open(target_url)
        except Exception:
            pass

    print("\n" + "=" * 70)
    print("  NexSolve is running! Press Ctrl+C at any time to gracefully shut down.")
    print("=" * 70 + "\n")

    try:
        while True:
            time.sleep(1)
            if backend_proc.poll() is not None or frontend_proc.poll() is not None:
                break
    except KeyboardInterrupt:
        print("\n[*] Shutting down NexSolve services...")
    finally:
        for p in (backend_proc, frontend_proc):
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        print("[+] All services stopped cleanly.")

    return 0


if __name__ == "__main__":
    sys.exit(main())


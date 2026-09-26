"""NexSolve backend engine lifecycle and service management.

Handles health verification, local engine discovery, and automatic background
startup for seamless CLI operation without manual server intervention.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

from nexsolve.config import DEFAULT_API_URL
from nexsolve.errors import EngineStartupError, ServerConnectionError
from nexsolve.output.terminal import TerminalRenderer


def is_local_endpoint(url: str) -> bool:
    """Check if the given server URL points to the local machine."""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").lower()
        return host in ("127.0.0.1", "localhost", "0.0.0.0", "::1", "")
    except Exception:
        return False


def is_port_bound(host: str, port: int, timeout: float = 0.5) -> bool:
    """Check whether a TCP port is actively accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def check_engine_health(base_url: str, timeout: float = 1.0) -> bool:
    """Probe the NexSolve backend /health endpoint to verify engine readiness."""
    url = f"{base_url.rstrip('/')}/health"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "NexSolve-CLI/1.0", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw)
                return data.get("service_status") == "ok" or data.get("model_loaded") is True
    except Exception:
        return False
    return False


def find_project_root() -> Path | None:
    """Locate the root directory of the NexSolve repository."""
    # 1. Environment variable override
    if env_root := os.getenv("NEXSOLVE_ROOT"):
        p = Path(env_root).resolve()
        if (p / "model_service" / "app.py").exists():
            return p

    # 2. Ascend from the location of this source file
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "model_service" / "app.py").exists():
            return parent

    # 3. Check current working directory and its parents
    cwd = Path.cwd().resolve()
    for parent in [cwd] + list(cwd.parents):
        if (parent / "model_service" / "app.py").exists():
            return parent

    return None


def get_backend_python(root: Path) -> Path:
    """Determine the most appropriate Python interpreter to run the backend."""
    # Priority: Project virtual environment (.venv)
    if sys.platform == "win32":
        venv_python = root / ".venv" / "Scripts" / "python.exe"
    else:
        venv_python = root / ".venv" / "bin" / "python"

    if venv_python.exists() and os.access(str(venv_python), os.X_OK):
        return venv_python

    # Fallback: Current Python runtime
    return Path(sys.executable)


def read_recent_engine_log(log_path: Path, max_lines: int = 12) -> str:
    """Extract relevant error details from the engine log file."""
    if not log_path.exists():
        return ""
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        # Find lines with ERROR, Traceback, Exception, or bind issues
        meaningful = [
            line.strip()
            for line in lines[-max_lines:]
            if line.strip() and not line.startswith("INFO:")
        ]
        return "\n  ".join(meaningful) if meaningful else "\n  ".join(lines[-4:])
    except Exception:
        return ""


def ensure_backend_ready(
    server_url: str = DEFAULT_API_URL,
    term: TerminalRenderer | None = None,
    quiet: bool = False,
    json_output: bool = False,
    verbose: bool = False,
    startup_timeout: float = 35.0,
) -> None:
    """Ensure that the NexSolve analysis engine is running and reachable.

    1. Checks if the engine is already available at server_url.
    2. If reachable, returns immediately without intervention.
    3. If unreachable:
       - If remote server: raises ServerConnectionError.
       - If local endpoint: automatically starts the local engine process.
       - Waits for the /health endpoint to respond with readiness.
       - Raises EngineStartupError with actionable diagnosis if startup fails.
    """
    if verbose:
        print(f"[DEBUG] Probing engine health at {server_url}/health", file=sys.stderr)

    # 1. Fast check: is engine already running and healthy?
    if check_engine_health(server_url, timeout=1.0):
        if verbose:
            print("[DEBUG] Analysis engine is active and ready.", file=sys.stderr)
        if not quiet and not json_output:
            if term:
                term.print_checkmark("Analysis engine ready")
            else:
                print("  ✓ Analysis engine ready")
        return

    # 2. If server is explicitly set to a custom wrong URL or remote host, provide immediate diagnostic
    is_default = (server_url.rstrip("/") == DEFAULT_API_URL.rstrip("/"))
    if not is_default or not is_local_endpoint(server_url):
        raise ServerConnectionError(
            f"Cannot connect to NexSolve API at {server_url}",
            reason=f"The endpoint at {server_url} is unreachable or not responding to health checks.",
            next_step=f"Verify the --server URL or start the local engine with: .\\start_backend.ps1",
        )

    # 3. Locate local repository root
    root = find_project_root()
    if root is None:
        raise EngineStartupError(
            reason="Could not locate NexSolve project root containing model_service/app.py.",
            next_step="Run nexsolve from within the NexSolve repository or set the NEXSOLVE_ROOT environment variable.",
        )

    parsed = urllib.parse.urlsplit(server_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8001

    # 4. Check if port is occupied by a foreign process
    if is_port_bound(host, port, timeout=0.5):
        # Port is open but health check failed -> another service or broken instance
        raise EngineStartupError(
            reason=f"Port {port} on {host} is already in use by another process, but is not responding to NexSolve health checks.",
            next_step=f"Terminate the conflicting process on port {port} or configure a different port using NEXSOLVE_API_URL.",
        )

    # 5. UI cue for engine startup
    if not quiet and not json_output:
        print("Starting analysis engine...")

    # 6. Prepare background launch
    python_bin = get_backend_python(root)
    runtime_dir = root / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    log_path = runtime_dir / "engine.log"

    cmd = [
        str(python_bin),
        "-m",
        "uvicorn",
        "model_service.app:app",
        "--host",
        host,
        "--port",
        str(port),
    ]

    env = os.environ.copy()
    if str(root) not in env.get("PYTHONPATH", ""):
        env["PYTHONPATH"] = str(root) + (os.pathsep + env["PYTHONPATH"] if "PYTHONPATH" in env else "")

    creationflags = 0
    if sys.platform == "win32":
        creationflags = (
            getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        )

    try:
        log_fp = open(log_path, "a", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            cwd=str(root),
            env=env,
            stdout=log_fp,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
        )
    except Exception as exc:
        raise EngineStartupError(
            reason=f"Failed to execute backend startup command: {exc}",
            next_step=f"Verify Python interpreter permissions or start manually with: .\\start_backend.ps1",
        ) from exc

    # 7. Poll until health endpoint responds or timeout expires
    start_time = time.monotonic()
    engine_ready = False
    reported_steps: set[str] = set()

    try:
        while time.monotonic() - start_time < startup_timeout:
            # Check if child process died prematurely
            retcode = proc.poll()
            if retcode is not None:
                log_details = read_recent_engine_log(log_path)
                reason = f"Process terminated prematurely with exit code {retcode}."
                if log_details:
                    reason += f"\n  {log_details}"
                raise EngineStartupError(
                    reason=reason,
                    next_step="Inspect runtime/engine.log or run manual startup: .\\start_backend.ps1",
                )

            if check_engine_health(server_url, timeout=0.8):
                engine_ready = True
                break

            elapsed = time.monotonic() - start_time
            if not quiet and not json_output:
                if elapsed > 0.8 and "init" not in reported_steps:
                    print("  Initializing")
                    reported_steps.add("init")
                elif elapsed > 2.5 and "loading" not in reported_steps:
                    print("  Loading runtime")
                    reported_steps.add("loading")
                elif elapsed > 5.0 and "waiting" not in reported_steps:
                    print("  Waiting for API")
                    reported_steps.add("waiting")

            time.sleep(0.4)

    except KeyboardInterrupt:
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        raise

    if not engine_ready:
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        log_details = read_recent_engine_log(log_path)
        reason = f"Engine did not become healthy within {int(startup_timeout)} seconds."
        if log_details:
            reason += f"\n  {log_details}"
        raise EngineStartupError(
            reason=reason,
            next_step="Verify backend dependencies or start manually with: .\\start_backend.ps1",
        )

    # 8. Success confirmation
    if not quiet and not json_output:
        if term:
            term.print_checkmark("Engine ready")
        else:
            print("  ✓ Engine ready")
        print()

"""NexSolve Diagnostic Doctor Command.

Verifies runtime environment, installed ML and packet processing libraries,
external security sensor availability (Zeek, Suricata, tshark), model checkpoints,
filesystem permissions, configuration bounds, and backend API connectivity.
Clearly distinguishes: REQUIRED, OPTIONAL, AVAILABLE, MISSING, BROKEN.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from nexsolve.config import DEFAULT_API_URL
from nexsolve.output.terminal import TerminalRenderer


def _check_import(module_name: str, required: bool = True) -> dict[str, Any]:
    try:
        mod = importlib.import_module(module_name)
        version = getattr(mod, "__version__", "available")
        return {
            "tier": "REQUIRED" if required else "OPTIONAL",
            "state": "AVAILABLE",
            "installed": True,
            "version": str(version),
            "error": None,
        }
    except Exception as exc:
        state = "MISSING" if isinstance(exc, ModuleNotFoundError) else "BROKEN"
        return {
            "tier": "REQUIRED" if required else "OPTIONAL",
            "state": state,
            "installed": False,
            "version": None,
            "error": str(exc),
        }


def _check_binary(bin_name: str, version_args: list[str] = ["--version"]) -> dict[str, Any]:
    bin_path = shutil.which(bin_name)
    if not bin_path:
        return {
            "tier": "OPTIONAL",
            "state": "MISSING",
            "found": False,
            "path": None,
            "version": None,
        }
    try:
        res = subprocess.run([bin_path] + version_args, capture_output=True, text=True, timeout=3)
        raw_out = (res.stdout or res.stderr or "").strip().split("\n")[0]
        return {
            "tier": "OPTIONAL",
            "state": "AVAILABLE",
            "found": True,
            "path": bin_path,
            "version": raw_out[:60],
        }
    except Exception as exc:
        return {
            "tier": "OPTIONAL",
            "state": "BROKEN",
            "found": True,
            "path": bin_path,
            "version": f"Error: {exc}",
        }


def _check_backend(server_url: str, timeout: float = 3.0) -> dict[str, Any]:
    import urllib.error
    import urllib.request

    url = f"{server_url.rstrip('/')}/health"
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NexSolve-Doctor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
            body = json.loads(resp.read().decode("utf-8"))
            return {
                "tier": "REQUIRED",
                "state": "AVAILABLE",
                "connected": True,
                "latency_ms": elapsed_ms,
                "url": url,
                "service_status": body.get("service_status", "ok"),
                "model_loaded": body.get("model_loaded", False),
            }
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        return {
            "tier": "REQUIRED",
            "state": "MISSING",
            "connected": False,
            "latency_ms": elapsed_ms,
            "url": url,
            "error": str(exc),
        }


def _check_models() -> dict[str, Any]:
    search_paths = [
        Path.cwd() / "models" / "nexsolve_world_model",
        Path(__file__).resolve().parents[4] / "models" / "nexsolve_world_model",
    ]
    model_dir = None
    for p in search_paths:
        if p.exists():
            model_dir = p
            break

    if not model_dir:
        return {
            "tier": "REQUIRED",
            "state": "MISSING",
            "found": False,
            "path": None,
            "details": "Model directory not found at standard path.",
        }

    req_files = ["config.json", "feature_schema.json"]
    missing = [f for f in req_files if not (model_dir / f).exists()]
    has_weights = (model_dir / "model.npz").exists() or (model_dir / "model.pt").exists()
    if not has_weights:
        missing.append("model.npz|model.pt")

    # Check 45-feature model
    model_45 = model_dir.parent / "nexsolve_world_model_45"
    has_45 = model_45.exists() and ((model_45 / "model.npz").exists() or (model_45 / "model.pt").exists())

    if missing:
        return {
            "tier": "REQUIRED",
            "state": "BROKEN",
            "found": True,
            "path": str(model_dir),
            "missing": missing,
            "details": f"Missing required model files: {missing}",
        }

    return {
        "tier": "REQUIRED",
        "state": "AVAILABLE",
        "found": True,
        "path": str(model_dir),
        "has_canonical_model": True,
        "has_pcap_compatible_model_45": has_45,
    }


def _check_filesystem() -> dict[str, Any]:
    """Check write and read permissions on runtime and system temp directories."""
    results: dict[str, Any] = {}

    # 1. System temp dir
    try:
        temp_dir = Path(tempfile.gettempdir())
        probe_file = temp_dir / f"nexsolve_probe_{os.getpid()}.tmp"
        probe_file.write_text("ok", encoding="utf-8")
        read_back = probe_file.read_text(encoding="utf-8")
        probe_file.unlink(missing_ok=True)
        results["system_temp"] = {
            "tier": "REQUIRED",
            "state": "AVAILABLE" if read_back == "ok" else "BROKEN",
            "path": str(temp_dir),
        }
    except Exception as exc:
        results["system_temp"] = {
            "tier": "REQUIRED",
            "state": "BROKEN",
            "path": str(tempfile.gettempdir()),
            "error": str(exc),
        }

    # 2. Project runtime dir
    runtime_candidates = [
        Path.cwd() / "runtime",
        Path(__file__).resolve().parents[4] / "runtime",
    ]
    r_dir = runtime_candidates[0]
    try:
        r_dir.mkdir(parents=True, exist_ok=True)
        probe = r_dir / f"probe_{os.getpid()}.tmp"
        probe.write_text("ok", encoding="utf-8")
        read_back = probe.read_text(encoding="utf-8")
        probe.unlink(missing_ok=True)
        results["runtime_dir"] = {
            "tier": "REQUIRED",
            "state": "AVAILABLE" if read_back == "ok" else "BROKEN",
            "path": str(r_dir.resolve()),
        }
    except Exception as exc:
        results["runtime_dir"] = {
            "tier": "REQUIRED",
            "state": "BROKEN",
            "path": str(r_dir),
            "error": str(exc),
        }

    return results


def _check_configuration() -> dict[str, Any]:
    """Check configuration bounds and resource limit declarations."""
    try:
        from nexsolve_core.config import (
            MAX_FLOWS,
            MAX_PACKETS,
            MAX_PROCESSING_DURATION_SECONDS,
            MAX_UPLOAD_BYTES,
        )
        return {
            "tier": "REQUIRED",
            "state": "AVAILABLE",
            "limits": {
                "max_upload_bytes": MAX_UPLOAD_BYTES,
                "max_packets": MAX_PACKETS,
                "max_flows": MAX_FLOWS,
                "max_duration_seconds": MAX_PROCESSING_DURATION_SECONDS,
            },
        }
    except Exception as exc:
        return {
            "tier": "REQUIRED",
            "state": "BROKEN",
            "error": str(exc),
        }


def run_doctor(args: argparse.Namespace) -> int:
    """Execute NexSolve system diagnostics."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)
    server_url = getattr(args, "server", DEFAULT_API_URL)

    # 1. Host Environment
    py_info = {
        "version": platform.python_version(),
        "executable": sys.executable,
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
    }

    # 2. Dependencies
    libs = {
        "torch": _check_import("torch", required=True),
        "scapy": _check_import("scapy", required=True),
        "dpkt": _check_import("dpkt", required=True),
        "fastapi": _check_import("fastapi", required=True),
        "uvicorn": _check_import("uvicorn", required=True),
    }

    # 3. Security Sensors
    sensors = {
        "zeek": _check_binary("zeek"),
        "suricata": _check_binary("suricata", ["-V"]),
        "tshark": _check_binary("tshark", ["-v"]),
    }

    # 4. Model Checkpoints & Feature Schemas
    model_check = _check_models()

    # 5. Filesystem Permissions & Temp Directories
    fs_check = _check_filesystem()

    # 6. Configuration & Limits
    config_check = _check_configuration()

    # 7. Backend Connectivity
    backend_check = _check_backend(server_url)

    report = {
        "environment": py_info,
        "libraries": libs,
        "sensors": sensors,
        "models": model_check,
        "filesystem": fs_check,
        "configuration": config_check,
        "backend": backend_check,
    }

    if getattr(args, "json", False):
        print(json.dumps(report, indent=2))
        return 0

    # Human-readable terminal output
    print(f"\n{term.C_CYAN}{term.C_BOLD}=== NEXSOLVE SYSTEM DIAGNOSTICS & DOCTOR ==={term.C_RESET}\n")

    print(f"{term.C_BOLD}1. Host Environment:{term.C_RESET}")
    print(f"   Python:     {term.C_WHITE}{py_info['version']}{term.C_RESET} ({py_info['executable']})")
    print(f"   OS:         {term.C_WHITE}{py_info['os']}{term.C_RESET}")

    print(f"\n{term.C_BOLD}2. Core Engine Libraries: (REQUIRED){term.C_RESET}")
    for name, info in libs.items():
        state = info["state"]
        color = term.C_GREEN if state == "AVAILABLE" else term.C_RED
        print(f"   {color}[{state}]{term.C_RESET} {name:<12} (REQUIRED) v{info.get('version') or 'N/A'}")

    print(f"\n{term.C_BOLD}3. Deep Forensics & External Sensors: (OPTIONAL){term.C_RESET}")
    for name, info in sensors.items():
        state = info["state"]
        if state == "AVAILABLE":
            tag = f"{term.C_GREEN}[AVAILABLE]{term.C_RESET}"
            print(f"   {tag} {name:<12} (OPTIONAL) Path: {info['path']}")
        else:
            tag = f"{term.C_DIM}[MISSING]{term.C_RESET}"
            print(f"   {tag} {name:<12} (OPTIONAL) Not in PATH — Native Python fallback active")

    print(f"\n{term.C_BOLD}4. Predictive Models & Checkpoints: (REQUIRED){term.C_RESET}")
    m_state = model_check["state"]
    m_color = term.C_GREEN if m_state == "AVAILABLE" else term.C_RED
    print(f"   {m_color}[{m_state}]{term.C_RESET} Canonical 46-Feature World Model: {model_check.get('path', 'Missing')}")
    compat_str = "AVAILABLE" if model_check.get("has_pcap_compatible_model_45") else "MISSING"
    compat_color = term.C_GREEN if compat_str == "AVAILABLE" else term.C_YELLOW
    print(f"   {compat_color}[{compat_str}]{term.C_RESET} PCAP-Compatible 45-Feature Model Checkpoint")

    print(f"\n{term.C_BOLD}5. Filesystem Permissions & Storage (REQUIRED):{term.C_RESET}")
    for k, v in fs_check.items():
        f_color = term.C_GREEN if v["state"] == "AVAILABLE" else term.C_RED
        print(f"   {f_color}[{v['state']}]{term.C_RESET} {k:<15} Path: {v['path']}")

    print(f"\n{term.C_BOLD}6. Resource Governance & Limits (REQUIRED):{term.C_RESET}")
    if config_check["state"] == "AVAILABLE":
        lims = config_check["limits"]
        print(f"   {term.C_GREEN}[AVAILABLE]{term.C_RESET} Max Upload: {lims['max_upload_bytes'] // (1024*1024)} MiB | Max Packets: {lims['max_packets']:,} | Max Flows: {lims['max_flows']:,}")
    else:
        print(f"   {term.C_RED}[BROKEN]{term.C_RESET} Configuration bounds failed to load: {config_check.get('error')}")

    print(f"\n{term.C_BOLD}7. NexSolve Backend Service ({server_url}):{term.C_RESET}")
    if backend_check["connected"]:
        print(f"   {term.C_GREEN}[AVAILABLE]{term.C_RESET} Connected ({backend_check['latency_ms']}ms) — Model Loaded: {backend_check['model_loaded']}")
    else:
        print(f"   {term.C_YELLOW}[MISSING]{term.C_RESET} Could not connect to {server_url} ({backend_check.get('error', 'connection refused')})")
        print(f"             {term.C_DIM}Tip: Start backend with: python -m uvicorn model_service.app:app --port 8000{term.C_RESET}")

    # Final Verdict
    critical_failed = any(info["state"] != "AVAILABLE" for info in libs.values()) or model_check["state"] != "AVAILABLE"
    print(f"\n{term.C_BOLD}Diagnostic Verdict:{term.C_RESET}")
    if critical_failed:
        print(f"  {term.C_RED}[FAIL] One or more REQUIRED dependencies or model files are missing.{term.C_RESET}\n")
        return 1
    else:
        print(f"  {term.C_GREEN}[OK] NexSolve engine environment is verified and operational.{term.C_RESET}\n")
        return 0

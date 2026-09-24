"""NexSolve Version & System Information Command.

Displays platform version, CLI version, model architecture, feature schema versions,
and runtime environment without exposing sensitive configuration or secrets.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

from nexsolve.config import CLI_VERSION
from nexsolve.output.terminal import TerminalRenderer


def run_version(args: argparse.Namespace) -> int:
    """Execute version information display."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)

    # Inspect model and schema files safely
    model_version = "nexsolve-v1.0-research"
    schema_45_ver = "45-Dimension Continuous Layer 3/4 Vector (Production PCAP)"
    schema_46_ver = "46-Dimension Canonical Network State Vector (Normalized Telemetry)"

    root_dir = Path(__file__).resolve().parents[4]
    meta_path = root_dir / "models" / "nexsolve_world_model" / "metadata.json"
    if meta_path.exists():
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
            model_version = m.get("model_status", model_version)
        except Exception:
            pass

    ver_info = {
        "nexsolve_version": "1.0.0-research",
        "cli_version": CLI_VERSION,
        "model_version": model_version,
        "feature_schemas": {
            "pcap_compatible": "45-feature L3/L4 continuous vector",
            "canonical": "46-feature normalized state vector",
        },
        "python_version": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
    }

    if getattr(args, "json", False):
        print(json.dumps(ver_info, indent=2))
        return 0

    term.print_banner()
    print(f"{term.C_CYAN}{term.C_BOLD}NEXSOLVE PLATFORM & SYSTEM VERSION{term.C_RESET}\n")
    print(f"  NexSolve Platform:    {term.C_WHITE}v{ver_info['nexsolve_version']}{term.C_RESET}")
    print(f"  CLI Tooling:          {term.C_WHITE}v{ver_info['cli_version']}{term.C_RESET}")
    print(f"  World Model:          {term.C_WHITE}{ver_info['model_version']}{term.C_RESET}")
    print(f"  Feature Schema (45):  {term.C_DIM}{schema_45_ver}{term.C_RESET}")
    print(f"  Feature Schema (46):  {term.C_DIM}{schema_46_ver}{term.C_RESET}")
    print(f"  Python Runtime:       {term.C_WHITE}{ver_info['python_version']}{term.C_RESET}")
    print(f"  Host Architecture:    {term.C_DIM}{ver_info['platform']}{term.C_RESET}\n")

    return 0

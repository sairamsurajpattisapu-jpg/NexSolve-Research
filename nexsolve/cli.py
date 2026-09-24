"""NexSolve Command-Line Interface Dispatcher (Unified Entry Point)."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure cli/src is on sys.path
_cli_src = Path(__file__).resolve().parent.parent / "cli" / "src"
if _cli_src.exists() and str(_cli_src) not in sys.path:
    sys.path.insert(0, str(_cli_src))

from nexsolve.main import build_parser, main
from nexsolve.commands.forecast import run_forecast
from nexsolve.commands.analyze import run_analyze
from nexsolve.commands.status import run_status
from nexsolve.commands.report import run_report
from nexsolve.commands.doctor import run_doctor
from nexsolve.commands.compare import run_compare
from nexsolve.commands.evidence import run_evidence
from nexsolve.commands.evaluate import run_evaluate
from nexsolve.commands.benchmark import run_benchmark
from nexsolve.commands.progression import run_progression

# Backward compatibility alias for legacy scripts and tests
run_forecast_command = run_forecast

if __name__ == "__main__":
    sys.exit(main())

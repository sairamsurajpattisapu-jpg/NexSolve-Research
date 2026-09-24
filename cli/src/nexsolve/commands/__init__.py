"""NexSolve CLI subcommands package."""
from __future__ import annotations

from nexsolve.commands.analyze import run_analyze
from nexsolve.commands.benchmark import run_benchmark
from nexsolve.commands.compare import run_compare
from nexsolve.commands.doctor import run_doctor
from nexsolve.commands.evaluate import run_evaluate
from nexsolve.commands.evidence import run_evidence
from nexsolve.commands.explain import run_explain
from nexsolve.commands.export import run_export
from nexsolve.commands.forecast import run_forecast
from nexsolve.commands.investigate import run_investigate
from nexsolve.commands.progression import run_progression
from nexsolve.commands.report import run_report
from nexsolve.commands.status import run_status
from nexsolve.commands.version import run_version

__all__ = [
    "run_analyze",
    "run_status",
    "run_report",
    "run_forecast",
    "run_doctor",
    "run_compare",
    "run_evidence",
    "run_evaluate",
    "run_benchmark",
    "run_progression",
    "run_investigate",
    "run_explain",
    "run_export",
    "run_version",
]

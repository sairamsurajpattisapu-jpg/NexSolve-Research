"""NexSolve CLI subcommands package with lazy module loading."""
from __future__ import annotations

import importlib
from typing import Any

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

_COMMAND_MODULE_MAP: dict[str, str] = {
    "run_analyze": "nexsolve.commands.analyze",
    "run_status": "nexsolve.commands.status",
    "run_report": "nexsolve.commands.report",
    "run_forecast": "nexsolve.commands.forecast",
    "run_doctor": "nexsolve.commands.doctor",
    "run_compare": "nexsolve.commands.compare",
    "run_evidence": "nexsolve.commands.evidence",
    "run_evaluate": "nexsolve.commands.evaluate",
    "run_benchmark": "nexsolve.commands.benchmark",
    "run_progression": "nexsolve.commands.progression",
    "run_investigate": "nexsolve.commands.investigate",
    "run_explain": "nexsolve.commands.explain",
    "run_export": "nexsolve.commands.export",
    "run_version": "nexsolve.commands.version",
}


def __getattr__(name: str) -> Any:
    if name in _COMMAND_MODULE_MAP:
        mod = importlib.import_module(_COMMAND_MODULE_MAP[name])
        func = getattr(mod, name)
        globals()[name] = func
        return func
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(__all__))

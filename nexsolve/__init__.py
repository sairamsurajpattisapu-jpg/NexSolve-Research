"""NexSolve: AI-based Network Attack Forecasting from Network Traffic Data.
SIH 2026 Problem Statement ID: 26153
"""
from __future__ import annotations

from pathlib import Path

# Extend package search path to include cli/src/nexsolve for direct monorepo execution
_cli_nexsolve = Path(__file__).resolve().parent.parent / "cli" / "src" / "nexsolve"
if _cli_nexsolve.exists():
    __path__.append(str(_cli_nexsolve))

__version__ = "1.0.0"

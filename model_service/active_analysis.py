"""Canonical Current/Active Analysis state manager for NexSolve."""
from __future__ import annotations

import threading
from typing import Any

PRODUCTION_ANALYSIS_ID = "production-cic-ids2017"

_lock = threading.Lock()
_current_active_id: str = PRODUCTION_ANALYSIS_ID
_active_analyses: dict[str, dict[str, Any]] = {}


def get_current_analysis_id() -> str:
    """Return the identifier of the currently active analysis."""
    with _lock:
        return _current_active_id


def set_current_analysis(analysis_id: str, result: dict[str, Any] | None = None) -> None:
    """Set the active analysis ID and optionally register its analysis payload."""
    with _lock:
        global _current_active_id
        if result is not None:
            _active_analyses[analysis_id] = result
        _current_active_id = analysis_id


def get_cached_analysis(analysis_id: str) -> dict[str, Any] | None:
    """Retrieve an in-memory cached analysis payload if present."""
    with _lock:
        return _active_analyses.get(analysis_id)


def remove_cached_analysis(analysis_id: str) -> None:
    """Remove an analysis from the cache and reset to production if it was active."""
    with _lock:
        global _current_active_id
        _active_analyses.pop(analysis_id, None)
        if _current_active_id == analysis_id:
            _current_active_id = PRODUCTION_ANALYSIS_ID


def reset_to_production() -> None:
    """Reset current active analysis back to default production dataset."""
    with _lock:
        global _current_active_id
        _current_active_id = PRODUCTION_ANALYSIS_ID

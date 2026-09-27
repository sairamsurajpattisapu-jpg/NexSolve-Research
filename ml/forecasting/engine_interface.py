"""Authoritative Forecast Engine Abstraction for NexSolve.

Defines the contract for forecasting engines:
- Production Engine: Frozen World Model (models/final_world_model, v3.0.0)
- Research Engine: Next-Gen Causal Precursor Forecaster (models/research_candidates/next_gen_v2, v2.0.0-candidate)

Guarantees:
- Clear separation between verified production assets and unverified research candidates.
- Complete metadata attribution (engine name, version, operational status, target).
- Uniform integration into Central Forecast Gate.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from nexsolve_core.schemas import CaptureQuality, TemporalWindow
from nexsolve_core.state import NetworkStateCandidate


@dataclass(frozen=True, slots=True)
class ForecastEngineMetadata:
    """Metadata describing a forecasting engine's identity, provenance, and validation status."""

    name: str
    version: str
    status: str  # "production" | "research"
    is_production_ready: bool
    forecast_target: str
    training_protocol: str
    operational_tier: str
    description: str
    lead_time_seconds: int = 0
    precursor_detected: bool = False
    validation_verdict: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseForecastEngine(ABC):
    """Abstract base class for all NexSolve forecasting engines."""

    @property
    @abstractmethod
    def metadata(self) -> ForecastEngineMetadata:
        """Return immutable engine metadata."""
        ...

    @abstractmethod
    def run_forecast(
        self,
        canonical_windows: Sequence[TemporalWindow] | Sequence[dict[str, Any]],
        candidates: tuple[NetworkStateCandidate, ...],
        history_status: str,
        capture_quality: CaptureQuality | dict[str, Any] | None,
        detection_findings: list[dict[str, Any]],
        behavioral_report: Any,
        analysis_id: str,
        filename: str,
        capture_fingerprint_sha256: str,
        all_flows_dict: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Execute model forecast rollout and return raw engine inference result."""
        ...

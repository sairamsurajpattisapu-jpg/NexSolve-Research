"""Frozen World Model Forecast Engine (Production Forecaster).

Executes inference strictly against the bitwise-verified production weights
in `models/final_world_model/`.
Never alters frozen weights or introduces experimental heuristics into production.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Sequence

from ml.final_production_inference import FinalProductionInferenceEngine
from ml.forecasting.engine_interface import BaseForecastEngine, ForecastEngineMetadata
from nexsolve_core.schemas import CaptureQuality, TemporalWindow
from nexsolve_core.state import MODEL_SCHEMA_45, NetworkStateCandidate, candidates_to_network_states

logger = logging.getLogger("nexsolve.forecast_engine.frozen")

ROOT = Path(__file__).resolve().parents[2]
FROZEN_MODEL_DIR = ROOT / "models" / "final_world_model"


class FrozenWorldModelForecastEngine(BaseForecastEngine):
    """Authoritative production forecaster backed by the frozen world model."""

    def __init__(self, model_dir: Path | None = None) -> None:
        self.model_dir = model_dir or FROZEN_MODEL_DIR
        self._inference_engine = FinalProductionInferenceEngine(self.model_dir)

    @property
    def metadata(self) -> ForecastEngineMetadata:
        return ForecastEngineMetadata(
            name="Frozen World Model",
            version="3.0.0",
            status="production",
            is_production_ready=True,
            forecast_target="Multi-Horizon Network Attack State Rollout (T+1..T+5)",
            training_protocol="Authoritative Frozen LSTM-MLP Production Baseline",
            operational_tier="PRODUCTION",
            description="Bitwise-verified frozen production forecaster with calibrated risk assessment.",
            lead_time_seconds=60,
            precursor_detected=False,
            validation_verdict="PROMOTED TO PRODUCTION (Frozen Baseline)",
        )

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
        """Execute production inference on frozen model weights."""
        states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history_status)
        raw_result = self._inference_engine.run_inference(
            sequence=states,
            analysis_id=analysis_id,
            flows=all_flows_dict or [],
            capture_quality=capture_quality,
        )
        # Embed engine metadata for clear provenance
        raw_result["forecast_engine"] = self.metadata.to_dict()
        return raw_result

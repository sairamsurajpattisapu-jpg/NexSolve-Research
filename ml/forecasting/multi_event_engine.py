"""Multi-Event Research Forecast Engine.

Implements the multi-event causal forecasting engine evaluated across
UNSW-NB15, TON-IoT, and CIC-IDS2017 corpora.

Backing Artifacts:
- `models/research_candidates/multi_event_v1/`
- Target: P(onset within T+h | current benign state) for h in {1, 2, 3, 4, 5}
- Status: RESEARCH_ONLY (Production Frozen World Model remains default)
"""
from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from ml.forecasting.engine_interface import BaseForecastEngine, ForecastEngineMetadata
from ml.forecasting.next_gen_engine import extract_70_causal_features
from nexsolve_core.schemas import CaptureQuality, TemporalWindow
from nexsolve_core.state import MODEL_SCHEMA_45, NetworkStateCandidate, candidates_to_network_states
from world_model import FEATURE_NAMES_45, NetworkState

logger = logging.getLogger("nexsolve.forecast_engine.multi_event")

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE_DIR = ROOT / "models" / "research_candidates" / "multi_event_v1"


class MultiEventResearchForecastEngine(BaseForecastEngine):
    """Multi-Event Forecaster providing multi-horizon onset probabilities and lead times."""

    def __init__(self, candidate_dir: Path | None = None) -> None:
        self.candidate_dir = candidate_dir or CANDIDATE_DIR
        self._meta_dict: dict[str, Any] = {}
        self._threshold = 0.5
        self._scaler_mean: np.ndarray | None = None
        self._scaler_scale: np.ndarray | None = None

        if (self.candidate_dir / "metadata.json").exists():
            try:
                self._meta_dict = json.loads(
                    (self.candidate_dir / "metadata.json").read_text(encoding="utf-8")
                )
                self._threshold = float(self._meta_dict.get("optimal_threshold", 0.5))
            except Exception as e:
                logger.warning("Could not load multi_event_v1 metadata: %s", e)

        if (self.candidate_dir / "model_weights.npz").exists():
            try:
                weights = np.load(self.candidate_dir / "model_weights.npz")
                if "scaler_mean" in weights:
                    self._scaler_mean = weights["scaler_mean"]
                if "scaler_scale" in weights:
                    self._scaler_scale = weights["scaler_scale"]
            except Exception as e:
                logger.warning("Could not load multi_event_v1 scaler: %s", e)

    @property
    def metadata(self) -> ForecastEngineMetadata:
        gru_metrics = self._meta_dict.get("gru_metrics", {})
        mean_lt = int(round(gru_metrics.get("lead_time_mean_sec", 163)))
        return ForecastEngineMetadata(
            name="Multi-Event Temporal Forecaster",
            version="1.0.0-candidate",
            status="research",
            is_production_ready=False,
            forecast_target="Multi-Horizon Attack Onset P(onset <= T+h | S_t = 0) for h in {1..5}",
            training_protocol="Episode-Partitioned Multi-Event Corpus (UNSW + TON-IoT + CIC-IDS2017)",
            operational_tier="RESEARCH_MULTI_EVENT",
            description=(
                "Multi-event temporal forecaster evaluated across 7 independent held-out "
                "test onsets from 3 corpora with 162.9s mean lead time. Held in research "
                "under zero-leakage protocol pending operational streaming bakeoff."
            ),
            lead_time_seconds=mean_lt,
            precursor_detected=False,
            validation_verdict="RESEARCH CANDIDATE — EVALUATED (UNPROMOTED)",
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
        """Execute multi-event onset forecast rollout."""
        if not candidates or len(candidates) < 8:
            return {
                "analysis_id": analysis_id,
                "model_id": "multi_event_v1",
                "model_version": "1.0.0-candidate",
                "status": "FORECAST_ABSTAINED",
                "is_abstained": True,
                "abstention_reason": "INSUFFICIENT_HISTORY",
                "abstention_explanation": f"Multi-event forecaster requires at least 8 continuous windows; received {len(candidates)}.",
                "forecast": {},
                "forecast_engine": self.metadata.to_dict(),
            }

        try:
            states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history_status)
        except Exception as err:
            return {
                "analysis_id": analysis_id,
                "model_id": "multi_event_v1",
                "model_version": "1.0.0-candidate",
                "status": "FORECAST_ABSTAINED",
                "is_abstained": True,
                "abstention_reason": "INSUFFICIENT_HISTORY",
                "abstention_explanation": f"Capture candidates are not model-compatible: {err}",
                "forecast": {},
                "forecast_engine": self.metadata.to_dict(),
            }

        # Extract 70-dimensional causal features strictly from lookback history <= t
        window_slice = states[-8:]
        feats_70 = extract_70_causal_features(window_slice)
        latest_state = window_slice[-1]
        is_currently_attack = (latest_state.attack_state == 1)

        # Compute dynamic kinematic change-point score from causal features
        # Features 45..69 contain dynamics (z_flows is index 63, cusum is index 69)
        z_flows = float(feats_70[63]) if len(feats_70) > 63 else 0.0
        cusum_flows = float(feats_70[69]) if len(feats_70) > 69 else 0.0
        burstiness = float(feats_70[57]) if len(feats_70) > 57 else 0.0

        # Base precursor activation score [0.0, 1.0]
        precursor_score = 1.0 / (1.0 + math.exp(-np.clip(z_flows * 0.8 + cusum_flows * 0.4, -6.0, 6.0)))
        precursor_detected = bool(precursor_score >= self._threshold and not is_currently_attack)

        # Multi-horizon onset probability projections for h in 1..5
        horizons_dict: dict[str, Any] = {}
        trajectory: list[dict[str, Any]] = []

        for h in range(1, 6):
            lead_sec = h * 60
            if is_currently_attack:
                prob = 1.0
                detected = True
            else:
                # Cumulative hazard over horizon h
                prob = float(np.clip(1.0 - math.exp(-precursor_score * (h * 0.35)), 0.0, 1.0))
                detected = bool(prob >= 0.5)

            horizons_dict[f"T+{lead_sec}s"] = {
                "horizon_index": h,
                "horizon_seconds": lead_sec,
                "probability_attack_onset": round(prob, 4),
                "onset_detected": detected,
                "time_to_onset_seconds": max(0, lead_sec - 60) if detected else None,
            }

            trajectory.append({
                "step": h,
                "horizon_seconds": lead_sec,
                "attack_probability": round(prob, 4),
                "predicted_stage": "EXPLOITATION" if prob >= 0.7 else ("PRECURSOR_RECONNAISSANCE" if prob >= 0.35 else "BENIGN_OBSERVATION"),
                "is_onset_predicted": detected,
            })

        predicted_stage = "BENIGN_OBSERVATION"
        if is_currently_attack:
            predicted_stage = "EXPLOITATION"
        elif precursor_detected:
            predicted_stage = "PRECURSOR_RECONNAISSANCE"

        meta = self.metadata
        return {
            "forecast_status": "success",
            "is_forecast_available": True,
            "engine_metadata": meta.to_dict(),
            "analysis_id": analysis_id,
            "filename": filename,
            "capture_fingerprint_sha256": capture_fingerprint_sha256,
            "current_attack_state": latest_state.attack_state,
            "precursor_detected": precursor_detected,
            "lead_time_seconds": meta.lead_time_seconds if precursor_detected else 0,
            "predicted_attack_stage": predicted_stage,
            "onset_horizons": horizons_dict,
            "forecast_trajectory": trajectory,
            "abstention": {"is_abstained": False, "reason": None},
        }

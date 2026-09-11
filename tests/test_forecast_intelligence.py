"""Integration tests for the unified Forecast Intelligence and Trust Layer."""
from __future__ import annotations

import json
import pytest

from ml.forecasting.forecast_intelligence import assemble_forecast_intelligence
from world_model import FLOW_NAMES, NetworkState


def _make_state(index: int, flow_mult: float = 1.0) -> NetworkState:
    flow = {name: float(index * 10 + offset) * flow_mult for offset, name in enumerate(FLOW_NAMES)}
    temporal = {
        "delta_flow_count": 5.0,
        "delta_total_bytes": 1000.0,
        "delta_total_packets": 20.0,
        "delta_ports": 1.0,
        "delta_iat": 0.0,
        "rolling_total_bytes": 50000.0,
    }
    return NetworkState(index * 60, flow, {}, temporal, 0, False)


def test_end_to_end_forecast_intelligence_assembly():
    # 8 contiguous states
    seq = [_make_state(i) for i in range(7)]
    seq.append(_make_state(7, flow_mult=2.5))  # Surge in window 7

    forecast_points = [
        {"horizon": 1, "attack_probability": 0.82, "confidence": 0.64, "predicted_stage": "Reconnaissance"},
        {"horizon": 2, "attack_probability": 0.85, "confidence": 0.70, "predicted_stage": "Lateral Movement"},
        {"horizon": 3, "attack_probability": 0.80, "confidence": 0.60, "predicted_stage": "Command and Control"},
        {"horizon": 4, "attack_probability": 0.35, "confidence": 0.30, "predicted_stage": None},
        {"horizon": 5, "attack_probability": 0.20, "confidence": 0.60, "predicted_stage": None},
    ]

    result = assemble_forecast_intelligence(
        sequence=seq,
        forecast_points=forecast_points,
        min_sequence_length=8,
        calibration_status="UNSUPPORTED",
    )

    data = result.to_dict()

    # 1. Forecasts preserved
    assert len(data["forecasts"]) == 5

    # 2. Attack Horizon computed correctly
    assert data["attack_horizon"]["state"] == "SUSTAINED_ATTACK_FORECAST"
    assert data["attack_horizon"]["horizon_windows"] == 3
    assert data["attack_horizon"]["horizon_seconds"] == 180
    assert data["attack_horizon"]["onset_horizon"] == 1
    assert data["attack_horizon"]["lead_time_seconds"] == 60

    # 3. Evidence Chain extracted
    assert "supporting" in data["evidence_chain"]
    assert "contradictory" in data["evidence_chain"]
    assert data["evidence_chain"]["supporting_feature_count"] >= 2
    assert data["evidence_chain"]["evidence_strength"] >= 0.50

    # 4. Confidence separated from score
    assert data["confidence"]["forecast_score"] == 0.82
    assert data["confidence"]["confidence_value"] is None  # Uncalibrated!
    assert data["confidence"]["calibration_status"] == "UNSUPPORTED"
    assert data["confidence"]["confidence_state"] == "UNCALIBRATED"

    # 5. Unknown behavior classified
    assert data["unknown_behavior"]["classification"] in ["KNOWN_PATTERN", "WEAK_PATTERN"]

    # 6. Abstention check
    assert data["abstention"]["abstained"] is False
    assert data["abstention"]["status"] == "FORECAST_AVAILABLE_BUT_UNCALIBRATED"

    # 7. Complete JSON serializability check
    serialized = json.dumps(data)
    assert len(serialized) > 0


def test_insufficient_history_abstention_in_intelligence():
    # Only 2 states
    seq = [_make_state(i) for i in range(2)]
    forecast_points = [{"horizon": 1, "attack_probability": None, "confidence": None, "predicted_stage": None}]

    result = assemble_forecast_intelligence(
        sequence=seq,
        forecast_points=forecast_points,
        min_sequence_length=8,
    )
    data = result.to_dict()

    assert data["abstention"]["abstained"] is True
    assert data["abstention"]["reason"] == "INSUFFICIENT_HISTORY"
    assert data["attack_horizon"]["state"] == "ABSTAINED"
    assert data["confidence"]["confidence_state"] == "UNKNOWN"

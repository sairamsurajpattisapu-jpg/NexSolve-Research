"""Unit tests for NexSolve Forecast Abstention engine."""
from __future__ import annotations

import pytest

from ml.forecasting.forecast_abstention import (
    AbstentionSeverity,
    ForecastAbstentionResult,
    ForecastAvailabilityStatus,
    evaluate_forecast_abstention,
)
from ml.forecasting.forecast_confidence import CalibrationStatus, ForecastConfidenceResult, ConfidenceState, UncertaintyLevel
from ml.forecasting.unknown_behavior import BehaviorClassification, UnknownBehaviorResult
from nexsolve_core.schemas import CaptureQuality, QualityStatus
from world_model import FLOW_NAMES, NetworkState


def _make_state(timestamp: int, flow: dict[str, float] | None = None) -> NetworkState:
    f = flow if flow is not None else {name: 10.0 for name in FLOW_NAMES}
    return NetworkState(timestamp, f, {}, {}, 0, False)


def test_insufficient_history_abstention():
    # Only 3 windows instead of required 8
    seq = [_make_state(1700000000 + i * 60) for i in range(3)]
    res = evaluate_forecast_abstention(seq, min_sequence_length=8)
    assert res.abstained is True
    assert res.reason == "INSUFFICIENT_HISTORY"
    assert res.severity == AbstentionSeverity.CRITICAL
    assert res.status == ForecastAvailabilityStatus.FORECAST_UNAVAILABLE
    assert len(res.missing_requirements) >= 1


def test_gapped_history_abstention():
    # 8 windows, but step 4 has a 180s gap instead of 60s
    seq = [
        _make_state(1700000000),
        _make_state(1700000060),
        _make_state(1700000120),
        _make_state(1700000300),  # Gap!
        _make_state(1700000360),
        _make_state(1700000420),
        _make_state(1700000480),
        _make_state(1700000540),
    ]
    res = evaluate_forecast_abstention(seq, min_sequence_length=8)
    assert res.abstained is True
    assert res.reason == "GAPPED_HISTORY"
    assert res.severity == AbstentionSeverity.HIGH
    assert res.status == ForecastAvailabilityStatus.FORECAST_UNAVAILABLE


def test_missing_required_features_abstention():
    seq = [_make_state(1700000000 + i * 60, flow={"flow_count": 10.0}) for i in range(8)]
    # We require both flow_count and total_src_bytes
    res = evaluate_forecast_abstention(seq, min_sequence_length=8, required_features=["flow_count", "total_src_bytes"])
    assert res.abstained is True
    assert res.reason == "MISSING_REQUIRED_FEATURES"
    assert any("total_src_bytes" in r for r in res.missing_requirements)


def test_poor_capture_quality_abstention():
    seq = [_make_state(1700000000 + i * 60) for i in range(8)]
    quality = CaptureQuality(
        total_packets_observed=1,
        parsed_packets=1,
        malformed_packets=0,
        unsupported_packets=0,
        truncated_packets=0,
        timestamp_anomalies=0,
        duplicate_packets=0,
        ipv4_count=1,
        ipv6_count=0,
        tcp_count=1,
        udp_count=0,
        icmp_count=0,
        arp_count=0,
        vlan_count=0,
        fragmented_packet_count=0,
        incomplete_flow_count=0,
        status=QualityStatus.INSUFFICIENT,
        reason="Single packet capture",
        capture_id="cap-bad",
    )
    res = evaluate_forecast_abstention(seq, capture_quality=quality)
    assert res.abstained is True
    assert res.reason == "POOR_CAPTURE_QUALITY"
    assert res.severity == AbstentionSeverity.CRITICAL


def test_unknown_behavior_abstain_recommended():
    seq = [_make_state(1700000000 + i * 60) for i in range(8)]
    ub = UnknownBehaviorResult(
        classification=BehaviorClassification.UNKNOWN_BEHAVIOR,
        reason="Semantic contradiction: 1M bytes without packets",
        supporting_evidence=[],
        contradictory_evidence=[],
        coverage=0.20,
        abstain_recommended=True,
    )
    res = evaluate_forecast_abstention(seq, unknown_behavior=ub)
    assert res.abstained is True
    assert res.reason == "UNKNOWN_BEHAVIOR"


def test_clean_sequence_forecast_available_but_uncalibrated():
    seq = [_make_state(1700000000 + i * 60) for i in range(8)]
    conf = ForecastConfidenceResult(
        forecast_score=0.75,
        confidence_value=None,
        confidence_state=ConfidenceState.UNCALIBRATED,
        evidence_strength=0.70,
        calibration_status=CalibrationStatus.UNSUPPORTED,
        uncertainty_level=UncertaintyLevel.LOW,
        explanation="Uncalibrated",
    )
    res = evaluate_forecast_abstention(seq, confidence_result=conf)
    # Does NOT abstain!
    assert res.abstained is False
    assert res.status == ForecastAvailabilityStatus.FORECAST_AVAILABLE_BUT_UNCALIBRATED
    assert res.severity == AbstentionSeverity.LOW


def test_clean_calibrated_forecast_available():
    seq = [_make_state(1700000000 + i * 60) for i in range(8)]
    conf = ForecastConfidenceResult(
        forecast_score=0.75,
        confidence_value=0.75,
        confidence_state=ConfidenceState.CALIBRATED,
        evidence_strength=0.80,
        calibration_status=CalibrationStatus.CALIBRATED,
        uncertainty_level=UncertaintyLevel.LOW,
        explanation="Calibrated",
    )
    res = evaluate_forecast_abstention(seq, confidence_result=conf)
    assert res.abstained is False
    assert res.status == ForecastAvailabilityStatus.FORECAST_AVAILABLE
    assert res.severity == AbstentionSeverity.NONE

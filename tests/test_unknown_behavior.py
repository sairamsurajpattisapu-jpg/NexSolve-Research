"""Unit tests for NexSolve Unknown Behavior classification layer."""
from __future__ import annotations

import pytest

from ml.forecasting.attack_horizon import compute_attack_horizon
from ml.forecasting.evidence_intelligence import (
    EvidenceChain,
    EvidenceDirection,
    EvidenceItem,
    EvidenceQuality,
    EvidenceSeverity,
    EvidenceType,
    build_evidence_chain,
)
from ml.forecasting.unknown_behavior import (
    BehaviorClassification,
    UnknownBehaviorResult,
    classify_unknown_behavior,
)
from world_model import NetworkState


def _make_chain(
    supporting_count: int = 0,
    contradictory_count: int = 0,
    strength: float = 0.5,
    quality: EvidenceQuality = EvidenceQuality.HIGH,
) -> EvidenceChain:
    supporting = [
        EvidenceItem(
            evidence_id=f"EV-S{i}",
            timestamp="2026-09-10T06:00:00Z",
            window_id=f"w-{i}",
            evidence_type=EvidenceType.FLOW_ACTIVITY,
            feature_name="flow_count",
            observed_value=200.0,
            baseline_value=100.0,
            delta=100.0,
            relative_change=1.0,
            direction=EvidenceDirection.INCREASE,
            severity=EvidenceSeverity.HIGH,
            reliability=1.0,
            source="test",
            provenance={},
            explanation=f"Supporting flow surge {i}",
            is_supporting=True,
        ).to_dict()
        for i in range(supporting_count)
    ]
    contradictory = [
        EvidenceItem(
            evidence_id=f"EV-C{i}",
            timestamp="2026-09-10T06:00:00Z",
            window_id=f"w-{i}",
            evidence_type=EvidenceType.BYTE_RATE_CHANGE,
            feature_name="total_src_bytes",
            observed_value=10.0,
            baseline_value=1000.0,
            delta=-990.0,
            relative_change=-0.99,
            direction=EvidenceDirection.DECREASE,
            severity=EvidenceSeverity.HIGH,
            reliability=1.0,
            source="test",
            provenance={},
            explanation=f"Contradictory collapse {i}",
            is_supporting=False,
        ).to_dict()
        for i in range(contradictory_count)
    ]
    return EvidenceChain(
        current_window_id="w-0",
        current_timestamp="2026-09-10T06:00:00Z",
        forecast_horizon=3,
        supporting=supporting,
        contradictory=contradictory,
        evidence_strength=strength,
        evidence_quality=quality,
        supporting_feature_count=supporting_count,
        contradictory_feature_count=contradictory_count,
        provenance_complete=True,
        explanation="Test evidence chain",
        limitations=[],
    )


def test_known_pattern_baseline():
    chain = _make_chain(supporting_count=0, contradictory_count=0, strength=0.0)
    res = classify_unknown_behavior(chain)
    assert res.classification == BehaviorClassification.KNOWN_PATTERN
    assert "conforms cleanly to stable baseline" in res.reason
    assert res.abstain_recommended is False


def test_known_pattern_supported_attack():
    chain = _make_chain(supporting_count=3, contradictory_count=0, strength=0.80)
    horizon = compute_attack_horizon(
        "2026-09-10T06:00:00Z",
        [{"horizon": 1, "attack_probability": 0.85}, {"horizon": 2, "attack_probability": 0.88}],
    )
    res = classify_unknown_behavior(chain, attack_horizon=horizon)
    assert res.classification == BehaviorClassification.KNOWN_PATTERN
    assert "supported multi-step attack" in res.reason
    assert res.coverage >= 0.80


def test_weak_pattern():
    chain = _make_chain(supporting_count=1, contradictory_count=0, strength=0.30)
    horizon = compute_attack_horizon("2026-09-10T06:00:00Z", [{"horizon": 1, "attack_probability": 0.70}])
    res = classify_unknown_behavior(chain, attack_horizon=horizon)
    assert res.classification == BehaviorClassification.WEAK_PATTERN
    assert "Sparse or borderline" in res.reason


def test_unknown_behavior_insufficient_capture_quality():
    chain = _make_chain(supporting_count=2, contradictory_count=0, quality=EvidenceQuality.INSUFFICIENT)
    res = classify_unknown_behavior(chain)
    assert res.classification == BehaviorClassification.UNKNOWN_BEHAVIOR
    assert "Capture quality is INSUFFICIENT" in res.reason
    assert res.abstain_recommended is True


def test_unknown_behavior_unsupported_protocol():
    chain = _make_chain(supporting_count=2, contradictory_count=0)
    state = NetworkState(
        1700000000,
        {"proto_tcp_count": 5.0, "proto_udp_count": 5.0, "proto_other_count": 80.0},
        {},
        {},
        0,
        False,
    )
    res = classify_unknown_behavior(chain, current_state=state)
    assert res.classification == BehaviorClassification.UNKNOWN_BEHAVIOR
    assert "Unsupported protocol behavior" in res.reason


def test_unknown_behavior_unusual_feature_combination():
    chain = _make_chain(supporting_count=2, contradictory_count=0)
    # 100 flows with 0 destination ports
    state = NetworkState(
        1700000000,
        {"flow_count": 100.0, "unique_dst_ports": 0.0},
        {},
        {},
        0,
        False,
    )
    res = classify_unknown_behavior(chain, current_state=state)
    assert res.classification == BehaviorClassification.UNKNOWN_BEHAVIOR
    assert "Unusual feature combination" in res.reason


def test_unknown_behavior_forecast_evidence_disagreement():
    # Attack forecast with probability 0.90, but evidence strength 0.05 and 2 contradictory signals
    chain = _make_chain(supporting_count=0, contradictory_count=2, strength=0.05)
    horizon = compute_attack_horizon("2026-09-10T06:00:00Z", [{"horizon": 1, "attack_probability": 0.90}])
    res = classify_unknown_behavior(chain, attack_horizon=horizon)
    assert res.classification == BehaviorClassification.UNKNOWN_BEHAVIOR
    assert "Forecast and evidence disagreement" in res.reason


def test_unknown_behavior_conflicting_evidence_overload():
    chain = _make_chain(supporting_count=1, contradictory_count=4, strength=0.20)
    res = classify_unknown_behavior(chain)
    assert res.classification == BehaviorClassification.UNKNOWN_BEHAVIOR
    assert "Conflicting evidence" in res.reason

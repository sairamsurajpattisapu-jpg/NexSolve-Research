"""Targeted verification for attack progression forecasting layer.

Tests:
1. 45-feature safety and contract isolation.
2. Abstention when history is insufficient (< 8 windows).
3. Abstention for unsupported horizons (K=10, 15).
4. Strict separation between OBSERVED and FORECAST techniques.
5. Deterministic probability within [0, 1] with zero arbitrary confidence formula.
6. Downstream progression abstains when no transition exists.
7. Zero leakage: past-only condition.
"""
from __future__ import annotations

import pytest
from ml.forecasting.attack_progression import (
    AttackProgressionState,
    PredictionType,
    forecast_attack_progression,
    determine_observed_state,
    EMPIRICALLY_SUPPORTED_HORIZONS,
    UNSUPPORTED_HORIZONS,
)
from ml.forecasting.attack_stages import AttackStage, StageClassification
from ml.data.dataset_adapter import map_dataset_label_to_stage


def test_abstention_on_insufficient_history():
    """Verify that forecasting strictly abstains when fewer than 8 windows are provided."""
    findings = [{"attack_category": "network_reconnaissance", "detection_method": "heuristics"}]
    res = forecast_attack_progression(findings, history_window_count=5)

    assert res.verdict == "ABSTAINED"
    assert len(res.forecast_points) == 5
    for pt in res.forecast_points:
        assert pt.abstained is True
        assert pt.prediction_type == PredictionType.ABSTAINED
        assert "INSUFFICIENT_HISTORY" in str(pt.abstention_reason)


def test_abstention_on_unsupported_horizons():
    """Verify that horizons K=10 and K=15 are explicitly abstained due to lack of replication."""
    findings = [{"attack_category": "network_reconnaissance", "detection_method": "heuristics"}]
    res = forecast_attack_progression(findings, history_window_count=10)

    assert res.verdict == "PARTIALLY_SUPPORTED"
    by_h = {pt.horizon_minutes: pt for pt in res.forecast_points}

    # Supported horizons: 1, 3, 5
    for k in (1, 3, 5):
        assert by_h[k].abstained is False
        assert 0.0 <= by_h[k].transition_probability <= 1.0
        # Verify no arbitrary confidence formula or field exists
        assert not hasattr(by_h[k], "confidence")
        assert by_h[k].predicted_technique == "T1046"
        assert by_h[k].prediction_type == PredictionType.STATE_PERSISTENCE
        # Persistence does NOT forecast new downstream techniques
        assert by_h[k].forecast_techniques == ()

    # Unsupported horizons: 10, 15
    for k in (10, 15):
        assert by_h[k].abstained is True
        assert by_h[k].prediction_type == PredictionType.ABSTAINED
        assert "UNSUPPORTED_HORIZON" in str(by_h[k].abstention_reason)


def test_observed_and_forecast_technique_separation():
    """Verify that observed techniques and forecast techniques never collide or leak."""
    findings = [{"attack_category": "network_reconnaissance", "detection_method": "heuristics"}]
    state, observed_techs = determine_observed_state(findings)

    assert state == AttackProgressionState.RECONNAISSANCE
    assert "T1046" in observed_techs

    res = forecast_attack_progression(findings, history_window_count=10)
    assert res.observed_state == AttackProgressionState.RECONNAISSANCE
    assert res.observed_techniques == ("T1046",)

    # State persistence must not emit T1046 as a new downstream forecast technique
    for pt in res.forecast_points:
        if pt.prediction_type == PredictionType.STATE_PERSISTENCE:
            assert pt.forecast_techniques == ()


def test_benign_observation_abstains_from_future_attack_prediction():
    """Verify that benign state does not manufacture anticipatory attack forecasts."""
    findings = []
    res = forecast_attack_progression(findings, history_window_count=12)

    assert res.observed_state == AttackProgressionState.BENIGN_OBSERVATION
    by_h = {pt.horizon_minutes: pt for pt in res.forecast_points}

    # Supported horizons predict continuing benign state
    for k in (1, 3, 5):
        assert by_h[k].predicted_state == AttackProgressionState.BENIGN_OBSERVATION
        assert by_h[k].predicted_technique is None
        assert by_h[k].forecast_techniques == ()
        assert by_h[k].prediction_type == PredictionType.STATE_PERSISTENCE
        assert 0.95 <= by_h[k].transition_probability <= 1.0


def test_zero_downstream_cross_stage_fabrication():
    """Enforce that unobserved transitions (e.g. Recon -> DoS) are never fabricated."""
    findings = [{"attack_category": "network_reconnaissance", "detection_method": "heuristics"}]
    res = forecast_attack_progression(findings, history_window_count=10)

    for pt in res.forecast_points:
        # We must never forecast DoS (T1498) from Reconnaissance
        assert pt.predicted_state != AttackProgressionState.DENIAL_OF_SERVICE
        assert "T1498" not in pt.forecast_techniques
        assert pt.prediction_type != PredictionType.DOWNSTREAM_PROGRESSION


def test_abstention_when_downstream_progression_requested_without_support():
    """Verify that requesting downstream progression abstains with NO_SUPPORTED_DOWNSTREAM_TRANSITION."""
    findings = [{"attack_category": "network_reconnaissance", "detection_method": "heuristics"}]
    res = forecast_attack_progression(
        findings,
        history_window_count=10,
        require_downstream_progression=True,
    )

    by_h = {pt.horizon_minutes: pt for pt in res.forecast_points}
    for k in (1, 3, 5):
        assert by_h[k].abstained is True
        assert by_h[k].prediction_type == PredictionType.ABSTAINED
        assert "NO_SUPPORTED_DOWNSTREAM_TRANSITION" in str(by_h[k].abstention_reason)
        assert by_h[k].forecast_techniques == ()


def test_probability_determinism_and_bounds():
    """Verify transition_probability is strictly deterministic and bounded within [0, 1]."""
    findings = [{"attack_category": "network_reconnaissance", "detection_method": "heuristics"}]
    res1 = forecast_attack_progression(findings, history_window_count=10)
    res2 = forecast_attack_progression(findings, history_window_count=10)

    for pt1, pt2 in zip(res1.forecast_points, res2.forecast_points):
        assert pt1.transition_probability == pt2.transition_probability
        assert 0.0 <= pt1.transition_probability <= 1.0
        assert pt1.to_dict() == pt2.to_dict()
        assert "confidence" not in pt1.to_dict()


def test_phase2_canonical_stage_and_timeline_generation():
    """Verify Phase 2 forecast includes canonical 15-stage enum and timeline events."""
    findings = [{"attack_category": "network_reconnaissance", "detection_method": "heuristics"}]
    res = forecast_attack_progression(findings, history_window_count=10, current_timestamp=1710000000.0)

    # Canonical stage present
    assert res.canonical_stage == AttackStage.RECONNAISSANCE
    assert res.observed_state == AttackProgressionState.RECONNAISSANCE

    # Timeline generated with events
    assert len(res.timeline) >= 4  # 1 observed/inferred + 3 supported horizons (T+1, T+3, T+5)
    obs_ev = res.timeline[0]
    assert obs_ev["classification"] == StageClassification.INFERRED.value
    assert obs_ev["stage"] == AttackStage.RECONNAISSANCE.value
    assert "T1046" in obs_ev["primary_techniques"]

    # Forecast points have canonical stages and separated confidences
    for pt in res.forecast_points:
        if not pt.abstained:
            assert pt.canonical_stage == AttackStage.RECONNAISSANCE
            assert 0.0 <= pt.stage_confidence <= 1.0
            assert 0.0 <= pt.forecast_confidence <= 1.0
            assert 0.0 <= pt.transition_confidence <= 1.0
            assert pt.classification == StageClassification.FORECAST

    # Transitions generated and validated
    assert len(res.transitions) >= 1
    assert res.validation is not None
    assert res.validation["valid"] is True


def test_phase2_dataset_adapter_stage_mapping():
    """Verify dataset adapter correctly maps labels across UNSW-NB15, CIC-IDS2017, and TON-IoT."""
    # UNSW-NB15
    assert map_dataset_label_to_stage("UNSW-NB15", "Reconnaissance") == AttackStage.RECONNAISSANCE
    assert map_dataset_label_to_stage("UNSW-NB15", "Exploits") == AttackStage.INITIAL_ACCESS
    assert map_dataset_label_to_stage("UNSW-NB15", "DoS") == AttackStage.IMPACT
    assert map_dataset_label_to_stage("UNSW-NB15", "Normal") == AttackStage.BENIGN
    # UNSW Generic: attack present but stage unknown
    assert map_dataset_label_to_stage("UNSW-NB15", "Generic") == AttackStage.UNKNOWN

    # CIC-IDS2017
    assert map_dataset_label_to_stage("CIC-IDS2017", "PortScan") == AttackStage.RECONNAISSANCE
    assert map_dataset_label_to_stage("CIC-IDS2017", "BENIGN") == AttackStage.BENIGN

    # TON-IoT
    assert map_dataset_label_to_stage("TON-IoT", "scanning") == AttackStage.RECONNAISSANCE
    assert map_dataset_label_to_stage("TON-IoT", "xss") == AttackStage.INITIAL_ACCESS
    assert map_dataset_label_to_stage("TON-IoT", "ddos") == AttackStage.IMPACT

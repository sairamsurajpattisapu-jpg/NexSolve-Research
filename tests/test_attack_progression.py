import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research_intelligence.engine import (
    TrendThresholds,
    analyze_forecast,
    infer_stage,
    load_attack_technique,
    probability_trend,
)
from world_model import FLOW_NAMES, NetworkState


def make_state(index=0, ports=2, attack=0):
    flow = {name: 0.0 for name in FLOW_NAMES}
    flow.update(flow_count=20.0, unique_dst_ports=float(ports), mean_duration=500.0,
                total_src_bytes=100.0, total_dst_bytes=100.0)
    return NetworkState(index * 60, flow, {name: 0.0 for name in ["packet_count"]}, {}, attack, False)


def point(horizon, probability, predicted_state=None, confidence=0.8, abstained=False):
    return {"horizon": horizon, "attack_probability": probability, "predicted_state": predicted_state,
            "confidence": confidence, "abstained": abstained}


def test_benign_traffic_is_unknown_without_scan_evidence():
    result = infer_stage(make_state(), mitre_bundle=Path("MITRE/enterprise-attack-19.2.json"))
    assert result["stage"] == "UNKNOWN"
    assert result["status"] == "INSUFFICIENT_EVIDENCE"


def test_scan_like_behavior_is_contextual_and_mitre_validated():
    result = infer_stage(make_state(ports=15), mitre_bundle=Path("MITRE/enterprise-attack-19.2.json"))
    assert result["behavioral_signal"] == "PORT_SCAN_LIKE_ACTIVITY"
    assert result["stage"] == "RECONNAISSANCE"
    assert result["status"] == "CONTEXTUAL_HYPOTHESIS"
    assert result["techniques"][0]["technique_id"] == "T1046"


def test_probability_trends_cover_rising_falling_and_uncertain():
    thresholds = TrendThresholds()
    assert probability_trend([0.2, 0.35, 0.7], thresholds) == ["STABLE_LOW", "RISING", "RAPIDLY_RISING"]
    assert probability_trend([0.8, 0.6], thresholds) == ["STABLE_HIGH", "FALLING"]
    assert probability_trend([0.5], thresholds) == ["UNCERTAIN"]


def test_insufficient_history_abstains_without_forcing_stage():
    result = analyze_forecast([], [point(1, None, None, None, True)])
    assert result["forecast"][0]["status"] == "INSUFFICIENT_EVIDENCE"
    assert result["forecast"][0]["stage"]["stage"] == "UNKNOWN"
    assert result["defender_guidance"]["priority"] == "LOW"


def test_missing_features_and_unsupported_mapping_abstain():
    assert infer_stage({"flow_features": {}})["status"] == "INSUFFICIENT_EVIDENCE"
    assert load_attack_technique("T999999", Path("MITRE/enterprise-attack-19.2.json")) is None
    assert load_attack_technique("not-an-id", Path("MITRE/enterprise-attack-19.2.json")) is None


def test_forecast_technique_is_separate_from_observed_context():
    predicted = {"flow_count": 20.0, "unique_dst_ports": 15.0, "mean_duration": 500.0}
    result = analyze_forecast([make_state(ports=15)], [point(1, 0.8, predicted)], mitre_bundle=Path("MITRE/enterprise-attack-19.2.json"))
    assert result["current_state"]["stage"]["techniques"][0]["status"] == "CONTEXTUAL_TECHNIQUE"
    assert result["forecast"][0]["stage"]["techniques"][0]["status"] == "FORECAST_CONTEXT"
    assert result["forecast"][0]["status"] == "MODEL_PREDICTION"


def test_identical_inputs_are_deterministic_and_labels_do_not_leak():
    first = analyze_forecast([make_state(attack=0)], [point(1, 0.4, None, None, True)])
    second = analyze_forecast([make_state(attack=1)], [point(1, 0.4, None, None, True)])
    assert first == second
    assert first == analyze_forecast([make_state(attack=0)], [point(1, 0.4, None, None, True)])

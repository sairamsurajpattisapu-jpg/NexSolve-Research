import pytest

from ml.detection import HeuristicDetector, MLDetector, analyze_packet_windows


def window(**overrides):
    value = {
        "window_start": 0,
        "packet_count": 100,
        "port_scan_score": 0.0,
        "tcp_retransmission_rate": 0.0,
        "fragment_ratio": 0.0,
        "syn_count": 0,
    }
    value.update(overrides)
    return value


def test_detector_exposes_fired_rules_and_supported_explanations():
    result = analyze_packet_windows([window(port_scan_score=0.8, syn_count=60)])
    assert result["detection_method"] == "traffic_heuristics"
    assert result["model_prediction_available"] is False
    finding = result["findings"][0]
    assert finding["detection_method"] == "traffic_heuristics"
    assert {item["rule_id"] for item in finding["evidence"]} == {"PORT_SCAN_SCORE_HIGH", "SYN_PRESSURE_HIGH"}
    assert finding["explanation"] == [item["message"] for item in finding["evidence"]]


def test_detector_handles_empty_and_benign_windows_without_findings():
    detector = HeuristicDetector()
    assert detector.analyze([])["status"] == "completed"
    result = detector.analyze([window()])
    assert result["detected_events"] == 0
    assert result["findings"] == []
    assert result["risk_score"] == 0.0


def test_detector_handles_missing_optional_values_as_zero():
    result = analyze_packet_windows([{"window_start": 0, "packet_count": 10}])
    assert result["detected_events"] == 0
    assert result["risk_score"] == 0.0


def test_validated_ml_detector_is_explicitly_future_only():
    assert MLDetector.detection_method == "validated_ml"
    with pytest.raises(NotImplementedError, match="compatible labeled packet windows"):
        MLDetector().analyze([])

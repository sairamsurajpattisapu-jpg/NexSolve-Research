import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest

from ml.calibration.calibrator import PlattCalibrator
from ml.calibration.evaluation import calibration_metrics
from ml.data.flow_packet_aligner import AlignmentConfig, align_observations
from ml.data.packet_features import PacketWindow, packet_feature_vector
from ml.evaluation.metrics import binary_metrics
from ml.evaluation.error_analysis import classify_errors
from ml.evaluation.model_runner import run_plugin
from ml.evaluation.model_selection import select_model
from ml.evaluation.temporal_evaluator import evaluate_horizons, validate_temporal_splits


def test_metrics_reject_invalid_probabilities_and_report_one_class_auc():
    with pytest.raises(ValueError):
        binary_metrics([0], [1.1])
    result = binary_metrics([0, 0], [0.1, 0.2])
    assert result["roc_auc"]["status"] == "not_available"


def test_horizon_contract_requires_real_t_plus_one_to_five():
    targets = [0, 1]
    predictions = {horizon: [0.2, 0.8] for horizon in range(1, 6)}
    assert set(evaluate_horizons(targets, predictions)) == {"T+1", "T+2", "T+3", "T+4", "T+5"}
    with pytest.raises(ValueError):
        evaluate_horizons(targets, {1: [0.2, 0.8]})


def test_temporal_split_validation_rejects_overlap_and_unsorted_data():
    validate_temporal_splits([type("S", (), {"timestamp": 1})()], [type("S", (), {"timestamp": 2})()], [type("S", (), {"timestamp": 3})()])
    with pytest.raises(ValueError):
        validate_temporal_splits([type("S", (), {"timestamp": 2})(), type("S", (), {"timestamp": 1})()], [], [])


def test_calibration_is_validation_only_and_requires_two_classes():
    with pytest.raises(ValueError):
        PlattCalibrator().fit([0.1, 0.2], [0, 0])
    calibrator = PlattCalibrator().fit([0.1, 0.9, 0.2, 0.8], [0, 1, 0, 1])
    assert len(calibrator.transform([0.3, 0.7])) == 2
    assert calibration_metrics([0, 1], [0.2, 0.8])["status"] == "computed"


def test_alignment_tolerance_and_missing_packet_branch_are_explicit():
    result = align_observations([{"timestamp": 60.1}], [{"timestamp": 60.9}], AlignmentConfig(timestamp_tolerance_seconds=1.0))
    assert result["matched_windows"] == 1
    assert result["feature_fabrication"] is False
    vector = packet_feature_vector(PacketWindow(0, 60, ({"timestamp": 1, "src_ip": "a", "dst_ip": "b", "protocol": "TCP"},)))
    assert vector["status"] == "PENDING_PCAP"


def test_model_selection_does_not_select_incomplete_results():
    result = select_model({"Persistence": {"T+1": {"macro_f1": 0.9}}})
    assert result["status"] == "HOLD"


def test_error_analysis_preserves_abstentions_and_error_classes():
    result = classify_errors([1, 0, 1, 0], [0.9, 0.1, None, 0.8])
    assert result["true_positive"] == 1
    assert result["true_negative"] == 1
    assert result["false_positive"] == 1
    assert result["abstention"] == 1


def test_model_plugin_runner_preserves_all_horizons():
    class Plugin:
        name = "fixture"

        def predict_horizon(self, history, horizon):
            return float(horizon) / 10

    result = run_plugin(Plugin(), [[1], [2]], seed=7)
    assert result.predictions == {horizon: [horizon / 10, horizon / 10] for horizon in range(1, 6)}
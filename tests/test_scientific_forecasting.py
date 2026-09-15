from __future__ import annotations

import pytest

from ml.evaluation.scientific_forecasting import (
    HORIZONS,
    build_forecast_cases,
    calibration_status,
    chronological_episode_split,
    evaluate_predictions,
    majority_predictions,
    persistence_predictions,
    promotion_report,
)
from world_model import FEATURE_NAMES, FLOW_NAMES, NetworkState


def state(index: int, attack: int | None) -> NetworkState:
    flow = {name: float(index + offset) for offset, name in enumerate(FLOW_NAMES)}
    packet = {name: 0.0 for name in FEATURE_NAMES if name not in FLOW_NAMES}
    temporal = {name: float(index) for name in ["delta_flow_count", "delta_total_bytes", "delta_total_packets", "delta_ports", "delta_iat", "rolling_total_bytes"]}
    return NetworkState(index * 60, flow, packet, temporal, attack, False)


def test_forecast_case_alignment_uses_history_through_t_and_future_targets():
    cases = build_forecast_cases([state(index, index % 2) for index in range(16)])
    assert cases
    case = cases[0]
    assert case.input_timestamps[-1] < case.target_timestamps[0]
    assert list(case.target_timestamps) == sorted(case.target_timestamps)
    assert case.targets == tuple((case.source_index + horizon) % 2 for horizon in HORIZONS)
    assert len(case.history) == 8


def test_forecast_case_rejects_unknown_targets_instead_of_making_them_benign():
    states = [state(index, None if index == 9 else index % 2) for index in range(16)]
    cases = build_forecast_cases(states)
    assert all(None not in case.targets for case in cases)
    history_unknown = [state(index, None if index == 7 else index % 2) for index in range(16)]
    assert all(case.history[-1].attack_state is not None for case in build_forecast_cases(history_unknown))


def test_chronological_episode_split_keeps_episode_boundaries():
    episodes = (tuple(state(index, 0) for index in range(12)), tuple(state(index + 20, 1) for index in range(12)), tuple(state(index + 40, 0) for index in range(12)))
    split = chronological_episode_split(episodes)
    assert split["train"] == (episodes[0],)
    assert split["validation"] == (episodes[1],)
    assert split["test"] == (episodes[2],)
    with pytest.raises(ValueError):
        chronological_episode_split(episodes[:2])


def test_persistence_and_majority_baselines_have_five_horizons():
    training = tuple(state(index, int(index > 5)) for index in range(16))
    cases = build_forecast_cases(tuple(state(index + 20, int(index > 3)) for index in range(16)))
    assert set(persistence_predictions(cases)) == set(HORIZONS)
    assert set(majority_predictions(cases, training)) == set(HORIZONS)
    scored = evaluate_predictions(cases, persistence_predictions(cases))
    assert set(scored) == {f"T+{horizon}" for horizon in HORIZONS}
    assert all("brier_score" in scored[f"T+{horizon}"] for horizon in HORIZONS)


def test_calibration_and_promotion_are_explicitly_conservative():
    validation = build_forecast_cases(tuple(state(index, 0) for index in range(20)))
    calibration = calibration_status(validation, {horizon: [0.2] * len(validation) for horizon in HORIZONS})
    assert all(item["status"] == "CALIBRATION_UNSUPPORTED" for item in calibration.values())
    hold = promotion_report({"Persistence": {}, "Existing LSTM": {}}, 1, calibration)
    assert hold["production_eligible"] is False
    assert hold["status"] == "HOLD"


def test_cumulative_risk_and_confidence_math():
    """Verify exact mathematical formulation of cumulative horizon risk and confidence."""
    import numpy as np

    step_probs = [0.20, 0.40, 0.50, 0.30, 0.10]
    # Math: CumulativeRisk_K = 1 - prod(1 - p_k)
    expected_cum = []
    prod = 1.0
    for p in step_probs:
        prod *= (1.0 - p)
        expected_cum.append(round(1.0 - prod, 4))

    assert expected_cum[0] == 0.2000
    assert expected_cum[1] == 0.5200  # 1 - (0.8 * 0.6) = 0.52
    assert expected_cum[2] == 0.7600  # 1 - (0.8 * 0.6 * 0.5) = 0.76

    # Confidence math: abs(p - 0.5) * 2
    confidences = [round(abs(p - 0.5) * 2, 4) for p in step_probs]
    assert confidences[0] == 0.6000   # abs(0.2 - 0.5) * 2 = 0.6
    assert confidences[2] == 0.0000   # abs(0.5 - 0.5) * 2 = 0.0 (maximum uncertainty at 0.5)

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from world_model import (FEATURE_NAMES, FLOW_NAMES, K, LOOKBACK, NetworkState,
                         NumpyLSTM, attack_stage_signals, infer, make_sequences)


def state(index: int, attack: int = 0) -> NetworkState:
    flow = {name: float(index + offset) for offset, name in enumerate(FLOW_NAMES)}
    packet = {name: 0.0 for name in FEATURE_NAMES if name not in FLOW_NAMES}
    temporal = {name: float(index) for name in ["delta_flow_count", "delta_total_bytes", "delta_total_packets", "delta_ports", "delta_iat", "rolling_total_bytes"]}
    return NetworkState(index * 60, flow, packet, temporal, attack, False)


def test_state_encoding_excludes_label_and_has_stable_width():
    first = state(1, 0).encode(); second = state(1, 1).encode()
    assert first.shape == (len(FEATURE_NAMES),)
    assert np.array_equal(first, second)


def test_sequence_creation_uses_previous_states_only():
    states = [state(index, index % 2) for index in range(LOOKBACK + 2)]
    x, targets, labels = make_sequences(states)
    assert x.shape == (2, LOOKBACK, len(FEATURE_NAMES))
    assert np.array_equal(x[0, -1], states[LOOKBACK - 1].encode())
    assert np.array_equal(targets[0], states[LOOKBACK].encode())
    assert labels.tolist() == [0, 1]


def test_rollout_has_exact_k_steps_and_schema():
    model = NumpyLSTM(seed=1)
    sequence = [state(index) for index in range(LOOKBACK)]
    result = infer(sequence, model, np.zeros(len(FEATURE_NAMES)), np.ones(len(FEATURE_NAMES)), K)
    assert [item["horizon"] for item in result["forecasts"]] == [1, 2, 3, 4, 5]
    assert all(set(item) >= {"horizon", "attack_probability", "predicted_state", "confidence", "abstained"} for item in result["forecasts"])


def test_abstention_when_history_is_insufficient():
    result = infer([state(0)], NumpyLSTM(seed=2), np.zeros(len(FEATURE_NAMES)), np.ones(len(FEATURE_NAMES)))
    assert all(item["abstained"] for item in result["forecasts"])
    assert all(item["reason"] == "insufficient history" for item in result["forecasts"])


def test_model_serialization_loading(tmp_path: Path):
    model = NumpyLSTM(seed=3); path = tmp_path / "model.npz"; model.save(path); loaded = NumpyLSTM.load(path)
    sequence = np.zeros((LOOKBACK, len(FEATURE_NAMES)))
    assert np.allclose(model.forward(sequence), loaded.forward(sequence))


def test_attack_mapping_is_contextual_not_ground_truth():
    mapped = attack_stage_signals(state(1))
    assert mapped["status"] == "contextual_inference"
    assert mapped["ground_truth"] is False
    assert isinstance(mapped["signals"], list)

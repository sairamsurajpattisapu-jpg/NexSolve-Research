"""Leakage-safe NumPy LSTM world model for the local UNSW temporal research data."""
from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.metrics import (average_precision_score, balanced_accuracy_score,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)

ROOT = Path(__file__).resolve().parent
TRAFFIC_FILES = [ROOT / "UNSW-NB15" / "raw" / f"UNSW-NB15_{i}.csv" for i in range(1, 5)]
WINDOW_SECONDS = 60
LOOKBACK = 8
K = 5
FLOW_NAMES = [
    "flow_count", "total_src_bytes", "total_dst_bytes", "total_packets", "mean_duration",
    "mean_flow_bytes", "mean_flow_packets", "mean_sttl", "mean_dttl", "mean_swin",
    "mean_dwin", "mean_iat", "mean_tcp_rtt", "unique_src_ports", "unique_dst_ports",
    "proto_tcp_count", "proto_udp_count", "proto_other_count",
]
PACKET_NAMES = [
    "packet_count", "mean_packet_size", "std_packet_size", "min_packet_size", "max_packet_size",
    "mean_ttl", "std_ttl", "min_ttl", "max_ttl", "tcp_syn_count", "tcp_ack_count",
    "tcp_fin_count", "tcp_rst_count", "tcp_psh_count", "tcp_urg_count", "mean_tcp_window",
    "std_tcp_window", "fragment_count", "retransmission_count", "mean_iat", "std_iat", "max_iat",
]
TEMPORAL_NAMES = ["delta_flow_count", "delta_total_bytes", "delta_total_packets", "delta_ports", "delta_iat", "rolling_total_bytes"]
FEATURE_NAMES = FLOW_NAMES + PACKET_NAMES + TEMPORAL_NAMES


@dataclass
class NetworkState:
    timestamp: int
    flow_features: dict[str, float]
    packet_features: dict[str, float]
    temporal_features: dict[str, float]
    attack_state: int | None = None
    packet_features_available: bool = False

    def encode(self) -> np.ndarray:
        """Encode only observable numeric state; attack_state is never encoded."""
        return np.asarray([self.flow_features.get(n, 0.0) for n in FLOW_NAMES]
                          + [self.packet_features.get(n, 0.0) for n in PACKET_NAMES]
                          + [self.temporal_features.get(n, 0.0) for n in TEMPORAL_NAMES], dtype=np.float64)

    def to_dict(self) -> dict:
        return asdict(self)


def _number(value: str) -> float:
    try:
        result = float(value.strip())
        return result if math.isfinite(result) else 0.0
    except (TypeError, ValueError):
        return 0.0


def build_network_states(files: Iterable[Path] = TRAFFIC_FILES) -> tuple[list[NetworkState], dict[int, int]]:
    """Aggregate flow records by UTC epoch minute. Labels are retained only as targets."""
    bins: dict[int, dict] = {}
    for path in files:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
            for row in csv.reader(stream):
                if len(row) != 49:
                    continue
                timestamp = _number(row[28])
                if timestamp <= 0:
                    continue
                bucket = int(timestamp // WINDOW_SECONDS)
                item = bins.setdefault(bucket, {"n": 0, "attack": 0, "src_bytes": 0.0, "dst_bytes": 0.0,
                    "packets": 0.0, "duration": 0.0, "iat": 0.0, "rtt": 0.0, "sttl": 0.0, "dttl": 0.0,
                    "swin": 0.0, "dwin": 0.0, "ports_src": set(), "ports_dst": set(), "proto": {"tcp": 0, "udp": 0, "other": 0}})
                item["n"] += 1
                item["attack"] = max(item["attack"], int(_number(row[48]) != 0))
                item["src_bytes"] += _number(row[7]); item["dst_bytes"] += _number(row[8])
                item["packets"] += _number(row[16]) + _number(row[17]); item["duration"] += _number(row[6])
                item["sttl"] += _number(row[9]); item["dttl"] += _number(row[10]); item["swin"] += _number(row[18]); item["dwin"] += _number(row[19])
                item["iat"] += _number(row[30]) + _number(row[31]); item["rtt"] += _number(row[32])
                item["ports_src"].add(row[1].strip()); item["ports_dst"].add(row[3].strip())
                proto = row[4].strip().lower(); item["proto"]["tcp" if proto == "tcp" else "udp" if proto == "udp" else "other"] += 1
    ordered = sorted(bins)
    states: list[NetworkState] = []
    labels: dict[int, int] = {}
    previous = np.zeros(len(FLOW_NAMES), dtype=np.float64)
    rolling_bytes: list[float] = []
    for bucket in ordered:
        item = bins[bucket]; n = max(item["n"], 1); total_bytes = item["src_bytes"] + item["dst_bytes"]
        flow = {"flow_count": float(item["n"]), "total_src_bytes": item["src_bytes"], "total_dst_bytes": item["dst_bytes"],
                "total_packets": item["packets"], "mean_duration": item["duration"] / n, "mean_flow_bytes": total_bytes / n,
                "mean_flow_packets": item["packets"] / n, "mean_sttl": item["sttl"] / n, "mean_dttl": item["dttl"] / n,
                "mean_swin": item["swin"] / n, "mean_dwin": item["dwin"] / n, "mean_iat": item["iat"] / n,
                "mean_tcp_rtt": item["rtt"] / n, "unique_src_ports": float(len(item["ports_src"])), "unique_dst_ports": float(len(item["ports_dst"])),
                "proto_tcp_count": float(item["proto"]["tcp"]), "proto_udp_count": float(item["proto"]["udp"]), "proto_other_count": float(item["proto"]["other"])}
        current = np.asarray([flow[name] for name in FLOW_NAMES])
        rolling_bytes.append(total_bytes); prior_bytes = rolling_bytes[-4:]
        temporal = {"delta_flow_count": current[0] - previous[0], "delta_total_bytes": total_bytes - previous[1],
                    "delta_total_packets": current[3] - previous[3], "delta_ports": current[13] + current[14] - previous[13] - previous[14],
                    "delta_iat": current[11] - previous[11], "rolling_total_bytes": float(np.mean(prior_bytes))}
        # Packet features are an explicit unavailable interface until a raw PCAP is audited.
        packet = {name: 0.0 for name in PACKET_NAMES}
        state = NetworkState(bucket * WINDOW_SECONDS, flow, packet, temporal, item["attack"], False)
        states.append(state); labels[bucket] = item["attack"]; previous = current
    return states, labels


def chronological_split(states: list[NetworkState]) -> dict[str, list[NetworkState]]:
    buckets = [state.timestamp // WINDOW_SECONDS for state in states]
    runs: list[list[int]] = [[]]
    for bucket in buckets:
        if runs[-1] and bucket != runs[-1][-1] + 1: runs.append([])
        runs[-1].append(bucket)
    first_mixed = next(i for i, run in enumerate(runs[1:], 1) if {states[buckets.index(b)].attack_state for b in run} == {0, 1})
    pre_test = [b for run in runs[:first_mixed] for b in run]; cut = int(len(pre_test) * 0.8)
    by_bucket = {b: state for b, state in zip(buckets, states)}
    return {"train": [by_bucket[b] for b in pre_test[:cut]], "validation": [by_bucket[b] for b in pre_test[cut:]],
            "test": [by_bucket[b] for b in runs[first_mixed]]}


def make_sequences(states: list[NetworkState], lookback: int = LOOKBACK) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    if len(states) <= lookback: return np.empty((0, lookback, len(FEATURE_NAMES))), np.empty((0, len(FEATURE_NAMES))), np.empty(0)
    x = np.asarray([state.encode() for state in states]); y = np.asarray([state.attack_state for state in states[lookback:]], dtype=np.float64)
    return np.asarray([x[i - lookback:i] for i in range(lookback, len(states))]), x[lookback:], y


class NumpyLSTM:
    def __init__(self, input_size: int = len(FEATURE_NAMES), hidden_size: int = 24, seed: int = 7):
        rng = np.random.default_rng(seed); self.input_size = input_size; self.hidden_size = hidden_size
        self.output_size = input_size + 1; scale = 1.0 / np.sqrt(hidden_size)
        self.W = rng.normal(0, scale, (4 * hidden_size, input_size + hidden_size)); self.b = np.zeros(4 * hidden_size)
        self.Wy = rng.normal(0, scale, (self.output_size, hidden_size)); self.by = np.zeros(self.output_size)

    def forward(self, sequence: np.ndarray, cache: bool = False):
        h = np.zeros(self.hidden_size); c = np.zeros(self.hidden_size); history = []
        for vector in sequence:
            gates = self.W @ np.r_[vector, h] + self.b; i, f, g, o = np.split(gates, 4)
            i = 1 / (1 + np.exp(-np.clip(i, -30, 30))); f = 1 / (1 + np.exp(-np.clip(f, -30, 30))); o = 1 / (1 + np.exp(-np.clip(o, -30, 30))); g = np.tanh(g)
            c = f * c + i * g; h = o * np.tanh(c); history.append((h.copy(), c.copy(), i, f, g, o, vector.copy()))
        output = self.Wy @ h + self.by
        return (output, history) if cache else output

    def train(self, x: np.ndarray, targets: np.ndarray, labels: np.ndarray, epochs: int = 35, learning_rate: float = 0.002) -> list[float]:
        losses = []
        for _ in range(epochs):
            total = 0.0
            for sequence, target, label in zip(x, targets, labels):
                output, history = self.forward(sequence, True); state_error = output[:-1] - target; probability = 1 / (1 + np.exp(-np.clip(output[-1], -30, 30)))
                total += float(np.mean(state_error ** 2) + (-(label * np.log(probability + 1e-9) + (1 - label) * np.log(1 - probability + 1e-9))))
                d_out = np.r_[2 * state_error / len(state_error), probability - label]; dWy = np.outer(d_out, history[-1][0]); dby = d_out
                dh = self.Wy.T @ d_out; dc = np.zeros(self.hidden_size); dW = np.zeros_like(self.W); db = np.zeros_like(self.b)
                for index in range(len(history) - 1, -1, -1):
                    h, c, i, f, g, o, vector = history[index]; old_c = history[index - 1][1] if index else np.zeros(self.hidden_size)
                    do = dh * np.tanh(c); dc += dh * o * (1 - np.tanh(c) ** 2); df = dc * old_c; di = dc * g; dg = dc * i
                    dz = np.r_[di * i * (1 - i), df * f * (1 - f), dg * (1 - g ** 2), do * o * (1 - o)]
                    dW += np.outer(dz, np.r_[vector, history[index - 1][0] if index else np.zeros(self.hidden_size)]); db += dz
                    dh = self.W[:, self.input_size:].T @ dz; dc *= f
                for parameter, gradient in ((self.W, dW), (self.b, db), (self.Wy, dWy), (self.by, dby)): parameter -= learning_rate * np.clip(gradient, -5, 5)
            losses.append(total / max(len(x), 1))
        return losses

    def predict(self, sequence: np.ndarray) -> tuple[np.ndarray, float]:
        output = self.forward(sequence); probability = float(1 / (1 + np.exp(-np.clip(output[-1], -30, 30))))
        return output[:-1], probability

    def save(self, path: Path) -> None:
        np.savez(path, W=self.W, b=self.b, Wy=self.Wy, by=self.by, input_size=self.input_size, hidden_size=self.hidden_size)

    @classmethod
    def load(cls, path: Path) -> "NumpyLSTM":
        data = np.load(path); model = cls(int(data["input_size"]), int(data["hidden_size"])); model.W = data["W"]; model.b = data["b"]; model.Wy = data["Wy"]; model.by = data["by"]; return model


def infer(sequence: list[NetworkState], model: NumpyLSTM, scaler_mean: np.ndarray, scaler_scale: np.ndarray, k: int = K) -> dict:
    current = sequence[-1].to_dict() if sequence else None; forecasts = []
    if len(sequence) < LOOKBACK:
        return {"current_state": current, "forecasts": [{"horizon": step, "attack_probability": None, "predicted_state": None, "confidence": 0.0, "abstained": True, "reason": "insufficient history"} for step in range(1, k + 1)]}
    rolling = list(sequence[-LOOKBACK:])
    for step in range(1, k + 1):
        matrix = np.asarray([state.encode() for state in rolling[-LOOKBACK:]])
        scaled = (matrix - scaler_mean) / scaler_scale; predicted_scaled, probability = model.predict(scaled); vector = predicted_scaled * scaler_scale + scaler_mean
        confidence = float(abs(probability - 0.5) * 2); predicted = {name: float(value) for name, value in zip(FEATURE_NAMES, vector)}
        forecasts.append({"horizon": step, "attack_probability": probability, "predicted_state": predicted, "confidence": confidence, "abstained": False})
        rolling.append(NetworkState(rolling[-1].timestamp + WINDOW_SECONDS, {n: predicted[n] for n in FLOW_NAMES}, {n: predicted[n] for n in PACKET_NAMES}, {n: predicted[n] for n in TEMPORAL_NAMES}, int(probability >= 0.5), rolling[-1].packet_features_available))
    return {"current_state": current, "forecasts": forecasts}


def metrics(actual: list[int], probabilities: list[float], threshold: float = 0.5) -> dict:
    predicted = [int(value >= threshold) for value in probabilities]; result = {"precision": precision_score(actual, predicted, zero_division=0), "recall": recall_score(actual, predicted, zero_division=0), "f1": f1_score(actual, predicted, zero_division=0), "macro_f1": f1_score(actual, predicted, average="macro", zero_division=0), "balanced_accuracy": balanced_accuracy_score(actual, predicted), "confusion_matrix": confusion_matrix(actual, predicted, labels=[0, 1]).tolist(), "roc_auc": roc_auc_score(actual, probabilities) if len(set(actual)) == 2 else "Not valid: one class", "pr_auc": average_precision_score(actual, probabilities) if len(set(actual)) == 2 else "Not valid: one class", "coverage": 1.0, "abstention_rate": 0.0, "forecast_cases": len(actual)}; return result


def attack_stage_signals(state: NetworkState) -> dict:
    flow = state.flow_features; signals = []
    if flow.get("unique_dst_ports", 0) >= 10 or flow.get("proto_tcp_count", 0) > flow.get("flow_count", 1) * 0.8: signals.append({"stage": "Reconnaissance", "technique": "Network Service Scanning (contextual)", "confidence": 0.35})
    if flow.get("total_dst_bytes", 0) > flow.get("total_src_bytes", 0) * 5: signals.append({"stage": "Command and Control", "technique": "Application Layer Protocol (contextual)", "confidence": 0.2})
    return {"status": "contextual_inference", "signals": signals, "ground_truth": False}


def explain(sequence: list[NetworkState], model: NumpyLSTM, mean: np.ndarray, scale: np.ndarray) -> list[dict]:
    if len(sequence) < LOOKBACK: return []
    baseline = infer(sequence, model, mean, scale, 1)["forecasts"][0]["attack_probability"]; values = []
    matrix = np.asarray([state.encode() for state in sequence[-LOOKBACK:]])
    for index, name in enumerate(FEATURE_NAMES):
        changed = matrix.copy(); changed[-1, index] = mean[index]; probability = model.predict((changed - mean) / scale)[1]; values.append({"feature": name, "contribution": float(baseline - probability), "language": "contributed to the model forecast; not causal"})
    return sorted(values, key=lambda item: abs(item["contribution"]), reverse=True)[:8]


def load_model(package_dir: Path | None = None) -> tuple[NumpyLSTM, np.ndarray, np.ndarray]:
    package_dir = package_dir or (ROOT / "models" / "nexsolve_world_model")
    scaler = np.load(package_dir / "preprocessing.npz")
    return NumpyLSTM.load(package_dir / "model.npz"), scaler["mean"], scaler["scale"]


def predict(sequence: list[NetworkState], package_dir: Path | None = None) -> dict:
    model, mean, scale = load_model(package_dir)
    return infer(sequence, model, mean, scale, 1)["forecasts"][0]


def forecast_k_steps(sequence: list[NetworkState], k: int = K, package_dir: Path | None = None) -> dict:
    model, mean, scale = load_model(package_dir)
    return infer(sequence, model, mean, scale, k)


def run_training(epochs: int = 35) -> dict:
    states, _ = build_network_states(); split = chronological_split(states); train = split["train"]
    x, targets, labels = make_sequences(train); mean = np.mean(np.asarray([s.encode() for s in train]), axis=0); scale = np.std(np.asarray([s.encode() for s in train]), axis=0); scale[scale < 1e-9] = 1.0
    x = (x - mean) / scale; targets = (targets - mean) / scale; model = NumpyLSTM(); losses = model.train(x, targets, labels, epochs); model.save(ROOT / "results" / "world_model_lstm.npz"); np.savez(ROOT / "results" / "world_model_scaler.npz", mean=mean, scale=scale)
    return {"dataset": "UNSW-NB15", "split": {key: len(value) for key, value in split.items()}, "lookback": LOOKBACK, "K": K, "input_features": FEATURE_NAMES, "packet_features_available": False, "architecture": "NumPy LSTM encoder with continuous state decoder and binary attack head", "hyperparameters": {"hidden_size": 24, "epochs": epochs, "learning_rate": 0.002, "seed": 7}, "training_loss_final": losses[-1], "training_loss_curve": losses}


def run_evaluation() -> dict:
    states, _ = build_network_states(); split = chronological_split(states); train = split["train"]; test = split["test"]; data = np.load(ROOT / "results" / "world_model_scaler.npz"); model = NumpyLSTM.load(ROOT / "results" / "world_model_lstm.npz"); mean, scale = data["mean"], data["scale"]
    actual, probabilities = [], []
    for source_index in range(len(test) - 1):
        if source_index < LOOKBACK:
            continue
        sequence = test[source_index - LOOKBACK:source_index]
        _, probability = model.predict((np.asarray([s.encode() for s in sequence]) - mean) / scale)
        actual.append(test[source_index + 1].attack_state); probabilities.append(probability)
    lstm = metrics(actual, probabilities); lstm.update({"forecast_cases": len(test) - 1, "evaluated_cases": len(actual), "coverage": len(actual) / max(len(test) - 1, 1), "abstentions": (len(test) - 1) - len(actual), "abstention_rate": ((len(test) - 1) - len(actual)) / max(len(test) - 1, 1)})
    persistence_actual = [state.attack_state for state in test[1:]]
    persistence = metrics(persistence_actual, [float(state.attack_state) for state in test[:-1]])
    report = {"dataset": "UNSW-NB15", "feature_groups": {"flow": FLOW_NAMES, "packet": PACKET_NAMES, "temporal": TEMPORAL_NAMES}, "split_definition": "Existing 60-second contiguous-run split: first two runs pre-test, 80/20 train/validation; first later mixed-state run untouched test.", "model": "LSTM trained only on train windows; packet interface currently unavailable and zero-filled with availability=false.", "training_results": {"source": "results/world_model_training.json"}, "test_results": {"lstm": lstm, "temporal_persistence": persistence}, "baseline_comparison": "No improvement claim is made without a measured advantage over persistence.", "existing_logistic_regression_baseline": {"source": "results/detection_baseline.json", "status": "Not directly comparable: it is a CIC-IDS2017 static detection baseline, while this is UNSW-NB15 next-window forecasting.", "preserved": True}, "leakage_checks": ["labels used only as next-state targets", "attack_ratio, filenames, scenarios, IPs, and tuple identifiers excluded", "scaler fit on training windows only", "chronological split preserved", "test labels read only for scoring", "train/test time gap was not crossed for LSTM context"], "limitations": ["One 24-pair mixed-state test episode", "LSTM abstains on the first eight test sources because contiguous test history is insufficient", "No raw PCAP is available yet", "Packet features are an explicit unavailable interface, not fabricated observations", "NumPy LSTM is a compact execution-critical prototype"], "packet_audit_blocker": "Stop model work and audit the PCAP immediately when the Friday PCAP appears."}; (ROOT / "reports/world_model_evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8"); (ROOT / "reports/world_model_evaluation.md").write_text("# World Model Evaluation\n\n```json\n" + json.dumps(report, indent=2) + "\n```\n", encoding="utf-8"); return report


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("command", choices=["train", "evaluate", "train-evaluate"]); parser.add_argument("--epochs", type=int, default=35); args = parser.parse_args(); (ROOT / "results").mkdir(exist_ok=True)
    if args.command in {"train", "train-evaluate"}:
        training = run_training(args.epochs); (ROOT / "reports/world_model_training.json").write_text(json.dumps(training, indent=2), encoding="utf-8"); (ROOT / "reports/world_model_training.md").write_text("# World Model Training\n\n```json\n" + json.dumps(training, indent=2) + "\n```\n", encoding="utf-8")
    if args.command in {"evaluate", "train-evaluate"}: run_evaluation()


if __name__ == "__main__": main()

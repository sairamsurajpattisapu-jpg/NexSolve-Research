"""Multi-View Encoders and Cross-View Fusion for NexSolve World Model.

Implements modular representation learning:
- Separate sub-encoders for independent telemetry views:
  1. PacketEncoder (22 packet features -> d_pkt=16)
  2. FlowEncoder (17 flow features -> d_flow=16)
  3. ProtocolEncoder (16 L4/L7 protocol features -> d_proto=12)
  4. HostEncoder (5 host features -> d_host=8)
  5. TemporalEncoder (10 temporal dynamics features -> d_temp=8)
  6. BehaviorEncoder (12 interaction features -> d_beh=8)
  7. GraphEncoder (11 topological graph features -> d_graph=8)
  8. ObservabilityEncoder (10 quality/missingness features -> d_obs=6)
- Gated Cross-View Fusion producing the canonical Network World State Z_t (dim=32).
- Recurrent Temporal World State Accumulator (LSTM cell, H=32).
- Full ablation support: Individual encoders can be dynamically enabled/disabled.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np


def _tanh(x: np.ndarray) -> np.ndarray:
    return np.tanh(np.clip(x, -20.0, 20.0))


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -25.0, 25.0)))


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0.0, x)


class LinearEncoder:
    """Individual linear projection layer with non-linear activation."""

    def __init__(self, in_features: int, out_features: int, seed: int = 42) -> None:
        self.in_features = in_features
        self.out_features = out_features
        rng = np.random.default_rng(seed)
        scale = 1.0 / np.sqrt(max(1, in_features))
        self.W = rng.normal(0.0, scale, (out_features, in_features))
        self.b = np.zeros(out_features, dtype=np.float64)

    def forward(self, x: np.ndarray) -> np.ndarray:
        return _tanh(self.W @ x + self.b)


class MultiViewEncoders:
    """Modular collection of encoders representing distinct network telemetry views."""

    def __init__(
        self,
        d_z: int = 32,
        seed: int = 42,
        enabled_views: set[str] | None = None,
    ) -> None:
        self.d_z = d_z
        self.enabled_views = enabled_views or {
            "packet", "flow", "protocol", "host",
            "temporal", "behavior", "graph", "observability"
        }

        # Input dimensionalities per view
        self.dim_specs = {
            "packet": (22, 16),
            "flow": (17, 16),
            "protocol": (16, 12),
            "host": (5, 8),
            "temporal": (10, 8),
            "behavior": (12, 8),
            "graph": (11, 8),
            "observability": (10, 6),
        }

        rng = np.random.default_rng(seed)
        self.encoders: dict[str, LinearEncoder] = {}
        curr_seed = seed
        total_view_dim = 0

        for view_name, (in_dim, out_dim) in self.dim_specs.items():
            curr_seed += 1
            self.encoders[view_name] = LinearEncoder(in_dim, out_dim, seed=curr_seed)
            total_view_dim += out_dim

        self.total_view_dim = total_view_dim

        # Cross-View Gated Fusion layer
        # Z_t = tanh(W_fuse @ fused_views + b_fuse)
        scale = 1.0 / np.sqrt(max(1, total_view_dim))
        self.W_fuse = rng.normal(0.0, scale, (d_z, total_view_dim))
        self.b_fuse = np.zeros(d_z, dtype=np.float64)

        # Gate weights for cross-view weighting: g = sigmoid(W_gate @ fused_views + b_gate)
        self.W_gate = rng.normal(0.0, scale, (d_z, total_view_dim))
        self.b_gate = np.zeros(d_z, dtype=np.float64)

    def encode_views(self, view_inputs: Mapping[str, np.ndarray]) -> dict[str, np.ndarray]:
        """Encodes each view independently. If a view is disabled, emits zeros."""
        encoded: dict[str, np.ndarray] = {}
        for view_name, enc in self.encoders.items():
            out_dim = enc.out_features
            if view_name not in self.enabled_views:
                encoded[view_name] = np.zeros(out_dim, dtype=np.float64)
                continue

            raw_vec = view_inputs.get(view_name)
            if raw_vec is None or len(raw_vec) == 0:
                encoded[view_name] = np.zeros(out_dim, dtype=np.float64)
            else:
                # Pad or slice to match expected input dimension safely
                expected = enc.in_features
                if len(raw_vec) < expected:
                    padded = np.zeros(expected, dtype=np.float64)
                    padded[:len(raw_vec)] = raw_vec
                    encoded[view_name] = enc.forward(padded)
                else:
                    encoded[view_name] = enc.forward(raw_vec[:expected])

        return encoded

    def fuse(self, encoded_views: Mapping[str, np.ndarray]) -> np.ndarray:
        """Cross-View Fusion producing unified latent state Z_t."""
        concat_list = []
        for view_name in self.dim_specs.keys():
            vec = encoded_views.get(view_name)
            out_dim = self.dim_specs[view_name][1]
            if vec is None or len(vec) != out_dim:
                concat_list.append(np.zeros(out_dim, dtype=np.float64))
            else:
                concat_list.append(vec)

        fused_vec = np.concatenate(concat_list)
        candidate = _tanh(self.W_fuse @ fused_vec + self.b_fuse)
        gate = _sigmoid(self.W_gate @ fused_vec + self.b_gate)
        z_t = candidate * gate
        return z_t

    def encode_and_fuse(self, view_inputs: Mapping[str, np.ndarray]) -> np.ndarray:
        views = self.encode_views(view_inputs)
        return self.fuse(views)


class RecurrentWorldStateAccumulator:
    """Vectorized LSTM cell aggregating unified world states Z_t over temporal lookback."""

    def __init__(self, input_dim: int = 32, hidden_dim: int = 32, seed: int = 42) -> None:
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        rng = np.random.default_rng(seed)
        scale = 1.0 / np.sqrt(hidden_dim)
        # Combined gates: [i, f, g, o]
        self.W = rng.normal(0.0, scale, (4 * hidden_dim, input_dim + hidden_dim))
        self.b = np.zeros(4 * hidden_dim, dtype=np.float64)

    def forward_step(
        self,
        z_t: np.ndarray,
        h_prev: np.ndarray,
        c_prev: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Single recurrence step."""
        combined = np.r_[z_t, h_prev]
        gates = self.W @ combined + self.b
        i, f, g, o = np.split(gates, 4)
        i = _sigmoid(i)
        f = _sigmoid(f)
        o = _sigmoid(o)
        g = np.tanh(g)
        c = f * c_prev + i * g
        h = o * np.tanh(c)
        return h, c

    def forward_sequence(
        self,
        z_seq: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray, list[tuple]]:
        """Processes lookback sequence (L, input_dim) -> final (h, c) and step caches."""
        h = np.zeros(self.hidden_dim, dtype=np.float64)
        c = np.zeros(self.hidden_dim, dtype=np.float64)
        history = []
        for z_t in z_seq:
            h_old, c_old = h.copy(), c.copy()
            h, c = self.forward_step(z_t, h, c)
            history.append((z_t.copy(), h_old, c_old, h.copy(), c.copy()))
        return h, c, history

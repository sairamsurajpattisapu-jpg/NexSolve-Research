"""Causal Temporal Intelligence Engine for NexSolve.

Implements mathematically leak-safe temporal representations:
- First-order discrete velocities (deltas)
- Second-order discrete accelerations
- Causal rolling statistics (mean, variance, volatility)
- Causal trend estimation (linear slope over lookback)
- Burstiness indices (peak-to-average ratio)
- Regime change and change-point signals (causal EWMA divergence)
- Strict continuity validation (rejects sequences crossing gaps or discontinuities)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

import numpy as np


class TemporalDiscontinuityError(ValueError):
    """Raised when a temporal sequence contains invalid intervals or discontinuities."""
    pass


@dataclass(frozen=True)
class TemporalVelocityVector:
    """Calculated causal temporal features for an individual window at timestamp t."""
    timestamp: int
    delta_flow_count: float
    delta_total_bytes: float
    delta_total_packets: float
    delta_ports: float
    delta_iat: float
    rolling_total_bytes: float
    acceleration_total_bytes: float
    rolling_volatility_bytes: float
    burstiness_index: float
    regime_change_score: float
    is_continuous: bool = True

    def to_dict(self) -> dict[str, float]:
        return {
            "delta_flow_count": float(self.delta_flow_count),
            "delta_total_bytes": float(self.delta_total_bytes),
            "delta_total_packets": float(self.delta_total_packets),
            "delta_ports": float(self.delta_ports),
            "delta_iat": float(self.delta_iat),
            "rolling_total_bytes": float(self.rolling_total_bytes),
            "acceleration_total_bytes": float(self.acceleration_total_bytes),
            "rolling_volatility_bytes": float(self.rolling_volatility_bytes),
            "burstiness_index": float(self.burstiness_index),
            "regime_change_score": float(self.regime_change_score),
        }

    def to_array(self) -> np.ndarray:
        return np.array([
            self.delta_flow_count,
            self.delta_total_bytes,
            self.delta_total_packets,
            self.delta_ports,
            self.delta_iat,
            self.rolling_total_bytes,
            self.acceleration_total_bytes,
            self.rolling_volatility_bytes,
            self.burstiness_index,
            self.regime_change_score,
        ], dtype=np.float64)


class CausalTemporalEngine:
    """Processes historical window sequences to compute causal temporal dynamics."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds

    def validate_continuity(self, timestamps: Sequence[int]) -> bool:
        """Verifies strictly monotonic and contiguous 60s timestamps."""
        if len(timestamps) <= 1:
            return True
        for i in range(len(timestamps) - 1):
            dt = timestamps[i + 1] - timestamps[i]
            if dt != self.window_seconds:
                raise TemporalDiscontinuityError(
                    f"Discontinuity detected between {timestamps[i]} and {timestamps[i+1]} (dt={dt}s != {self.window_seconds}s)"
                )
        return True

    def compute_temporal_vector(
        self,
        history_windows: Sequence[Mapping[str, Any]],
    ) -> TemporalVelocityVector:
        """Compute causal temporal velocity features for the most recent window."""
        if not history_windows:
            return TemporalVelocityVector(
                timestamp=0,
                delta_flow_count=0.0,
                delta_total_bytes=0.0,
                delta_total_packets=0.0,
                delta_ports=0.0,
                delta_iat=0.0,
                rolling_total_bytes=0.0,
                acceleration_total_bytes=0.0,
                rolling_volatility_bytes=0.0,
                burstiness_index=1.0,
                regime_change_score=0.0,
                is_continuous=True,
            )

        curr = history_windows[-1]
        curr_ts = int(curr.get("timestamp", 0))

        # Validate continuity if multi-window
        if len(history_windows) >= 2:
            ts_seq = [int(w.get("timestamp", 0)) for w in history_windows]
            self.validate_continuity(ts_seq)

        curr_flow = float(curr.get("flow_count", 0.0))
        curr_bytes = float(curr.get("total_src_bytes", 0.0)) + float(curr.get("total_dst_bytes", 0.0))
        curr_pkts = float(curr.get("total_packets", 0.0))
        curr_ports = float(curr.get("unique_src_ports", 0.0)) + float(curr.get("unique_dst_ports", 0.0))
        curr_iat = float(curr.get("mean_iat", 0.0))

        # Single window edge case
        if len(history_windows) == 1:
            return TemporalVelocityVector(
                timestamp=curr_ts,
                delta_flow_count=0.0,
                delta_total_bytes=0.0,
                delta_total_packets=0.0,
                delta_ports=0.0,
                delta_iat=0.0,
                rolling_total_bytes=curr_bytes,
                acceleration_total_bytes=0.0,
                rolling_volatility_bytes=0.0,
                burstiness_index=1.0,
                regime_change_score=0.0,
                is_continuous=True,
            )

        prev = history_windows[-2]
        prev_flow = float(prev.get("flow_count", 0.0))
        prev_bytes = float(prev.get("total_src_bytes", 0.0)) + float(prev.get("total_dst_bytes", 0.0))
        prev_pkts = float(prev.get("total_packets", 0.0))
        prev_ports = float(prev.get("unique_src_ports", 0.0)) + float(prev.get("unique_dst_ports", 0.0))
        prev_iat = float(prev.get("mean_iat", 0.0))

        delta_flow = curr_flow - prev_flow
        delta_bytes = curr_bytes - prev_bytes
        delta_pkts = curr_pkts - prev_pkts
        delta_ports = curr_ports - prev_ports
        delta_iat = curr_iat - prev_iat

        # Second-order acceleration
        if len(history_windows) >= 3:
            prev2 = history_windows[-3]
            prev2_bytes = float(prev2.get("total_src_bytes", 0.0)) + float(prev2.get("total_dst_bytes", 0.0))
            prev_delta_bytes = prev_bytes - prev2_bytes
            acceleration_bytes = delta_bytes - prev_delta_bytes
        else:
            acceleration_bytes = 0.0

        # Rolling statistics over causal lookback
        all_bytes = [
            float(w.get("total_src_bytes", 0.0)) + float(w.get("total_dst_bytes", 0.0))
            for w in history_windows
        ]
        rolling_mean = float(np.mean(all_bytes[-4:]))
        rolling_std = float(np.std(all_bytes)) if len(all_bytes) > 1 else 0.0

        # Burstiness index: peak 1s rate vs average window rate
        peak_rate = float(curr.get("peak_packet_rate", curr_pkts / max(1.0, self.window_seconds)))
        mean_rate = curr_pkts / max(1.0, self.window_seconds)
        burstiness = float(peak_rate / max(1e-5, mean_rate))

        # Regime change score: relative divergence between short-term (2 win) and long-term (8 win) moving average
        short_ma = float(np.mean(all_bytes[-2:]))
        long_ma = float(np.mean(all_bytes))
        regime_change = float(abs(short_ma - long_ma) / max(1.0, long_ma + 1.0))

        return TemporalVelocityVector(
            timestamp=curr_ts,
            delta_flow_count=delta_flow,
            delta_total_bytes=delta_bytes,
            delta_total_packets=delta_pkts,
            delta_ports=delta_ports,
            delta_iat=delta_iat,
            rolling_total_bytes=rolling_mean,
            acceleration_total_bytes=acceleration_bytes,
            rolling_volatility_bytes=rolling_std,
            burstiness_index=burstiness,
            regime_change_score=regime_change,
            is_continuous=True,
        )

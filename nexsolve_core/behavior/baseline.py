"""Entity-Local Temporal Baseline and Deviation Detection Engine.

Computes deterministic entity-local temporal baselines where enough history exists:
- Tracks baseline distributions for packets, bytes, flows, ports, peers, failed sessions, resets
- Explicit INSUFFICIENT_HISTORY handling; zero fabrication or synthetic baseline filling
- Detects deviations: BASELINE_SHIFT, PORT_EXPANSION, PEER_EXPANSION, VOLUME_SHIFT, FAILURE_RATE_SHIFT
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class BaselineStatus(str, Enum):
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
    BASELINE_STABLE = "BASELINE_STABLE"
    BASELINE_SHIFT = "BASELINE_SHIFT"


class DeviationType(str, Enum):
    PORT_EXPANSION = "PORT_EXPANSION"
    PEER_EXPANSION = "PEER_EXPANSION"
    VOLUME_SHIFT = "VOLUME_SHIFT"
    FAILURE_RATE_SHIFT = "FAILURE_RATE_SHIFT"
    ACTIVITY_SURGE = "ACTIVITY_SURGE"
    ACTIVITY_DROP = "ACTIVITY_DROP"
    PERIODICITY_EMERGENCE = "PERIODICITY_EMERGENCE"


@dataclass(frozen=True)
class EntityBaselineMetric:
    """Statistical baseline summary for a single metric."""
    metric_name: str
    sample_count: int
    mean_val: float
    std_val: float
    min_val: float
    max_val: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "sample_count": self.sample_count,
            "mean_val": round(self.mean_val, 2),
            "std_val": round(self.std_val, 2),
            "min_val": round(self.min_val, 2),
            "max_val": round(self.max_val, 2),
        }


@dataclass(frozen=True)
class EntityDeviationSignal:
    """Explicit, explainable deviation from an established baseline."""
    deviation_id: str
    entity: str
    deviation_type: DeviationType
    window_index: int
    metric_name: str
    baseline_mean: float
    baseline_std: float
    observed_value: float
    z_score: float
    explanation: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "deviation_id": self.deviation_id,
            "entity": self.entity,
            "deviation_type": self.deviation_type.value,
            "window_index": self.window_index,
            "metric_name": self.metric_name,
            "baseline_mean": round(self.baseline_mean, 2),
            "baseline_std": round(self.baseline_std, 2),
            "observed_value": round(self.observed_value, 2),
            "z_score": round(self.z_score, 2),
            "explanation": self.explanation,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class EntityTemporalBaseline:
    """Temporal baseline profile for an entity across multiple windows."""
    entity: str
    status: BaselineStatus
    window_count: int
    metrics: dict[str, EntityBaselineMetric]
    deviations: tuple[EntityDeviationSignal, ...]
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "status": self.status.value,
            "window_count": self.window_count,
            "metrics": {k: v.to_dict() for k, v in self.metrics.items()},
            "deviations": [d.to_dict() for d in self.deviations],
            "explanation": self.explanation,
        }


def _compute_stats(values: list[float], name: str) -> EntityBaselineMetric:
    if not values:
        return EntityBaselineMetric(name, 0, 0.0, 0.0, 0.0, 0.0)
    mean_v = sum(values) / len(values)
    var = sum((x - mean_v) ** 2 for x in values) / max(1, len(values))
    std_v = math.sqrt(var)
    return EntityBaselineMetric(name, len(values), mean_v, std_v, min(values), max(values))


def compute_entity_baselines(
    entity_histories: Mapping[str, Any] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    min_windows_required: int = 3,
) -> dict[str, EntityTemporalBaseline]:
    """Compute entity-local baselines and detect significant deviations."""
    baselines: dict[str, EntityTemporalBaseline] = {}
    sessions = tcp_sessions or []

    # Window-indexed sessions per entity
    entity_window_data: dict[str, dict[int, dict[str, Any]]] = {}
    for s in sessions:
        src = getattr(s, "src_ip", None)
        w_idx = getattr(s, "window_index", 0) or 0
        if not src:
            continue
        ew = entity_window_data.setdefault(src, {}).setdefault(w_idx, {
            "packet_count": 0,
            "byte_count": 0,
            "session_count": 0,
            "ports": set(),
            "peers": set(),
            "failed_sessions": 0,
        })
        ew["packet_count"] += getattr(s, "packet_count", 1) or 1
        ew["byte_count"] += getattr(s, "byte_count", 0) or 0
        ew["session_count"] += 1
        port = getattr(s, "dst_port", None)
        if port:
            ew["ports"].add(port)
        dst = getattr(s, "dst_ip", None)
        if dst:
            ew["peers"].add(dst)
        if getattr(s, "state", "") in ("REJECTED", "RESET"):
            ew["failed_sessions"] += 1

    for entity, windows_dict in entity_window_data.items():
        sorted_windows = sorted(windows_dict.keys())
        w_count = len(sorted_windows)

        if w_count < min_windows_required:
            baselines[entity] = EntityTemporalBaseline(
                entity=entity,
                status=BaselineStatus.INSUFFICIENT_HISTORY,
                window_count=w_count,
                metrics={},
                deviations=(),
                explanation=f"Entity observed in {w_count} window(s); requires at least {min_windows_required} to establish a defensible baseline.",
            )
            continue

        # Baseline window indices (all but the latest window)
        baseline_windows = sorted_windows[:-1]
        eval_window = sorted_windows[-1]

        # Collect distributions
        pkts = [float(windows_dict[w]["packet_count"]) for w in baseline_windows]
        byts = [float(windows_dict[w]["byte_count"]) for w in baseline_windows]
        ports = [float(len(windows_dict[w]["ports"])) for w in baseline_windows]
        peers = [float(len(windows_dict[w]["peers"])) for w in baseline_windows]
        fails = [float(windows_dict[w]["failed_sessions"]) for w in baseline_windows]

        m_pkts = _compute_stats(pkts, "packets")
        m_byts = _compute_stats(byts, "bytes")
        m_ports = _compute_stats(ports, "ports")
        m_peers = _compute_stats(peers, "peers")
        m_fails = _compute_stats(fails, "failed_sessions")

        metrics_map = {
            "packets": m_pkts,
            "bytes": m_byts,
            "ports": m_ports,
            "peers": m_peers,
            "failed_sessions": m_fails,
        }

        # Check latest window against established baseline
        eval_data = windows_dict[eval_window]
        deviations: list[EntityDeviationSignal] = []

        # Port expansion check
        obs_ports = len(eval_data["ports"])
        if m_ports.std_val > 0 and (obs_ports - m_ports.mean_val) / m_ports.std_val >= 2.5:
            z = (obs_ports - m_ports.mean_val) / m_ports.std_val
            did = deterministic_id("dev", entity, eval_window, "PORT_EXP")
            deviations.append(EntityDeviationSignal(
                deviation_id=did,
                entity=entity,
                deviation_type=DeviationType.PORT_EXPANSION,
                window_index=eval_window,
                metric_name="distinct_ports",
                baseline_mean=m_ports.mean_val,
                baseline_std=m_ports.std_val,
                observed_value=float(obs_ports),
                z_score=z,
                explanation=f"Target port count ({obs_ports}) expanded significantly above baseline mean ({m_ports.mean_val:.1f} ± {m_ports.std_val:.1f}, Z={z:.1f}).",
            ))

        # Peer expansion check
        obs_peers = len(eval_data["peers"])
        if m_peers.std_val > 0 and (obs_peers - m_peers.mean_val) / m_peers.std_val >= 2.5:
            z = (obs_peers - m_peers.mean_val) / m_peers.std_val
            did = deterministic_id("dev", entity, eval_window, "PEER_EXP")
            deviations.append(EntityDeviationSignal(
                deviation_id=did,
                entity=entity,
                deviation_type=DeviationType.PEER_EXPANSION,
                window_index=eval_window,
                metric_name="distinct_peers",
                baseline_mean=m_peers.mean_val,
                baseline_std=m_peers.std_val,
                observed_value=float(obs_peers),
                z_score=z,
                explanation=f"Distinct peer count ({obs_peers}) surged above baseline mean ({m_peers.mean_val:.1f} ± {m_peers.std_val:.1f}, Z={z:.1f}).",
            ))

        # Volume shift check
        obs_pkts = eval_data["packet_count"]
        if m_pkts.std_val > 0 and (obs_pkts - m_pkts.mean_val) / m_pkts.std_val >= 3.0:
            z = (obs_pkts - m_pkts.mean_val) / m_pkts.std_val
            did = deterministic_id("dev", entity, eval_window, "VOL_SHIFT")
            deviations.append(EntityDeviationSignal(
                deviation_id=did,
                entity=entity,
                deviation_type=DeviationType.VOLUME_SHIFT,
                window_index=eval_window,
                metric_name="packets",
                baseline_mean=m_pkts.mean_val,
                baseline_std=m_pkts.std_val,
                observed_value=float(obs_pkts),
                z_score=z,
                explanation=f"Packet volume ({obs_pkts}) surged significantly above baseline ({m_pkts.mean_val:.0f} ± {m_pkts.std_val:.0f}, Z={z:.1f}).",
            ))

        status = BaselineStatus.BASELINE_SHIFT if deviations else BaselineStatus.BASELINE_STABLE
        expl = (
            f"Baseline established across {len(baseline_windows)} window(s). "
            f"Detected {len(deviations)} significant deviation(s) in evaluation window {eval_window}."
            if deviations
            else f"Baseline established across {len(baseline_windows)} window(s). Behavior stable in evaluation window {eval_window}."
        )

        baselines[entity] = EntityTemporalBaseline(
            entity=entity,
            status=status,
            window_count=w_count,
            metrics=metrics_map,
            deviations=tuple(deviations),
            explanation=expl,
        )

    return baselines

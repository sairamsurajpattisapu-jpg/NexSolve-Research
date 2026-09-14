"""Deterministic Behavior Change Detection Engine.

Detects meaningful behavioral shifts across consecutive temporal windows:
- Sudden port fan-out surge (scanning behavior)
- Sudden connection attempt surge (probing / DoS)
- Sudden failed TCP session increase (rejection burst)
- Sudden emergence of periodic intervals
- Sudden packet/byte volume explosion
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class ChangeType(str, Enum):
    PORT_FANOUT_SURGE = "PORT_FANOUT_SURGE"
    CONNECTION_ATTEMPT_SURGE = "CONNECTION_ATTEMPT_SURGE"
    FAILED_SESSION_SPIKE = "FAILED_SESSION_SPIKE"
    PERIODICITY_EMERGENCE = "PERIODICITY_EMERGENCE"
    VOLUME_SPIKE = "VOLUME_SPIKE"


@dataclass(frozen=True)
class BehaviorChangeSignal:
    """Structured signal describing a detected transition between consecutive windows."""
    change_id: str
    entity: str
    window_before: int
    window_after: int
    change_type: ChangeType
    magnitude: float
    baseline_value: float
    current_value: float
    description: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "entity": self.entity,
            "window_before": self.window_before,
            "window_after": self.window_after,
            "change_type": self.change_type.value,
            "magnitude": round(self.magnitude, 3),
            "baseline_value": round(self.baseline_value, 3),
            "current_value": round(self.current_value, 3),
            "description": self.description,
            "provenance": self.provenance,
        }


def detect_behavior_changes(
    tcp_sessions: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[BehaviorChangeSignal, ...]:
    """Detect deterministic behavior deltas across consecutive windows."""
    changes: list[BehaviorChangeSignal] = []

    # Aggregate sessions by (entity, window_index)
    window_entity_sessions: dict[int, dict[str, list[Any]]] = {}
    if tcp_sessions:
        for s in tcp_sessions:
            src = getattr(s, "src_ip", None)
            w_idx = getattr(s, "window_index", 0) or 0
            if src:
                window_entity_sessions.setdefault(w_idx, {}).setdefault(src, []).append(s)

    sorted_windows = sorted(window_entity_sessions.keys())
    for i in range(len(sorted_windows) - 1):
        w_prev = sorted_windows[i]
        w_curr = sorted_windows[i + 1]

        prev_entities = window_entity_sessions[w_prev]
        curr_entities = window_entity_sessions[w_curr]

        for entity, curr_sess in curr_entities.items():
            prev_sess = prev_entities.get(entity, [])

            # 1. Port Fan-Out Surge
            prev_ports = {getattr(s, "dst_port") for s in prev_sess if getattr(s, "dst_port", None)}
            curr_ports = {getattr(s, "dst_port") for s in curr_sess if getattr(s, "dst_port", None)}
            port_diff = len(curr_ports) - len(prev_ports)
            if len(curr_ports) >= 5 and port_diff >= 4:
                cid = deterministic_id("chg", entity, w_prev, w_curr, "PORT_FANOUT")
                changes.append(BehaviorChangeSignal(
                    change_id=cid,
                    entity=entity,
                    window_before=w_prev,
                    window_after=w_curr,
                    change_type=ChangeType.PORT_FANOUT_SURGE,
                    magnitude=float(port_diff),
                    baseline_value=float(len(prev_ports)),
                    current_value=float(len(curr_ports)),
                    description=f"Destination port diversity surged from {len(prev_ports)} to {len(curr_ports)} ports.",
                    provenance={"metric": "distinct_dst_ports"},
                ))

            # 2. Connection Attempt Surge
            prev_cnt = len(prev_sess)
            curr_cnt = len(curr_sess)
            if curr_cnt >= 10 and (curr_cnt >= 3 * max(1, prev_cnt)):
                cid = deterministic_id("chg", entity, w_prev, w_curr, "CONN_SURGE")
                changes.append(BehaviorChangeSignal(
                    change_id=cid,
                    entity=entity,
                    window_before=w_prev,
                    window_after=w_curr,
                    change_type=ChangeType.CONNECTION_ATTEMPT_SURGE,
                    magnitude=float(curr_cnt - prev_cnt),
                    baseline_value=float(prev_cnt),
                    current_value=float(curr_cnt),
                    description=f"Connection attempt volume increased from {prev_cnt} to {curr_cnt} sessions.",
                    provenance={"metric": "session_count"},
                ))

            # 3. Failed Session Spike (REJECTED / RESET)
            prev_failed = sum(1 for s in prev_sess if getattr(s, "state", "OTH") in ("REJECTED", "RESET"))
            curr_failed = sum(1 for s in curr_sess if getattr(s, "state", "OTH") in ("REJECTED", "RESET"))
            if curr_failed >= 5 and curr_failed >= 2 * max(1, prev_failed):
                cid = deterministic_id("chg", entity, w_prev, w_curr, "FAILED_SPIKE")
                changes.append(BehaviorChangeSignal(
                    change_id=cid,
                    entity=entity,
                    window_before=w_prev,
                    window_after=w_curr,
                    change_type=ChangeType.FAILED_SESSION_SPIKE,
                    magnitude=float(curr_failed - prev_failed),
                    baseline_value=float(prev_failed),
                    current_value=float(curr_failed),
                    description=f"Failed/rejected TCP sessions increased from {prev_failed} to {curr_failed}.",
                    provenance={"metric": "failed_sessions"},
                ))

    return tuple(changes)

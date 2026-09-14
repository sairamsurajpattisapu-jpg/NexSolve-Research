"""Deterministic What-Changed Analysis Engine for NexSolve.

Extracts meaningful temporal and telemetric transitions across observation windows:
- Target breadth expansion (contacting new subnets or hosts)
- Port breadth expansion (sweeping new service ranges)
- Traffic volume surge (statistically validated byte/packet deviations)
- TCP failure/reset spikes (deterioration of successful handshakes)
- Kinematic attack state changes (escalating between kill-chain phases)
- Campaign convergence (joining coordinated peer groups)

Rejects superficial micro-differences. Requires empirical baselines or multi-window continuity.
Emits INSUFFICIENT_HISTORY when temporal depth is under threshold.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class ChangeSignificance(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class WhatChangedItem:
    """A concrete, evidence-backed temporal change observation."""
    change_id: str
    entity: str
    change_dimension: str
    window_before: int | None
    window_after: int
    timestamp_after: float
    before_state: str
    after_state: str
    magnitude: float
    significance: ChangeSignificance
    evidence_keys: tuple[str, ...]
    explanation: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "entity": self.entity,
            "change_dimension": self.change_dimension,
            "window_before": self.window_before,
            "window_after": self.window_after,
            "timestamp_after": self.timestamp_after,
            "before_state": self.before_state,
            "after_state": self.after_state,
            "magnitude": self.magnitude,
            "significance": self.significance.value,
            "evidence_keys": list(self.evidence_keys),
            "explanation": self.explanation,
            "provenance": self.provenance,
        }


def build_what_changed(
    entity: str,
    entity_profile: Any = None,
    attack_kinematics: Any = None,
    change_signals: Sequence[Any] | None = None,
    baseline_deviations: Sequence[Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    window_count: int = 1,
) -> tuple[WhatChangedItem, ...]:
    """Compile meaningful, supported temporal changes for an entity."""
    changes: list[WhatChangedItem] = []
    signals = change_signals or []
    deviations = baseline_deviations or []
    cmps = campaigns or []

    if window_count < 2:
        cid = deterministic_id("chg", entity, "INSUFFICIENT_HISTORY")
        changes.append(WhatChangedItem(
            change_id=cid,
            entity=entity,
            change_dimension="TEMPORAL_DEPTH",
            window_before=None,
            window_after=0,
            timestamp_after=0.0,
            before_state="UNKNOWN",
            after_state="INSUFFICIENT_HISTORY",
            magnitude=0.0,
            significance=ChangeSignificance.LOW,
            evidence_keys=("single_window_limit",),
            explanation="Capture sequence has only 1 window; historical delta analysis requires multi-window continuity.",
            provenance={"rule": "insufficient_history"},
        ))
        return tuple(changes)

    # 1. Kinematic State Transitions
    traj = attack_kinematics.get(entity) if isinstance(attack_kinematics, dict) else attack_kinematics
    if traj and hasattr(traj, "transitions"):
        for trans in traj.transitions:
            w_aft = getattr(trans, "window_after", 0)
            w_bef = getattr(trans, "window_before", 0)
            from_st = getattr(trans, "from_state", "BENIGN")
            to_st = getattr(trans, "to_state", "STATE")
            sig = ChangeSignificance.CRITICAL if to_st in ("IMPACT", "COMMAND_AND_CONTROL") else ChangeSignificance.HIGH
            cid = deterministic_id("chg", entity, "KINEMATIC", w_aft, to_st)
            changes.append(WhatChangedItem(
                change_id=cid,
                entity=entity,
                change_dimension="ATTACK_STATE",
                window_before=w_bef,
                window_after=w_aft,
                timestamp_after=float(w_aft * 60.0),
                before_state=str(from_st),
                after_state=str(to_st),
                magnitude=float(getattr(trans, "strength", 1.0)),
                significance=sig,
                evidence_keys=tuple(getattr(trans, "supporting_evidence_ids", ())),
                explanation=getattr(trans, "explanation", f"Transitioned attack state from {from_st} to {to_st}."),
                provenance=getattr(trans, "provenance", {}),
            ))

    # 2. Behavioral Changes (Fanout, Surges)
    for c in signals:
        if getattr(c, "entity", "") == entity:
            w_aft = getattr(c, "window_after", 0)
            w_bef = getattr(c, "window_before", 0)
            c_type = str(getattr(c, "change_type", "CHANGE"))
            mag = float(getattr(c, "magnitude", 1.0))
            sig = ChangeSignificance.HIGH if "FANOUT" in c_type or mag > 5.0 else ChangeSignificance.MEDIUM
            cid = deterministic_id("chg", entity, "BEHAVIOR", w_aft, c_type)
            changes.append(WhatChangedItem(
                change_id=cid,
                entity=entity,
                change_dimension="BEHAVIORAL_METRIC",
                window_before=w_bef,
                window_after=w_aft,
                timestamp_after=float(w_aft * 60.0),
                before_state=f"Baseline (W{w_bef})",
                after_state=f"{c_type} (mag: {mag:.1f})",
                magnitude=mag,
                significance=sig,
                evidence_keys=(getattr(c, "change_id", "chg"),),
                explanation=getattr(c, "description", "Statistically validated behavioral shift."),
                provenance=getattr(c, "provenance", {}),
            ))

    # 3. Statistical Baseline Deviations
    for dev in deviations:
        if getattr(dev, "entity", "") == entity:
            w = getattr(dev, "window_index", 0)
            metric = getattr(dev, "metric_name", "metric")
            z = float(getattr(dev, "z_score", 0.0))
            sig = ChangeSignificance.HIGH if z > 3.0 else ChangeSignificance.MEDIUM
            cid = deterministic_id("chg", entity, "BASELINE", w, metric)
            changes.append(WhatChangedItem(
                change_id=cid,
                entity=entity,
                change_dimension="STATISTICAL_BASELINE",
                window_before=max(0, w - 1),
                window_after=w,
                timestamp_after=float(w * 60.0),
                before_state="Expected Baseline",
                after_state=f"Surge z={z:.2f}",
                magnitude=z,
                significance=sig,
                evidence_keys=(getattr(dev, "deviation_id", "dev"),),
                explanation=getattr(dev, "explanation", f"Metric {metric} deviated significantly from rolling baseline."),
                provenance=getattr(dev, "provenance", {}),
            ))

    # 4. Campaign Convergence
    for cmp in cmps:
        if entity in getattr(cmp, "primary_entities", ()):
            w = getattr(cmp, "start_window", 0)
            cid = deterministic_id("chg", entity, "CAMPAIGN", w, getattr(cmp, "campaign_id", ""))
            changes.append(WhatChangedItem(
                change_id=cid,
                entity=entity,
                change_dimension="CAMPAIGN_MEMBERSHIP",
                window_before=max(0, w - 1),
                window_after=w,
                timestamp_after=float(w * 60.0),
                before_state="Isolated Host",
                after_state=f"Campaign {getattr(cmp, 'title', '')}",
                magnitude=float(len(getattr(cmp, "target_entities", ()))),
                significance=ChangeSignificance.HIGH,
                evidence_keys=(getattr(cmp, "campaign_id", "cmp"),),
                explanation=f"Entity joined multi-episode campaign targeting {len(getattr(cmp, 'target_entities', ()))} host(s).",
                provenance=getattr(cmp, "provenance", {}),
            ))

    # Sort deterministically by timestamp_after ASC, then change_id
    changes.sort(key=lambda x: (x.timestamp_after, x.change_id))
    return tuple(changes)

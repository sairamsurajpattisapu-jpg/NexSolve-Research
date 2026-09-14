"""Deterministic Investigation Value Metric for NexSolve.

Approximates which investigation opportunity will reduce system uncertainty the most:
- Unresolved anomaly/finding count
- Contradictory evidence presence (high value in resolving ambiguity)
- Breadth of affected targets and participating entities
- Severity of potential attack state
- Campaign scope and coordinated presence
- Lookback window deficit

Produces a clear explanatory breakdown without using black-box machine learning or LLMs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class InvestigationValueReport:
    """Estimated investigative utility and uncertainty-reduction value."""
    entity: str
    investigation_value_score: int
    value_tier: str  # "VERY_HIGH", "HIGH", "MODERATE", "LOW"
    drivers: tuple[str, ...]
    uncertainty_reduction_summary: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "investigation_value_score": self.investigation_value_score,
            "value_tier": self.value_tier,
            "drivers": list(self.drivers),
            "uncertainty_reduction_summary": self.uncertainty_reduction_summary,
            "provenance": self.provenance,
        }


def compute_investigation_value(
    entity: str,
    entity_profile: Any = None,
    attack_kinematics: Any = None,
    campaigns: Sequence[Any] | None = None,
    contradictions: Sequence[Any] | None = None,
    findings_count: int = 0,
    window_count: int = 1,
) -> InvestigationValueReport:
    """Deterministically compute the investigative value of focusing analyst effort on an entity."""
    score = 0
    drivers: list[str] = []

    # 1. Contradictions (Ambiguity resolution has the highest investigative value)
    contra_cnt = len(contradictions or [])
    if contra_cnt > 0:
        score += contra_cnt * 25
        drivers.append(f"{contra_cnt} conflicting evidence signal(s) requiring resolution")

    # 2. Attack State & Escalation
    traj = attack_kinematics.get(entity) if isinstance(attack_kinematics, dict) else attack_kinematics
    curr_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
    curr_state_val = getattr(curr_state, "value", str(curr_state))
    if curr_state_val in ("IMPACT", "COMMAND_AND_CONTROL"):
        score += 50
        drivers.append(f"Critical attack state {curr_state_val} with high potential impact")
    elif curr_state_val in ("EXPLOITATION_INDICATOR", "RECONNAISSANCE"):
        score += 35
        drivers.append(f"Active {curr_state_val} phase preceding potential lateral movement")

    # 3. Campaign Association (Multi-host blast radius)
    ent_cmps = [c for c in (campaigns or []) if entity in getattr(c, "primary_entities", ())]
    if ent_cmps:
        score += 30
        drivers.append(f"Anchor participant in multi-episode campaign {getattr(ent_cmps[0], 'campaign_id', '')}")

    # 4. Target Breadth
    peers_cnt = getattr(entity_profile, "peer_count", 0) if entity_profile else 0
    ports_cnt = getattr(entity_profile, "targeted_ports_count", 0) if entity_profile else 0
    if peers_cnt >= 5 or ports_cnt >= 10:
        score += 20
        drivers.append(f"Broad targeting footprint ({peers_cnt} peer(s), {ports_cnt} port(s))")

    # 5. Unresolved Findings
    if findings_count > 0:
        score += min(20, findings_count * 5)
        drivers.append(f"{findings_count} unadjudicated security finding(s)")

    # 6. Lookback Gap (High value in validating persistence)
    if window_count < 8:
        score += 15
        drivers.append("Limited temporal history; verifying persistence will clarify rollout confidence")

    if score >= 80:
        tier = "VERY_HIGH"
    elif score >= 50:
        tier = "HIGH"
    elif score >= 25:
        tier = "MODERATE"
    else:
        tier = "LOW"

    summary = (
        f"Investigating {entity} yields {tier} utility ({score} pts). "
        f"Key benefit: clarifies {len(drivers)} critical dimension(s) and bounds lateral risk."
    )

    return InvestigationValueReport(
        entity=entity,
        investigation_value_score=score,
        value_tier=tier,
        drivers=tuple(drivers),
        uncertainty_reduction_summary=summary,
        provenance={"engine": "deterministic_investigation_value_v1"},
    )

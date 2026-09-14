"""Deterministic Analyst Investigation Question Generation Engine.

Generates targeted, high-value questions an analyst must answer to resolve ambiguity:
- Host authorization status
- Continuation beyond capture observation window
- Vulnerability/exposure of targeted ports
- Coordinated multi-entity participation
- Counter-evidence or mitigating circumstances
- Verification of observed vs inferred attack state

Only emits questions where unresolved ambiguity or missing context exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


@dataclass(frozen=True)
class InvestigationQuestion:
    """A targeted, answerable analyst question."""
    question_id: str
    target_entity: str
    category: str
    question: str
    operational_context: str
    suggested_verification_source: str
    current_hypothesis: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "question_id": self.question_id,
            "target_entity": self.target_entity,
            "category": self.category,
            "question": self.question,
            "operational_context": self.operational_context,
            "suggested_verification_source": self.suggested_verification_source,
            "current_hypothesis": self.current_hypothesis,
            "provenance": self.provenance,
        }


def generate_analyst_questions(
    entity: str,
    entity_profile: Any = None,
    attack_kinematics: Any = None,
    campaigns: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    contradictions: Sequence[Any] | None = None,
    benign_hypotheses: Sequence[Any] | None = None,
    window_count: int = 1,
) -> tuple[InvestigationQuestion, ...]:
    """Deterministically generate key investigation questions for an entity."""
    questions: list[InvestigationQuestion] = []
    roles = set(getattr(entity_profile, "roles", ())) if entity_profile else set()
    ports_cnt = getattr(entity_profile, "targeted_ports_count", 0) if entity_profile else 0
    peers_cnt = getattr(entity_profile, "peer_count", 0) if entity_profile else 0

    traj = attack_kinematics.get(entity) if isinstance(attack_kinematics, dict) else attack_kinematics
    curr_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
    curr_state_val = getattr(curr_state, "value", str(curr_state))

    # 1. Authorization Question (Scanner)
    if any("SCANNER" in str(r) for r in roles) or curr_state_val in ("RECONNAISSANCE", "DISCOVERY"):
        qid = deterministic_id("q", entity, "AUTHORIZATION")
        questions.append(InvestigationQuestion(
            question_id=qid,
            target_entity=entity,
            category="AUTHORIZATION",
            question=f"Was {entity} scheduled or authorized to perform vulnerability/port scans across internal targets?",
            operational_context=f"Observed sweeps across {ports_cnt} port(s) and {peers_cnt} peer(s).",
            suggested_verification_source="Change Management Tickets / Vulnerability Management Schedule",
            current_hypothesis="Suspicious horizontal/vertical reconnaissance sweep",
            provenance={"rule": "recon_authorization"},
        ))

    # 2. Target Service Exposure Question
    if ports_cnt > 0:
        qid = deterministic_id("q", entity, "EXPOSED_SERVICES")
        questions.append(InvestigationQuestion(
            question_id=qid,
            target_entity=entity,
            category="ATTACK_SURFACE",
            question=f"Are the {ports_cnt} port(s) targeted by {entity} actively listening and exposed to this network segment?",
            operational_context="Determines whether scanning was opportunistic blind probing or targeted against confirmed open listeners.",
            suggested_verification_source="Endpoint Netstat / Shodan / Firewall Policy",
            current_hypothesis="Reconnaissance identifying exploitable entry points",
            provenance={"rule": "exposed_service_audit"},
        ))

    # 3. Persistence & Temporal Continuity Question
    if window_count < 8:
        qid = deterministic_id("q", entity, "TEMPORAL_CONTINUITY")
        questions.append(InvestigationQuestion(
            question_id=qid,
            target_entity=entity,
            category="TEMPORAL_PERSISTENCE",
            question=f"Did activity from {entity} persist after window {window_count} in subsequent live network telemetry?",
            operational_context=f"Lookback is limited to {window_count} window(s) (canonical forecast requires 8).",
            suggested_verification_source="SIEM Log Search (Expanded 24-hour time range)",
            current_hypothesis="Ephemeral burst vs persistent adversary foothold",
            provenance={"rule": "temporal_persistence_check"},
        ))

    # 4. Campaign Coordination Question
    ent_cmps = [c for c in (campaigns or []) if entity in getattr(c, "primary_entities", ())]
    if ent_cmps:
        cmp = ent_cmps[0]
        cid = getattr(cmp, "campaign_id", "cmp")
        qid = deterministic_id("q", entity, "CAMPAIGN_COORDINATION")
        questions.append(InvestigationQuestion(
            question_id=qid,
            target_entity=entity,
            category="CAMPAIGN_CORRELATION",
            question=f"Are other hosts associated with campaign {cid} exhibiting overlapping command artifacts or timestamps?",
            operational_context=f"Correlated into campaign encompassing {len(getattr(cmp, 'primary_entities', ()))} entity(ies).",
            suggested_verification_source="EDR Process Lineage / Shared C2 Netflow",
            current_hypothesis="Coordinated multi-stage intrusion campaign",
            provenance={"rule": "campaign_coordination_check"},
        ))

    # 5. Benign Hypothesis Verification Question
    b_hypos = benign_hypotheses or []
    for h in b_hypos:
        if getattr(h, "missing_evidence", ()):
            qid = deterministic_id("q", entity, "BENIGN_VERIFICATION", getattr(h, "hypothesis_type", ""))
            questions.append(InvestigationQuestion(
                question_id=qid,
                target_entity=entity,
                category="BENIGN_DISPROVAL",
                question=f"Can we verify: {getattr(h, 'missing_evidence', ())[0]}?",
                operational_context=f"Needed to validate or dismiss benign hypothesis: '{getattr(h, 'title', '')}'.",
                suggested_verification_source="IT Asset Inventory / CMDB",
                current_hypothesis=getattr(h, "title", "Benign Alternative"),
                provenance={"rule": "benign_hypothesis_verification"},
            ))

    return tuple(questions)

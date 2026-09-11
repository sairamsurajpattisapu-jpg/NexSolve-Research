"""Deterministic Unknown Behavior classification layer for NexSolve.

Classifies network behavior into KNOWN_PATTERN, WEAK_PATTERN, or UNKNOWN_BEHAVIOR
based on evidence coherence, protocol support, capture quality, and forecast consistency.
UNKNOWN_BEHAVIOR does NOT automatically imply malicious activity; it indicates that
observed signals fall outside the supported interpretation space.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Sequence

from ml.forecasting.attack_horizon import AttackHorizonResult, AttackHorizonState
from ml.forecasting.evidence_intelligence import EvidenceChain, EvidenceQuality


class BehaviorClassification(str, Enum):
    KNOWN_PATTERN = "KNOWN_PATTERN"
    WEAK_PATTERN = "WEAK_PATTERN"
    UNKNOWN_BEHAVIOR = "UNKNOWN_BEHAVIOR"


@dataclass(frozen=True)
class UnknownBehaviorResult:
    """Deterministic classification of observed behavior within the interpretation space."""
    classification: BehaviorClassification
    reason: str
    supporting_evidence: list[str]
    contradictory_evidence: list[str]
    coverage: float  # Fraction of evaluated dimensions mapped cleanly [0.0, 1.0]
    abstain_recommended: bool

    def to_dict(self) -> dict[str, Any]:
        res = asdict(self)
        res["classification"] = self.classification.value
        return res


def classify_unknown_behavior(
    evidence_chain: EvidenceChain,
    attack_horizon: AttackHorizonResult | None = None,
    current_state: Any = None,
) -> UnknownBehaviorResult:
    """Deterministically classify whether behavior matches a known pattern or is unknown.

    Parameters
    ----------
    evidence_chain : EvidenceChain
        Synthesized evidence chain from current state and historical lookback.
    attack_horizon : AttackHorizonResult | None, optional
        Precomputed Attack Horizon result.
    current_state : Any, optional
        Current observation state for direct protocol and quality inspection.
    """
    supporting_reasons: list[str] = [item["explanation"] for item in evidence_chain.supporting]
    contradictory_reasons: list[str] = [item["explanation"] for item in evidence_chain.contradictory]

    # 1. Check Capture Quality Blocker
    if evidence_chain.evidence_quality == EvidenceQuality.INSUFFICIENT:
        return UnknownBehaviorResult(
            classification=BehaviorClassification.UNKNOWN_BEHAVIOR,
            reason="Capture quality is INSUFFICIENT to reliably map observed traffic.",
            supporting_evidence=supporting_reasons,
            contradictory_evidence=contradictory_reasons,
            coverage=0.20,
            abstain_recommended=True,
        )

    # 2. Check Protocol Support
    if current_state is not None:
        flow_feats = getattr(current_state, "flow_features", {})
        if isinstance(current_state, dict):
            flow_feats = current_state.get("flow_features") or current_state.get("flowFeatures") or {}

        tcp_count = flow_feats.get("proto_tcp_count", 0.0)
        udp_count = flow_feats.get("proto_udp_count", 0.0)
        other_count = flow_feats.get("proto_other_count", 0.0)
        total_proto = tcp_count + udp_count + other_count

        if total_proto > 10 and (other_count / total_proto) > 0.60:
            return UnknownBehaviorResult(
                classification=BehaviorClassification.UNKNOWN_BEHAVIOR,
                reason="Unsupported protocol behavior: non-TCP/UDP traffic exceeds 60% of total flows.",
                supporting_evidence=supporting_reasons,
                contradictory_evidence=contradictory_reasons,
                coverage=0.35,
                abstain_recommended=False,
            )

        # 3. Check Unusual Feature Combinations (Physical / Semantic Contradictions)
        # e.g., massive flow count with 0 destination ports, or high bytes with 0 packets
        flow_count = flow_feats.get("flow_count", 0.0)
        dst_ports = flow_feats.get("unique_dst_ports", 0.0)
        total_packets = flow_feats.get("total_packets", 0.0)
        total_bytes = flow_feats.get("total_src_bytes", 0.0) + flow_feats.get("total_dst_bytes", 0.0)

        if flow_count > 50 and dst_ports == 0:
            return UnknownBehaviorResult(
                classification=BehaviorClassification.UNKNOWN_BEHAVIOR,
                reason="Unusual feature combination: 50+ flows observed with zero destination port records.",
                supporting_evidence=supporting_reasons,
                contradictory_evidence=contradictory_reasons,
                coverage=0.40,
                abstain_recommended=False,
            )

        if total_bytes > 1_000_000 and total_packets == 0:
            return UnknownBehaviorResult(
                classification=BehaviorClassification.UNKNOWN_BEHAVIOR,
                reason="Unusual feature combination: byte volume observed without packet count observations.",
                supporting_evidence=supporting_reasons,
                contradictory_evidence=contradictory_reasons,
                coverage=0.30,
                abstain_recommended=True,
            )

    # 4. Check Forecast vs Evidence Disagreement
    attack_predicted = False
    if attack_horizon is not None:
        if attack_horizon.state in (AttackHorizonState.SUSTAINED_ATTACK_FORECAST, AttackHorizonState.EARLY_SIGNAL):
            attack_predicted = True

    if attack_predicted and evidence_chain.evidence_strength < 0.15 and len(evidence_chain.contradictory) >= 2:
        return UnknownBehaviorResult(
            classification=BehaviorClassification.UNKNOWN_BEHAVIOR,
            reason="Forecast and evidence disagreement: model predicts attack but traffic indicators contradict attack hypothesis.",
            supporting_evidence=supporting_reasons,
            contradictory_evidence=contradictory_reasons,
            coverage=0.50,
            abstain_recommended=False,
        )

    # 5. Check Conflicting Evidence Overload
    if evidence_chain.contradictory_feature_count >= 3 and evidence_chain.contradictory_feature_count > evidence_chain.supporting_feature_count:
        return UnknownBehaviorResult(
            classification=BehaviorClassification.UNKNOWN_BEHAVIOR,
            reason="Conflicting evidence: contradictory signals exceed supporting indicators across multiple dimensions.",
            supporting_evidence=supporting_reasons,
            contradictory_evidence=contradictory_reasons,
            coverage=0.45,
            abstain_recommended=False,
        )

    # 6. Check Known vs Weak Pattern
    if attack_predicted:
        if evidence_chain.evidence_strength >= 0.60 and evidence_chain.supporting_feature_count >= 2:
            return UnknownBehaviorResult(
                classification=BehaviorClassification.KNOWN_PATTERN,
                reason="Observed traffic conforms cleanly to supported multi-step attack progression patterns.",
                supporting_evidence=supporting_reasons,
                contradictory_evidence=contradictory_reasons,
                coverage=0.92,
                abstain_recommended=False,
            )
        else:
            return UnknownBehaviorResult(
                classification=BehaviorClassification.WEAK_PATTERN,
                reason="Sparse or borderline traffic shifts; limited feature support for forecast attack.",
                supporting_evidence=supporting_reasons,
                contradictory_evidence=contradictory_reasons,
                coverage=0.70,
                abstain_recommended=False,
            )
    else:
        # Non-attack baseline pattern
        if evidence_chain.contradictory_feature_count == 0:
            return UnknownBehaviorResult(
                classification=BehaviorClassification.KNOWN_PATTERN,
                reason="Observed traffic conforms cleanly to stable baseline network operation.",
                supporting_evidence=supporting_reasons,
                contradictory_evidence=contradictory_reasons,
                coverage=0.95,
                abstain_recommended=False,
            )
        else:
            return UnknownBehaviorResult(
                classification=BehaviorClassification.WEAK_PATTERN,
                reason="Baseline traffic contains minor non-conforming fluctuations.",
                supporting_evidence=supporting_reasons,
                contradictory_evidence=contradictory_reasons,
                coverage=0.75,
                abstain_recommended=False,
            )

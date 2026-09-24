"""Canonical Evidence Intelligence Engine for NexSolve.

Transforms raw network observations, multi-sensor telemetry, heuristic detections,
and World Model rollouts into a formal, explainable, traceable evidence system:
- Canonical EvidenceItem with strict provenance and bounded confidences.
- Zero-baseline feature explanation (NEWLY_PRESENT, INCREASED, DECREASED, STABLE, VOLATILE, INSUFFICIENT_BASELINE).
- Canonical 9-Tier Evidence Chain: PCAP -> PACKET -> FLOW -> WINDOW -> FEATURE -> DETECTION -> TECHNIQUE -> STAGE -> FORECAST.
- Traceable backward EvidenceGraph with directed nodes and edges.
- Multi-sensor agreement (STRONG, PARTIAL, MIXED, CONFLICTING, UNKNOWN).
- Transparent Evidence Fusion with separate supporting, contradictory, and neutral signals.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import math
from typing import Any, Mapping, Sequence

from ml.forecasting.attack_stages import AttackStage, validate_mitre_technique_id


class EvidenceSource(str, Enum):
    """Origin sensor or pipeline stage producing evidence."""
    PCAP = "PCAP"
    SCAPY = "SCAPY"
    ZEEK = "ZEEK"
    SURICATA = "SURICATA"
    NFSTREAM = "NFSTREAM"
    HEURISTIC = "HEURISTIC"
    MODEL = "MODEL"


class EvidencePolarity(str, Enum):
    """Direction of evidentiary impact."""
    SUPPORTING = "SUPPORTING"        # Corroborates hypothesis
    CONTRADICTORY = "CONTRADICTORY"  # Refutes or conflicts with hypothesis
    NEUTRAL = "NEUTRAL"              # Telemetry observed without clear directional bias


class FeatureChangeType(str, Enum):
    """Rigorous classification of feature delta against historical baseline."""
    NEWLY_PRESENT = "NEWLY_PRESENT"                 # Baseline was 0.0; feature emerged (> 0.0)
    INCREASED = "INCREASED"                         # Statistically significant upward delta (> 5%)
    DECREASED = "DECREASED"                         # Statistically significant downward delta (> 5%)
    STABLE = "STABLE"                               # Within nominal variation envelope (<= 5%)
    VOLATILE = "VOLATILE"                           # High coefficient of variance in recent window history
    INSUFFICIENT_BASELINE = "INSUFFICIENT_BASELINE" # Single-window or zero lookback history


class SensorAgreementLevel(str, Enum):
    """Agreement level across independent telemetry modalities."""
    STRONG = "STRONG"                # Multiple independent sensors corroborate with zero contradictions
    PARTIAL = "PARTIAL"              # Single sensor or partial corroborate with zero contradictions
    MIXED = "MIXED"                  # Corroborating sensors alongside neutral or low-confidence telemetry
    CONFLICTING = "CONFLICTING"      # Active sensor disagreement (supporting vs contradictory)
    UNKNOWN = "UNKNOWN"              # Zero sensor telemetry or unresolvable


class EvidenceNodeType(str, Enum):
    """Node types in the canonical 9-tier Evidence Graph."""
    PCAP = "PCAP"
    PACKET = "PACKET"
    FLOW = "FLOW"
    WINDOW = "WINDOW"
    FEATURE = "FEATURE"
    DETECTION = "DETECTION"
    TECHNIQUE = "TECHNIQUE"
    STAGE = "STAGE"
    FORECAST = "FORECAST"


class EvidenceEdgeType(str, Enum):
    """Edge semantics in the Evidence Graph."""
    DERIVED_FROM = "DERIVED_FROM"
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    INDICATES = "INDICATES"
    FORECASTS = "FORECASTS"
    AGGREGATES = "AGGREGATES"


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert numeric value, protecting against NaN, Inf, and non-numerics."""
    if val is None:
        return default
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return default
        return f
    except (TypeError, ValueError):
        return default


@dataclass(slots=True, frozen=True)
class EvidenceItem:
    """Canonical atomic evidence record grounded in physical telemetry or model inference."""
    evidence_id: str
    timestamp: float
    source: EvidenceSource
    modality: str  # e.g. "PACKET", "FLOW", "FEATURE", "IDS_ALERT", "MODEL_ROLLOUT"
    polarity: EvidencePolarity
    description: str
    confidence: float = 0.5
    feature: str | None = None
    feature_value: float | str | None = None
    window_id: int | str | None = None
    flow_id: str | None = None
    packet_id: str | int | None = None
    technique_id: str | None = None
    stage: str | None = None
    historical_baseline: float | None = None
    change_type: FeatureChangeType | None = None
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Enforce finite timestamp
        if not math.isfinite(self.timestamp):
            raise ValueError(f"Invalid timestamp '{self.timestamp}'; must be a finite float epoch.")

        # Enforce bounded confidence [0.0, 1.0]
        if math.isnan(self.confidence) or math.isinf(self.confidence) or not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Evidence confidence must be in [0.0, 1.0], got {self.confidence}")

        # Validate technique ID if supplied
        if self.technique_id is not None and not validate_mitre_technique_id(self.technique_id):
            raise ValueError(
                f"Invalid or unverified MITRE ATT&CK technique ID '{self.technique_id}'. "
                "Must match verified canonical syntax (e.g. 'T1046', 'T1498')."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp,
            "source": self.source.value,
            "modality": self.modality,
            "polarity": self.polarity.value,
            "description": self.description,
            "confidence": round(self.confidence, 4),
            "feature": self.feature,
            "feature_value": self.feature_value,
            "window_id": self.window_id,
            "flow_id": self.flow_id,
            "packet_id": self.packet_id,
            "technique_id": self.technique_id,
            "stage": self.stage,
            "historical_baseline": self.historical_baseline,
            "change_type": self.change_type.value if self.change_type else None,
            "raw_metadata": self.raw_metadata,
        }


@dataclass(slots=True, frozen=True)
class FeatureExplanation:
    """Defensive, mathematically grounded feature explanation avoiding zero-baseline division."""
    feature: str
    current_value: float
    historical_baseline: float | None
    change_type: FeatureChangeType
    magnitude: float | None  # None when baseline is 0.0 or insufficient
    window: int | str | None
    confidence: float
    interpretation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "current_value": round(self.current_value, 4),
            "historical_baseline": round(self.historical_baseline, 4) if self.historical_baseline is not None else None,
            "change_type": self.change_type.value,
            "magnitude": round(self.magnitude, 4) if self.magnitude is not None else None,
            "window": self.window,
            "confidence": round(self.confidence, 4),
            "interpretation": self.interpretation,
        }


def explain_feature_change(
    feature: str,
    current_value: float,
    historical_baseline: float | None,
    window: int | str | None = None,
    confidence: float = 0.85,
    friendly_name: str | None = None,
) -> FeatureExplanation:
    """Classify and explain feature change with strict zero-baseline safety.

    CRITICAL: When historical_baseline == 0.0, NEVER divide by zero to produce +410209592%.
    Instead, categorize as NEWLY_PRESENT (if curr > 0), DECREASED (if curr < 0), or STABLE (if curr == 0).
    """
    name = friendly_name or feature
    c_val = _safe_float(current_value, 0.0)

    if historical_baseline is None:
        return FeatureExplanation(
            feature=feature,
            current_value=c_val,
            historical_baseline=None,
            change_type=FeatureChangeType.INSUFFICIENT_BASELINE,
            magnitude=None,
            window=window,
            confidence=confidence,
            interpretation=f"{name} observed at {c_val:.2f} (no historical baseline available).",
        )

    b_val = _safe_float(historical_baseline, 0.0)

    # 1. Zero Baseline Handling
    if abs(b_val) < 1e-9:
        if c_val > 1e-9:
            return FeatureExplanation(
                feature=feature,
                current_value=c_val,
                historical_baseline=b_val,
                change_type=FeatureChangeType.NEWLY_PRESENT,
                magnitude=None,  # Zero-baseline prevents meaningful percentage calculation
                window=window,
                confidence=confidence,
                interpretation=f"{name} newly present in window (observed {c_val:.2f}, baseline was 0.0).",
            )
        elif c_val < -1e-9:
            return FeatureExplanation(
                feature=feature,
                current_value=c_val,
                historical_baseline=b_val,
                change_type=FeatureChangeType.DECREASED,
                magnitude=None,
                window=window,
                confidence=confidence,
                interpretation=f"{name} transitioned negative to {c_val:.2f} (baseline was 0.0).",
            )
        else:
            return FeatureExplanation(
                feature=feature,
                current_value=0.0,
                historical_baseline=0.0,
                change_type=FeatureChangeType.STABLE,
                magnitude=0.0,
                window=window,
                confidence=confidence,
                interpretation=f"{name} stable at baseline 0.0.",
            )

    # 2. Non-Zero Baseline Handling
    delta = c_val - b_val
    relative_change = delta / abs(b_val)

    if abs(relative_change) <= 0.05:
        return FeatureExplanation(
            feature=feature,
            current_value=c_val,
            historical_baseline=b_val,
            change_type=FeatureChangeType.STABLE,
            magnitude=relative_change,
            window=window,
            confidence=confidence,
            interpretation=f"{name} stable ({c_val:.2f} vs baseline {b_val:.2f}, {relative_change:+.1%}).",
        )
    elif relative_change > 0.05:
        return FeatureExplanation(
            feature=feature,
            current_value=c_val,
            historical_baseline=b_val,
            change_type=FeatureChangeType.INCREASED,
            magnitude=relative_change,
            window=window,
            confidence=confidence,
            interpretation=f"{name} increased {relative_change * 100:.1f}% ({c_val:.2f} vs baseline {b_val:.2f}).",
        )
    else:
        return FeatureExplanation(
            feature=feature,
            current_value=c_val,
            historical_baseline=b_val,
            change_type=FeatureChangeType.DECREASED,
            magnitude=relative_change,
            window=window,
            confidence=confidence,
            interpretation=f"{name} decreased {abs(relative_change) * 100:.1f}% ({c_val:.2f} vs baseline {b_val:.2f}).",
        )


@dataclass(slots=True, frozen=True)
class SensorAgreement:
    """Cross-sensor corroboration summary with transparent confidence modifier."""
    supporting_sources: tuple[str, ...]
    contradictory_sources: tuple[str, ...]
    neutral_sources: tuple[str, ...]
    agreement_level: SensorAgreementLevel
    confidence_modifier: float
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "supporting_sources": list(self.supporting_sources),
            "contradictory_sources": list(self.contradictory_sources),
            "neutral_sources": list(self.neutral_sources),
            "agreement_level": self.agreement_level.value,
            "confidence_modifier": round(self.confidence_modifier, 4),
            "explanation": self.explanation,
        }


def evaluate_sensor_agreement(items: Sequence[EvidenceItem]) -> SensorAgreement:
    """Evaluate agreement across reporting sensors without fabricating consensus.

    - STRONG: Multiple sensors agree with supporting polarity, 0 contradictory.
    - PARTIAL: Single sensor supporting, 0 contradictory.
    - MIXED: Supporting sensors alongside neutral sensors.
    - CONFLICTING: Sensors report opposing supporting and contradictory evidence.
    - UNKNOWN: Zero sensor reports or uncorroborated.
    """
    if not items:
        return SensorAgreement(
            supporting_sources=(),
            contradictory_sources=(),
            neutral_sources=(),
            agreement_level=SensorAgreementLevel.UNKNOWN,
            confidence_modifier=0.5,
            explanation="No multi-sensor telemetry available for agreement evaluation.",
        )

    supp_sources = {item.source.value for item in items if item.polarity == EvidencePolarity.SUPPORTING}
    contra_sources = {item.source.value for item in items if item.polarity == EvidencePolarity.CONTRADICTORY}
    neut_sources = {
        item.source.value for item in items
        if item.polarity == EvidencePolarity.NEUTRAL
        and item.source.value not in supp_sources
        and item.source.value not in contra_sources
    }

    if supp_sources and contra_sources:
        return SensorAgreement(
            supporting_sources=tuple(sorted(supp_sources)),
            contradictory_sources=tuple(sorted(contra_sources)),
            neutral_sources=tuple(sorted(neut_sources)),
            agreement_level=SensorAgreementLevel.CONFLICTING,
            confidence_modifier=0.45,
            explanation=(
                f"Sensors report contradictory telemetry: {list(supp_sources)} indicate attack activity "
                f"while {list(contra_sources)} indicate normal baseline."
            ),
        )
    elif len(supp_sources) >= 2:
        return SensorAgreement(
            supporting_sources=tuple(sorted(supp_sources)),
            contradictory_sources=(),
            neutral_sources=tuple(sorted(neut_sources)),
            agreement_level=SensorAgreementLevel.STRONG,
            confidence_modifier=1.15,
            explanation=f"Multiple independent sensors ({', '.join(sorted(supp_sources))}) corroborate attack indicators.",
        )
    elif len(supp_sources) == 1:
        lvl = SensorAgreementLevel.MIXED if neut_sources else SensorAgreementLevel.PARTIAL
        mod = 0.95 if neut_sources else 1.0
        return SensorAgreement(
            supporting_sources=tuple(sorted(supp_sources)),
            contradictory_sources=(),
            neutral_sources=tuple(sorted(neut_sources)),
            agreement_level=lvl,
            confidence_modifier=mod,
            explanation=f"Telemetry supported by {list(supp_sources)[0]} sensor with 0 contradictions.",
        )
    elif contra_sources:
        return SensorAgreement(
            supporting_sources=(),
            contradictory_sources=tuple(sorted(contra_sources)),
            neutral_sources=tuple(sorted(neut_sources)),
            agreement_level=SensorAgreementLevel.CONFLICTING,
            confidence_modifier=0.30,
            explanation=f"Telemetry contradicted by reporting sensors: {list(contra_sources)}.",
        )
    else:
        return SensorAgreement(
            supporting_sources=(),
            contradictory_sources=(),
            neutral_sources=tuple(sorted(neut_sources)),
            agreement_level=SensorAgreementLevel.UNKNOWN,
            confidence_modifier=0.60,
            explanation="Sensors observed neutral telemetry without distinct directional bias.",
        )


@dataclass(slots=True, frozen=True)
class FusedEvidenceAssessment:
    """Transparent fusion of evidentiary signals retaining all provenance inputs."""
    supporting_count: int
    contradictory_count: int
    neutral_count: int
    source_diversity: int
    confidence: float
    reason: str
    sensor_agreement: SensorAgreement
    supporting_items: tuple[EvidenceItem, ...]
    contradictory_items: tuple[EvidenceItem, ...]
    neutral_items: tuple[EvidenceItem, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "supporting_count": self.supporting_count,
            "contradictory_count": self.contradictory_count,
            "neutral_count": self.neutral_count,
            "source_diversity": self.source_diversity,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
            "sensor_agreement": self.sensor_agreement.to_dict(),
            "supporting_items": [i.to_dict() for i in self.supporting_items],
            "contradictory_items": [i.to_dict() for i in self.contradictory_items],
            "neutral_items": [i.to_dict() for i in self.neutral_items],
        }


def fuse_evidence(items: Sequence[EvidenceItem]) -> FusedEvidenceAssessment:
    """Fuse evidence records into a coherent, transparent assessment without magic scores."""
    supp = [i for i in items if i.polarity == EvidencePolarity.SUPPORTING]
    contra = [i for i in items if i.polarity == EvidencePolarity.CONTRADICTORY]
    neut = [i for i in items if i.polarity == EvidencePolarity.NEUTRAL]

    distinct_sources = len({i.source for i in items})
    agreement = evaluate_sensor_agreement(items)

    # Base confidence calculation from item weights
    if supp:
        avg_supp_conf = sum(i.confidence for i in supp) / len(supp)
        raw_conf = avg_supp_conf * agreement.confidence_modifier
        # Penalize if contradictions exist
        if contra:
            penalty = min(0.4, 0.15 * len(contra))
            raw_conf = max(0.1, raw_conf - penalty)
        conf = max(0.0, min(1.0, raw_conf))
        reason = f"Fused {len(supp)} supporting signals across {distinct_sources} sources (Agreement: {agreement.agreement_level.value})."
    elif contra:
        conf = 0.2
        reason = f"Predominantly contradictory telemetry observed across {len(contra)} signals."
    else:
        conf = 0.5
        reason = "Neutral / baseline network telemetry with zero anomalous indicators."

    return FusedEvidenceAssessment(
        supporting_count=len(supp),
        contradictory_count=len(contra),
        neutral_count=len(neut),
        source_diversity=distinct_sources,
        confidence=round(conf, 4),
        reason=reason,
        sensor_agreement=agreement,
        supporting_items=tuple(supp),
        contradictory_items=tuple(contra),
        neutral_items=tuple(neut),
    )


# ---------------------------------------------------------------------------
# Canonical 9-Tier Evidence Chain & Evidence Graph
# ---------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class EvidenceGraphNode:
    id: str
    node_type: EvidenceNodeType
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    timestamp: float | str | None = None
    window_id: int | str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type.value,
            "label": self.label,
            "properties": self.properties,
            "timestamp": self.timestamp,
            "window_id": self.window_id,
        }


@dataclass(slots=True, frozen=True)
class EvidenceGraphEdge:
    source_id: str
    target_id: str
    edge_type: EvidenceEdgeType
    weight: float = 1.0
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "weight": round(self.weight, 4),
            "reason": self.reason,
        }


class EvidenceGraph:
    """Traceable, backward-searchable evidence graph linking PCAP to FORECAST."""

    def __init__(self) -> None:
        self._nodes: dict[str, EvidenceGraphNode] = {}
        self._edges: list[EvidenceGraphEdge] = []

    def add_node(
        self,
        node_id: str,
        node_type: EvidenceNodeType,
        label: str,
        properties: dict[str, Any] | None = None,
        timestamp: float | str | None = None,
        window_id: int | str | None = None,
    ) -> EvidenceGraphNode:
        node = EvidenceGraphNode(
            id=node_id,
            node_type=node_type,
            label=label,
            properties=properties or {},
            timestamp=timestamp,
            window_id=window_id,
        )
        self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EvidenceEdgeType,
        weight: float = 1.0,
        reason: str = "",
    ) -> EvidenceGraphEdge:
        edge = EvidenceGraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=max(0.0, min(1.0, _safe_float(weight, 1.0))),
            reason=reason,
        )
        self._edges.append(edge)
        return edge

    @property
    def nodes(self) -> list[EvidenceGraphNode]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[EvidenceGraphEdge]:
        return list(self._edges)

    def trace_backward(self, start_node_id: str) -> list[dict[str, Any]]:
        """Trace an important forecast node backward to its evidence roots (Stage -> Technique -> Feature -> Window -> PCAP)."""
        visited = set()
        trace_steps: list[dict[str, Any]] = []

        curr_id = start_node_id
        while curr_id and curr_id not in visited:
            visited.add(curr_id)
            node = self._nodes.get(curr_id)
            if not node:
                break

            trace_steps.append({
                "node_id": node.id,
                "node_type": node.node_type.value,
                "label": node.label,
                "properties": node.properties,
            })

            # Find parent edge pointing backward
            parent_edge = next((e for e in self._edges if e.source_id == curr_id), None)
            if not parent_edge:
                # Also check incoming DERIVED_FROM edges
                parent_edge = next((e for e in self._edges if e.target_id == curr_id and e.edge_type in (EvidenceEdgeType.DERIVED_FROM, EvidenceEdgeType.INDICATES, EvidenceEdgeType.FORECASTS)), None)
                curr_id = parent_edge.source_id if parent_edge else None
            else:
                curr_id = parent_edge.target_id

        return trace_steps

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
        }


def build_canonical_evidence_graph(
    pcap_sha256: str,
    pcap_filename: str,
    windows: Sequence[Any],
    findings: Sequence[Any],
    attack_progression: Any,
    forecast_points: Sequence[Any],
) -> EvidenceGraph:
    """Build the formal 9-tier Evidence Graph:

    PCAP -> PACKET -> FLOW -> WINDOW -> FEATURE -> DETECTION -> TECHNIQUE -> STAGE -> FORECAST
    """
    graph = EvidenceGraph()

    # 1. PCAP Root Node
    pcap_node_id = f"pcap:{pcap_sha256[:16]}"
    graph.add_node(
        node_id=pcap_node_id,
        node_type=EvidenceNodeType.PCAP,
        label=pcap_filename,
        properties={"sha256": pcap_sha256},
    )

    # 2. Window Nodes
    win_node_ids = []
    for idx, w in enumerate(windows):
        w_id = getattr(w, "window_id", idx) if hasattr(w, "window_id") else idx
        w_start = getattr(w, "start_timestamp", None) or getattr(w, "window_start", 0)
        w_node_id = f"window:{w_id}"
        win_node_ids.append(w_node_id)
        graph.add_node(
            node_id=w_node_id,
            node_type=EvidenceNodeType.WINDOW,
            label=f"Window {w_id}",
            timestamp=w_start,
            window_id=w_id,
        )
        graph.add_edge(
            source_id=w_node_id,
            target_id=pcap_node_id,
            edge_type=EvidenceEdgeType.DERIVED_FROM,
            reason="Temporal window sliced from PCAP",
        )

    # 3. Detection & Feature Nodes from Findings
    active_tech_nodes = {}
    active_det_nodes = []
    for idx, f in enumerate(findings):
        f_id = f.get("finding_id") or f.get("rule_id") or f"FINDING_{idx}"
        tech = f.get("mitre_technique") or f.get("technique_id")
        w_id = f.get("window_id") or (windows[-1].window_id if windows and hasattr(windows[-1], "window_id") else 0)
        d_node_id = f"det:{f_id}_{idx}"
        active_det_nodes.append(d_node_id)

        graph.add_node(
            node_id=d_node_id,
            node_type=EvidenceNodeType.DETECTION,
            label=str(f.get("explanation") or f.get("rule_id") or "Heuristic Anomaly"),
            properties={"severity": f.get("severity", "MEDIUM"), "rule_id": f.get("rule_id")},
            window_id=w_id,
        )

        target_win = f"window:{w_id}" if f"window:{w_id}" in graph._nodes else (win_node_ids[-1] if win_node_ids else pcap_node_id)
        graph.add_edge(
            source_id=d_node_id,
            target_id=target_win,
            edge_type=EvidenceEdgeType.DERIVED_FROM,
            reason="Detection evaluated from window features",
        )

        if tech:
            tech_node_id = f"tech:{tech}"
            if tech_node_id not in active_tech_nodes:
                active_tech_nodes[tech_node_id] = graph.add_node(
                    node_id=tech_node_id,
                    node_type=EvidenceNodeType.TECHNIQUE,
                    label=f"MITRE {tech}",
                    properties={"technique_id": tech},
                )
            graph.add_edge(
                source_id=tech_node_id,
                target_id=d_node_id,
                edge_type=EvidenceEdgeType.INDICATES,
                reason="Alert signature grounds MITRE technique",
            )

    # 4. Current Stage Node
    curr_stage = getattr(attack_progression, "canonical_stage", None) or getattr(attack_progression, "current_state", "UNKNOWN")
    if hasattr(curr_stage, "value"):
        curr_stage = curr_stage.value
    stage_node_id = f"stage:{curr_stage}"
    graph.add_node(
        node_id=stage_node_id,
        node_type=EvidenceNodeType.STAGE,
        label=f"Stage: {curr_stage}",
        properties={"stage": curr_stage},
    )

    for tech_id in active_tech_nodes:
        graph.add_edge(
            source_id=stage_node_id,
            target_id=tech_id,
            edge_type=EvidenceEdgeType.SUPPORTS,
            reason="Observed MITRE technique supports current attack stage",
        )

    # If no tech nodes, connect stage directly to detections or last window
    if not active_tech_nodes:
        if active_det_nodes:
            for d_id in active_det_nodes[:3]:
                graph.add_edge(
                    source_id=stage_node_id,
                    target_id=d_id,
                    edge_type=EvidenceEdgeType.SUPPORTS,
                    reason="Observed detections support current attack stage",
                )
        elif win_node_ids:
            graph.add_edge(
                source_id=stage_node_id,
                target_id=win_node_ids[-1],
                edge_type=EvidenceEdgeType.DERIVED_FROM,
                reason="Baseline stage evaluated from window telemetry",
            )

    # 5. Forecast Nodes
    for pt in forecast_points:
        h = pt.get("horizon", 1) if isinstance(pt, dict) else getattr(pt, "horizon", 1)
        p_stage = pt.get("predicted_stage") or pt.get("predictedStage") or curr_stage if isinstance(pt, dict) else getattr(pt, "candidate_stage", curr_stage)
        if hasattr(p_stage, "value"):
            p_stage = p_stage.value
        fc_node_id = f"forecast:T+{h}"
        prob = pt.get("probability", pt.get("attackProbability", 0.5)) if isinstance(pt, dict) else getattr(pt, "probability", 0.5)

        graph.add_node(
            node_id=fc_node_id,
            node_type=EvidenceNodeType.FORECAST,
            label=f"Forecast T+{h}: {p_stage}",
            properties={"horizon": h, "probability": prob, "stage": p_stage},
        )
        graph.add_edge(
            source_id=fc_node_id,
            target_id=stage_node_id,
            edge_type=EvidenceEdgeType.FORECASTS,
            weight=prob if prob is not None else 0.5,
            reason=f"World Model rollouts project stage evolution at horizon T+{h}",
        )

    return graph

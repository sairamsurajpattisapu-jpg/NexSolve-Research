"""Threat-Centric Investigation View Engine.

Instead of only listing disconnected alerts, this module aggregates all multi-modal
intelligence around the primary threat entity into an actionable, investigable representation:
- Entity identity & role
- Current inferred attack state & confidence rationale
- Activity timeline & window progression
- Corroborating signals across modalities (Zeek, RITA, NFStream, Suricata, ML)
- Explicit contradiction evidence (e.g. benign protocol exceptions)
- Future threat horizon & progression hypothesis
- Actionable investigation explanation chain
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


@dataclass(frozen=True)
class ThreatCentricView:
    """Consolidated threat intelligence view focused on a primary threat entity."""
    entity_key: str
    threat_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    current_attack_state: str
    mitre_techniques: tuple[str, ...]
    first_seen_window: int
    last_seen_window: int
    associated_peers: tuple[str, ...]
    targeted_ports: tuple[int, ...]
    total_sessions: int
    total_findings: int
    corroborating_modalities: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    explanation_chain: tuple[str, ...]
    forecast_hypothesis: str | None
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_key": self.entity_key,
            "threat_level": self.threat_level,
            "current_attack_state": self.current_attack_state,
            "mitre_techniques": list(self.mitre_techniques),
            "first_seen_window": self.first_seen_window,
            "last_seen_window": self.last_seen_window,
            "associated_peers": list(self.associated_peers),
            "targeted_ports": list(self.targeted_ports),
            "total_sessions": self.total_sessions,
            "total_findings": self.total_findings,
            "corroborating_modalities": list(self.corroborating_modalities),
            "contradicting_evidence": list(self.contradicting_evidence),
            "explanation_chain": list(self.explanation_chain),
            "forecast_hypothesis": self.forecast_hypothesis,
            "provenance": self.provenance,
        }


def build_threat_centric_views(
    entity_histories: Mapping[str, Any] | None = None,
    attack_states: Sequence[Any] | None = None,
    episodes: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
) -> tuple[ThreatCentricView, ...]:
    """Compile threat-centric views for entities involved in active findings or episodes."""
    views: list[ThreatCentricView] = []

    # Map attack states by entity
    entity_state_map = {}
    if attack_states:
        for s in attack_states:
            entity_state_map[getattr(s, "entity", "")] = s

    # Candidate threat entities
    candidate_entities = set()
    if episodes:
        for ep in episodes:
            if ep.primary_entity:
                candidate_entities.add(ep.primary_entity)
    if attack_states:
        for st in attack_states:
            if st.entity and st.entity != "network":
                candidate_entities.add(st.entity)

    if not candidate_entities and observed_findings:
        for f in observed_findings:
            ent = f.get("destination_ip") or f.get("source_ip")
            if ent:
                candidate_entities.add(str(ent))

    for ent in sorted(candidate_entities):
        hist = (entity_histories or {}).get(ent)
        st = entity_state_map.get(ent)

        st_val = getattr(st, "state", None)
        state_str = getattr(st_val, "value", str(st_val)) if st_val else "BENIGN_OBSERVATION"

        # Check corroborating modalities
        modalities = ["ML_DETECTION"]
        if hist and hist.session_count > 0:
            modalities.append("ZEEK_TCP_SESSION")
        if hist and hist.unique_ports:
            modalities.append("FLOW_STATISTICS")

        # Contradictions
        contradictions = []
        # If port 80 or 443 only with low sessions, potential benign web traffic
        if hist and set(hist.unique_ports).issubset({80, 443, 53}) and hist.findings_count <= 1:
            contradictions.append("Traffic is restricted to standard well-known web/DNS ports (80/443/53).")

        # Construct explanation chain
        chain = [
            f"Entity {ent} observed across windows {getattr(hist, 'first_seen_window', 0)}..{getattr(hist, 'last_seen_window', 0)}",
            f"Evaluated with {getattr(hist, 'activity_count', 0)} total interaction(s) and {getattr(hist, 'findings_count', 0)} finding(s)",
            f"Inferred attack state: {state_str}",
        ]
        if st and st.confidence_rationale:
            chain.append(st.confidence_rationale)

        # Forecast hypothesis
        fc_hyp = None
        if forecast_points and len(forecast_points) > 0:
            p0 = forecast_points[0]
            prob = p0.get("attackProbability")
            if prob is not None:
                fc_hyp = f"K=1m recursive forecast predicts P(Attack)={float(prob):.2f} grounded on state persistence."

        techs = tuple(getattr(st, "mitre_techniques", ())) if st else tuple()

        views.append(ThreatCentricView(
            entity_key=ent,
            threat_level="HIGH" if state_str in ("RECONNAISSANCE", "DENIAL_OF_SERVICE") else "LOW",
            current_attack_state=state_str,
            mitre_techniques=techs,
            first_seen_window=getattr(hist, "first_seen_window", 0) if hist else 0,
            last_seen_window=getattr(hist, "last_seen_window", 0) if hist else 0,
            associated_peers=tuple(getattr(hist, "unique_peers", ()))[:10] if hist else tuple(),
            targeted_ports=tuple(getattr(hist, "unique_ports", ()))[:10] if hist else tuple(),
            total_sessions=getattr(hist, "session_count", 0) if hist else 0,
            total_findings=getattr(hist, "findings_count", 0) if hist else 0,
            corroborating_modalities=tuple(modalities),
            contradicting_evidence=tuple(contradictions),
            explanation_chain=tuple(chain),
            forecast_hypothesis=fc_hyp,
            provenance={"builder": "threat_centric_view_engine"},
        ))

    return tuple(views)

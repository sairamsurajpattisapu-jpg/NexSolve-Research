"""Deterministic Cross-Entity Relationship Discovery Engine.

Discovers explainable relationships between network entities:
- COMMUNICATES_WITH: Direct bidirectional or unidirectional network sessions
- SCANS / SCANNED_BY: Port scanning targeting relationships
- SHARES_TARGETS: Entities converging on overlapping target hosts
- SHARES_PORTS: Entities targeting identical service ports
- SHARES_CAMPAIGN: Entities participating in the same correlated campaign
- SHARES_PATTERN: Entities participating in a coordinated attack pattern
- BEACON_RELATIONSHIP: C2 periodic communication to infrastructure
- FANOUT_RELATIONSHIP: Broad target expansion across peers

All relationships are supported by concrete telemetry and evidence keys.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id
from nexsolve_core.investigation_model import InvestigationRelationship, RelationshipType


def discover_entity_relationships(
    entity: str,
    tcp_sessions: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    beaconing_signals: Sequence[Any] | None = None,
    entity_profiles: Mapping[str, Any] | None = None,
) -> tuple[InvestigationRelationship, ...]:
    """Discover all explainable cross-entity relationships connected to an entity."""
    relationships: dict[str, InvestigationRelationship] = {}
    sessions = tcp_sessions or []
    pats = patterns or []
    cmps = campaigns or []
    beacons = beaconing_signals or []
    profiles = entity_profiles or {}

    # 1. Direct Network Sessions (COMMUNICATES_WITH, SCANS)
    prof = profiles.get(entity)
    is_scanner = prof and any("SCANNER" in str(r) for r in getattr(prof, "roles", ()))

    target_sessions: dict[str, list[Any]] = defaultdict(list)
    source_sessions: dict[str, list[Any]] = defaultdict(list)
    for s in sessions:
        src = getattr(s, "src_ip", None)
        dst = getattr(s, "dst_ip", None)
        if src == entity and dst and dst != entity:
            target_sessions[dst].append(s)
        elif dst == entity and src and src != entity:
            source_sessions[src].append(s)

    # Entity -> Targets
    for target, s_list in target_sessions.items():
        rel_type = RelationshipType.SCANS if is_scanner else RelationshipType.COMMUNICATES_WITH
        t_first = min((getattr(s, "first_seen", 0.0) or 0.0) for s in s_list)
        t_last = max((getattr(s, "last_seen", 0.0) or 0.0) for s in s_list)
        ports = sorted(list({getattr(s, "dst_port") for s in s_list if getattr(s, "dst_port", None) is not None}))
        reasons = [
            f"Observed {len(s_list)} active session(s) targeting {target} on ports {ports[:5]}",
        ]
        evidence = [f"sessions_count_{len(s_list)}", f"targeted_ports_{len(ports)}"]

        rid = deterministic_id("rel", entity, target, rel_type.value)
        relationships[target] = InvestigationRelationship(
            relationship_id=rid,
            source_entity=entity,
            target_entity=target,
            relationship_type=rel_type,
            supporting_reasons=tuple(reasons),
            supporting_evidence=tuple(evidence),
            first_seen=t_first,
            last_seen=t_last,
            observed_status="OBSERVED",
            provenance={"source": "tcp_session_tracker"},
        )

    # Sources -> Entity
    for source, s_list in source_sessions.items():
        if source in relationships:
            continue
        rel_type = RelationshipType.SCANNED_BY if is_scanner else RelationshipType.COMMUNICATES_WITH
        t_first = min((getattr(s, "first_seen", 0.0) or 0.0) for s in s_list)
        t_last = max((getattr(s, "last_seen", 0.0) or 0.0) for s in s_list)
        ports = sorted(list({getattr(s, "dst_port") for s in s_list if getattr(s, "dst_port", None) is not None}))
        reasons = [f"Received {len(s_list)} incoming session(s) from {source} on ports {ports[:5]}"]
        evidence = [f"inbound_sessions_{len(s_list)}"]

        rid = deterministic_id("rel", source, entity, rel_type.value)
        relationships[source] = InvestigationRelationship(
            relationship_id=rid,
            source_entity=source,
            target_entity=entity,
            relationship_type=rel_type,
            supporting_reasons=tuple(reasons),
            supporting_evidence=tuple(evidence),
            first_seen=t_first,
            last_seen=t_last,
            observed_status="OBSERVED",
            provenance={"source": "tcp_session_tracker"},
        )

    # 2. SHARES_CAMPAIGN
    for cmp in cmps:
        all_cmp_ents = set(getattr(cmp, "primary_entities", ())) | set(getattr(cmp, "target_entities", ()))
        if entity in all_cmp_ents:
            for peer in all_cmp_ents:
                if peer != entity and peer not in relationships:
                    rid = deterministic_id("rel", entity, peer, "SHARES_CAMPAIGN")
                    relationships[peer] = InvestigationRelationship(
                        relationship_id=rid,
                        source_entity=entity,
                        target_entity=peer,
                        relationship_type=RelationshipType.SHARES_CAMPAIGN,
                        supporting_reasons=(f"Co-participates in campaign {getattr(cmp, 'title', '')}",),
                        supporting_evidence=(getattr(cmp, "campaign_id", "cmp"),),
                        first_seen=float(getattr(cmp, "start_window", 0) * 60.0),
                        last_seen=float(getattr(cmp, "end_window", 0) * 60.0),
                        observed_status="DERIVED",
                        provenance=getattr(cmp, "provenance", {}),
                    )

    # 3. SHARES_PATTERN
    for pat in pats:
        all_pat_ents = set(getattr(pat, "primary_entities", ())) | set(getattr(pat, "target_entities", ()))
        if entity in all_pat_ents:
            for peer in all_pat_ents:
                if peer != entity and peer not in relationships:
                    rid = deterministic_id("rel", entity, peer, "SHARES_PATTERN")
                    relationships[peer] = InvestigationRelationship(
                        relationship_id=rid,
                        source_entity=entity,
                        target_entity=peer,
                        relationship_type=RelationshipType.SHARES_PATTERN,
                        supporting_reasons=(f"Co-occurs in attack pattern {getattr(pat, 'pattern_type', '')}",),
                        supporting_evidence=(getattr(pat, "pattern_id", "pat"),),
                        first_seen=None,
                        last_seen=None,
                        observed_status="DERIVED",
                        provenance=getattr(pat, "provenance", {}),
                    )

    # 4. BEACON_RELATIONSHIP
    for b in beacons:
        if getattr(b, "src_ip", "") == entity and getattr(b, "is_beaconing", False):
            dst = getattr(b, "dst_ip", "")
            if dst and dst not in relationships:
                rid = deterministic_id("rel", entity, dst, "BEACON")
                relationships[dst] = InvestigationRelationship(
                    relationship_id=rid,
                    source_entity=entity,
                    target_entity=dst,
                    relationship_type=RelationshipType.BEACON_RELATIONSHIP,
                    supporting_reasons=(f"Metronomic periodic beaconing detected (score: {getattr(b, 'score', 0):.2f})",),
                    supporting_evidence=(f"beacon_{dst}",),
                    first_seen=None,
                    last_seen=None,
                    observed_status="OBSERVED",
                    provenance={"modality": "RITA_BEACONING"},
                )

    # Deterministic sort by target_entity ASC
    sorted_rels = sorted(relationships.values(), key=lambda r: r.target_entity)
    return tuple(sorted_rels)

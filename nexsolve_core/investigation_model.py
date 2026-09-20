"""Unified Security Investigation Data Model for NexSolve.

Provides a strongly typed, deterministic investigation model linking:
NETWORK -> ENTITIES -> BEHAVIOR -> ANOMALIES -> PATTERNS -> ATTACK STATES -> TRANSITIONS -> CAMPAIGNS -> EVIDENCE -> FORECAST CONTEXT -> RISK/PRIORITY.

Every subject, finding, relationship, and timeline event strictly preserves provenance.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class InvestigationSubjectType(str, Enum):
    ENTITY = "ENTITY"
    IP = "IP"
    CAMPAIGN = "CAMPAIGN"
    PATTERN = "PATTERN"
    EPISODE = "EPISODE"
    ATTACK_STATE = "ATTACK_STATE"
    MITRE_TECHNIQUE = "MITRE_TECHNIQUE"
    BEHAVIOR_CHANGE = "BEHAVIOR_CHANGE"


class RelationshipType(str, Enum):
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    SCANS = "SCANS"
    SCANNED_BY = "SCANNED_BY"
    SHARES_TARGETS = "SHARES_TARGETS"
    SHARES_PORTS = "SHARES_PORTS"
    SHARES_CAMPAIGN = "SHARES_CAMPAIGN"
    SHARES_PATTERN = "SHARES_PATTERN"
    COORDINATED_BEHAVIOR = "COORDINATED_BEHAVIOR"
    BEACON_RELATIONSHIP = "BEACON_RELATIONSHIP"
    FANOUT_RELATIONSHIP = "FANOUT_RELATIONSHIP"
    FANIN_RELATIONSHIP = "FANIN_RELATIONSHIP"
    TRANSITIONS_TO = "TRANSITIONS_TO"


@dataclass(frozen=True)
class InvestigationFinding:
    """An individual verified finding or observation belonging to an investigation."""
    finding_id: str
    title: str
    category: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    window_index: int
    timestamp: float | str | None
    observed_or_forecast: str  # "OBSERVED" | "FORECAST"
    description: str
    supporting_evidence_keys: tuple[str, ...]
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = getattr(self, "_dict_cache", None)
        if d is not None:
            return d
        d = {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "window_index": self.window_index,
            "timestamp": self.timestamp,
            "observed_or_forecast": self.observed_or_forecast,
            "description": self.description,
            "supporting_evidence_keys": list(self.supporting_evidence_keys),
            "provenance": self.provenance,
        }
        object.__setattr__(self, "_dict_cache", d)
        return d


@dataclass(frozen=True)
class InvestigationRelationship:
    """A concrete, evidence-backed relationship between two investigation subjects."""
    relationship_id: str
    source_entity: str
    target_entity: str
    relationship_type: RelationshipType
    supporting_reasons: tuple[str, ...]
    supporting_evidence: tuple[str, ...]
    first_seen: float | None
    last_seen: float | None
    observed_status: str  # "OBSERVED" | "DERIVED"
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = getattr(self, "_dict_cache", None)
        if d is not None:
            return d
        rel_type = self.relationship_type.value if hasattr(self.relationship_type, "value") else self.relationship_type
        d = {
            "relationship_id": self.relationship_id,
            "source_entity": self.source_entity,
            "target_entity": self.target_entity,
            "relationship_type": rel_type,
            "supporting_reasons": list(self.supporting_reasons),
            "supporting_evidence": list(self.supporting_evidence),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observed_status": self.observed_status,
            "provenance": self.provenance,
        }
        object.__setattr__(self, "_dict_cache", d)
        return d


@dataclass(frozen=True)
class InvestigationTimelineEvent:
    """A strictly ordered, provenance-preserved event in an investigation timeline."""
    event_id: str
    timestamp: float
    window_index: int
    event_type: str
    entity: str
    headline: str
    details: str
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    observed_or_forecast: str  # "OBSERVED" | "FORECAST"
    source_modality: str
    supporting_evidence_keys: tuple[str, ...]
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = getattr(self, "_dict_cache", None)
        if d is not None:
            return d
        d = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "window_index": self.window_index,
            "event_type": self.event_type,
            "entity": self.entity,
            "headline": self.headline,
            "details": self.details,
            "severity": self.severity,
            "observed_or_forecast": self.observed_or_forecast,
            "source_modality": self.source_modality,
            "supporting_evidence_keys": list(self.supporting_evidence_keys),
            "provenance": self.provenance,
        }
        object.__setattr__(self, "_dict_cache", d)
        return d


@dataclass(frozen=True)
class InvestigationSubject:
    """The central focus entity or campaign of an active investigation."""
    subject_id: str
    subject_type: InvestigationSubjectType
    label: str
    first_seen: float | None
    last_seen: float | None
    active_windows: tuple[int, ...]
    primary_roles: tuple[str, ...]
    inferred_attack_state: str
    current_priority: str
    associated_campaign_ids: tuple[str, ...]
    associated_pattern_ids: tuple[str, ...]
    summary: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = getattr(self, "_dict_cache", None)
        if d is not None:
            return d
        sub_type = self.subject_type.value if hasattr(self.subject_type, "value") else self.subject_type
        d = {
            "subject_id": self.subject_id,
            "subject_type": sub_type,
            "label": self.label,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "active_windows": list(self.active_windows),
            "primary_roles": list(self.primary_roles),
            "inferred_attack_state": self.inferred_attack_state,
            "current_priority": self.current_priority,
            "associated_campaign_ids": list(self.associated_campaign_ids),
            "associated_pattern_ids": list(self.associated_pattern_ids),
            "summary": self.summary,
            "provenance": self.provenance,
        }
        object.__setattr__(self, "_dict_cache", d)
        return d


@dataclass(frozen=True)
class InvestigationContext:
    """The consolidated investigation package for an investigator."""
    investigation_id: str
    subject: InvestigationSubject
    findings: tuple[InvestigationFinding, ...]
    timeline: tuple[InvestigationTimelineEvent, ...]
    relationships: tuple[InvestigationRelationship, ...]
    contradictions: tuple[str, ...]
    mitigating_factors: tuple[str, ...]
    forecast_context_summary: str | None
    recommended_action: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "subject": self.subject.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "timeline": [t.to_dict() for t in self.timeline],
            "relationships": [r.to_dict() for r in self.relationships],
            "contradictions": list(self.contradictions),
            "mitigating_factors": list(self.mitigating_factors),
            "forecast_context_summary": self.forecast_context_summary,
            "recommended_action": self.recommended_action,
            "provenance": self.provenance,
        }

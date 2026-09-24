"""Canonical Stage Evidence Contract and Sensor Corroboration Engine.

Strictly encapsulates evidentiary signals supporting or contradicting attack stages:
- Multi-source provenance: PCAP, SCAPY, ZEEK, SURICATA, NFSTREAM, HEURISTIC, MODEL.
- Polarities: SUPPORTING, CONTRADICTORY, NEUTRAL.
- Sensor agreement assessment: FULL, PARTIAL, CONFLICTING.
- Strict confidence bounds in [0.0, 1.0].
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import math
from typing import Any, Sequence

from ml.forecasting.attack_stages import AttackStage, validate_mitre_technique_id


class EvidenceSource(str, Enum):
    """Origin sensor or pipeline stage producing the evidence."""
    PCAP = "PCAP"
    SCAPY = "SCAPY"
    ZEEK = "ZEEK"
    SURICATA = "SURICATA"
    NFSTREAM = "NFSTREAM"
    HEURISTIC = "HEURISTIC"
    MODEL = "MODEL"


class EvidencePolarity(str, Enum):
    """Direction of evidentiary impact."""
    SUPPORTING = "SUPPORTING"        # Evidence reinforces stage hypothesis
    CONTRADICTORY = "CONTRADICTORY"  # Evidence contradicts or refutes stage hypothesis
    NEUTRAL = "NEUTRAL"              # Telemetry observed without clear directional alignment


class SensorAgreement(str, Enum):
    """Degree of corroboration across independent telemetry sensors."""
    FULL = "FULL"                # All reporting sensors agree on stage indicators
    PARTIAL = "PARTIAL"          # Some sensors report supporting evidence, others neutral
    CONFLICTING = "CONFLICTING"  # Sensors report conflicting or contradictory indicators
    INSUFFICIENT = "INSUFFICIENT"# Zero or single sensor reporting


@dataclass(slots=True, frozen=True)
class StageEvidence:
    """Atomic evidence item grounding an observed, inferred, or forecast stage."""
    evidence_id: str
    source: EvidenceSource
    timestamp: float
    description: str
    stage: AttackStage = AttackStage.UNKNOWN
    technique_id: str | None = None
    feature: str | None = None
    feature_value: float | str | None = None
    confidence: float = 0.5
    polarity: EvidencePolarity = EvidencePolarity.SUPPORTING
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Enforce confidence bounds [0.0, 1.0]
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Evidence confidence must be in [0.0, 1.0], got {self.confidence}")

        # Validate technique syntax if provided
        if self.technique_id is not None and not validate_mitre_technique_id(self.technique_id):
            raise ValueError(
                f"Invalid or unverified MITRE ATT&CK technique ID '{self.technique_id}'. "
                "Must match verified canonical syntax (e.g. 'T1046', 'T1498')."
            )

        # Enforce valid timestamp
        if not math.isfinite(self.timestamp):
            raise ValueError(f"Invalid timestamp '{self.timestamp}'; must be a finite float epoch.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source.value,
            "timestamp": self.timestamp,
            "description": self.description,
            "stage": self.stage.value,
            "technique_id": self.technique_id,
            "feature": self.feature,
            "feature_value": self.feature_value,
            "confidence": round(self.confidence, 4),
            "polarity": self.polarity.value,
            "raw_metadata": self.raw_metadata,
        }


def evaluate_sensor_agreement(evidence_items: Sequence[StageEvidence]) -> tuple[SensorAgreement, float]:
    """Evaluate corroboration and calculate sensor agreement modifier.

    Returns:
        (SensorAgreement, confidence_multiplier)
    """
    if not evidence_items:
        return SensorAgreement.INSUFFICIENT, 0.5

    sources = {e.source for e in evidence_items}
    has_supporting = any(e.polarity == EvidencePolarity.SUPPORTING for e in evidence_items)
    has_contradictory = any(e.polarity == EvidencePolarity.CONTRADICTORY for e in evidence_items)

    if has_supporting and has_contradictory:
        # Conflicting signals reduce confidence significantly
        return SensorAgreement.CONFLICTING, 0.45
    elif len(sources) >= 2 and has_supporting and not has_contradictory:
        # Multiple independent corroborating sources boost confidence
        return SensorAgreement.FULL, 1.10
    elif has_supporting:
        # Single source supporting
        return SensorAgreement.PARTIAL, 0.90
    else:
        # Neutral or ambiguous only
        return SensorAgreement.INSUFFICIENT, 0.50

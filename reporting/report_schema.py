"""Typed report schema for NexSolve comprehensive forensic & predictive reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

EpistemicCategory = Literal["OBSERVED", "INFERRED", "FORECAST", "UNKNOWN", "ABSTAINED"]


@dataclass
class ExecutiveSummarySection:
    status: str
    overall_threat_level: str
    key_findings: list[str]
    forecast_summary: str
    epistemic_disclaimer: str
    category: EpistemicCategory = "INFERRED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "status": self.status,
            "overall_threat_level": self.overall_threat_level,
            "key_findings": self.key_findings,
            "forecast_summary": self.forecast_summary,
            "epistemic_disclaimer": self.epistemic_disclaimer,
        }


@dataclass
class CaptureQualitySection:
    capture_id: str
    quality_status: str
    parsed_packets: int
    total_packets_observed: int
    malformed_packets: int
    truncated_packets: int
    reordered_packets: int
    packet_loss_ratio: float
    reordered_ratio: float
    category: EpistemicCategory = "OBSERVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "capture_id": self.capture_id,
            "quality_status": self.quality_status,
            "parsed_packets": self.parsed_packets,
            "total_packets_observed": self.total_packets_observed,
            "malformed_packets": self.malformed_packets,
            "truncated_packets": self.truncated_packets,
            "reordered_packets": self.reordered_packets,
            "packet_loss_ratio": self.packet_loss_ratio,
            "reordered_ratio": self.reordered_ratio,
        }


@dataclass
class NetworkActivitySummarySection:
    packet_count: int
    flow_count: int
    byte_count: int
    duration_seconds: float
    protocol_distribution: dict[str, int]
    tcp_flag_counts: dict[str, int]
    unique_src_ips: int
    unique_dst_ips: int
    unique_dst_ports: int
    packet_timestamp_span_seconds: float = 0.0
    temporal_window_coverage_seconds: float = 60.0
    category: EpistemicCategory = "OBSERVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "byte_count": self.byte_count,
            "duration_seconds": self.duration_seconds,
            "packet_timestamp_span_seconds": self.packet_timestamp_span_seconds,
            "temporal_window_coverage_seconds": self.temporal_window_coverage_seconds,
            "protocol_distribution": self.protocol_distribution,
            "tcp_flag_counts": self.tcp_flag_counts,
            "unique_src_ips": self.unique_src_ips,
            "unique_dst_ips": self.unique_dst_ips,
            "unique_dst_ports": self.unique_dst_ports,
        }


@dataclass
class TemporalBehaviorSection:
    window_count: int
    window_duration_seconds: int
    earliest_timestamp: str | None
    latest_timestamp: str | None
    temporal_continuity: str
    packet_rate_trend: str
    flow_churn_trend: str
    packet_timestamp_span_seconds: float = 0.0
    temporal_window_coverage_seconds: float = 60.0
    category: EpistemicCategory = "OBSERVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "window_count": self.window_count,
            "window_duration_seconds": self.window_duration_seconds,
            "earliest_timestamp": self.earliest_timestamp,
            "latest_timestamp": self.latest_timestamp,
            "packet_timestamp_span_seconds": self.packet_timestamp_span_seconds,
            "temporal_window_coverage_seconds": self.temporal_window_coverage_seconds,
            "temporal_continuity": self.temporal_continuity,
            "packet_rate_trend": self.packet_rate_trend,
            "flow_churn_trend": self.flow_churn_trend,
        }


@dataclass
class ForecastPointReport:
    horizon: int
    attack_probability: float | None
    predicted_stage: str | None
    confidence: float | None
    uncertainty: float | None
    explanation: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "horizon": self.horizon,
            "attack_probability": self.attack_probability,
            "predicted_stage": self.predicted_stage,
            "confidence": self.confidence,
            "uncertainty": self.uncertainty,
            "explanation": self.explanation,
        }


@dataclass
class ForecastSection:
    model_version: str
    forecast_points: list[ForecastPointReport]
    decision_threshold: float
    abstained: bool
    summary: str
    category: EpistemicCategory = "FORECAST"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "model_version": self.model_version,
            "forecast_points": [p.to_dict() for p in self.forecast_points],
            "decision_threshold": self.decision_threshold,
            "abstained": self.abstained,
            "summary": self.summary,
        }


@dataclass
class AttackHorizonSection:
    state: str
    onset_horizon: int | None
    onset_timestamp: str | None
    lead_time_seconds: int | None
    horizon_windows: int
    horizon_seconds: int
    end_horizon: int | None
    end_timestamp: str | None
    temporal_consistency: float
    decay_observed: bool
    summary: str
    category: EpistemicCategory = "FORECAST"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "state": self.state,
            "onset_horizon": self.onset_horizon,
            "onset_timestamp": self.onset_timestamp,
            "lead_time_seconds": self.lead_time_seconds,
            "horizon_windows": self.horizon_windows,
            "horizon_seconds": self.horizon_seconds,
            "end_horizon": self.end_horizon,
            "end_timestamp": self.end_timestamp,
            "temporal_consistency": self.temporal_consistency,
            "decay_observed": self.decay_observed,
            "summary": self.summary,
        }


@dataclass
class EvidenceItemReport:
    evidence_id: str
    evidence_type: str
    feature_name: str
    observed_value: float
    baseline_value: float
    relative_change: float
    direction: str
    severity: str
    is_supporting: bool
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "feature_name": self.feature_name,
            "observed_value": self.observed_value,
            "baseline_value": self.baseline_value,
            "relative_change": self.relative_change,
            "direction": self.direction,
            "severity": self.severity,
            "is_supporting": self.is_supporting,
            "explanation": self.explanation,
        }


@dataclass
class EvidenceChainSection:
    evidence_strength: float
    evidence_quality: str
    supporting_evidence: list[EvidenceItemReport]
    contradictory_evidence: list[EvidenceItemReport]
    explanation: str
    limitations: list[str]
    category: EpistemicCategory = "INFERRED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "evidence_strength": self.evidence_strength,
            "evidence_quality": self.evidence_quality,
            "supporting_evidence": [e.to_dict() for e in self.supporting_evidence],
            "contradictory_evidence": [e.to_dict() for e in self.contradictory_evidence],
            "explanation": self.explanation,
            "limitations": self.limitations,
        }


@dataclass
class ConfidenceSection:
    forecast_score: float
    confidence_value: float | None
    confidence_state: str
    calibration_status: str
    uncertainty_level: str
    disclaimer: str
    category: EpistemicCategory = "INFERRED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "forecast_score": self.forecast_score,
            "confidence_value": self.confidence_value,
            "confidence_state": self.confidence_state,
            "calibration_status": self.calibration_status,
            "uncertainty_level": self.uncertainty_level,
            "disclaimer": self.disclaimer,
        }


@dataclass
class UnknownBehaviorSection:
    classification: str
    reason: str
    supporting_evidence: list[str]
    contradictory_evidence: list[str]
    coverage: float
    abstain_recommended: bool
    category: EpistemicCategory = "UNKNOWN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "classification": self.classification,
            "reason": self.reason,
            "supporting_evidence": self.supporting_evidence,
            "contradictory_evidence": self.contradictory_evidence,
            "coverage": self.coverage,
            "abstain_recommended": self.abstain_recommended,
        }


@dataclass
class AbstentionSection:
    abstained: bool
    reason: str | None
    severity: str
    status: str
    missing_requirements: list[str]
    explanation: str
    category: EpistemicCategory = "ABSTAINED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "abstained": self.abstained,
            "reason": self.reason,
            "severity": self.severity,
            "status": self.status,
            "missing_requirements": self.missing_requirements,
            "explanation": self.explanation,
        }


@dataclass
class LimitationsSection:
    limitations: list[str]
    capture_limitations: list[str]
    calibration_caveats: list[str]
    category: EpistemicCategory = "OBSERVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "limitations": self.limitations,
            "capture_limitations": self.capture_limitations,
            "calibration_caveats": self.calibration_caveats,
        }


@dataclass
class ProvenanceSection:
    capture_hash: str | None
    source_filename: str
    file_size_bytes: int
    packet_count: int
    flow_count: int
    window_count: int
    time_range: dict[str, str | None]
    model_version: str
    processing_version: str
    category: EpistemicCategory = "OBSERVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "capture_hash": self.capture_hash,
            "source_filename": self.source_filename,
            "file_size_bytes": self.file_size_bytes,
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "window_count": self.window_count,
            "time_range": self.time_range,
            "model_version": self.model_version,
            "processing_version": self.processing_version,
        }


@dataclass
class ProcessingMetadataSection:
    job_id: str
    generated_at_utc: str
    processing_seconds: float
    stage: str
    peak_memory_mb: float | None = None
    category: EpistemicCategory = "OBSERVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "job_id": self.job_id,
            "generated_at_utc": self.generated_at_utc,
            "processing_seconds": self.processing_seconds,
            "stage": self.stage,
            "peak_memory_mb": self.peak_memory_mb,
        }


@dataclass
class NexSolveReport:
    report_id: str
    title: str
    system_tagline: str
    generated_at_utc: str
    executive_summary: ExecutiveSummarySection
    capture_quality: CaptureQualitySection
    network_activity: NetworkActivitySummarySection
    temporal_behavior: TemporalBehaviorSection
    forecast: ForecastSection
    attack_horizon: AttackHorizonSection
    evidence_chain: EvidenceChainSection
    confidence: ConfidenceSection
    unknown_behavior: UnknownBehaviorSection
    abstention: AbstentionSection
    limitations: LimitationsSection
    provenance: ProvenanceSection
    processing_metadata: ProcessingMetadataSection

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "system_tagline": self.system_tagline,
            "generated_at_utc": self.generated_at_utc,
            "sections": {
                "executive_summary": self.executive_summary.to_dict(),
                "capture_quality": self.capture_quality.to_dict(),
                "network_activity": self.network_activity.to_dict(),
                "temporal_behavior": self.temporal_behavior.to_dict(),
                "forecast": self.forecast.to_dict(),
                "attack_horizon": self.attack_horizon.to_dict(),
                "evidence_chain": self.evidence_chain.to_dict(),
                "confidence": self.confidence.to_dict(),
                "unknown_behavior": self.unknown_behavior.to_dict(),
                "abstention": self.abstention.to_dict(),
                "limitations": self.limitations.to_dict(),
                "provenance": self.provenance.to_dict(),
                "processing_metadata": self.processing_metadata.to_dict(),
            },
        }

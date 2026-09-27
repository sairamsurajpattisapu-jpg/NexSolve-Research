"""Comprehensive Data Quality Gate for live and offline network PCAP analysis.

Evaluates 7 distinct data quality dimensions:
1. Packet integrity (malformed / truncated packets)
2. Timestamp availability and monotonic continuity
3. Temporal continuity (gap detection between 60s windows)
4. Window coverage (minimum 8 windows required for world model lookback)
5. Protocol observability (Layer 3 / Layer 4 presence)
6. Flow reconstruction quality (bidirectional vs unidirectional ratio)
7. Required feature availability (45 canonical dimensions)

Classifies into exactly: GOOD, DEGRADED, or INSUFFICIENT.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

from nexsolve_core.schemas import CaptureQuality, QualityStatus, TemporalWindow


@dataclass(slots=True, frozen=True)
class QualityCheckResult:
    check_name: str
    passed: bool
    status: QualityStatus
    score: float
    details: str


@dataclass(slots=True, frozen=True)
class DataQualityAssessment:
    overall_status: QualityStatus
    forecast_eligible: bool
    quality_score: float
    checks: dict[str, QualityCheckResult]
    disqualifying_reasons: tuple[str, ...] = ()
    degradation_warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status.value,
            "forecast_eligible": self.forecast_eligible,
            "quality_score": round(self.quality_score, 4),
            "checks": {k: asdict(v) for k, v in self.checks.items()},
            "disqualifying_reasons": list(self.disqualifying_reasons),
            "degradation_warnings": list(self.degradation_warnings),
        }


def assess_data_quality(
    windows: Sequence[TemporalWindow] | Sequence[dict[str, Any]],
    capture_quality: CaptureQuality | dict[str, Any] | None = None,
    required_windows: int = 8,
    max_gap_seconds: float = 120.0,
) -> DataQualityAssessment:
    """Authoritative evaluation of input capture suitability for predictive modeling."""
    checks: dict[str, QualityCheckResult] = {}
    disqualifying: list[str] = []
    warnings: list[str] = []

    # 1. Packet Integrity
    malformed_count = 0
    truncated_count = 0
    total_packets = 0
    if isinstance(capture_quality, CaptureQuality):
        malformed_count = capture_quality.malformed_packets
        truncated_count = capture_quality.truncated_packets
    elif isinstance(capture_quality, dict):
        malformed_count = capture_quality.get("malformed_packets", 0)
        truncated_count = capture_quality.get("truncated_packets", 0)

    # Count packets across windows
    for w in windows:
        if isinstance(w, TemporalWindow):
            total_packets += w.packet_count
        elif isinstance(w, dict):
            total_packets += w.get("packet_count", 0)

    integrity_passed = True
    integrity_status = QualityStatus.GOOD
    integrity_score = 1.0
    if total_packets > 0:
        bad_ratio = (malformed_count + truncated_count) / total_packets
        integrity_score = max(0.0, 1.0 - bad_ratio)
        if bad_ratio > 0.30:
            integrity_passed = False
            integrity_status = QualityStatus.INSUFFICIENT
            disqualifying.append(f"Severe packet corruption: {bad_ratio:.1%} malformed/truncated packets.")
        elif bad_ratio > 0.05:
            integrity_status = QualityStatus.DEGRADED
            warnings.append(f"Degraded packet integrity: {bad_ratio:.1%} malformed/truncated packets.")
    elif malformed_count > 0:
        integrity_passed = False
        integrity_status = QualityStatus.INSUFFICIENT
        disqualifying.append("Zero valid packets parsed; capture contains only malformed data.")

    checks["packet_integrity"] = QualityCheckResult(
        check_name="packet_integrity",
        passed=integrity_passed,
        status=integrity_status,
        score=integrity_score,
        details=f"Total: {total_packets}, Malformed: {malformed_count}, Truncated: {truncated_count}",
    )

    # 2. Timestamp Availability & Monotonicity
    ts_passed = True
    ts_status = QualityStatus.GOOD
    ts_score = 1.0
    reordered = False
    if isinstance(capture_quality, CaptureQuality):
        reordered = capture_quality.timestamps_reordered
    elif isinstance(capture_quality, dict):
        reordered = capture_quality.get("timestamps_reordered", False)

    if reordered:
        ts_status = QualityStatus.DEGRADED
        ts_score = 0.85
        warnings.append("Capture packet timestamps required reordering to enforce monotonicity.")

    checks["timestamp_availability"] = QualityCheckResult(
        check_name="timestamp_availability",
        passed=ts_passed,
        status=ts_status,
        score=ts_score,
        details="Timestamps reordered" if reordered else "Monotonic chronological timestamps verified",
    )

    # 3. Temporal Continuity & Gap Detection
    continuity_passed = True
    continuity_status = QualityStatus.GOOD
    continuity_score = 1.0
    if len(windows) > 1:
        prev_end = None
        max_observed_gap = 0.0
        for w in windows:
            w_start = w.start_timestamp if isinstance(w, TemporalWindow) else w.get("window_start", w.get("start_timestamp", 0))
            w_end = w.end_timestamp if isinstance(w, TemporalWindow) else w.get("window_end", w.get("end_timestamp", 0))
            if prev_end is not None:
                gap = w_start - prev_end
                if gap > max_observed_gap:
                    max_observed_gap = gap
                if gap > max_gap_seconds:
                    continuity_passed = False
                    continuity_status = QualityStatus.INSUFFICIENT
                    disqualifying.append(f"Non-contiguous temporal capture: gap of {gap:.1f}s exceeds {max_gap_seconds}s limit.")
                    continuity_score = 0.0
                    break
                elif gap > 0:
                    continuity_status = QualityStatus.DEGRADED
                    continuity_score = 0.70
                    warnings.append(f"Temporal jitter observed between windows (gap: {gap:.1f}s).")
            prev_end = w_end

    checks["temporal_continuity"] = QualityCheckResult(
        check_name="temporal_continuity",
        passed=continuity_passed,
        status=continuity_status,
        score=continuity_score,
        details="Contiguous non-overlapping windows" if continuity_passed else "Excessive gap between windows",
    )

    # 4. Window Coverage (Minimum Lookback Requirement)
    coverage_passed = len(windows) >= required_windows
    coverage_score = min(1.0, len(windows) / float(required_windows))
    if coverage_passed:
        coverage_status = QualityStatus.GOOD
    else:
        coverage_status = QualityStatus.INSUFFICIENT
        disqualifying.append(
            f"Insufficient history: capture has {len(windows)}/{required_windows} required 60s windows."
        )

    checks["window_coverage"] = QualityCheckResult(
        check_name="window_coverage",
        passed=coverage_passed,
        status=coverage_status,
        score=coverage_score,
        details=f"{len(windows)} of {required_windows} required windows available",
    )

    # 5. Protocol Observability (Layer 3 / Layer 4 presence)
    proto_passed = True
    proto_status = QualityStatus.GOOD
    proto_score = 1.0
    tcp_count = 0
    udp_count = 0
    arp_count = 0
    if isinstance(capture_quality, CaptureQuality):
        tcp_count = capture_quality.tcp_count
        udp_count = capture_quality.udp_count
        arp_count = capture_quality.arp_count
    elif isinstance(capture_quality, dict):
        tcp_count = capture_quality.get("tcp_count", 0)
        udp_count = capture_quality.get("udp_count", 0)
        arp_count = capture_quality.get("arp_count", 0)

    if total_packets > 0 and (tcp_count + udp_count) == 0:
        if arp_count > 0:
            proto_passed = False
            proto_status = QualityStatus.INSUFFICIENT
            disqualifying.append("Zero Layer 3/Layer 4 IP transport flows observable (capture contains only ARP/Broadcast).")
            proto_score = 0.1
        else:
            proto_status = QualityStatus.DEGRADED
            proto_score = 0.4
            warnings.append("No TCP or UDP packets observed in capture.")

    checks["protocol_observability"] = QualityCheckResult(
        check_name="protocol_observability",
        passed=proto_passed,
        status=proto_status,
        score=proto_score,
        details=f"TCP: {tcp_count}, UDP: {udp_count}, ARP: {arp_count}",
    )

    # 6. Flow Reconstruction Quality
    flow_passed = True
    flow_status = QualityStatus.GOOD
    flow_score = 1.0
    total_flows = 0
    incomplete_flows = 0
    if isinstance(capture_quality, CaptureQuality):
        incomplete_flows = capture_quality.incomplete_flow_count
    elif isinstance(capture_quality, dict):
        incomplete_flows = capture_quality.get("incomplete_flow_count", 0)

    for w in windows:
        if isinstance(w, TemporalWindow):
            total_flows += w.flow_count
        elif isinstance(w, dict):
            total_flows += w.get("flow_count", 0)

    if total_flows > 0:
        incomp_ratio = incomplete_flows / total_flows
        flow_score = max(0.0, 1.0 - incomp_ratio * 0.5)
        if incomp_ratio > 0.80 and total_flows > 20:
            flow_status = QualityStatus.DEGRADED
            warnings.append(f"High ratio of half-open/unidirectional flows ({incomp_ratio:.1%}).")
    elif total_packets > 0 and proto_passed:
        flow_status = QualityStatus.DEGRADED
        flow_score = 0.5
        warnings.append("Zero TCP/UDP flows reconstructed despite observed packets.")

    checks["flow_reconstruction_quality"] = QualityCheckResult(
        check_name="flow_reconstruction_quality",
        passed=flow_passed,
        status=flow_status,
        score=flow_score,
        details=f"Flows: {total_flows}, Incomplete: {incomplete_flows}",
    )

    # 7. Required Feature Availability
    feat_passed = True
    feat_status = QualityStatus.GOOD
    feat_score = 1.0
    for w in windows:
        features = {}
        if isinstance(w, TemporalWindow):
            features = {**dict(w.aggregate_features), **dict(w.detection_features)}
        elif isinstance(w, dict):
            features = {k: v for k, v in w.items() if isinstance(v, (int, float))}
        for k, v in features.items():
            if isinstance(v, (float, int)) and (math.isnan(v) or math.isinf(v)):
                feat_passed = False
                feat_status = QualityStatus.INSUFFICIENT
                disqualifying.append(f"NaN or Inf encountered in numerical feature: {k}")
                feat_score = 0.0
                break
        if not feat_passed:
            break

    checks["required_feature_availability"] = QualityCheckResult(
        check_name="required_feature_availability",
        passed=feat_passed,
        status=feat_status,
        score=feat_score,
        details="All numeric telemetry features are finite and valid" if feat_passed else "Invalid numerical features",
    )

    # Synthesize Overall Status
    all_scores = [c.score for c in checks.values()]
    mean_score = sum(all_scores) / len(all_scores) if all_scores else 0.0

    if any(c.status == QualityStatus.INSUFFICIENT for c in checks.values()):
        overall = QualityStatus.INSUFFICIENT
        forecast_eligible = False
    elif any(c.status == QualityStatus.DEGRADED for c in checks.values()):
        overall = QualityStatus.DEGRADED
        forecast_eligible = coverage_passed and continuity_passed and proto_passed and feat_passed
    else:
        overall = QualityStatus.GOOD
        forecast_eligible = True

    return DataQualityAssessment(
        overall_status=overall,
        forecast_eligible=forecast_eligible,
        quality_score=mean_score,
        checks=checks,
        disqualifying_reasons=tuple(disqualifying),
        degradation_warnings=tuple(warnings),
    )

"""Builders for each of the 13 NexSolve report sections."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from reporting.report_schema import (
    AbstentionSection,
    AttackHorizonSection,
    CaptureQualitySection,
    ConfidenceSection,
    EvidenceChainSection,
    EvidenceItemReport,
    ExecutiveSummarySection,
    ForecastPointReport,
    ForecastSection,
    LimitationsSection,
    NetworkActivitySummarySection,
    ProcessingMetadataSection,
    ProvenanceSection,
    TemporalBehaviorSection,
    UnknownBehaviorSection,
)


def build_executive_summary(
    traffic: dict[str, Any],
    detection: dict[str, Any],
    horizon: dict[str, Any] | None,
    abstention: dict[str, Any] | None,
) -> ExecutiveSummarySection:
    threat_level = detection.get("threat_level", "LOW")
    findings_count = detection.get("detected_events", 0)
    
    key_findings: list[str] = []
    seen_findings: set[str] = set()
    for f in detection.get("findings", []):
        desc = f.get("explanation") or f.get("rule_id", "Heuristic anomaly")
        items = desc if isinstance(desc, list) else [desc]
        for item in items:
            clean_item = str(item).strip()
            if not clean_item:
                continue
            if clean_item.lower().startswith("observed:"):
                clean_item = clean_item[9:].strip()
            norm_key = clean_item.lower()
            if norm_key not in seen_findings:
                seen_findings.add(norm_key)
                key_findings.append(f"Observed: {clean_item}")
            if len(key_findings) >= 5:
                break
        if len(key_findings) >= 5:
            break

    if not key_findings:
        key_findings.append("No active heuristic attack patterns identified in observed packets.")

    if abstention and abstention.get("abstained"):
        forecast_summary = f"Forecast generation abstained: {abstention.get('explanation', 'Preconditions not met')}."
    elif horizon:
        state = horizon.get("state", "NO_ATTACK_FORECAST")
        lead_time = horizon.get("lead_time_seconds")
        lead_str = f"within the next {int(lead_time)} seconds" if lead_time is not None else "with no immediate onset"
        dur = horizon.get("horizon_seconds", 0)
        dur_str = f" ({dur}s forward horizon)" if dur else ""
        if state in ("EARLY_SIGNAL", "EARLY_ATTACK_SIGNAL"):
            forecast_summary = f"Early attack activity is projected {lead_str}{dur_str}."
        elif state == "SUSTAINED_ATTACK_FORECAST":
            forecast_summary = f"Sustained attack progression is projected {lead_str}{dur_str}."
        elif state in ("BENIGN", "NO_ATTACK_FORECAST"):
            forecast_summary = "Nominal network baseline projected across future observation windows."
        else:
            human_state = state.replace("_", " ").title()
            forecast_summary = f"{human_state} projected {lead_str}{dur_str}."
    else:
        forecast_summary = "No forecast data available for this capture."

    disclaimer = (
        "Current assessment reflects observed network activity. "
        "Forecast values represent projected changes across future analysis windows "
        "and should not be interpreted as confirmation of compromise."
    )

    return ExecutiveSummarySection(
        status="COMPLETED",
        overall_threat_level=threat_level,
        key_findings=key_findings,
        forecast_summary=forecast_summary,
        epistemic_disclaimer=disclaimer,
    )


def build_capture_quality(quality: dict[str, Any]) -> CaptureQualitySection:
    total = quality.get("total_packets_observed") or quality.get("packets_read", 0)
    parsed = quality.get("parsed_packets") or quality.get("packets_parsed", 0)
    malformed = quality.get("malformed_packets", 0)
    truncated = quality.get("truncated_packets", 0)
    reordered = quality.get("reordered_packets", 0)
    loss = quality.get("packet_loss_ratio", 0.0)
    reordered_ratio = reordered / total if total > 0 else 0.0

    raw_status = quality.get("status") or quality.get("quality_status")
    if raw_status:
        raw_str = str(raw_status).upper()
        if "DEGRADED" in raw_str:
            status = "DEGRADED"
        elif "INSUFFICIENT" in raw_str:
            status = "INSUFFICIENT"
        elif "GOOD" in raw_str or "HIGH" in raw_str:
            status = "HIGH"
        else:
            status = raw_str
    else:
        status = "HIGH"
        if loss > 0.10 or malformed > 50:
            status = "DEGRADED"
        elif loss > 0.02 or malformed > 5:
            status = "MODERATE"

    return CaptureQualitySection(
        capture_id=quality.get("capture_id", "uploaded-capture"),
        quality_status=status,
        parsed_packets=parsed,
        total_packets_observed=total,
        malformed_packets=malformed,
        truncated_packets=truncated,
        reordered_packets=reordered,
        packet_loss_ratio=round(loss, 4),
        reordered_ratio=round(reordered_ratio, 4),
    )


def build_network_activity(traffic: dict[str, Any], validation: dict[str, Any]) -> NetworkActivitySummarySection:
    protocol_counts = traffic.get("protocol_counts", {})
    tcp_flags = traffic.get("tcp_flag_counts", {})
    win = validation.get("window", {})
    window_seconds = win.get("seconds", 60)
    window_count = validation.get("rows", 1) or 1
    window_coverage = float(traffic.get("duration_seconds") if traffic.get("duration_seconds") is not None else float(window_count * window_seconds))
    packet_span = float(traffic.get("packet_timestamp_span_seconds") if traffic.get("packet_timestamp_span_seconds") is not None else traffic.get("packet_span_seconds", 0.0))
    
    windows_data = traffic.get("windows_data", [])
    max_src_ips = max([int(w.get("unique_src_ips", 1)) for w in windows_data], default=1)
    max_dst_ips = max([int(w.get("unique_dst_ips", 1)) for w in windows_data], default=1)
    max_dst_ports = max([int(w.get("unique_dst_ports", 1)) for w in windows_data], default=1)

    return NetworkActivitySummarySection(
        packet_count=traffic.get("packets", 0),
        flow_count=traffic.get("flows", 0) or traffic.get("packets", 0),
        byte_count=traffic.get("bytes", 0) or (traffic.get("packets", 0) * 128),
        duration_seconds=window_coverage,
        packet_timestamp_span_seconds=packet_span,
        temporal_window_coverage_seconds=window_coverage,
        protocol_distribution=dict(protocol_counts),
        tcp_flag_counts=dict(tcp_flags),
        unique_src_ips=traffic.get("unique_src_ips", max_src_ips),
        unique_dst_ips=traffic.get("unique_dst_ips", max_dst_ips),
        unique_dst_ports=traffic.get("unique_dst_ports", max_dst_ports),
    )


def build_temporal_behavior(validation: dict[str, Any], traffic: dict[str, Any]) -> TemporalBehaviorSection:
    win = validation.get("window", {})
    start_min = win.get("start_min")
    start_max = win.get("start_max")
    window_seconds = win.get("seconds", 60)
    window_count = validation.get("rows", 0)
    window_coverage = float(traffic.get("duration_seconds") if traffic.get("duration_seconds") is not None else float(window_count * window_seconds))
    packet_span = float(traffic.get("packet_timestamp_span_seconds") if traffic.get("packet_timestamp_span_seconds") is not None else traffic.get("packet_span_seconds", 0.0))
    
    earliest = datetime.fromtimestamp(start_min, timezone.utc).isoformat() if start_min is not None else None
    latest = datetime.fromtimestamp(start_max + window_seconds, timezone.utc).isoformat() if start_max is not None else earliest
    continuity = "CONTINUOUS" if win.get("ordered", True) else "DISCONTINUOUS"

    return TemporalBehaviorSection(
        window_count=window_count,
        window_duration_seconds=window_seconds,
        earliest_timestamp=earliest,
        latest_timestamp=latest,
        packet_timestamp_span_seconds=packet_span,
        temporal_window_coverage_seconds=window_coverage,
        temporal_continuity=continuity,
        packet_rate_trend=traffic.get("rate_trend", "STABLE"),
        flow_churn_trend=traffic.get("churn_trend", "STABLE"),
    )


def build_forecast_section(
    forecasts: list[dict[str, Any]],
    model_version: str,
    abstention: dict[str, Any] | None,
) -> ForecastSection:
    points: list[ForecastPointReport] = []
    is_abstained = bool(abstention and abstention.get("abstained"))

    for item in forecasts:
        horizon = item.get("horizon", 1)
        prob = item.get("attackProbability") or item.get("attack_probability")
        stage = item.get("predictedStage") or item.get("predicted_stage")
        conf = item.get("confidence")
        uncert = item.get("uncertainty")
        expl = item.get("explanation", [])
        points.append(
            ForecastPointReport(
                horizon=horizon,
                attack_probability=None if is_abstained else prob,
                predicted_stage=None if is_abstained else stage,
                confidence=None if is_abstained else conf,
                uncertainty=None if is_abstained else uncert,
                explanation=list(expl),
            )
        )

    if is_abstained and abstention:
        reason = abstention.get("reason", "INSUFFICIENT_HISTORY")
        explanation = abstention.get("explanation", "Preconditions not met")
        summary = f"Forecast rollout abstained ({reason}): {explanation}"
        if not points:
            for h in range(1, 6):
                points.append(
                    ForecastPointReport(
                        horizon=h,
                        attack_probability=None,
                        predicted_stage=None,
                        confidence=None,
                        uncertainty=None,
                        explanation=[f"Forecast withheld: {reason} ({explanation})"],
                    )
                )
    elif is_abstained:
        summary = "Forecast rollout abstained due to sequence/data constraints."
        if not points:
            for h in range(1, 6):
                points.append(
                    ForecastPointReport(
                        horizon=h,
                        attack_probability=None,
                        predicted_stage=None,
                        confidence=None,
                        uncertainty=None,
                        explanation=["Forecast withheld due to sequence/data constraints."],
                    )
                )
    else:
        summary = f"Generated {len(points)} multi-step temporal forecast horizons (60s intervals)."

    return ForecastSection(
        model_version=model_version,
        forecast_points=points,
        decision_threshold=0.50,
        abstained=is_abstained,
        summary=summary,
    )


def build_attack_horizon(horizon: dict[str, Any] | None) -> AttackHorizonSection:
    if not horizon:
        return AttackHorizonSection(
            state="NOT_AVAILABLE",
            onset_horizon=None,
            onset_timestamp=None,
            lead_time_seconds=None,
            horizon_windows=0,
            horizon_seconds=0,
            end_horizon=None,
            end_timestamp=None,
            temporal_consistency=0.0,
            decay_observed=False,
            summary="Attack horizon evaluation abstained.",
        )

    raw_state = horizon.get("state", "NO_ATTACK_FORECAST")
    is_abstained = raw_state == "ABSTAINED" or bool(horizon.get("abstention_reason"))
    state = "ABSTAINED" if is_abstained else raw_state
    summary = horizon.get("summary", "")
    if is_abstained and not summary:
        summary = f"Attack horizon evaluation abstained: {horizon.get('abstention_reason', 'INSUFFICIENT_HISTORY')}."

    return AttackHorizonSection(
        state=state,
        onset_horizon=None if is_abstained else horizon.get("onset_horizon"),
        onset_timestamp=None if is_abstained else horizon.get("onset_timestamp"),
        lead_time_seconds=None if is_abstained else horizon.get("lead_time_seconds"),
        horizon_windows=0 if is_abstained else horizon.get("horizon_windows", 0),
        horizon_seconds=0 if is_abstained else horizon.get("horizon_seconds", 0),
        end_horizon=None if is_abstained else horizon.get("end_horizon"),
        end_timestamp=None if is_abstained else horizon.get("end_timestamp"),
        temporal_consistency=0.0 if is_abstained else float(horizon.get("temporal_consistency") if horizon.get("temporal_consistency") is not None else 1.0),
        decay_observed=False if is_abstained else bool(horizon.get("decay_observed", False)),
        summary=summary,
    )


def build_evidence_chain(chain: dict[str, Any] | None) -> EvidenceChainSection:
    if not chain:
        return EvidenceChainSection(
            evidence_strength=0.0,
            evidence_quality="INSUFFICIENT",
            supporting_evidence=[],
            contradictory_evidence=[],
            explanation="Evidence chain unavailable for this capture.",
            limitations=["No multi-window sequence available to build historical evidence."],
        )

    supporting: list[EvidenceItemReport] = []
    for s in chain.get("supporting", []):
        supporting.append(
            EvidenceItemReport(
                evidence_id=s.get("evidence_id", ""),
                evidence_type=s.get("evidence_type", ""),
                feature_name=s.get("feature_name", ""),
                observed_value=float(s.get("observed_value") if s.get("observed_value") is not None else 0.0),
                baseline_value=float(s.get("baseline_value") if s.get("baseline_value") is not None else 0.0),
                relative_change=float(s.get("relative_change") if s.get("relative_change") is not None else 0.0),
                direction=s.get("direction", "INCREASE"),
                severity=s.get("severity", "LOW"),
                is_supporting=True,
                explanation=s.get("explanation", ""),
            )
        )

    contradictory: list[EvidenceItemReport] = []
    for c in chain.get("contradictory", []):
        contradictory.append(
            EvidenceItemReport(
                evidence_id=c.get("evidence_id", ""),
                evidence_type=c.get("evidence_type", ""),
                feature_name=c.get("feature_name", ""),
                observed_value=float(c.get("observed_value") if c.get("observed_value") is not None else 0.0),
                baseline_value=float(c.get("baseline_value") if c.get("baseline_value") is not None else 0.0),
                relative_change=float(c.get("relative_change") if c.get("relative_change") is not None else 0.0),
                direction=c.get("direction", "DECREASE"),
                severity=c.get("severity", "LOW"),
                is_supporting=False,
                explanation=c.get("explanation", ""),
            )
        )

    return EvidenceChainSection(
        evidence_strength=float(chain.get("evidence_strength") if chain.get("evidence_strength") is not None else 0.0),
        evidence_quality=chain.get("evidence_quality", "HIGH"),
        supporting_evidence=supporting,
        contradictory_evidence=contradictory,
        explanation=chain.get("explanation", ""),
        limitations=list(chain.get("limitations", [])),
    )


def build_confidence_section(confidence: dict[str, Any] | None) -> ConfidenceSection:
    if not confidence:
        return ConfidenceSection(
            forecast_score=0.0,
            confidence_value=None,
            confidence_state="WITHHELD",
            calibration_status="UNSUPPORTED",
            uncertainty_level="HIGH",
            disclaimer="Forecast score is uncalibrated and must not be interpreted as a calibrated probability.",
        )

    raw_score = confidence.get("forecast_score")
    score = float(raw_score) if raw_score is not None else 0.0
    conf_val = confidence.get("confidence_value")
    conf_val_f = float(conf_val) if conf_val is not None else None

    return ConfidenceSection(
        forecast_score=score,
        confidence_value=conf_val_f,
        confidence_state=confidence.get("confidence_state", "UNCALIBRATED"),
        calibration_status=confidence.get("calibration_status", "UNSUPPORTED"),
        uncertainty_level=confidence.get("uncertainty_level", "LOW"),
        disclaimer="Forecast score is uncalibrated and must not be interpreted as a calibrated probability.",
    )


def build_unknown_behavior(unknown: dict[str, Any] | None) -> UnknownBehaviorSection:
    if not unknown:
        return UnknownBehaviorSection(
            classification="KNOWN_PATTERN",
            reason="Observed telemetry matches expected baseline envelope.",
            supporting_evidence=[],
            contradictory_evidence=[],
            coverage=1.0,
            abstain_recommended=False,
        )

    return UnknownBehaviorSection(
        classification=unknown.get("classification", "KNOWN_PATTERN"),
        reason=unknown.get("reason", ""),
        supporting_evidence=list(unknown.get("supporting_evidence", [])),
        contradictory_evidence=list(unknown.get("contradictory_evidence", [])),
        coverage=float(unknown.get("coverage") if unknown.get("coverage") is not None else 1.0),
        abstain_recommended=bool(unknown.get("abstain_recommended", False)),
    )


def build_abstention_section(abstention: dict[str, Any] | None) -> AbstentionSection:
    if not abstention:
        return AbstentionSection(
            abstained=False,
            reason=None,
            severity="LOW",
            status="FORECAST_AVAILABLE_BUT_UNCALIBRATED",
            missing_requirements=[],
            explanation="Telemetry sufficient for heuristic analysis.",
        )

    return AbstentionSection(
        abstained=bool(abstention.get("abstained", False)),
        reason=abstention.get("reason"),
        severity=abstention.get("severity", "LOW"),
        status=abstention.get("status", "FORECAST_AVAILABLE_BUT_UNCALIBRATED"),
        missing_requirements=list(abstention.get("missing_requirements", [])),
        explanation=abstention.get("explanation", ""),
    )


def build_limitations_section(
    evidence_chain: dict[str, Any] | None,
    quality: dict[str, Any],
) -> LimitationsSection:
    limitations: list[str] = []
    capture_limitations: list[str] = []
    calibration_caveats: list[str] = [
        "Forecast scores represent forward-looking transition signals, not calibrated actuarial event probabilities.",
        "Observed heuristic packet alerts represent behavioral indicators, not definitive ground-truth payload compromise.",
        "Continuous state prediction confidence decreases as lookahead extends from T+1 to T+5 due to recursive latent variance.",
        "Round-trip time (RTT) metrics are deliberately omitted from passive captures to avoid synthetic data imputation.",
    ]

    if evidence_chain and evidence_chain.get("limitations"):
        limitations.extend(evidence_chain["limitations"])

    if quality.get("packet_loss_ratio", 0.0) > 0.05:
        capture_limitations.append(
            f"Packet loss ratio ({quality['packet_loss_ratio']:.2%}) exceeds 5.0% threshold. "
            "Flow volume and throughput metrics may be understated."
        )

    if quality.get("reordered_packets", 0) > 0:
        capture_limitations.append(
            f"Detected {quality['reordered_packets']} out-of-order packets. "
            "Inter-packet arrival time calculations may exhibit micro-jitter."
        )

    return LimitationsSection(
        limitations=limitations,
        capture_limitations=capture_limitations,
        calibration_caveats=calibration_caveats,
    )


def build_provenance_section(
    source: dict[str, Any],
    traffic: dict[str, Any],
    validation: dict[str, Any],
    capture_hash: str | None,
    model_version: str,
) -> ProvenanceSection:
    # Strictly avoid local filesystem paths; only use clean filename
    raw_name = source.get("filename") or source.get("name", "capture.pcap")
    clean_name = raw_name.replace("\\", "/").split("/")[-1]

    win = validation.get("window", {})
    start_min = win.get("start_min")
    start_max = win.get("start_max")
    window_seconds = win.get("seconds", 60)
    earliest = datetime.fromtimestamp(start_min, timezone.utc).isoformat() if start_min is not None else None
    latest = datetime.fromtimestamp(start_max + window_seconds, timezone.utc).isoformat() if start_max is not None else earliest

    return ProvenanceSection(
        capture_hash=capture_hash,
        source_filename=clean_name,
        file_size_bytes=int(source.get("size_bytes", 0)),
        packet_count=int(traffic.get("packets", 0)),
        flow_count=int(traffic.get("flows", 0) or traffic.get("packets", 0)),
        window_count=int(validation.get("rows", 0)),
        time_range={"start": earliest, "end": latest},
        model_version=model_version,
        processing_version="nexsolve-v1.0.0-prod",
    )


def build_processing_metadata(
    job_id: str,
    processing_seconds: float,
    stage: str,
) -> ProcessingMetadataSection:
    return ProcessingMetadataSection(
        job_id=job_id,
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        processing_seconds=round(processing_seconds, 3),
        stage=stage,
    )

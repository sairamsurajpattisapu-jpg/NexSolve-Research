"""Deterministic, server-side Evidence Intelligence for NexSolve.

Converts actual observed NetworkState, historical lookback, and forecast
rollouts into a traceable, explainable evidence chain without fabricating
features or conflating evidence strength with attack probabilities.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from ml.forecasting.attack_horizon import AttackHorizonResult, AttackHorizonState, parse_timestamp


class EvidenceType(str, Enum):
    """Controlled vocabulary for deterministic evidence items."""
    TRAFFIC_VOLUME = "TRAFFIC_VOLUME"
    FLOW_ACTIVITY = "FLOW_ACTIVITY"
    PACKET_ACTIVITY = "PACKET_ACTIVITY"
    PROTOCOL_SHIFT = "PROTOCOL_SHIFT"
    PORT_DIVERSITY = "PORT_DIVERSITY"
    BYTE_RATE_CHANGE = "BYTE_RATE_CHANGE"
    PACKET_RATE_CHANGE = "PACKET_RATE_CHANGE"
    TEMPORAL_CHANGE = "TEMPORAL_CHANGE"
    FORECAST_SUPPORT = "FORECAST_SUPPORT"
    CAPTURE_QUALITY = "CAPTURE_QUALITY"
    CONTRADICTION = "CONTRADICTION"


class EvidenceDirection(str, Enum):
    INCREASE = "INCREASE"
    DECREASE = "DECREASE"
    ANOMALOUS = "ANOMALOUS"
    NEUTRAL = "NEUTRAL"


class EvidenceSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EvidenceQuality(str, Enum):
    HIGH = "HIGH"
    DEGRADED = "DEGRADED"
    INSUFFICIENT = "INSUFFICIENT"


# Configurable engineering change thresholds (NOT attack probabilities)
LOW_CHANGE = 0.10
MEDIUM_CHANGE = 0.25
HIGH_CHANGE = 0.50


@dataclass(frozen=True)
class EvidenceItem:
    """Individual deterministic evidence record derived from real observation."""
    evidence_id: str
    timestamp: str
    window_id: str | int | None
    evidence_type: EvidenceType
    feature_name: str
    observed_value: float
    baseline_value: float | None
    delta: float | None
    relative_change: float | None
    direction: EvidenceDirection
    severity: EvidenceSeverity
    reliability: float
    source: str
    provenance: dict[str, Any]
    explanation: str
    is_supporting: bool

    def to_dict(self) -> dict[str, Any]:
        res = asdict(self)
        res["evidence_type"] = self.evidence_type.value
        res["direction"] = self.direction.value
        res["severity"] = self.severity.value
        return res


@dataclass(frozen=True)
class EvidenceChain:
    """Synthesized evidence chain linking observation, change, and forecast."""
    current_window_id: str | int | None
    current_timestamp: str
    forecast_horizon: int
    supporting: list[dict[str, Any]]
    contradictory: list[dict[str, Any]]
    evidence_strength: float  # Explainability/consistency score [0.0, 1.0], NOT probability
    evidence_quality: EvidenceQuality
    supporting_feature_count: int
    contradictory_feature_count: int
    provenance_complete: bool
    explanation: str
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        res = asdict(self)
        res["evidence_quality"] = self.evidence_quality.value
        return res


def _extract_state_feature(state: Any, feature_name: str) -> float | None:
    """Safely extract a feature from a NetworkState or dict without fabrication."""
    if state is None:
        return None

    # Handle NetworkState object
    if hasattr(state, "flow_features") and feature_name in state.flow_features:
        val = state.flow_features[feature_name]
        return float(val) if math.isfinite(val) else None
    if hasattr(state, "packet_features") and feature_name in state.packet_features:
        val = state.packet_features[feature_name]
        return float(val) if math.isfinite(val) else None
    if hasattr(state, "temporal_features") and feature_name in state.temporal_features:
        val = state.temporal_features[feature_name]
        return float(val) if math.isfinite(val) else None

    # Handle dictionary representation
    if isinstance(state, Mapping):
        for grp in ("flow_features", "packet_features", "temporal_features", "flowFeatures", "packetFeatures", "temporalFeatures"):
            sub = state.get(grp)
            if isinstance(sub, Mapping) and feature_name in sub:
                val = sub[feature_name]
                return float(val) if math.isfinite(val) else None
        if feature_name in state:
            val = state[feature_name]
            try:
                f_val = float(val)
                return f_val if math.isfinite(f_val) else None
            except (TypeError, ValueError):
                return None

    return None


def _check_feature_group_availability(state: Any, group_name: str) -> bool:
    """Check whether a feature group is genuinely available on state."""
    if hasattr(state, "packet_features_available") and group_name in ("packet", "packet_features", "packetFeatures"):
        return bool(state.packet_features_available)
    if hasattr(state, group_name):
        val = getattr(state, group_name)
        return bool(val and len(val) > 0)
    if isinstance(state, Mapping):
        if group_name in ("packet", "packet_features", "packetFeatures"):
            if state.get("packetFeaturesAvailable") is False or state.get("packet_features_available") is False:
                return False
        sub = state.get(group_name)
        return bool(sub and len(sub) > 0)
    return False


def build_evidence_chain(
    sequence: Sequence[Any],
    forecast_horizon_result: AttackHorizonResult | None = None,
    capture_quality: Any = None,
    provenance_info: Mapping[str, Any] | None = None,
) -> EvidenceChain:
    """Construct an explainable EvidenceChain from temporal network states and forecast rollout.

    Parameters
    ----------
    sequence : Sequence[Any]
        Ordered sequence of NetworkState objects or state dicts up to current time T_0.
    forecast_horizon_result : AttackHorizonResult | None, optional
        Precomputed Attack Horizon result.
    capture_quality : Any, optional
        CaptureQuality record from ingestion foundation.
    provenance_info : Mapping[str, Any] | None, optional
        Metadata on capture source, file, and window IDs.
    """
    if not sequence:
        return _build_empty_evidence_chain()

    current_state = sequence[-1]
    history_states = sequence[:-1] if len(sequence) > 1 else []

    # Extract timestamps and window identification
    curr_ts = getattr(current_state, "timestamp", None)
    if curr_ts is None and isinstance(current_state, Mapping):
        curr_ts = current_state.get("timestamp")
    if curr_ts is None:
        curr_ts = 0

    _, iso_ts = parse_timestamp(curr_ts)
    window_id = getattr(current_state, "window_id", None)
    if window_id is None and isinstance(current_state, Mapping):
        window_id = current_state.get("window_id")

    # Evaluate Capture Quality signals
    quality_status = EvidenceQuality.HIGH
    quality_limitations: list[str] = []
    reliability = 1.0

    if capture_quality is not None:
        c_status = getattr(capture_quality, "status", None)
        if isinstance(c_status, Enum):
            c_status = c_status.value
        elif isinstance(capture_quality, Mapping):
            c_status = capture_quality.get("status")

        if c_status == "DEGRADED":
            quality_status = EvidenceQuality.DEGRADED
            reliability = 0.75
            quality_limitations.append("Underlying network capture is flagged DEGRADED.")
        elif c_status == "INSUFFICIENT":
            quality_status = EvidenceQuality.INSUFFICIENT
            reliability = 0.30
            quality_limitations.append("Underlying network capture quality is INSUFFICIENT.")

        # Check timestamp anomalies
        anomalies = getattr(capture_quality, "timestamp_anomalies", 0)
        if isinstance(capture_quality, Mapping):
            anomalies = capture_quality.get("timestamp_anomalies", 0)
        if anomalies and anomalies > 0:
            quality_limitations.append(f"Capture contains {anomalies} timestamp anomalies.")
            reliability = min(reliability, 0.70)

        # Check truncation
        truncated = getattr(capture_quality, "truncated_packets", 0)
        if isinstance(capture_quality, Mapping):
            truncated = capture_quality.get("truncated_packets", 0)
        if truncated and truncated > 0:
            quality_limitations.append(f"Capture contains {truncated} truncated packets.")
            reliability = min(reliability, 0.80)

    # Determine provenance completeness
    prov_dict = dict(provenance_info) if provenance_info else {}
    provenance_complete = bool(
        prov_dict.get("capture_id") or getattr(current_state, "provenance", None)
    )

    # Target features to evaluate if genuinely present
    feature_candidates: list[tuple[str, EvidenceType, str, str]] = [
        ("flow_count", EvidenceType.FLOW_ACTIVITY, "flow", "Active concurrent flow volume"),
        ("total_packets", EvidenceType.PACKET_RATE_CHANGE, "flow", "Total aggregate packet volume"),
        ("total_src_bytes", EvidenceType.BYTE_RATE_CHANGE, "flow", "Source data transmission volume"),
        ("total_dst_bytes", EvidenceType.BYTE_RATE_CHANGE, "flow", "Destination data reception volume"),
        ("unique_dst_ports", EvidenceType.PORT_DIVERSITY, "flow", "Destination port diversity"),
        ("unique_src_ports", EvidenceType.PORT_DIVERSITY, "flow", "Source port diversity"),
        ("proto_tcp_count", EvidenceType.PROTOCOL_SHIFT, "flow", "TCP protocol distribution count"),
        ("proto_udp_count", EvidenceType.PROTOCOL_SHIFT, "flow", "UDP protocol distribution count"),
        ("packet_count", EvidenceType.PACKET_ACTIVITY, "packet", "Direct window packet count"),
        ("mean_packet_size", EvidenceType.PACKET_ACTIVITY, "packet", "Mean packet size"),
        ("tcp_syn_count", EvidenceType.FLOW_ACTIVITY, "packet", "TCP SYN attempt count"),
        ("retransmission_count", EvidenceType.FLOW_ACTIVITY, "packet", "TCP retransmission count"),
        ("delta_flow_count", EvidenceType.TEMPORAL_CHANGE, "temporal", "Sequential flow count acceleration"),
        ("delta_total_bytes", EvidenceType.TEMPORAL_CHANGE, "temporal", "Sequential byte volume acceleration"),
    ]

    supporting_items: list[EvidenceItem] = []
    contradictory_items: list[EvidenceItem] = []
    item_counter = 1

    # Check forecast hypothesis
    attack_hypothesized = False
    if forecast_horizon_result is not None:
        if forecast_horizon_result.state in (
            AttackHorizonState.SUSTAINED_ATTACK_FORECAST,
            AttackHorizonState.EARLY_SIGNAL,
        ):
            attack_hypothesized = True

    # 1. Feature change evaluation against historical baseline
    for feat_name, ev_type, grp_name, feat_desc in feature_candidates:
        # Check genuine feature presence
        curr_val = _extract_state_feature(current_state, feat_name)
        if curr_val is None:
            # Feature is genuinely unavailable; NEVER fabricate!
            continue

        # If it's a packet feature but packet features are flagged unavailable, skip!
        if grp_name == "packet" and not _check_feature_group_availability(current_state, "packet"):
            continue

        # Compute baseline from history if available
        baseline_val: float | None = None
        if history_states:
            hist_vals = [
                v for s in history_states if (v := _extract_state_feature(s, feat_name)) is not None
            ]
            if hist_vals:
                baseline_val = sum(hist_vals) / len(hist_vals)

        # Delta and relative change
        delta = None
        rel_change = None
        direction = EvidenceDirection.NEUTRAL

        if baseline_val is not None:
            delta = curr_val - baseline_val
            denom = max(abs(baseline_val), 1.0)
            rel_change = delta / denom

            if rel_change > LOW_CHANGE:
                direction = EvidenceDirection.INCREASE
            elif rel_change < -LOW_CHANGE:
                direction = EvidenceDirection.DECREASE
        else:
            # First window or no history: check absolute magnitude if temporal delta
            if feat_name.startswith("delta_") and abs(curr_val) > 0.0:
                delta = curr_val
                direction = EvidenceDirection.INCREASE if curr_val > 0 else EvidenceDirection.DECREASE

        # Filter out negligible changes unless it's a critical port scan or volume spike
        if rel_change is None and delta is None:
            continue

        abs_rel = abs(rel_change) if rel_change is not None else 0.0
        if abs_rel < LOW_CHANGE and (delta is None or abs(delta) < 1.0):
            continue

        # Determine severity based on magnitude
        if abs_rel >= HIGH_CHANGE:
            severity = EvidenceSeverity.HIGH
        elif abs_rel >= MEDIUM_CHANGE:
            severity = EvidenceSeverity.MEDIUM
        else:
            severity = EvidenceSeverity.LOW

        # Classify as supporting vs contradictory
        # Under attack hypothesis: significant increase in volume, ports, or syn count is supporting;
        # sharp drop in volume or quiet port activity during attack forecast is contradictory.
        if attack_hypothesized:
            if direction == EvidenceDirection.INCREASE:
                is_supp = True
                exp = f"{feat_desc} ({feat_name}) increased {abs_rel * 100:.1f}% over baseline ({curr_val:.1f} vs {baseline_val:.1f})."
            else:
                is_supp = False
                exp = f"{feat_desc} ({feat_name}) decreased {abs_rel * 100:.1f}% during an attack forecast window."
        else:
            # Baseline traffic expected: anomalous surge contradicts normal baseline; quiet state supports it
            if direction == EvidenceDirection.INCREASE and abs_rel >= MEDIUM_CHANGE:
                is_supp = False
                exp = f"Unexplained surge in {feat_desc} ({feat_name}) +{abs_rel * 100:.1f}% contradicts baseline forecast."
            else:
                is_supp = True
                exp = f"{feat_desc} ({feat_name}) conforms to baseline behavior."

        item = EvidenceItem(
            evidence_id=f"EV-{item_counter:03d}",
            timestamp=iso_ts,
            window_id=window_id,
            evidence_type=ev_type,
            feature_name=feat_name,
            observed_value=round(curr_val, 4),
            baseline_value=round(baseline_val, 4) if baseline_val is not None else None,
            delta=round(delta, 4) if delta is not None else None,
            relative_change=round(rel_change, 4) if rel_change is not None else None,
            direction=direction,
            severity=severity,
            reliability=round(reliability, 2),
            source=f"state.{grp_name}_features",
            provenance={**prov_dict, "derivation": "historical_rolling_comparison"},
            explanation=exp,
            is_supporting=is_supp,
        )
        item_counter += 1

        if is_supp:
            supporting_items.append(item)
        else:
            contradictory_items.append(item)

    # 2. Integrate Forecast Rollout Evidence
    if forecast_horizon_result is not None:
        if forecast_horizon_result.state == AttackHorizonState.SUSTAINED_ATTACK_FORECAST:
            supporting_items.append(
                EvidenceItem(
                    evidence_id=f"EV-{item_counter:03d}",
                    timestamp=iso_ts,
                    window_id=window_id,
                    evidence_type=EvidenceType.FORECAST_SUPPORT,
                    feature_name="attack_horizon",
                    observed_value=float(forecast_horizon_result.horizon_windows),
                    baseline_value=0.0,
                    delta=float(forecast_horizon_result.horizon_windows),
                    relative_change=1.0,
                    direction=EvidenceDirection.INCREASE,
                    severity=EvidenceSeverity.HIGH,
                    reliability=round(reliability, 2),
                    source="ml.forecasting.attack_horizon",
                    provenance={**prov_dict, "derivation": "multi_step_lstm_rollout"},
                    explanation=(
                        f"Forecast rollout indicates sustained attack across {forecast_horizon_result.horizon_windows} "
                        f"windows ({forecast_horizon_result.horizon_seconds}s) with consistency {forecast_horizon_result.temporal_consistency:.2f}."
                    ),
                    is_supporting=True,
                )
            )
            item_counter += 1
        elif forecast_horizon_result.state == AttackHorizonState.EARLY_SIGNAL:
            supporting_items.append(
                EvidenceItem(
                    evidence_id=f"EV-{item_counter:03d}",
                    timestamp=iso_ts,
                    window_id=window_id,
                    evidence_type=EvidenceType.FORECAST_SUPPORT,
                    feature_name="attack_horizon",
                    observed_value=1.0,
                    baseline_value=0.0,
                    delta=1.0,
                    relative_change=1.0,
                    direction=EvidenceDirection.INCREASE,
                    severity=EvidenceSeverity.MEDIUM,
                    reliability=round(reliability, 2),
                    source="ml.forecasting.attack_horizon",
                    provenance={**prov_dict, "derivation": "multi_step_lstm_rollout"},
                    explanation=f"Early attack signal isolated to horizon T+{forecast_horizon_result.onset_horizon}.",
                    is_supporting=True,
                )
            )
            item_counter += 1
        elif forecast_horizon_result.state == AttackHorizonState.UNCERTAIN_FORECAST:
            contradictory_items.append(
                EvidenceItem(
                    evidence_id=f"EV-{item_counter:03d}",
                    timestamp=iso_ts,
                    window_id=window_id,
                    evidence_type=EvidenceType.CONTRADICTION,
                    feature_name="attack_horizon",
                    observed_value=0.0,
                    baseline_value=0.0,
                    delta=0.0,
                    relative_change=0.0,
                    direction=EvidenceDirection.ANOMALOUS,
                    severity=EvidenceSeverity.MEDIUM,
                    reliability=round(reliability, 2),
                    source="ml.forecasting.attack_horizon",
                    provenance={**prov_dict, "derivation": "multi_step_lstm_rollout"},
                    explanation="Forecasting scores hover near the decision boundary or alternate contradictorily.",
                    is_supporting=False,
                )
            )
            item_counter += 1

    # 3. Integrate Capture Quality Evidence (Contradictory if degraded)
    if quality_limitations:
        contradictory_items.append(
            EvidenceItem(
                evidence_id=f"EV-{item_counter:03d}",
                timestamp=iso_ts,
                window_id=window_id,
                evidence_type=EvidenceType.CAPTURE_QUALITY,
                feature_name="capture_quality",
                observed_value=reliability,
                baseline_value=1.0,
                delta=round(reliability - 1.0, 2),
                relative_change=round((reliability - 1.0), 2),
                direction=EvidenceDirection.DECREASE,
                severity=EvidenceSeverity.HIGH if quality_status == EvidenceQuality.INSUFFICIENT else EvidenceSeverity.MEDIUM,
                reliability=1.0,
                source="nexsolve_core.schemas.CaptureQuality",
                provenance={**prov_dict, "derivation": "pcap_ingestion_audit"},
                explanation="; ".join(quality_limitations),
                is_supporting=False,
            )
        )
        item_counter += 1

    # 4. Deterministic Evidence Strength Scoring (0.0 to 1.0)
    # Reflects the volume and consistency of observed evidence. NOT attack probability!
    n_supp = len(supporting_items)
    n_contra = len(contradictory_items)

    if n_supp == 0 and n_contra == 0:
        evidence_strength = 0.0
    else:
        raw_ratio = n_supp / max(1, (n_supp + n_contra))
        # Factor in magnitudes of high-severity supporting items
        high_supp_count = sum(1 for item in supporting_items if item.severity == EvidenceSeverity.HIGH)
        magnitude_boost = min(0.25, high_supp_count * 0.08)
        # Factor in capture reliability
        evidence_strength = min(1.0, max(0.0, (raw_ratio * 0.75 + magnitude_boost) * reliability))
    evidence_strength = round(evidence_strength, 2)

    # 5. Build Explanation Summary
    if n_supp > 0 and n_contra == 0:
        explanation = f"Observation supported by {n_supp} consistent traffic indicators with high evidence quality."
    elif n_supp > 0 and n_contra > 0:
        explanation = (
            f"Observation supported by {n_supp} indicators, but qualified by {n_contra} contradictory signals "
            f"(e.g., {contradictory_items[0].explanation})."
        )
    elif n_supp == 0 and n_contra > 0:
        explanation = f"Current observation lacks supporting evidence; {n_contra} contradictory signals observed."
    else:
        explanation = "Traffic observed is stable with no meaningful relative change from recent history."

    return EvidenceChain(
        current_window_id=window_id,
        current_timestamp=iso_ts,
        forecast_horizon=forecast_horizon_result.horizon_windows if forecast_horizon_result else 0,
        supporting=[item.to_dict() for item in supporting_items],
        contradictory=[item.to_dict() for item in contradictory_items],
        evidence_strength=evidence_strength,
        evidence_quality=quality_status,
        supporting_feature_count=n_supp,
        contradictory_feature_count=n_contra,
        provenance_complete=provenance_complete,
        explanation=explanation,
        limitations=quality_limitations,
    )


def _build_empty_evidence_chain() -> EvidenceChain:
    """Empty default chain when no state sequence is available."""
    return EvidenceChain(
        current_window_id=None,
        current_timestamp="1970-01-01T00:00:00Z",
        forecast_horizon=0,
        supporting=[],
        contradictory=[],
        evidence_strength=0.0,
        evidence_quality=EvidenceQuality.INSUFFICIENT,
        supporting_feature_count=0,
        contradictory_feature_count=0,
        provenance_complete=False,
        explanation="No network states available for evidence extraction.",
        limitations=["Empty state sequence."],
    )

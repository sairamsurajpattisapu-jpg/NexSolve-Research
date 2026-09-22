"""Native RITA-inspired behavioral periodicity and interval regularity analyzer.

Implements mathematically defensible statistical algorithms over OBSERVED timestamps:
- Median interval and Median Absolute Deviation (MAD)
- Bowley Skewness over interval distributions
- Coefficient of variation (CV) and normalized jitter
- Shannon entropy of discrete interval bins
- Destination consistency and connection continuity
- Strict categorical classifications:
  INSUFFICIENT_OBSERVATIONS, IRREGULAR, WEAKLY_PERIODIC, PERIODIC, HIGHLY_PERIODIC

Zero copyleft source code is copied (RITA is GPLv3; this is a clean-room
mathematical formulation adhering to standard statistical definitions).
Output is strictly EVIDENCE ONLY and does not modify the ML feature vector.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable, Sequence

from nexsolve_core.schemas import FlowRecord, PacketRecord


class PeriodicityClassification(str, Enum):
    INSUFFICIENT_OBSERVATIONS = "INSUFFICIENT_OBSERVATIONS"
    IRREGULAR = "IRREGULAR"
    WEAKLY_PERIODIC = "WEAKLY_PERIODIC"
    PERIODIC = "PERIODIC"
    HIGHLY_PERIODIC = "HIGHLY_PERIODIC"


@dataclass(frozen=True)
class PeriodicityGroupResult:
    """Statistical evaluation of temporal regularity for a communication pair."""
    src_ip: str
    dst_ip: str
    dst_port: int | None
    protocol: str | None
    event_count: int
    observation_duration_seconds: float
    # Interval metrics
    interval_count: int
    median_interval_seconds: float | None
    mad_interval_seconds: float | None
    mean_interval_seconds: float | None
    std_interval_seconds: float | None
    coefficient_of_variation: float | None
    jitter_seconds: float | None  # Mean absolute consecutive interval delta
    bowley_skewness: float | None
    interval_entropy: float | None
    # Regularity scoring (strictly statistical, NOT confidence or maliciousness)
    regularity_score: float  # [0.0, 1.0] where 1.0 is perfectly metronomic
    destination_consistency: float  # Fraction of connections to this dst among src's activity
    classification: PeriodicityClassification
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "event_count": self.event_count,
            "observation_duration_seconds": self.observation_duration_seconds,
            "interval_count": self.interval_count,
            "median_interval_seconds": self.median_interval_seconds,
            "mad_interval_seconds": self.mad_interval_seconds,
            "mean_interval_seconds": self.mean_interval_seconds,
            "std_interval_seconds": self.std_interval_seconds,
            "coefficient_of_variation": self.coefficient_of_variation,
            "jitter_seconds": self.jitter_seconds,
            "bowley_skewness": self.bowley_skewness,
            "interval_entropy": self.interval_entropy,
            "regularity_score": self.regularity_score,
            "destination_consistency": self.destination_consistency,
            "classification": self.classification.value if hasattr(self.classification, "value") else str(self.classification),
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class PeriodicitySummary:
    """Aggregated periodicity analysis across all observed communication groups."""
    total_groups_evaluated: int
    insufficient_groups: int
    irregular_groups: int
    weakly_periodic_groups: int
    periodic_groups: int
    highly_periodic_groups: int
    groups: tuple[PeriodicityGroupResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_groups_evaluated": self.total_groups_evaluated,
            "insufficient_groups": self.insufficient_groups,
            "irregular_groups": self.irregular_groups,
            "weakly_periodic_groups": self.weakly_periodic_groups,
            "periodic_groups": self.periodic_groups,
            "highly_periodic_groups": self.highly_periodic_groups,
            "groups": [g.to_dict() for g in self.groups],
        }


def _calculate_median(sorted_values: Sequence[float]) -> float:
    n = len(sorted_values)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return float(sorted_values[mid])
    return float((sorted_values[mid - 1] + sorted_values[mid]) / 2.0)


def _calculate_quartiles(sorted_values: Sequence[float]) -> tuple[float, float, float]:
    """Compute (Q1, Q2, Q3) via Tukey's hinges."""
    n = len(sorted_values)
    if n == 0:
        return 0.0, 0.0, 0.0
    q2 = _calculate_median(sorted_values)
    mid = n // 2
    if n % 2 == 0:
        lower = sorted_values[:mid]
        upper = sorted_values[mid:]
    else:
        lower = sorted_values[:mid]
        upper = sorted_values[mid + 1:]
    q1 = _calculate_median(lower) if lower else q2
    q3 = _calculate_median(upper) if upper else q2
    return q1, q2, q3


def calculate_bowley_skewness(sorted_intervals: Sequence[float]) -> float | None:
    """Compute Bowley's Quartile Skewness: B = (Q3 + Q1 - 2*Q2) / (Q3 - Q1).

    Defined on [-1.0, 1.0]. A value near 0 indicates symmetric interval dispersion.
    Returns None if (Q3 - Q1) is near-zero (dispersion collapse).
    """
    if len(sorted_intervals) < 4:
        return None
    q1, q2, q3 = _calculate_quartiles(sorted_intervals)
    iqr = q3 - q1
    if iqr < 1e-6:
        return 0.0
    skew = (q3 + q1 - 2.0 * q2) / iqr
    return max(-1.0, min(1.0, float(skew)))


def calculate_mad(sorted_intervals: Sequence[float], median: float) -> float:
    """Median Absolute Deviation: median(|x_i - median|)."""
    if not sorted_intervals:
        return 0.0
    deviations = sorted(abs(x - median) for x in sorted_intervals)
    return _calculate_median(deviations)


def calculate_interval_entropy(intervals: Sequence[float], num_bins: int = 10) -> float:
    """Shannon entropy of binned interval distribution in bits."""
    if len(intervals) < 2:
        return 0.0
    min_val = min(intervals)
    max_val = max(intervals)
    span = max_val - min_val
    if span < 1e-6:
        return 0.0
    bin_width = span / num_bins
    counts = [0] * num_bins
    for x in intervals:
        idx = min(int((x - min_val) / bin_width), num_bins - 1)
        counts[idx] += 1
    total = len(intervals)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def analyze_periodicity_from_timestamps(
    grouped_timestamps: dict[tuple[str, str, int | None, str | None], list[float]],
    src_total_counts: dict[str, int],
    min_connections: int = 4,
) -> PeriodicitySummary:
    results: list[PeriodicityGroupResult] = []
    insufficient = 0
    irregular = 0
    weakly_periodic = 0
    periodic = 0
    highly_periodic = 0

    for (src_ip, dst_ip, dst_port, protocol), ts_list in grouped_timestamps.items():
        n_events = len(ts_list)
        total_src = src_total_counts.get(src_ip, n_events)
        dest_consistency = round(n_events / max(1, total_src), 4)

        if n_events < min_connections:
            insufficient += 1
            results.append(PeriodicityGroupResult(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                event_count=n_events,
                observation_duration_seconds=0.0 if not ts_list else round(max(ts_list) - min(ts_list), 2),
                interval_count=max(0, n_events - 1),
                median_interval_seconds=None,
                mad_interval_seconds=None,
                mean_interval_seconds=None,
                std_interval_seconds=None,
                coefficient_of_variation=None,
                jitter_seconds=None,
                bowley_skewness=None,
                interval_entropy=None,
                regularity_score=0.0,
                destination_consistency=dest_consistency,
                classification=PeriodicityClassification.INSUFFICIENT_OBSERVATIONS,
                explanation=f"Insufficient observations ({n_events} < {min_connections}) to evaluate periodicity.",
            ))
            continue

        ts_list.sort()
        duration = max(ts_list) - min(ts_list)
        raw_intervals = [t2 - t1 for t1, t2 in zip(ts_list, ts_list[1:]) if t2 > t1]

        if len(raw_intervals) < 3:
            insufficient += 1
            results.append(PeriodicityGroupResult(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                event_count=n_events,
                observation_duration_seconds=round(duration, 2),
                interval_count=len(raw_intervals),
                median_interval_seconds=None,
                mad_interval_seconds=None,
                mean_interval_seconds=None,
                std_interval_seconds=None,
                coefficient_of_variation=None,
                jitter_seconds=None,
                bowley_skewness=None,
                interval_entropy=None,
                regularity_score=0.0,
                destination_consistency=dest_consistency,
                classification=PeriodicityClassification.INSUFFICIENT_OBSERVATIONS,
                explanation="Fewer than 3 distinct non-zero intervals observed.",
            ))
            continue

        sorted_intervals = sorted(raw_intervals)
        n_int = len(raw_intervals)
        mean_int = float(sum(raw_intervals) / n_int)
        variance = float(sum((x - mean_int) ** 2 for x in raw_intervals) / n_int)
        std_int = math.sqrt(variance)
        cv = std_int / max(mean_int, 1e-6)

        median_int = _calculate_median(sorted_intervals)
        mad_int = calculate_mad(sorted_intervals, median_int)
        skew = calculate_bowley_skewness(sorted_intervals)
        entropy = calculate_interval_entropy(raw_intervals)

        jitters = [abs(raw_intervals[i] - raw_intervals[i - 1]) for i in range(1, len(raw_intervals))]
        mean_jitter = float(sum(jitters) / len(jitters)) if jitters else 0.0

        mad_score = max(0.0, 1.0 - (mad_int / max(median_int, 1e-6)))
        skew_score = max(0.0, 1.0 - abs(skew)) if skew is not None else mad_score
        cv_score = max(0.0, 1.0 - (cv / 0.70))

        regularity = round((0.4 * cv_score + 0.35 * mad_score + 0.25 * skew_score), 4)

        if regularity >= 0.85 and cv <= 0.15:
            classification = PeriodicityClassification.HIGHLY_PERIODIC
            highly_periodic += 1
            expl = f"Highly periodic traffic: median interval {median_int:.1f}s, low dispersion (CV={cv:.3f}, MAD={mad_int:.2f}s, score={regularity:.3f})."
        elif regularity >= 0.65 and cv <= 0.35:
            classification = PeriodicityClassification.PERIODIC
            periodic += 1
            expl = f"Periodic traffic observed: median interval {median_int:.1f}s (CV={cv:.3f}, score={regularity:.3f})."
        elif regularity >= 0.40 and cv <= 0.60:
            classification = PeriodicityClassification.WEAKLY_PERIODIC
            weakly_periodic += 1
            expl = f"Weakly periodic traffic: moderate interval jitter (CV={cv:.3f}, score={regularity:.3f})."
        else:
            classification = PeriodicityClassification.IRREGULAR
            irregular += 1
            expl = f"Irregular non-periodic traffic: high dispersion (CV={cv:.3f}, score={regularity:.3f})."

        results.append(PeriodicityGroupResult(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            event_count=n_events,
            observation_duration_seconds=round(duration, 2),
            interval_count=n_int,
            median_interval_seconds=round(median_int, 3),
            mad_interval_seconds=round(mad_int, 3),
            mean_interval_seconds=round(mean_int, 3),
            std_interval_seconds=round(std_int, 3),
            coefficient_of_variation=round(cv, 4),
            jitter_seconds=round(mean_jitter, 3),
            bowley_skewness=round(skew, 4) if skew is not None else None,
            interval_entropy=entropy,
            regularity_score=regularity,
            destination_consistency=dest_consistency,
            classification=classification,
            explanation=expl,
        ))

    results.sort(key=lambda r: (r.regularity_score, r.event_count), reverse=True)

    return PeriodicitySummary(
        total_groups_evaluated=len(results),
        insufficient_groups=insufficient,
        irregular_groups=irregular,
        weakly_periodic_groups=weakly_periodic,
        periodic_groups=periodic,
        highly_periodic_groups=highly_periodic,
        groups=tuple(results),
    )


def analyze_periodicity_groups(
    flows: Iterable[FlowRecord],
    min_connections: int = 4,
) -> PeriodicitySummary:
    """Evaluate temporal interval periodicity for all communication pairs in flows."""
    grouped_timestamps: dict[tuple[str, str, int | None, str | None], list[float]] = defaultdict(list)
    src_total_counts: dict[str, int] = defaultdict(int)

    for flow in flows:
        if flow.src_ip and flow.dst_ip:
            src_total_counts[flow.src_ip] += 1
            key = (flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol)
            grouped_timestamps[key].append(flow.start_timestamp)

    return analyze_periodicity_from_timestamps(
        grouped_timestamps=grouped_timestamps,
        src_total_counts=src_total_counts,
        min_connections=min_connections,
    )


analyze_periodicity = analyze_periodicity_groups

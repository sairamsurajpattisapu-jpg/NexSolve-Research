"""Analysis Comparison Engine for Forensic Auditing and Incident Response.

Compares two completed NexSolve analyses (e.g. before/after attack, baseline vs incident,
or multi-sensor captures) and determines threat escalation, forecast divergence, and feature deltas.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping


@dataclass(slots=True, frozen=True)
class HorizonDelta:
    horizon: int
    lookahead_seconds: int
    p_atk_a: float
    p_atk_b: float
    delta_p_atk: float
    cum_risk_a: float
    cum_risk_b: float
    delta_cum_risk: float
    stage_a: str
    stage_b: str
    stage_changed: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class AnalysisComparisonReport:
    """Comprehensive comparative evaluation between two analysis jobs."""

    job_id_a: str
    job_id_b: str
    filename_a: str
    filename_b: str
    threat_level_a: str
    threat_level_b: str
    threat_level_changed: bool
    risk_score_a: float
    risk_score_b: float
    delta_risk_score: float
    early_warning_score_a: int
    early_warning_score_b: int
    delta_early_warning_score: int
    verdict_a: str
    verdict_b: str
    verdict_changed: bool
    packet_delta: int
    flow_delta: int
    comparison_verdict: str  # "ESCALATION", "DE_ESCALATION", "EQUILIBRIUM", "DIVERGENT"
    horizon_deltas: list[HorizonDelta]
    significant_feature_shifts: list[dict[str, Any]]
    summary_text: str

    def to_dict(self) -> dict[str, Any]:
        res = asdict(self)
        res["horizon_deltas"] = [h.to_dict() for h in self.horizon_deltas]
        return res


def compare_analyses(analysis_a: Mapping[str, Any], analysis_b: Mapping[str, Any]) -> AnalysisComparisonReport:
    """Perform deterministic comparison between two NexSolve analysis payloads."""
    job_a = str(analysis_a.get("analysis_id") or "JOB_A")
    job_b = str(analysis_b.get("analysis_id") or "JOB_B")

    file_a = str(analysis_a.get("source", {}).get("name") or analysis_a.get("upload", {}).get("filename") or "capture_a.pcap")
    file_b = str(analysis_b.get("source", {}).get("name") or analysis_b.get("upload", {}).get("filename") or "capture_b.pcap")

    det_a = analysis_a.get("detection") or {}
    det_b = analysis_b.get("detection") or {}
    threat_a = str(det_a.get("threat_level", "LOW")).upper()
    threat_b = str(det_b.get("threat_level", "LOW")).upper()
    risk_a = float(det_a.get("risk_score", 0.0))
    risk_b = float(det_b.get("risk_score", 0.0))
    delta_risk = round(risk_b - risk_a, 2)

    ew_a = analysis_a.get("early_warning") or {}
    ew_b = analysis_b.get("early_warning") or {}
    ew_score_a = int(ew_a.get("early_warning_score", 0))
    ew_score_b = int(ew_b.get("early_warning_score", 0))
    delta_ew = ew_score_b - ew_score_a

    prog_a = analysis_a.get("attack_progression") or {}
    prog_b = analysis_b.get("attack_progression") or {}
    verd_a = str(prog_a.get("verdict", "BASELINE_EQUILIBRIUM"))
    verd_b = str(prog_b.get("verdict", "BASELINE_EQUILIBRIUM"))

    traffic_a = analysis_a.get("traffic") or {}
    traffic_b = analysis_b.get("traffic") or {}
    pkts_a = int(traffic_a.get("packets", 0))
    pkts_b = int(traffic_b.get("packets", 0))
    flows_a = int(traffic_a.get("flows", 0))
    flows_b = int(traffic_b.get("flows", 0))

    # Horizon forecast comparison
    f_list_a = {f.get("horizon", i + 1): f for i, f in enumerate(analysis_a.get("forecasts") or [])}
    f_list_b = {f.get("horizon", i + 1): f for i, f in enumerate(analysis_b.get("forecasts") or [])}

    all_horizons = sorted(list(set(f_list_a.keys()) | set(f_list_b.keys())))
    horizon_deltas: list[HorizonDelta] = []

    for h in all_horizons:
        pt_a = f_list_a.get(h, {})
        pt_b = f_list_b.get(h, {})

        p_a = float(pt_a.get("attackProbability") or 0.0)
        p_b = float(pt_b.get("attackProbability") or 0.0)
        c_a = float(pt_a.get("cumulativeRisk") or 0.0)
        c_b = float(pt_b.get("cumulativeRisk") or 0.0)
        st_a = str(pt_a.get("predictedStage", "NORMAL"))
        st_b = str(pt_b.get("predictedStage", "NORMAL"))

        horizon_deltas.append(HorizonDelta(
            horizon=h,
            lookahead_seconds=h * 60,
            p_atk_a=round(p_a, 4),
            p_atk_b=round(p_b, 4),
            delta_p_atk=round(p_b - p_a, 4),
            cum_risk_a=round(c_a, 4),
            cum_risk_b=round(c_b, 4),
            delta_cum_risk=round(c_b - c_a, 4),
            stage_a=st_a,
            stage_b=st_b,
            stage_changed=(st_a != st_b),
        ))

    # Determine overall comparison verdict
    if delta_risk > 15.0 or (threat_a != threat_b and threat_b in ("HIGH", "CRITICAL")):
        comp_verdict = "ESCALATION"
    elif delta_risk < -15.0:
        comp_verdict = "DE_ESCALATION"
    elif any(hd.stage_changed for hd in horizon_deltas):
        comp_verdict = "DIVERGENT"
    else:
        comp_verdict = "EQUILIBRIUM"

    # Compare traffic features
    shifts = []
    if pkts_a > 0:
        rel_pkts = (pkts_b - pkts_a) / pkts_a
        if abs(rel_pkts) > 0.2:
            shifts.append({
                "metric": "packet_volume",
                "val_a": pkts_a,
                "val_b": pkts_b,
                "relative_change": round(rel_pkts, 2),
                "direction": "INCREASE" if rel_pkts > 0 else "DECREASE",
            })
    if flows_a > 0:
        rel_flows = (flows_b - flows_a) / flows_a
        if abs(rel_flows) > 0.2:
            shifts.append({
                "metric": "flow_count",
                "val_a": flows_a,
                "val_b": flows_b,
                "relative_change": round(rel_flows, 2),
                "direction": "INCREASE" if rel_flows > 0 else "DECREASE",
            })

    summary = (
        f"Comparison of {job_a} ({file_a}) vs {job_b} ({file_b}): "
        f"Threat level transitioned from {threat_a} to {threat_b} (Risk: {risk_a:.1f} -> {risk_b:.1f}, delta: {delta_risk:+.1f}). "
        f"Overall comparison verdict is {comp_verdict}."
    )

    return AnalysisComparisonReport(
        job_id_a=job_a,
        job_id_b=job_b,
        filename_a=file_a,
        filename_b=file_b,
        threat_level_a=threat_a,
        threat_level_b=threat_b,
        threat_level_changed=(threat_a != threat_b),
        risk_score_a=risk_a,
        risk_score_b=risk_b,
        delta_risk_score=delta_risk,
        early_warning_score_a=ew_score_a,
        early_warning_score_b=ew_score_b,
        delta_early_warning_score=delta_ew,
        verdict_a=verd_a,
        verdict_b=verd_b,
        verdict_changed=(verd_a != verd_b),
        packet_delta=pkts_b - pkts_a,
        flow_delta=flows_b - flows_a,
        comparison_verdict=comp_verdict,
        horizon_deltas=horizon_deltas,
        significant_feature_shifts=shifts,
        summary_text=summary,
    )

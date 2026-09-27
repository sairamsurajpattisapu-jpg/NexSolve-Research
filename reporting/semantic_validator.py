"""Report-level semantic consistency validator for NexSolve.

Strictly verifies that no contradictory intelligence claims, fabricated predictions,
or conflicting confidence states exist within an assembled report.

Fails loudly by raising ReportSemanticContradictionError. Does NOT silently mutate
or repair contradictory data.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("nexsolve.semantic_validator")


class ReportSemanticContradictionError(ValueError):
    """Raised when an assembled report contains internal semantic contradictions."""


def validate_report_semantics(report: Any) -> None:
    """Validates the semantic consistency of an assembled NexSolveReport or report dictionary.

    Raises ReportSemanticContradictionError if any contradiction is detected.
    """
    if hasattr(report, "to_dict"):
        data = report.to_dict()
    elif isinstance(report, dict):
        data = report
    else:
        raise TypeError(f"Expected dict or NexSolveReport, got {type(report).__name__}")

    sections = data.get("sections", data)

    # Extract relevant sections
    abstention = sections.get("abstention", {})
    forecast = sections.get("forecast", {})
    attack_horizon = sections.get("attack_horizon", {})
    attack_progression = sections.get("attack_progression", {})
    confidence_sec = sections.get("confidence", {})

    forecast_points_list: list[dict[str, Any]] = []
    if isinstance(forecast, dict) and "forecast_points" in forecast:
        forecast_points_list = forecast.get("forecast_points", [])
    elif isinstance(data.get("forecast_points"), list):
        forecast_points_list = data.get("forecast_points", [])
    elif isinstance(data.get("forecasts"), list):
        forecast_points_list = data.get("forecasts", [])
    elif isinstance(forecast, list):
        forecast_points_list = forecast

    is_abstained = bool(
        abstention.get("abstained") is True
        or data.get("is_forecast_available") is False
        or data.get("analysis_state") == "ANALYSIS_COMPLETE_FORECAST_UNAVAILABLE"
        or (isinstance(abstention, dict) and abstention.get("status") in ("INSUFFICIENT_HISTORY", "NON_CONTIGUOUS_TIMESTAMPS", "MODEL_FEATURE_CONTRACT_MISMATCH"))
    )

    abstention_reason = (
        abstention.get("reason")
        or abstention.get("status")
        or data.get("forecast_abstention_reason")
        or ""
    )

    # -------------------------------------------------------------------------
    # Rule 1: Abstained == True AND forecast_probability is not None (> 0)
    # -------------------------------------------------------------------------
    if is_abstained:
        pts = forecast_points_list
        for idx, pt in enumerate(pts):
            p = pt.get("attack_probability") if pt.get("attack_probability") is not None else pt.get("attackProbability")
            if p is not None and float(p) > 0.0:
                raise ReportSemanticContradictionError(
                    f"Contradiction [Rule 1]: Report is marked abstained=True, but forecast point {idx} "
                    f"(horizon T+{pt.get('horizon_minutes', idx+1)}) contains non-null attack probability {p}."
                )

    # -------------------------------------------------------------------------
    # Rule 2: Abstained == True AND future predicted stage is not None/UNKNOWN
    # -------------------------------------------------------------------------
    if is_abstained:
        # Check forecast points
        pts = forecast_points_list
        for idx, pt in enumerate(pts):
            stage = pt.get("predicted_stage") if pt.get("predicted_stage") is not None else pt.get("predictedStage")
            if stage is not None and str(stage).upper() not in ("UNKNOWN", "UNKNOWN_STATE", "NONE", "WITHHELD"):
                raise ReportSemanticContradictionError(
                    f"Contradiction [Rule 2]: Report is marked abstained=True, but forecast point {idx} "
                    f"contains active predicted stage: '{stage}'."
                )

        # Check progression timeline future events (T+1..T+5)
        timeline = attack_progression.get("timeline", []) if isinstance(attack_progression, dict) else []
        for ev in timeline:
            lead_time = ev.get("lead_time_seconds", 0) or 0
            h_lbl = str(ev.get("horizon_label", ""))
            is_future = lead_time > 0 or h_lbl.startswith("T+")
            if is_future:
                st = str(ev.get("stage", "")).upper()
                cls_type = str(ev.get("classification", "")).upper()
                if st not in ("UNKNOWN", "UNKNOWN_STATE", "WITHHELD", ""):
                    raise ReportSemanticContradictionError(
                        f"Contradiction [Rule 2]: Report is marked abstained=True, but future progression event "
                        f"'{h_lbl}' contains active predicted stage: '{st}'."
                    )
                if cls_type not in ("UNKNOWN", "WITHHELD", "ABSTAINED", ""):
                    raise ReportSemanticContradictionError(
                        f"Contradiction [Rule 2]: Report is marked abstained=True, but future progression event "
                        f"'{h_lbl}' contains non-abstained classification: '{cls_type}'."
                    )

    # -------------------------------------------------------------------------
    # Rule 3: Forecast unavailable / abstained AND forecast confidence > 0
    # -------------------------------------------------------------------------
    if is_abstained:
        pts = forecast_points_list
        for idx, pt in enumerate(pts):
            conf = pt.get("confidence") if pt.get("confidence") is not None else pt.get("confidence_score")
            if conf is not None and float(conf) > 0.0:
                raise ReportSemanticContradictionError(
                    f"Contradiction [Rule 3]: Forecast is unavailable/abstained, but forecast point {idx} "
                    f"has positive confidence: {conf}."
                )

        # Check timeline future events
        timeline = attack_progression.get("timeline", []) if isinstance(attack_progression, dict) else []
        for ev in timeline:
            lead_time = ev.get("lead_time_seconds", 0) or 0
            h_lbl = str(ev.get("horizon_label", ""))
            is_future = lead_time > 0 or h_lbl.startswith("T+")
            if is_future:
                conf = ev.get("confidence")
                if conf is not None and float(conf) > 0.0:
                    raise ReportSemanticContradictionError(
                        f"Contradiction [Rule 3]: Forecast is unavailable/abstained, but future progression event "
                        f"'{h_lbl}' has positive confidence: {conf}."
                    )

    # -------------------------------------------------------------------------
    # Rule 4: MODEL_FEATURE_CONTRACT_MISMATCH AND valid forecast timeline
    # -------------------------------------------------------------------------
    if "MODEL_FEATURE_CONTRACT_MISMATCH" in abstention_reason:
        timeline = attack_progression.get("timeline", []) if isinstance(attack_progression, dict) else []
        for ev in timeline:
            lead_time = ev.get("lead_time_seconds", 0) or 0
            h_lbl = str(ev.get("horizon_label", ""))
            if lead_time > 0 or h_lbl.startswith("T+"):
                cls_type = str(ev.get("classification", "")).upper()
                if cls_type == "FORECAST":
                    raise ReportSemanticContradictionError(
                        f"Contradiction [Rule 4]: Model feature contract mismatch occurred, but future event "
                        f"'{h_lbl}' is marked as an active FORECAST."
                    )

    # -------------------------------------------------------------------------
    # Rule 5: UNKNOWN forecast stage AND positive confidence
    # -------------------------------------------------------------------------
    pts = forecast_points_list
    for idx, pt in enumerate(pts):
        st = str(pt.get("predicted_stage") or pt.get("predictedStage") or "").upper()
        conf = pt.get("confidence") if pt.get("confidence") is not None else pt.get("confidence_score")
        if st in ("UNKNOWN", "UNKNOWN_STATE", "WITHHELD") and conf is not None and float(conf) > 0.0:
            raise ReportSemanticContradictionError(
                f"Contradiction [Rule 5]: Forecast point {idx} has UNKNOWN stage but positive confidence {conf}."
            )

    timeline = attack_progression.get("timeline", []) if isinstance(attack_progression, dict) else []
    for ev in timeline:
        st = str(ev.get("stage", "")).upper()
        conf = ev.get("confidence")
        if st in ("UNKNOWN", "UNKNOWN_STATE") and conf is not None and float(conf) > 0.0:
            raise ReportSemanticContradictionError(
                f"Contradiction [Rule 5]: Timeline event '{ev.get('horizon_label')}' has UNKNOWN stage "
                f"but positive confidence {conf}."
            )

    # -------------------------------------------------------------------------
    # Rule 6: Attack horizon ABSTAINED but numeric lead time or onset horizon
    # -------------------------------------------------------------------------
    ah_state = str(attack_horizon.get("state", "")).upper() if isinstance(attack_horizon, dict) else ""
    if ah_state == "ABSTAINED":
        lead_time = attack_horizon.get("lead_time_seconds")
        if lead_time is not None:
            raise ReportSemanticContradictionError(
                f"Contradiction [Rule 6]: Attack horizon is marked ABSTAINED, but contains numeric "
                f"lead_time_seconds={lead_time}."
            )
        onset = attack_horizon.get("onset_horizon")
        if onset is not None:
            raise ReportSemanticContradictionError(
                f"Contradiction [Rule 6]: Attack horizon is marked ABSTAINED, but contains numeric "
                f"onset_horizon={onset}."
            )

    logger.debug("Report semantic consistency verified successfully.")

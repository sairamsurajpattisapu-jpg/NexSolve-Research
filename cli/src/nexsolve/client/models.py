"""Typed models for NexSolve API responses."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class JobStatus:
    """Represents a job status record returned by GET /jobs/{job_id}."""

    job_id: str
    filename: str = ""
    status: str = "QUEUED"
    stage: str = "INGESTION"
    progress: float = 0.10
    bytes_processed: int = 0
    bytes_total: int | None = None
    packets_processed: int = 0
    created_at: str = ""
    started_at: str | None = None
    completed_at: str | None = None
    error: dict[str, Any] | None = None
    processing_statistics: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JobStatus:
        return cls(
            job_id=str(data.get("job_id", "")),
            filename=str(data.get("filename", "")),
            status=str(data.get("status", "QUEUED")),
            stage=str(data.get("stage", "INGESTION")),
            progress=float(data.get("progress", 0.0)),
            bytes_processed=int(data.get("bytes_processed", 0)),
            bytes_total=data.get("bytes_total"),
            packets_processed=int(data.get("packets_processed", 0)),
            created_at=str(data.get("created_at", "")),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            error=data.get("error"),
            processing_statistics=data.get("processing_statistics") or {},
        )

    @property
    def is_complete(self) -> bool:
        return self.status == "COMPLETED"

    @property
    def is_failed(self) -> bool:
        return self.status in ("FAILED", "RESOURCE_LIMIT_EXCEEDED", "CANCELLED")

    @property
    def is_resource_limit_exceeded(self) -> bool:
        return self.status == "RESOURCE_LIMIT_EXCEEDED"

    @property
    def is_cancelled(self) -> bool:
        return self.status == "CANCELLED"

    @property
    def is_active(self) -> bool:
        return self.status in ("QUEUED", "PROCESSING")


@dataclass
class AnalysisSummary:
    """Consolidated SOC summary extracted from completed analysis payload."""

    job_id: str
    filename: str
    threat_level: str
    risk_score: float
    detected_events: int
    early_warning_score: int
    early_warning_level: str
    progression_verdict: str
    forecast_points: list[dict[str, Any]]
    top_drivers: list[dict[str, Any]]
    packet_count: int
    flow_count: int
    window_count: int
    duration_seconds: int
    visualization_url: str
    report_url: str
    abstention: dict[str, Any] | None = None

    @classmethod
    def from_result(cls, result: dict[str, Any], web_base_url: str) -> AnalysisSummary:
        job_id = str(result.get("analysis_id", ""))
        web_base = web_base_url.rstrip("/")

        traffic = result.get("traffic") or {}
        detection = result.get("detection") or {}
        early_warning = result.get("early_warning") or {}
        progression = result.get("attack_progression") or {}
        raw_forecasts = result.get("forecasts") or []
        abstention = result.get("abstention") or None
        forecast_summary = result.get("forecast_summary") or {}
        if not abstention and (
            forecast_summary.get("status") in ("INSUFFICIENT_HISTORY", "INCOMPATIBLE_FEATURES")
            or forecast_summary.get("available") is False
            or result.get("analysis_state") == "ANALYSIS_COMPLETE_FORECAST_UNAVAILABLE"
        ):
            abstention = {
                "abstained": True,
                "reason": forecast_summary.get("status", "INSUFFICIENT_HISTORY"),
                "observed_windows": forecast_summary.get("available_windows", int(traffic.get("windows", result.get("window_count", 0)))),
                "required_windows": forecast_summary.get("required_windows", 8),
            }

        # Sanitize and validate forecast points
        sanitized_forecasts: list[dict[str, Any]] = []
        last_cum_risk: float = 0.0

        for f in raw_forecasts:
            pt = dict(f)
            # Attack probability validation
            p_atk = pt.get("attackProbability")
            if p_atk is not None:
                try:
                    p_val = float(p_atk)
                    if math.isnan(p_val) or math.isinf(p_val):
                        pt["attackProbability"] = 0.0
                    else:
                        pt["attackProbability"] = max(0.0, min(1.0, p_val))
                except (ValueError, TypeError):
                    pt["attackProbability"] = None

            # Cumulative risk validation & non-decreasing monotonicity
            c_risk = pt.get("cumulativeRisk")
            if c_risk is not None:
                try:
                    c_val = float(c_risk)
                    if math.isnan(c_val) or math.isinf(c_val):
                        c_val = pt.get("attackProbability") or 0.0
                    else:
                        c_val = max(0.0, min(1.0, c_val))
                    c_val = max(c_val, last_cum_risk)
                    last_cum_risk = c_val
                    pt["cumulativeRisk"] = c_val
                except (ValueError, TypeError):
                    pt["cumulativeRisk"] = None

            sanitized_forecasts.append(pt)

        # Extract and sanitize top drivers from forecasts
        drivers: list[dict[str, Any]] = []
        for f in sanitized_forecasts:
            if f.get("topDrivers"):
                raw_drivers = f["topDrivers"]
                for d in raw_drivers:
                    driver = dict(d)
                    cur_val = driver.get("current_value", 0.0)
                    pred_val = driver.get("predicted_value", 0.0)
                    feat = driver.get("feature", "feature")
                    interp = driver.get("interpretation", "")

                    # Check for astronomical division percentages (e.g. 410209592.8%)
                    try:
                        cur_num = float(cur_val)
                    except (ValueError, TypeError):
                        cur_num = 0.0

                    if abs(cur_num) < 1e-4:
                        if "by " in interp and "%" in interp:
                            driver["interpretation"] = f"Feature '{feat}' newly present in forecast (0.0 -> {pred_val}) represents emerging network signal."
                    elif re.search(r"by \d{5,}(?:\.\d+)?%", interp):
                        driver["interpretation"] = f"Feature '{feat}' {driver.get('direction', 'changing')} significantly from {cur_val} to {pred_val} relative to current state."

                    drivers.append(driver)
                break

        # Sanitize detection risk score
        try:
            raw_risk = float(detection.get("risk_score", 0.0))
            if math.isnan(raw_risk) or math.isinf(raw_risk):
                risk_score = 0.0
            else:
                risk_score = max(0.0, min(100.0, raw_risk))
        except (ValueError, TypeError):
            risk_score = 0.0

        return cls(
            job_id=job_id,
            filename=str(result.get("source", {}).get("name") or result.get("upload", {}).get("filename") or "capture.pcap"),
            threat_level=str(detection.get("threat_level", "LOW")).upper(),
            risk_score=risk_score,
            detected_events=int(detection.get("detected_events", len(detection.get("findings", [])))),
            early_warning_score=int(early_warning.get("early_warning_score", 0)),
            early_warning_level=str(early_warning.get("early_warning_level", "NORMAL")),
            progression_verdict=str(progression.get("verdict", "BASELINE_EQUILIBRIUM")),
            forecast_points=sanitized_forecasts,
            top_drivers=drivers,
            packet_count=int(traffic.get("packets", result.get("packet_count", 0))),
            flow_count=int(traffic.get("flows", 0)),
            window_count=int(traffic.get("windows", result.get("window_count", 0))),
            duration_seconds=int(traffic.get("duration_seconds", result.get("duration_seconds", 0))),
            visualization_url=f"{web_base}/console/forecast/{job_id}",
            report_url=f"{web_base}/console/reports/{job_id}",
            abstention=abstention,
        )

    @property
    def is_abstained(self) -> bool:
        """Indicate whether the forecast was withheld or abstained due to data constraints."""
        if self.abstention and self.abstention.get("abstained"):
            return True
        if self.forecast_points and all(f.get("attackProbability") is None for f in self.forecast_points):
            return True
        return False

    @property
    def abstention_reason_text(self) -> str:
        """Provide a clean human-readable explanation for why forecasting abstained."""
        if not self.abstention:
            return "Insufficient temporal history"
        reason = self.abstention.get("reason", "INSUFFICIENT_HISTORY")
        if reason == "INSUFFICIENT_HISTORY":
            return "Insufficient temporal history"
        elif reason == "GAPPED_HISTORY":
            return "Non-contiguous timestamp gaps"
        elif reason == "INCOMPATIBLE_FEATURES":
            return "Incompatible feature contract"
        return str(reason).replace("_", " ").title()

    @property
    def abstention_observed_windows(self) -> int:
        """Return the number of observed windows associated with the abstention."""
        if self.abstention and "observed_windows" in self.abstention:
            return int(self.abstention["observed_windows"])
        return self.window_count

    @property
    def abstention_required_windows(self) -> int:
        """Return the minimum number of windows required for forecasting."""
        if self.abstention and "required_windows" in self.abstention:
            return int(self.abstention["required_windows"])
        return 8


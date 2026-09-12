"""Lightweight, in-process asynchronous job manager for NexSolve PCAP processing."""
from __future__ import annotations

import hashlib
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from ml.data.pcap_extractor import extract_canonical_capture
from ml.detection import analyze_packet_windows, traffic_summary
from ml.forecasting import assemble_forecast_intelligence
from model_service.database import persist_analysis
from nexsolve_core.config import (
    ALLOWED_EXTENSIONS,
    MAX_CONCURRENT_JOBS,
    MAX_FLOWS,
    MAX_PACKETS,
    MAX_PROCESSING_DURATION_SECONDS,
    MAX_TEMPORAL_WINDOWS,
    MAX_UPLOAD_BYTES,
    PCAP_MAGICS,
    ResourceLimitExceededError,
    sanitize_error_message,
    sanitize_filename,
)
from nexsolve_core.state import (
    build_network_state_candidates,
    build_state_history,
    candidates_to_network_states,
    evaluate_model_compatibility,
)
from reporting.report_engine import assemble_report, generate_html_report, generate_json_report

JobStatus = Literal[
    "QUEUED",
    "PROCESSING",
    "COMPLETED",
    "FAILED",
    "ABORTED",
    "RESOURCE_LIMIT_EXCEEDED",
]

JobStage = Literal[
    "INGESTION",
    "PARSING",
    "FLOW_RECONSTRUCTION",
    "WINDOWING",
    "NETWORK_STATE",
    "FORECAST",
    "EVIDENCE",
    "REPORT",
    "COMPLETE",
]

STAGE_PROGRESS_MAP: dict[JobStage, float] = {
    "INGESTION": 0.10,
    "PARSING": 0.25,
    "FLOW_RECONSTRUCTION": 0.40,
    "WINDOWING": 0.55,
    "NETWORK_STATE": 0.70,
    "FORECAST": 0.80,
    "EVIDENCE": 0.90,
    "REPORT": 0.95,
    "COMPLETE": 1.00,
}

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = ROOT / "runtime"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR = ROOT / "models" / "nexsolve_world_model"
MODEL_DIR_45 = ROOT / "models" / "nexsolve_world_model_45"
import json
MODEL_SCHEMA = json.loads((MODEL_DIR / "feature_schema.json").read_text(encoding="utf-8"))
MODEL_SCHEMA_45 = json.loads((MODEL_DIR / "feature_schema_45.json").read_text(encoding="utf-8")) if (MODEL_DIR / "feature_schema_45.json").exists() else json.loads((MODEL_DIR_45 / "feature_schema.json").read_text(encoding="utf-8"))
CONFIG = json.loads((MODEL_DIR / "config.json").read_text(encoding="utf-8"))
CONFIG_45 = json.loads((MODEL_DIR_45 / "config.json").read_text(encoding="utf-8")) if (MODEL_DIR_45 / "config.json").exists() else CONFIG
FLOW_FEATURES = tuple(MODEL_SCHEMA["flow_features"])
FLOW_FEATURES_45 = tuple(MODEL_SCHEMA_45["flow_features"])
PACKET_FEATURES = tuple(MODEL_SCHEMA["packet_features"])
TEMPORAL_FEATURES = tuple(MODEL_SCHEMA["temporal_features"])


@dataclass
class JobRecord:
    job_id: str
    filename: str
    status: JobStatus = "QUEUED"
    stage: JobStage = "INGESTION"
    progress: float = 0.10
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: str | None = None
    completed_at: str | None = None
    error: dict[str, Any] | None = None
    processing_statistics: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    report_json: str | None = None
    report_html: str | None = None

    def to_status_dict(self) -> dict[str, Any]:
        """Return public job status dict without internal filesystem details."""
        return {
            "job_id": self.job_id,
            "status": self.status,
            "progress": round(self.progress, 2),
            "stage": self.stage,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "processing_statistics": self.processing_statistics,
        }


def _validation(windows: list[dict[str, Any]], compatibility: dict[str, Any]) -> dict[str, Any]:
    columns = sorted({key for window in windows for key in window})
    null_counts = {column: sum(window.get(column) is None for window in windows) for column in columns}
    starts = [int(window["window_start"]) for window in windows]
    return {
        "status": "VALID" if windows else "INVALID",
        "rows": len(windows),
        "columns": columns,
        "dtypes": {column: "object" if column == "protocol_counts" else "float64" for column in columns},
        "missing_columns": [],
        "null_counts": null_counts,
        "null_ratios": {column: count / len(windows) for column, count in null_counts.items()} if windows else {},
        "constant_columns": [],
        "numeric_ranges": {},
        "protocol_counts": traffic_summary(windows)["protocol_counts"],
        "window": {
            "unit": "UTC epoch seconds",
            "seconds": 60,
            "start_min": min(starts) if starts else None,
            "start_max": max(starts) if starts else None,
            "ordered": starts == sorted(starts),
        },
        "model_compatibility": {
            "flow_features_available": any(f in FLOW_FEATURES for f in compatibility.get("available_features", [])),
            "packet_features_available": True,
            "labels_available": False,
            "forecast_model_ready": compatibility["model_ready"],
            "reason": compatibility["reason"],
            "available_features": compatibility["available_features"],
            "missing_features": compatibility["missing_features"],
            "unreliable_features": compatibility["unreliable_features"],
        },
    }


def validate_pcap_bytes(filename: str, content: bytes) -> tuple[str, str]:
    """Validate PCAP extension, size, and magic bytes. Returns (clean_filename, suffix)."""
    raw_suffix = Path(filename).suffix.lower()
    if raw_suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .pcap and .pcapng captures are supported.")
    clean_filename = sanitize_filename(filename)
    suffix = Path(clean_filename).suffix.lower()
    if not content:
        raise ValueError("The uploaded capture is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise ResourceLimitExceededError(
            resource="upload_bytes",
            observed=len(content),
            limit=MAX_UPLOAD_BYTES,
            explanation=f"Capture size ({len(content):,} bytes) exceeds upload limit of {MAX_UPLOAD_BYTES:,} bytes.",
            recoverable=False,
        )
    if content[:4] not in PCAP_MAGICS:
        raise RuntimeError("The file could not be parsed as a supported PCAP/PCAPNG capture.")
    return clean_filename, suffix


class JobManager:
    """Thread-safe in-process asynchronous job manager for NexSolve."""

    def __init__(self, max_workers: int = MAX_CONCURRENT_JOBS):
        self._jobs: dict[str, JobRecord] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="nexsolve-job-worker")

    def create_job(self, filename: str, content: bytes) -> JobRecord:
        clean_name, suffix = validate_pcap_bytes(filename, content)
        job_id = f"job-{hashlib.sha256(content[:64] + str(time.time()).encode()).hexdigest()[:12]}"
        
        job = JobRecord(
            job_id=job_id,
            filename=clean_name,
            status="QUEUED",
            stage="INGESTION",
            progress=STAGE_PROGRESS_MAP["INGESTION"],
        )
        
        with self._lock:
            self._jobs[job_id] = job

        # Submit worker
        self._executor.submit(self._run_job, job_id, clean_name, suffix, content)
        return job

    def get_job(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _update_stage(self, job_id: str, stage: JobStage) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status == "PROCESSING":
                job.stage = stage
                job.progress = STAGE_PROGRESS_MAP[stage]

    def _run_job(self, job_id: str, clean_name: str, suffix: str, content: bytes) -> None:
        start_time = time.perf_counter()
        capture_hash = hashlib.sha256(content).hexdigest()

        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = "PROCESSING"
            job.started_at = datetime.now(timezone.utc).isoformat()
            job.stage = "PARSING"
            job.progress = STAGE_PROGRESS_MAP["PARSING"]

        work_dir = None
        try:
            # 1. PARSING
            t_parse_start = time.perf_counter()
            work_dir = tempfile.mkdtemp(prefix=f"nexsolve-{job_id}-", dir=RUNTIME_DIR)
            capture_path = Path(work_dir) / f"capture{suffix}"
            capture_path.write_bytes(content)

            try:
                packets, canonical_windows, quality = extract_canonical_capture(capture_path)
            except Exception as error:
                raise RuntimeError("The file could not be parsed as a supported PCAP/PCAPNG capture.") from error
            pcap_parsing_ms = round((time.perf_counter() - t_parse_start) * 1000, 2)

            # Check Resource Limits on packets
            if len(packets) > MAX_PACKETS:
                raise ResourceLimitExceededError(
                    resource="packet_count",
                    observed=len(packets),
                    limit=MAX_PACKETS,
                    explanation=f"Observed packet count ({len(packets):,}) exceeds maximum limit of {MAX_PACKETS:,}.",
                    recoverable=False,
                )

            # Check timeout
            elapsed = time.perf_counter() - start_time
            if elapsed > MAX_PROCESSING_DURATION_SECONDS:
                raise ResourceLimitExceededError(
                    resource="processing_duration",
                    observed=elapsed,
                    limit=MAX_PROCESSING_DURATION_SECONDS,
                    explanation=f"Processing duration ({elapsed:.1f}s) exceeded limit of {MAX_PROCESSING_DURATION_SECONDS}s.",
                    recoverable=False,
                )

            if not canonical_windows:
                raise RuntimeError("The capture contained no parseable timestamped packets.")

            # 2. FLOW_RECONSTRUCTION & WINDOWING
            t_flow_start = time.perf_counter()
            self._update_stage(job_id, "FLOW_RECONSTRUCTION")
            windows = [window.to_dict() for window in canonical_windows]
            flow_reconstruction_ms = round((time.perf_counter() - t_flow_start) * 1000, 2)
            
            # Check Resource Limits on temporal windows
            if len(windows) > MAX_TEMPORAL_WINDOWS:
                raise ResourceLimitExceededError(
                    resource="window_count",
                    observed=len(windows),
                    limit=MAX_TEMPORAL_WINDOWS,
                    explanation=f"Temporal window count ({len(windows)}) exceeds limit of {MAX_TEMPORAL_WINDOWS}.",
                    recoverable=False,
                )

            t_win_start = time.perf_counter()
            self._update_stage(job_id, "WINDOWING")
            window_generation_ms = round((time.perf_counter() - t_win_start) * 1000, 2)

            # 3. NETWORK_STATE
            t_state_start = time.perf_counter()
            self._update_stage(job_id, "NETWORK_STATE")
            candidates = build_network_state_candidates(canonical_windows, MODEL_SCHEMA)
            history = build_state_history(candidates)
            compatibility = evaluate_model_compatibility(candidates, MODEL_SCHEMA, history.status).to_dict()

            active_schema = MODEL_SCHEMA
            active_model_dir = MODEL_DIR
            active_config = CONFIG
            active_flow_features = FLOW_FEATURES
            schema_variant = "46_feature_canonical"

            # Check if 45-feature PCAP-compatible schema can be activated:
            # Only when the primary 46-feature gate failed solely due to mean_tcp_rtt
            if not compatibility.get("model_ready", False):
                missing = compatibility.get("missing_features", [])
                if set(missing) == {"flow_features.mean_tcp_rtt"}:
                    compat_45 = evaluate_model_compatibility(candidates, MODEL_SCHEMA_45, history.status).to_dict()
                    if compat_45.get("model_ready", False) and MODEL_DIR_45.exists():
                        compatibility = compat_45
                        active_schema = MODEL_SCHEMA_45
                        active_model_dir = MODEL_DIR_45
                        active_config = CONFIG_45
                        active_flow_features = FLOW_FEATURES_45
                        schema_variant = "45_feature_pcap_compatible"

            traffic = traffic_summary(windows)
            detection = analyze_packet_windows(windows)
            duration_seconds = max(0, int(windows[-1]["window_end"]) - int(windows[0]["window_start"]))
            packet_ts = [p.timestamp for p in packets if p.timestamp is not None]
            packet_span_seconds = round(max(packet_ts) - min(packet_ts), 4) if packet_ts else 0.0
            traffic["duration_seconds"] = duration_seconds
            traffic["packet_timestamp_span_seconds"] = packet_span_seconds
            traffic["temporal_window_coverage_seconds"] = duration_seconds
            traffic["packet_span_seconds"] = packet_span_seconds
            if packets:
                traffic["unique_src_ips"] = len({p.src_ip for p in packets if p.src_ip})
                traffic["unique_dst_ips"] = len({p.dst_ip for p in packets if p.dst_ip})
                traffic["unique_dst_ports"] = len({p.dst_port for p in packets if p.dst_port is not None})
            if canonical_windows:
                all_flow_ids = {flow.flow_id for cw in canonical_windows for flow in cw.flows}
                if all_flow_ids:
                    traffic["flows"] = len(all_flow_ids)
            network_state_extraction_ms = round((time.perf_counter() - t_state_start) * 1000, 2)

            # 4. FORECAST
            t_forecast_start = time.perf_counter()
            self._update_stage(job_id, "FORECAST")
            forecast_points: list[dict[str, Any]] = []
            
            if compatibility.get("model_ready", False):
                try:
                    from world_model import explain, forecast_k_steps, load_model
                    states = candidates_to_network_states(candidates, active_schema, history.status)
                    model, mean, scale = load_model(active_model_dir)
                    forecast_res = forecast_k_steps(states, int(active_config["forecast_horizon"]), active_model_dir)
                    explanation_rows = explain(states, model, mean, scale)
                    exps = [f"{r['feature']} contributed ({r['contribution']:+.6f})" for r in explanation_rows]
                    for pt in forecast_res.get("forecasts", []):
                        forecast_points.append({
                            "horizon": pt["horizon"],
                            "attackProbability": pt["attack_probability"],
                            "predictedStage": None,
                            "confidence": pt["confidence"],
                            "uncertainty": None if pt["confidence"] is None else 1.0 - pt["confidence"],
                            "explanation": exps,
                        })
                except Exception:
                    # Model evaluation fallback to abstained points
                    for h in range(1, 6):
                        forecast_points.append({
                            "horizon": h,
                            "attackProbability": None,
                            "predictedStage": None,
                            "confidence": None,
                            "uncertainty": None,
                            "explanation": ["Forecast execution bypassed due to state compatibility."],
                        })
            else:
                reason = compatibility.get("reason", "Incompatible feature contract for world model.")
                for h in range(1, 6):
                    forecast_points.append({
                        "horizon": h,
                        "attackProbability": None,
                        "predictedStage": None,
                        "confidence": None,
                        "uncertainty": None,
                        "explanation": [f"Forecast abstained: {reason}"],
                    })
            forecasting_ms = round((time.perf_counter() - t_forecast_start) * 1000, 2)

            # 5. EVIDENCE & TRUST LAYER
            t_evidence_start = time.perf_counter()
            self._update_stage(job_id, "EVIDENCE")
            # Build sequence representation for assemble_forecast_intelligence
            state_dicts = [
                {
                    "timestamp": c.start_timestamp,
                    "flow_features": c.flow_features,
                    "packet_features": c.packet_features,
                    "temporal_features": c.temporal_features,
                    "packet_features_available": True,
                }
                for c in candidates
            ]
            intelligence = assemble_forecast_intelligence(
                sequence=state_dicts,
                forecast_points=forecast_points,
                capture_quality=quality,
                provenance_info={"capture_id": job_id, "source": clean_name, "schema_variant": schema_variant},
                min_sequence_length=8,
                required_features=active_flow_features,
                calibration_status="UNSUPPORTED",
                decision_threshold=0.5,
                window_seconds=60,
            )
            evidence_generation_ms = round((time.perf_counter() - t_evidence_start) * 1000, 2)

            # Combine full analysis result
            stage_timings = {
                "upload_validation_ms": 0.5,
                "pcap_parsing_ms": pcap_parsing_ms,
                "flow_reconstruction_ms": flow_reconstruction_ms,
                "window_generation_ms": window_generation_ms,
                "network_state_extraction_ms": network_state_extraction_ms,
                "forecasting_ms": forecasting_ms,
                "evidence_generation_ms": evidence_generation_ms,
            }

            analysis_result = {
                "analysis_id": job_id,
                "status": "completed",
                "source": {"name": clean_name, "kind": "uploaded_pcap", "filename": clean_name, "size_bytes": len(content)},
                "upload": {"filename": clean_name, "size_bytes": len(content), "format": suffix[1:]},
                "validation": _validation(windows, compatibility),
                "model_compatibility": compatibility,
                "network_state": {
                    "available": True,
                    "candidate_count": len(candidates),
                    "window_ids": [candidate.window_id for candidate in candidates],
                    "history": history.to_dict(),
                    "label_semantics": "UNKNOWN for unlabeled PCAP; heuristic findings are not ground-truth labels.",
                },
                "traffic": traffic,
                "detection": detection,
                "quality": quality,
                "packet_count": traffic["packets"],
                "window_count": traffic["windows"],
                "duration_seconds": duration_seconds,
                "protocol_summary": traffic["protocol_counts"],
                "findings": detection["findings"],
                "summary": {"packet_count": traffic["packets"], "window_count": traffic["windows"], "finding_count": detection["detected_events"], "threat_level": detection["threat_level"]},
                # Trust Layer
                "forecasts": forecast_points,
                "attack_horizon": intelligence.attack_horizon,
                "attackHorizon": intelligence.attack_horizon,
                "evidence_chain": intelligence.evidence_chain,
                "evidenceChain": intelligence.evidence_chain,
                "confidence": intelligence.confidence,
                "unknown_behavior": intelligence.unknown_behavior,
                "unknownBehavior": intelligence.unknown_behavior,
                "abstention": intelligence.abstention,
                "processing_metrics": stage_timings,
            }

            # Persist for legacy retrieval if database is available
            try:
                persist_analysis(analysis_result)
            except Exception:
                pass

            # 6. REPORT GENERATION
            t_report_start = time.perf_counter()
            self._update_stage(job_id, "REPORT")
            total_duration = time.perf_counter() - start_time
            report_obj = assemble_report(
                analysis_result=analysis_result,
                job_id=job_id,
                capture_hash=capture_hash,
                model_version=str(CONFIG.get("model_type", "nexsolve_world_model")),
                processing_seconds=total_duration,
            )
            report_json = generate_json_report(report_obj)
            report_html = generate_html_report(report_obj)
            report_generation_ms = round((time.perf_counter() - t_report_start) * 1000, 2)
            stage_timings["report_generation_ms"] = report_generation_ms
            stage_timings["total_processing_ms"] = round(total_duration * 1000, 2)
            analysis_result["processing_metrics"] = stage_timings

            # 7. COMPLETE
            with self._lock:
                job = self._jobs.get(job_id)
                if job:
                    job.status = "COMPLETED"
                    job.stage = "COMPLETE"
                    job.progress = STAGE_PROGRESS_MAP["COMPLETE"]
                    job.completed_at = datetime.now(timezone.utc).isoformat()
                    job.result = analysis_result
                    job.report_json = report_json
                    job.report_html = report_html
                    job.processing_statistics = {
                        "packets_processed": len(packets),
                        "flows_processed": traffic.get("flows", len(packets)),
                        "windows_processed": len(windows),
                        "processing_seconds": round(total_duration, 3),
                        "stage_timings_ms": stage_timings,
                    }
            from model_service.active_analysis import set_current_analysis
            set_current_analysis(job_id, analysis_result)

        except ResourceLimitExceededError as rle:
            with self._lock:
                job = self._jobs.get(job_id)
                if job:
                    job.status = "RESOURCE_LIMIT_EXCEEDED"
                    job.completed_at = datetime.now(timezone.utc).isoformat()
                    job.error = rle.to_dict()
                    job.processing_statistics = {
                        "processing_seconds": round(time.perf_counter() - start_time, 3),
                    }
        except Exception as exc:
            with self._lock:
                job = self._jobs.get(job_id)
                if job:
                    job.status = "FAILED"
                    job.completed_at = datetime.now(timezone.utc).isoformat()
                    clean_msg = sanitize_error_message(str(exc))
                    job.error = {
                        "code": "PROCESSING_FAILED",
                        "message": clean_msg,
                        "recoverable": False,
                    }
                    job.processing_statistics = {
                        "processing_seconds": round(time.perf_counter() - start_time, 3),
                    }
        finally:
            # Clean up isolated temporary directory
            if work_dir:
                try:
                    import shutil
                    shutil.rmtree(work_dir, ignore_errors=True)
                except Exception:
                    pass


# Global singleton job manager
JOB_MANAGER = JobManager()

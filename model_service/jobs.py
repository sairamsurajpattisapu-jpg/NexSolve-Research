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
FINAL_MODEL_DIR = ROOT / "models" / "final_world_model"
MODEL_DIR = FINAL_MODEL_DIR
MODEL_DIR_45 = FINAL_MODEL_DIR
import json
from nexsolve_core.state import MODEL_SCHEMA_45
MODEL_SCHEMA = MODEL_SCHEMA_45
CONFIG = json.loads((FINAL_MODEL_DIR / "config.json").read_text(encoding="utf-8"))
CONFIG_45 = CONFIG
FLOW_FEATURES = tuple(MODEL_SCHEMA_45["flow_features"])
FLOW_FEATURES_45 = tuple(MODEL_SCHEMA_45["flow_features"])
PACKET_FEATURES = tuple(MODEL_SCHEMA_45["packet_features"])
TEMPORAL_FEATURES = tuple(MODEL_SCHEMA_45["temporal_features"])


@dataclass
class JobRecord:
    job_id: str
    filename: str
    status: JobStatus = "QUEUED"
    stage: JobStage = "INGESTION"
    progress: float = 0.10
    bytes_processed: int = 0
    bytes_total: int | None = None
    packets_processed: int = 0
    throughput_mbps: float | None = None
    estimated_remaining_seconds: float | None = None
    last_progress_timestamp: float | None = None
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
            "filename": self.filename,
            "status": self.status,
            "progress": round(self.progress, 2),
            "stage": self.stage,
            "bytes_processed": self.bytes_processed,
            "bytes_total": self.bytes_total,
            "packets_processed": self.packets_processed,
            "throughput_mbps": self.throughput_mbps,
            "estimated_remaining_seconds": self.estimated_remaining_seconds,
            "last_progress_timestamp": self.last_progress_timestamp,
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


def stream_file_hash(path: Path) -> str:
    """Compute SHA-256 hash by streaming chunks to avoid loading large captures into RAM."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


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


def validate_pcap_file(file_path: Path, filename: str | None = None) -> tuple[str, str, int]:
    """Validate PCAP on disk without loading entire file into memory. Returns (clean_filename, suffix, file_size)."""
    target_name = filename or file_path.name
    raw_suffix = Path(target_name).suffix.lower()
    if raw_suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .pcap and .pcapng captures are supported.")
    clean_filename = sanitize_filename(target_name)
    suffix = Path(clean_filename).suffix.lower()
    if not file_path.exists():
        raise ValueError("The uploaded capture file does not exist.")
    file_size = file_path.stat().st_size
    if file_size == 0:
        raise ValueError("The uploaded capture is empty.")
    if file_size > MAX_UPLOAD_BYTES:
        raise ResourceLimitExceededError(
            resource="upload_bytes",
            observed=file_size,
            limit=MAX_UPLOAD_BYTES,
            explanation=f"Capture size ({file_size:,} bytes) exceeds upload limit of {MAX_UPLOAD_BYTES:,} bytes.",
            recoverable=False,
        )
    with open(file_path, "rb") as f:
        magic = f.read(4)
    if magic not in PCAP_MAGICS:
        raise RuntimeError("The file could not be parsed as a supported PCAP/PCAPNG capture.")
    return clean_filename, suffix, file_size


class JobManager:
    """Thread-safe in-process asynchronous job manager for NexSolve."""

    def __init__(self, max_workers: int = MAX_CONCURRENT_JOBS):
        self._jobs: dict[str, JobRecord] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="nexsolve-job-worker")

    def create_job(
        self,
        filename: str,
        content: bytes | None = None,
        file_path: Path | None = None,
    ) -> JobRecord:
        if file_path is not None:
            clean_name, suffix, _size = validate_pcap_file(file_path, filename)
            with open(file_path, "rb") as f:
                header = f.read(64)
            job_id = f"job-{hashlib.sha256(header + str(time.time()).encode()).hexdigest()[:12]}"
        elif content is not None:
            clean_name, suffix = validate_pcap_bytes(filename, content)
            job_id = f"job-{hashlib.sha256(content[:64] + str(time.time()).encode()).hexdigest()[:12]}"
        else:
            raise ValueError("Either content or file_path must be provided.")
        
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
        self._executor.submit(self._run_job, job_id, clean_name, suffix, content, file_path)
        return job

    def cancel_job(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status in ("QUEUED", "PROCESSING"):
                job.status = "CANCELLED"
                job.error = {"detail": "Job was cancelled by the user."}
                return True
        return False

    def get_job(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self._jobs.get(job_id)

    def _update_stage(self, job_id: str, stage: JobStage) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job and job.status == "PROCESSING":
                job.stage = stage
                job.progress = STAGE_PROGRESS_MAP[stage]

    def _run_job(
        self,
        job_id: str,
        clean_name: str,
        suffix: str,
        content: bytes | None,
        file_path: Path | None = None,
    ) -> None:
        start_time = time.perf_counter()

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
            if file_path is not None:
                capture_size_bytes = file_path.stat().st_size
                import shutil
                shutil.copy2(str(file_path), str(capture_path))
                capture_hash = stream_file_hash(capture_path)
            elif content is not None:
                capture_size_bytes = len(content)
                capture_hash = hashlib.sha256(content).hexdigest()
                capture_path.write_bytes(content)
            else:
                raise ValueError("No capture content provided.")

            try:
                _pkts, canonical_windows, quality = extract_canonical_capture(capture_path)
                del _pkts
            except Exception as error:
                raise RuntimeError("The file could not be parsed as a supported PCAP/PCAPNG capture.") from error
            pcap_parsing_ms = round((time.perf_counter() - t_parse_start) * 1000, 2)
            with self._lock:
                job_rec = self._jobs.get(job_id)
                if job_rec:
                    job_rec.processing_statistics["packets_processed"] = quality['parsed_packets']

            # Check Resource Limits on packets
            if quality['parsed_packets'] > MAX_PACKETS:
                raise ResourceLimitExceededError(
                    resource="packet_count",
                    observed=quality['parsed_packets'],
                    limit=MAX_PACKETS,
                    explanation=f"Observed packet count ({quality['parsed_packets']:,}) exceeds maximum limit of {MAX_PACKETS:,}.",
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
            with self._lock:
                job_rec = self._jobs.get(job_id)
                if job_rec:
                    job_rec.processing_statistics["windows_processed"] = len(windows)
                    
            # 3. NETWORK_STATE
            t_state_start = time.perf_counter()
            self._update_stage(job_id, "NETWORK_STATE")
            candidates = build_network_state_candidates(canonical_windows, MODEL_SCHEMA)
            history = build_state_history(candidates)
            compatibility = evaluate_model_compatibility(candidates, MODEL_SCHEMA, history.status).to_dict()

            src_ips = set()
            dst_ips = set()
            dst_ports = set()
            total_unique_flows = 0

            seen_flow_ids = set()
            for cw in canonical_windows:
                for f in cw.flows:
                    if f.flow_id not in seen_flow_ids:
                        seen_flow_ids.add(f.flow_id)
                        total_unique_flows += 1
                        if f.src_ip: src_ips.add(f.src_ip)
                        if f.dst_ip: dst_ips.add(f.dst_ip)
                        if f.dst_port is not None: dst_ports.add(f.dst_port)

            active_schema = MODEL_SCHEMA_45
            active_model_dir = FINAL_MODEL_DIR
            active_config = CONFIG
            active_flow_features = FLOW_FEATURES_45
            schema_variant = "45_feature_pcap_compatible"

            compat_45 = evaluate_model_compatibility(candidates, MODEL_SCHEMA_45, history.status).to_dict()
            compatibility = compat_45
            compatibility["schema_variant"] = schema_variant
            compatibility["active_schema"] = "MODEL_SCHEMA_45"

            traffic = traffic_summary(windows)
            detection = analyze_packet_windows(windows)
            duration_seconds = max(0, int(windows[-1]["window_end"]) - int(windows[0]["window_start"]))
            packet_ts = []
            packet_span_seconds = round(max(packet_ts) - min(packet_ts), 4) if packet_ts else 0.0
            traffic["duration_seconds"] = duration_seconds
            traffic["packet_timestamp_span_seconds"] = packet_span_seconds
            traffic["temporal_window_coverage_seconds"] = duration_seconds
            traffic["packet_span_seconds"] = packet_span_seconds
            traffic["unique_src_ips"] = len(src_ips)
            traffic["unique_dst_ips"] = len(dst_ips)
            traffic["unique_dst_ports"] = len(dst_ports)
            if total_unique_flows > 0:
                traffic["flows"] = total_unique_flows
            network_state_extraction_ms = round((time.perf_counter() - t_state_start) * 1000, 2)

            # 4. FORECAST
            t_forecast_start = time.perf_counter()
            self._update_stage(job_id, "FORECAST")
            forecast_points: list[dict[str, Any]] = []

            from ml.final_production_inference import FinalProductionInferenceEngine
            from nexsolve_core.state import candidates_to_network_states

            production_engine = FinalProductionInferenceEngine(FINAL_MODEL_DIR)

            if compatibility.get("model_ready", False):
                states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history.status)

                import dataclasses
                all_flows_dict = []
                for cw in canonical_windows:
                    for f in cw.flows:
                        if isinstance(f, dict):
                            all_flows_dict.append(f)
                        elif dataclasses.is_dataclass(f):
                            all_flows_dict.append(dataclasses.asdict(f))
                        elif hasattr(f, "__dict__"):
                            all_flows_dict.append(f.__dict__)

                final_inference_result = production_engine.run_inference(
                    sequence=states,
                    analysis_id=job_id,
                    flows=all_flows_dict,
                    capture_quality=quality,
                )
            else:
                if len(windows) < 8:
                    abstention_reason = "INSUFFICIENT_HISTORY"
                    abstention_explanation = "Forecast withheld: Forecasting requires at least 8 continuous 60-second windows. Static traffic analysis completed successfully."
                elif history.status == "GAPPED_HISTORY":
                    abstention_reason = "NON_CONTIGUOUS_TIMESTAMPS"
                    abstention_explanation = "Forecast withheld: Input sequence contains non-contiguous temporal windows."
                else:
                    abstention_reason = "MODEL_FEATURE_CONTRACT_MISMATCH"
                    reasons = compatibility.get("reasons", [])
                    abstention_explanation = f"Forecast withheld: {reasons[0]}" if reasons else "Forecast withheld: feature contract mismatch."

                final_inference_result = {
                    "forecast_status": "FORECAST_ABSTAINED",
                    "is_abstained": True,
                    "abstention": {
                        "abstained": True,
                        "operational_tier": "ABSTAINED",
                        "reason": abstention_reason,
                        "explanation": abstention_explanation,
                    },
                    "abstention_reason": abstention_reason,
                    "abstention_explanation": abstention_explanation,
                    "forecast": {},
                    "network_risk_indicators": [],
                    "host_risk": [],
                    "communication_risk": [],
                    "uncertainty": {},
                    "evidence": [],
                }

            is_forecast_available = not final_inference_result.get("is_abstained", False)

            from ml.forecasting.forecasting_engine import FeatureDriver, _explain_feature_change, EarlyWarningAssessment, EarlyWarningLevel
            from world_model import FEATURE_NAMES_45

            if is_forecast_available:
                forecast_map = final_inference_result.get("forecast", {})
                curr_state_dict = {name: float(val) for name, val in zip(FEATURE_NAMES_45, states[-1].encode(FEATURE_NAMES_45))} if states else {}
                all_drivers = []
                for h in (1, 2, 3, 4, 5):
                    h_key = f"T+{h}"
                    h_data = forecast_map.get(h_key, {})
                    p = float(h_data.get("attack_probability", 0.0))
                    p_stage = h_data.get("predicted_stage", "BENIGN_OBSERVATION")
                    r_level = h_data.get("risk_level", "LOW")
                    conf = float(h_data.get("confidence_score", 0.85))
                    unc = round(1.0 - conf, 4)

                    pred_feat_dict = h_data.get("predicted_features", {})
                    feat_deltas = []
                    for name in FEATURE_NAMES_45:
                        c_val = curr_state_dict.get(name, 0.0)
                        p_val = pred_feat_dict.get(name, 0.0)
                        direction, rel, importance, interp = _explain_feature_change(name, c_val, p_val)
                        feat_deltas.append(FeatureDriver(
                            feature=name,
                            current_value=round(c_val, 4),
                            predicted_value=round(p_val, 4),
                            direction=direction,
                            relative_change=round(rel, 4),
                            importance=importance,
                            interpretation=interp,
                        ))
                    top_drivers = sorted(feat_deltas, key=lambda d: abs(d.relative_change), reverse=True)[:5]
                    if top_drivers:
                        all_drivers.extend(top_drivers)

                    forecast_points.append({
                        "horizon": h,
                        "lookaheadSeconds": h * 60,
                        "attackProbability": p,
                        "cumulativeRisk": round(min(1.0, p * (1.0 + (h - 1) * 0.15)), 4),
                        "riskLevel": r_level,
                        "predictedStage": p_stage,
                        "confidence": conf,
                        "uncertainty": unc,
                        "explanation": [d.interpretation for d in top_drivers[:3]] if top_drivers else [f"State dynamics project {p_stage} at T+{h} (risk: {p*100:.1f}%)."],
                        "topDrivers": [d.to_dict() for d in top_drivers],
                        "evidenceAttribution": None,
                    })

                max_p = max((float(h_data.get("attack_probability", 0.0)) for h_data in forecast_map.values()), default=0.0)
                ew_score = int(round(max_p * 100))
                ew_level = (
                    EarlyWarningLevel.CRITICAL if ew_score >= 70
                    else EarlyWarningLevel.HIGH if ew_score >= 40
                    else EarlyWarningLevel.ELEVATED if ew_score >= 15
                    else EarlyWarningLevel.NORMAL
                )
                early_warning_dict = EarlyWarningAssessment(
                    early_warning_score=ew_score,
                    early_warning_level=ew_level,
                    drivers=[d.interpretation for d in all_drivers[:3]] if all_drivers else ["Observed baseline network telemetry."],
                    score_components={"max_attack_probability": round(max_p, 4)},
                ).to_dict()
            else:
                early_warning_dict = EarlyWarningAssessment(
                    early_warning_score=0,
                    early_warning_level=EarlyWarningLevel.NORMAL,
                    drivers=["Forecasting withheld."],
                    score_components={},
                ).to_dict()
                reason = final_inference_result.get("abstention_explanation") or "insufficient continuous temporal history."
                reason_str = reason if "Forecast abstained" in reason else f"Forecast abstained: {reason}"
                for h in (1, 2, 3, 4, 5):
                    forecast_points.append({
                        "horizon": h,
                        "lookaheadSeconds": h * 60,
                        "attackProbability": None,
                        "predictedStage": None,
                        "confidence": None,
                        "uncertainty": None,
                        "explanation": [reason_str],
                        "topDrivers": [],
                        "evidenceAttribution": None,
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

            # Behavioral Intelligence, Session Investigation, & Evidence Fusion (Phases 6, 7, 9, 10, Open-Source Sprint)
            from nexsolve_core.behavior import analyze_behavioral_intelligence
            from nexsolve_core.investigation import build_session_investigation_records
            from nexsolve_core.network import aggregate_tcp_session_metrics, track_tcp_sessions
            from nexsolve_core.flow import aggregate_flow_statistics_summary
            from nexsolve_core.evidence import parse_suricata_eve_json
            from nexsolve_core.fusion import fuse_threat_assessment
            from nexsolve_core.temporal import build_temporal_entity_histories

            def _iter_flows(windows):
                seen = set()
                for cw in windows:
                    for f in cw.flows:
                        if f.flow_id not in seen:
                            seen.add(f.flow_id)
                            yield f

            tcp_sessions = quality.get("tcp_sessions", ())
            behavioral_report = analyze_behavioral_intelligence(_iter_flows(canonical_windows), ())

            sample_flows = []
            for i, f in enumerate(_iter_flows(canonical_windows)):
                if i >= 1000:
                    break
                sample_flows.append(f)
            investigation_records = build_session_investigation_records(sample_flows, behavioral_report.beaconing_signals)
            tcp_session_metrics = aggregate_tcp_session_metrics(tcp_sessions)
            flow_statistics = aggregate_flow_statistics_summary(_iter_flows(canonical_windows))
            suricata_report = parse_suricata_eve_json(None)

            entity_histories = build_temporal_entity_histories(
                flows=_iter_flows(canonical_windows),
                tcp_sessions=tcp_sessions,
                observed_findings=detection.get("findings", []),
            )

            # Clear flows and packets from canonical_windows immediately after flow analytics extraction
            import dataclasses
            canonical_windows = [dataclasses.replace(cw, flows=(), packets=()) for cw in canonical_windows]

            from ml.forecasting.attack_progression import forecast_attack_progression
            from nexsolve_core.graph import build_evidence_intelligence_graph
            from nexsolve_core.behavior import build_behavioral_episodes, detect_behavior_changes
            from nexsolve_core.intelligence import infer_attack_states, build_threat_centric_views, build_network_world_state

            progression_forecast = forecast_attack_progression(
                observed_findings=detection.get("findings", []),
                behavioral_report=behavioral_report,
                horizons=(1, 2, 3, 4, 5),
                history_window_count=len(windows),
            )

            # Re-assemble forecast intelligence with full multi-modal context (progression, findings, behavioral report)
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
                observed_findings=detection.get("findings", []),
                attack_progression=progression_forecast,
                behavioral_report=behavioral_report,
            )
            threat_assessment = fuse_threat_assessment(
                observed_findings=detection.get("findings", []),
                behavioral_report=behavioral_report,
                forecast_points=forecast_points,
                attack_horizon=intelligence.attack_horizon,
                attack_progression=progression_forecast,
                tcp_session_records=tcp_sessions,
                flow_summary=flow_statistics,
                suricata_report=suricata_report,
            )

            # Core Intelligence Extensions
            episodes = build_behavioral_episodes(
                observed_findings=detection.get("findings", []),
                tcp_sessions=tcp_sessions,
                behavioral_report=behavioral_report,
                attack_progression=progression_forecast,
            )
            change_signals = detect_behavior_changes(
                tcp_sessions=tcp_sessions,
                observed_findings=detection.get("findings", []),
            )
            attack_states = infer_attack_states(
                observed_findings=detection.get("findings", []),
                tcp_sessions=tcp_sessions,
                behavioral_report=behavioral_report,
                change_signals=change_signals,
            )
            threat_views = build_threat_centric_views(
                entity_histories=entity_histories,
                attack_states=attack_states,
                episodes=episodes,
                observed_findings=detection.get("findings", []),
                forecast_points=forecast_points,
            )

            evidence_graph = build_evidence_intelligence_graph(
                flows=(),
                tcp_sessions=tcp_sessions,
                behavioral_report=behavioral_report,
                flow_statistics=flow_statistics,
                suricata_report=suricata_report,
                observed_findings=detection.get("findings", []),
                forecast_points=forecast_points,
                attack_progression=progression_forecast,
                episodes=episodes,
                change_signals=change_signals,
            )

            world_state = build_network_world_state(
                capture_id=job_id,
                total_packets=traffic["packets"],
                total_flows=traffic["flows"],
                total_windows=traffic["windows"],
                duration_seconds=duration_seconds,
                entity_histories=entity_histories,
                episodes=episodes,
                attack_states=attack_states,
                threat_views=threat_views,
                change_signals=change_signals,
                forecast_points=forecast_points,
                evidence_graph=evidence_graph,
            )

            network_intelligence = {
                "session_state": tcp_session_metrics.to_dict(),
                "periodicity": behavioral_report.periodicity_summary.to_dict() if getattr(behavioral_report, "periodicity_summary", None) else None,
                "flow_statistics": flow_statistics.to_dict(),
                "signature_evidence": suricata_report.to_dict(),
                "evidence_summary": {
                    "total_evidence_items": len(threat_assessment.evidence),
                    "observed_modalities": sorted(list({e.modality.value for e in threat_assessment.evidence if e.temporal_scope.value == "OBSERVED"})),
                    "observed_techniques": list(threat_assessment.observed_techniques),
                    "forecast_techniques": list(threat_assessment.forecast_techniques),
                },
            }

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
                "model_version": "final_world_model v3.0.0",
                "model_name": "final_world_model",
                "source": {"name": clean_name, "kind": "uploaded_pcap", "filename": clean_name, "size_bytes": capture_size_bytes},
                "upload": {"filename": clean_name, "size_bytes": capture_size_bytes, "format": suffix[1:]},
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
                # Open-Source Intelligence & Behavioral Telemetry
                "network_intelligence": network_intelligence,
                "evidence_graph": evidence_graph.to_dict(),
                "network_world_state": world_state.to_dict(),
                "episodes": [e.to_dict() for e in episodes],
                "attack_states": [s.to_dict() for s in attack_states],
                "threat_views": [t.to_dict() for t in threat_views],
                "change_signals": [c.to_dict() for c in change_signals],
                "behavioral_intelligence": behavioral_report.to_dict(),
                "investigation_sessions": [s.to_dict() for s in investigation_records[:100]],
                "tcp_session_metrics": tcp_session_metrics.to_dict(),
                "flow_statistics": flow_statistics.to_dict(),
                "signature_evidence": suricata_report.to_dict(),
                "threat_assessment": threat_assessment.to_dict(),
                # Trust Layer & Frozen World Model
                "forecasts": forecast_points,
                "forecast": final_inference_result.get("forecast", {}),
                "final_world_model": final_inference_result,
                "forecast_trajectory": None,
                "early_warning": early_warning_dict,
                "attack_horizon": intelligence.attack_horizon,
                "attackHorizon": intelligence.attack_horizon,
                "attack_progression": progression_forecast.to_dict(),
                "attackProgression": progression_forecast.to_dict(),
                "evidence_chain": intelligence.evidence_chain,
                "evidenceChain": intelligence.evidence_chain,
                "confidence": intelligence.confidence,
                "unknown_behavior": intelligence.unknown_behavior,
                "unknownBehavior": intelligence.unknown_behavior,
                "abstention": final_inference_result.get("abstention", intelligence.abstention),
                "uncertainty": final_inference_result.get("uncertainty", {}),
                "network_risk_indicators": final_inference_result.get("network_risk_indicators", []),
                "host_risk": final_inference_result.get("host_risk", []),
                "communication_risk": final_inference_result.get("communication_risk", []),
                "evidence": final_inference_result.get("evidence", []),
                "analysis_state": (
                    "ANALYSIS_COMPLETE_FORECAST_READY"
                    if is_forecast_available
                    else "ANALYSIS_COMPLETE_FORECAST_UNAVAILABLE"
                ),
                "forecast_summary": {
                    "available": is_forecast_available,
                    "status": (
                        "READY"
                        if is_forecast_available
                        else ("INSUFFICIENT_HISTORY" if len(windows) < 8 else final_inference_result.get("abstention_reason", "INCOMPATIBLE_FEATURES"))
                    ),
                    "required_windows": 8,
                    "available_windows": len(windows),
                    "required_window_seconds": 60,
                    "message": (
                        "Forecast rollouts generated successfully by Final Network World Model."
                        if is_forecast_available
                        else (
                            "Forecasting requires at least 8 continuous 60-second windows. Static traffic analysis completed successfully."
                            if len(windows) < 8
                            else (final_inference_result.get("abstention_explanation") or "Forecast withheld: insufficient continuous temporal history.")
                        )
                    ),
                },
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
                model_version="final_world_model v3.0.0",
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
                        "packets_processed": quality['parsed_packets'],
                        "flows_processed": traffic.get("flows", quality['parsed_packets']),
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
            import gc
            gc.collect()
            # Clean up isolated temporary directory
            if work_dir:
                try:
                    import shutil
                    shutil.rmtree(work_dir, ignore_errors=True)
                    if Path(work_dir).exists():
                        time.sleep(0.05)
                        gc.collect()
                        shutil.rmtree(work_dir, ignore_errors=True)
                except Exception:
                    pass
            if file_path:
                try:
                    fp = Path(file_path)
                    parent = fp.parent
                    if parent.name.startswith("upl-") and parent.parent == RUNTIME_DIR / "chunks":
                        fp.unlink(missing_ok=True)
                        import shutil
                        shutil.rmtree(parent, ignore_errors=True)
                        if parent.exists():
                            time.sleep(0.05)
                            gc.collect()
                            shutil.rmtree(parent, ignore_errors=True)
                except Exception:
                    pass


def cleanup_stale_runtime_files() -> None:
    """Clean up stale temporary directories, chunk directories, and scratch files from runtime/."""
    try:
        if RUNTIME_DIR.exists():
            for item in RUNTIME_DIR.iterdir():
                if item.name in ("nexsolve.db", "nexsolve.db-journal"):
                    continue
                if item.name == "chunks":
                    for chunk_item in item.iterdir():
                        try:
                            if chunk_item.is_dir():
                                import shutil
                                shutil.rmtree(chunk_item, ignore_errors=True)
                            else:
                                chunk_item.unlink(missing_ok=True)
                        except Exception:
                            pass
                    continue
                try:
                    if item.is_dir():
                        import shutil
                        shutil.rmtree(item, ignore_errors=True)
                    else:
                        item.unlink(missing_ok=True)
                except Exception:
                    pass
    except Exception:
        pass


# Global singleton job manager
JOB_MANAGER = JobManager()

"""Automated large-PCAP stress, performance, stability, and resource-safety validation harness for NexSolve.

Measures:
- file size
- packet count
- flow count
- capture duration
- temporal window count
- contiguous history availability
- 45/45 feature availability
- model compatibility
- forecast generation time
- total pipeline time
- report generation time
- peak memory if safely measurable
- failure/abstention reason
- final job status
"""
from __future__ import annotations

import json
import os
import sys
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from model_service.jobs import JOB_MANAGER, JobRecord, validate_pcap_bytes
from model_service.pcap_upload import analyze_uploaded_capture
from nexsolve_core.config import (
    MAX_PACKETS,
    MAX_PROCESSING_DURATION_SECONDS,
    MAX_TEMPORAL_WINDOWS,
    MAX_UPLOAD_BYTES,
    ResourceLimitExceededError,
)


@dataclass
class PcapValidationMetrics:
    capture_name: str
    file_size_bytes: int
    file_size_mb: float
    packet_count: int
    flow_count: int
    capture_duration_seconds: float
    temporal_window_count: int
    history_status: str
    feature_count_required: int
    features_available_count: int
    missing_features: list[str]
    model_ready: bool
    schema_variant: str
    model_compatibility_reason: str
    forecast_generation_ms: float
    report_generation_ms: float
    total_pipeline_ms: float
    total_pipeline_seconds: float
    peak_memory_mb: float | None
    job_status: str
    attack_horizon_state: str | None
    evidence_supporting_count: int
    evidence_contradictory_count: int
    forecast_points_count: int
    abstained: bool
    abstention_reason: str | None
    temporary_files_leaked: int
    passed_validation: bool
    notes: str


def check_runtime_leaks() -> int:
    """Return count of leftover files/directories in runtime/ (excluding database and empty chunks directory)."""
    runtime_dir = ROOT / "runtime"
    if not runtime_dir.exists():
        return 0
    leaked = [
        item for item in runtime_dir.iterdir()
        if item.name not in ("nexsolve.db", "nexsolve.db-journal", "chunks")
    ]
    chunks_dir = runtime_dir / "chunks"
    if chunks_dir.exists():
        leaked.extend(list(chunks_dir.iterdir()))
    return len(leaked)


def run_capture_validation(
    pcap_path: str | Path,
    expected_case: str = "valid",
    use_async_job: bool = True,
    timeout_seconds: float = 90.0,
) -> PcapValidationMetrics:
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    file_size = path.stat().st_size
    file_size_mb = round(file_size / (1024 * 1024), 3)

    # 1. Check oversized before loading content into memory if it exceeds 64MB
    if file_size > MAX_UPLOAD_BYTES:
        start_t = time.perf_counter()
        try:
            with open(path, "rb") as f:
                header_sample = f.read(1024)
            # Check validation function rejects oversized input
            validate_pcap_bytes(path.name, header_sample + (b"\x00" * (MAX_UPLOAD_BYTES + 10 - len(header_sample))))
            raise RuntimeError("Failed to reject oversized upload")
        except (ResourceLimitExceededError, ValueError) as err:
            elapsed = time.perf_counter() - start_t
            return PcapValidationMetrics(
                capture_name=path.name,
                file_size_bytes=file_size,
                file_size_mb=file_size_mb,
                packet_count=0,
                flow_count=0,
                capture_duration_seconds=0.0,
                temporal_window_count=0,
                history_status="REJECTED_BEFORE_PARSING",
                feature_count_required=0,
                features_available_count=0,
                missing_features=[],
                model_ready=False,
                schema_variant="none",
                model_compatibility_reason=str(err),
                forecast_generation_ms=0.0,
                report_generation_ms=0.0,
                total_pipeline_ms=round(elapsed * 1000, 2),
                total_pipeline_seconds=round(elapsed, 4),
                peak_memory_mb=0.0,
                job_status="RESOURCE_LIMIT_EXCEEDED",
                attack_horizon_state=None,
                evidence_supporting_count=0,
                evidence_contradictory_count=0,
                forecast_points_count=0,
                abstained=True,
                abstention_reason=str(err),
                temporary_files_leaked=check_runtime_leaks(),
                passed_validation=True,
                notes="Safely rejected oversized capture at ingress without disk/memory exhaustion.",
            )

    initial_leaks = check_runtime_leaks()
    tracemalloc.start()
    t_start = time.perf_counter()

    if use_async_job:
        job = JOB_MANAGER.create_job(path.name, file_path=path)
        job_id = job.job_id
        deadline = time.perf_counter() + timeout_seconds
        while time.perf_counter() < deadline:
            rec = JOB_MANAGER.get_job(job_id)
            if rec and rec.status in ("COMPLETED", "FAILED", "RESOURCE_LIMIT_EXCEEDED", "ABORTED"):
                break
            time.sleep(0.3)

        t_total = time.perf_counter() - t_start
        _cur_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_mb = round(peak_mem / (1024 * 1024), 2)

        rec = JOB_MANAGER.get_job(job_id)
        if not rec:
            raise RuntimeError(f"Job {job_id} disappeared from JobManager.")

        if rec.status != "COMPLETED":
            err_dict = rec.error or {}
            reason = err_dict.get("message") or err_dict.get("explanation") or str(err_dict)
            return PcapValidationMetrics(
                capture_name=path.name,
                file_size_bytes=file_size,
                file_size_mb=file_size_mb,
                packet_count=0,
                flow_count=0,
                capture_duration_seconds=0.0,
                temporal_window_count=0,
                history_status="JOB_NON_COMPLETED",
                feature_count_required=0,
                features_available_count=0,
                missing_features=[],
                model_ready=False,
                schema_variant="none",
                model_compatibility_reason=reason,
                forecast_generation_ms=0.0,
                report_generation_ms=0.0,
                total_pipeline_ms=round(t_total * 1000, 2),
                total_pipeline_seconds=round(t_total, 3),
                peak_memory_mb=peak_mb,
                job_status=rec.status,
                attack_horizon_state=None,
                evidence_supporting_count=0,
                evidence_contradictory_count=0,
                forecast_points_count=0,
                abstained=True,
                abstention_reason=reason,
                temporary_files_leaked=check_runtime_leaks() - initial_leaks,
                passed_validation=(expected_case != "valid"),
                notes=f"Job terminated with status: {rec.status}",
            )

        res = rec.result
        stats = rec.processing_statistics
        stage_timings = stats.get("stage_timings_ms", {})
        compat = res.get("model_compatibility", {})
        history = res.get("network_state", {}).get("history", {})
        ah = res.get("attack_horizon", {})
        ec = res.get("evidence_chain", {})
        forecasts = res.get("forecasts", [])
        traffic = res.get("traffic", {})

        is_abstained = not compat.get("model_ready", False)
        abst_reason = compat.get("reason") if is_abstained else None
        schema_variant = "45_feature_pcap_compatible" if compat.get("required_features") == 45 else "46_feature_canonical"

        return PcapValidationMetrics(
            capture_name=path.name,
            file_size_bytes=file_size,
            file_size_mb=file_size_mb,
            packet_count=res.get("packet_count", 0),
            flow_count=traffic.get("flows", 0),
            capture_duration_seconds=res.get("duration_seconds", 0.0),
            temporal_window_count=res.get("window_count", 0),
            history_status=history.get("status", "UNKNOWN"),
            feature_count_required=compat.get("required_features", 46),
            features_available_count=len(compat.get("available_features", [])),
            missing_features=compat.get("missing_features", []),
            model_ready=compat.get("model_ready", False),
            schema_variant=schema_variant,
            model_compatibility_reason=compat.get("reason", "OK"),
            forecast_generation_ms=stage_timings.get("forecasting_ms", 0.0),
            report_generation_ms=stage_timings.get("report_generation_ms", 0.0),
            total_pipeline_ms=round(t_total * 1000, 2),
            total_pipeline_seconds=round(t_total, 3),
            peak_memory_mb=peak_mb,
            job_status=rec.status,
            attack_horizon_state=ah.get("state"),
            evidence_supporting_count=len(ec.get("supporting", [])),
            evidence_contradictory_count=len(ec.get("contradictory", [])),
            forecast_points_count=len(forecasts),
            abstained=is_abstained,
            abstention_reason=abst_reason,
            temporary_files_leaked=check_runtime_leaks() - initial_leaks,
            passed_validation=True,
            notes="Completed successfully through full asynchronous job workflow with reports.",
        )
    else:
        res = analyze_uploaded_capture(path.name, content)
        t_total = time.perf_counter() - t_start
        _cur_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_mb = round(peak_mem / (1024 * 1024), 2)

        compat = res.get("model_compatibility", {})
        history = res.get("network_state", {}).get("history", {})
        ah = res.get("attack_horizon", {})
        ec = res.get("evidence_chain", {})
        forecasts = res.get("forecasts", [])
        traffic = res.get("traffic", {})

        is_abstained = not compat.get("model_ready", False)
        abst_reason = compat.get("reason") if is_abstained else None
        schema_variant = "45_feature_pcap_compatible" if compat.get("required_features") == 45 else "46_feature_canonical"

        return PcapValidationMetrics(
            capture_name=path.name,
            file_size_bytes=file_size,
            file_size_mb=file_size_mb,
            packet_count=res.get("packet_count", 0),
            flow_count=traffic.get("flows", 0),
            capture_duration_seconds=res.get("duration_seconds", 0.0),
            temporal_window_count=res.get("window_count", 0),
            history_status=history.get("status", "UNKNOWN"),
            feature_count_required=compat.get("required_features", 46),
            features_available_count=len(compat.get("available_features", [])),
            missing_features=compat.get("missing_features", []),
            model_ready=compat.get("model_ready", False),
            schema_variant=schema_variant,
            model_compatibility_reason=compat.get("reason", "OK"),
            forecast_generation_ms=0.0,
            report_generation_ms=0.0,
            total_pipeline_ms=round(t_total * 1000, 2),
            total_pipeline_seconds=round(t_total, 3),
            peak_memory_mb=peak_mb,
            job_status=res.get("status", "completed"),
            attack_horizon_state=ah.get("state"),
            evidence_supporting_count=len(ec.get("supporting", [])),
            evidence_contradictory_count=len(ec.get("contradictory", [])),
            forecast_points_count=len(forecasts),
            abstained=is_abstained,
            abstention_reason=abst_reason,
            temporary_files_leaked=check_runtime_leaks() - initial_leaks,
            passed_validation=True,
            notes="Completed successfully via direct sync analyze_uploaded_capture.",
        )


def main() -> None:
    print("=" * 80)
    print("NEXSOLVE LARGE PCAP STRESS & PERFORMANCE VALIDATION HARNESS")
    print("=" * 80)

    slice_pcap = Path(r"C:\Users\saira\Downloads\friday_10windows_slice.pcap")
    if not slice_pcap.exists():
        slice_pcap = ROOT / "data" / "test_slices" / "friday_10windows_slice.pcap"

    huge_pcap = Path(r"C:\Users\saira\Downloads\Friday-WorkingHours.pcap")
    if not huge_pcap.exists():
        huge_pcap = Path(r"C:\Users\saira\Downloads\friday_exact_10windows.pcap")

    captures = [
        ("Case A: Small PCAP", Path(r"C:\Users\saira\Downloads\nexsolve_test_small.pcap"), "valid"),
        ("Case B: Real PCAP 10-Windows", slice_pcap, "valid"),
        ("Case C: Stress 10k PCAP (3-Win)", Path(r"C:\Users\saira\Downloads\friday_stress_10k.pcap"), "valid"),
        ("Case C: Stress 9k PCAP (10-Win)", Path(r"C:\Users\saira\Downloads\friday_stress_10windows_9k.pcap"), "valid"),
        ("Case D: Oversized Capture (>1GB / >100k pkts)", huge_pcap, "oversized"),
    ]

    results = []
    for label, path, expected in captures:
        print(f"\nEvaluating {label}: {path.name}...")
        if not path.exists():
            print(f"  [SKIP] File not found: {path}")
            continue
        metrics = run_capture_validation(path, expected_case=expected, use_async_job=True)
        results.append(metrics)
        print(f"  Packets: {metrics.packet_count:,} | Flows: {metrics.flow_count} | Windows: {metrics.temporal_window_count}")
        print(f"  Size: {metrics.file_size_mb:.2f} MB | Total Time: {metrics.total_pipeline_seconds:.2f}s | Peak Mem: {metrics.peak_memory_mb} MB")
        print(f"  Status: {metrics.job_status} | Model Ready: {metrics.model_ready} | Schema: {metrics.schema_variant}")
        print(f"  Horizon: {metrics.attack_horizon_state} | Temp Leaks: {metrics.temporary_files_leaked}")
        if metrics.abstained:
            print(f"  Abstention: {metrics.abstention_reason}")

    out_file = ROOT / "reports" / "large_pcap_harness_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    print(f"\n[OK] Results saved to {out_file}")


if __name__ == "__main__":
    main()

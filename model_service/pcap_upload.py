"""Isolated uploaded-PCAP analysis using the existing packet and heuristic pipeline."""
from __future__ import annotations

import tempfile
import uuid
from pathlib import Path
from typing import Any

from ml.data.pcap_extractor import extract_packet_windows
from ml.detection import analyze_packet_windows, traffic_summary
from model_service.database import DatabaseStorageError, get_analysis, persist_analysis

MAX_UPLOAD_BYTES = 64 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_MAGICS = {
    bytes.fromhex("0a0d0d0a"), bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"), bytes.fromhex("a1b23c4d"), bytes.fromhex("d4c3b2a1"),
}
RUNTIME_DIR = Path(__file__).resolve().parents[1] / "runtime"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)


def _validation(windows: list[dict[str, Any]]) -> dict[str, Any]:
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
            "flow_features_available": False,
            "packet_features_available": True,
            "labels_available": False,
            "forecast_model_ready": False,
            "reason": "Uploaded capture was analyzed as packet aggregates; no labels or forecast-model contract are inferred.",
        },
    }


def analyze_uploaded_capture(filename: str, content: bytes) -> dict[str, Any]:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .pcap and .pcapng captures are supported.")
    if not content:
        raise ValueError("The uploaded capture is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.")
    if content[:4] not in PCAP_MAGICS:
        raise RuntimeError("The file could not be parsed as a supported PCAP/PCAPNG capture.")

    analysis_id = f"upload-{uuid.uuid4().hex}"
    with tempfile.TemporaryDirectory(prefix=f"nexsolve-{analysis_id}-", dir=RUNTIME_DIR) as work_dir:
        capture_path = Path(work_dir) / f"capture{suffix}"
        capture_path.write_bytes(content)
        try:
            windows, quality = extract_packet_windows(capture_path)
        except Exception as error:
            raise RuntimeError("The file could not be parsed as a supported PCAP/PCAPNG capture.") from error

    if not windows:
        raise RuntimeError("The capture contained no parseable timestamped packets.")
    traffic = traffic_summary(windows)
    detection = analyze_packet_windows(windows)
    duration_seconds = max(0, int(windows[-1]["window_end"]) - int(windows[0]["window_start"]))
    result = {
        "analysis_id": analysis_id,
        "status": "completed",
        "source": {"name": filename, "kind": "uploaded_pcap", "filename": filename, "size_bytes": len(content)},
        "upload": {"filename": filename, "size_bytes": len(content), "format": suffix[1:]},
        "validation": _validation(windows),
        "traffic": traffic,
        "detection": detection,
        "quality": quality,
        "packet_count": traffic["packets"],
        "window_count": traffic["windows"],
        "duration_seconds": duration_seconds,
        "protocol_summary": traffic["protocol_counts"],
        "findings": detection["findings"],
        "summary": {"packet_count": traffic["packets"], "window_count": traffic["windows"], "finding_count": detection["detected_events"], "threat_level": detection["threat_level"]},
    }
    return persist_analysis(result)


def get_uploaded_analysis(analysis_id: str) -> dict[str, Any] | None:
    return get_analysis(analysis_id)

"""Isolated uploaded-PCAP analysis using the existing packet and heuristic pipeline."""
from __future__ import annotations

import tempfile
import uuid
import json
from pathlib import Path
from typing import Any

from ml.data.pcap_extractor import extract_canonical_capture
from ml.detection import analyze_packet_windows, traffic_summary
from model_service.database import DatabaseStorageError, get_analysis, persist_analysis
from nexsolve_core.state import build_network_state_candidates, build_state_history, evaluate_model_compatibility

MAX_UPLOAD_BYTES = 64 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_MAGICS = {
    bytes.fromhex("0a0d0d0a"), bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"), bytes.fromhex("a1b23c4d"), bytes.fromhex("d4c3b2a1"),
}
RUNTIME_DIR = Path(__file__).resolve().parents[1] / "runtime"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR = Path(__file__).resolve().parents[1] / "models" / "nexsolve_world_model"
MODEL_DIR_45 = Path(__file__).resolve().parents[1] / "models" / "nexsolve_world_model_45"
MODEL_SCHEMA = json.loads((MODEL_DIR / "feature_schema.json").read_text(encoding="utf-8"))
MODEL_SCHEMA_45 = json.loads((MODEL_DIR / "feature_schema_45.json").read_text(encoding="utf-8")) if (MODEL_DIR / "feature_schema_45.json").exists() else json.loads((MODEL_DIR_45 / "feature_schema.json").read_text(encoding="utf-8"))
CONFIG = json.loads((MODEL_DIR / "config.json").read_text(encoding="utf-8"))
CONFIG_45 = json.loads((MODEL_DIR_45 / "config.json").read_text(encoding="utf-8")) if (MODEL_DIR_45 / "config.json").exists() else CONFIG


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
            "flow_features_available": False,
            "packet_features_available": True,
            "labels_available": False,
            "forecast_model_ready": compatibility["model_ready"],
            "reason": compatibility["reason"],
            "available_features": compatibility["available_features"],
            "missing_features": compatibility["missing_features"],
            "unreliable_features": compatibility["unreliable_features"],
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
            _packets, canonical_windows, quality = extract_canonical_capture(capture_path)
        except Exception as error:
            raise RuntimeError("The file could not be parsed as a supported PCAP/PCAPNG capture.") from error

    if not canonical_windows:
        raise RuntimeError("The capture contained no parseable timestamped packets.")
    windows = [window.to_dict() for window in canonical_windows]
    candidates = build_network_state_candidates(canonical_windows, MODEL_SCHEMA)
    history = build_state_history(candidates)
    compatibility = evaluate_model_compatibility(candidates, MODEL_SCHEMA, history.status).to_dict()
    traffic = traffic_summary(windows)
    detection = analyze_packet_windows(windows)
    duration_seconds = max(0, int(windows[-1]["window_end"]) - int(windows[0]["window_start"]))
    packet_ts = [p.timestamp for p in _packets if p.timestamp is not None]
    packet_span_seconds = round(max(packet_ts) - min(packet_ts), 4) if packet_ts else 0.0
    traffic["duration_seconds"] = duration_seconds
    traffic["packet_timestamp_span_seconds"] = packet_span_seconds
    traffic["temporal_window_coverage_seconds"] = duration_seconds
    traffic["packet_span_seconds"] = packet_span_seconds
    if _packets:
        traffic["unique_src_ips"] = len({p.src_ip for p in _packets if p.src_ip})
        traffic["unique_dst_ips"] = len({p.dst_ip for p in _packets if p.dst_ip})
        traffic["unique_dst_ports"] = len({p.dst_port for p in _packets if p.dst_port is not None})
    if canonical_windows:
        all_flow_ids = {flow.flow_id for cw in canonical_windows for flow in cw.flows}
        if all_flow_ids:
            traffic["flows"] = len(all_flow_ids)

    active_schema = MODEL_SCHEMA
    active_model_dir = MODEL_DIR
    active_config = CONFIG
    active_flow_features = tuple(MODEL_SCHEMA.get("flow_features", ()))
    schema_variant = "46_feature_canonical"

    # Check if 45-feature PCAP-compatible schema can be activated:
    if not compatibility.get("model_ready", False):
        missing = compatibility.get("missing_features", [])
        if set(missing) == {"flow_features.mean_tcp_rtt"}:
            compat_45 = evaluate_model_compatibility(candidates, MODEL_SCHEMA_45, history.status).to_dict()
            if compat_45.get("model_ready", False) and MODEL_DIR_45.exists():
                compatibility = compat_45
                active_schema = MODEL_SCHEMA_45
                active_model_dir = MODEL_DIR_45
                active_config = CONFIG_45
                active_flow_features = tuple(MODEL_SCHEMA_45.get("flow_features", ()))
                schema_variant = "45_feature_pcap_compatible"

    # Trust Layer integration
    from ml.forecasting import assemble_forecast_intelligence
    forecast_points: list[dict[str, Any]] = []

    if compatibility.get("model_ready", False):
        try:
            from world_model import explain, forecast_k_steps, load_model
            from nexsolve_core.state import candidates_to_network_states
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
        provenance_info={"capture_id": analysis_id, "source": filename, "schema_variant": schema_variant},
        min_sequence_length=8,
        required_features=active_flow_features,
        calibration_status="UNSUPPORTED",
        decision_threshold=0.5,
        window_seconds=60,
    )

    result = {
        "analysis_id": analysis_id,
        "status": "completed",
        "source": {"name": filename, "kind": "uploaded_pcap", "filename": filename, "size_bytes": len(content)},
        "upload": {"filename": filename, "size_bytes": len(content), "format": suffix[1:]},
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
        # Trust Layer & Forecast Intelligence
        "forecasts": forecast_points,
        "attack_horizon": intelligence.attack_horizon,
        "attackHorizon": intelligence.attack_horizon,
        "evidence_chain": intelligence.evidence_chain,
        "evidenceChain": intelligence.evidence_chain,
        "confidence": intelligence.confidence,
        "unknown_behavior": intelligence.unknown_behavior,
        "unknownBehavior": intelligence.unknown_behavior,
        "abstention": intelligence.abstention,
    }
    return persist_analysis(result)


def get_uploaded_analysis(analysis_id: str) -> dict[str, Any] | None:
    return get_analysis(analysis_id)

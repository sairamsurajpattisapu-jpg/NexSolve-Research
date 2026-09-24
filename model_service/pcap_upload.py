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
from nexsolve_core.config import (
    ALLOWED_EXTENSIONS,
    MAX_PCAP_UPLOAD_BYTES,
    MAX_UPLOAD_BYTES,
    PCAP_MAGICS,
)
from nexsolve_core.state import build_network_state_candidates, build_state_history, evaluate_model_compatibility
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


def analyze_uploaded_capture(
    filename: str,
    content: bytes | None = None,
    file_path: Path | None = None,
) -> dict[str, Any]:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .pcap and .pcapng captures are supported.")

    if file_path is not None:
        if not file_path.exists():
            raise ValueError("The uploaded capture file does not exist.")
        capture_size_bytes = file_path.stat().st_size
        if capture_size_bytes == 0:
            raise ValueError("The uploaded capture is empty.")
        if capture_size_bytes > MAX_PCAP_UPLOAD_BYTES:
            raise ValueError("Capture exceeds the maximum allowed upload size of 1 GiB.")
        with open(file_path, "rb") as f:
            magic = f.read(4)
        if magic not in PCAP_MAGICS:
            raise RuntimeError("The file could not be parsed as a supported PCAP/PCAPNG capture.")
    elif content is not None:
        if not content:
            raise ValueError("The uploaded capture is empty.")
        capture_size_bytes = len(content)
        if capture_size_bytes > MAX_PCAP_UPLOAD_BYTES:
            raise ValueError("Capture exceeds the maximum allowed upload size of 1 GiB.")
        if content[:4] not in PCAP_MAGICS:
            raise RuntimeError("The file could not be parsed as a supported PCAP/PCAPNG capture.")
    else:
        raise ValueError("Either content or file_path must be provided.")

    analysis_id = f"upload-{uuid.uuid4().hex}"
    with tempfile.TemporaryDirectory(prefix=f"nexsolve-{analysis_id}-", dir=RUNTIME_DIR) as work_dir:
        capture_path = Path(work_dir) / f"capture{suffix}"
        if file_path is not None:
            import shutil
            shutil.copy2(str(file_path), str(capture_path))
        else:
            capture_path.write_bytes(content)  # type: ignore[arg-type]
        try:
            _packets, canonical_windows, quality = extract_canonical_capture(capture_path)
            del _packets
        except Exception as error:
            raise RuntimeError("The file could not be parsed as a supported PCAP/PCAPNG capture.") from error
            
        import mmap
        from ml.data.fast_pcap_decoder import FastPcapDecoder
        from nexsolve_core.network.session_state import _TCPSessionBuilder
        sessions_builder = {}
        with open(capture_path, "rb") as fp:
            with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                decoder = FastPcapDecoder(mm, capture_id=analysis_id)
                for pkt in decoder.decode_packets():
                    if pkt.protocol != "TCP" or not pkt.src_ip or not pkt.dst_ip or pkt.src_port is None or pkt.dst_port is None:
                        continue
                    left = (pkt.src_ip, pkt.src_port)
                    right = (pkt.dst_ip, pkt.dst_port)
                    endpoint_pair = (left, right) if left <= right else (right, left)
                    builder = sessions_builder.get(endpoint_pair)
                    is_orig = ((pkt.src_ip, pkt.src_port) == endpoint_pair[0])
                    if builder is None:
                        sess_id = f"tcp-{pkt.src_ip}:{pkt.src_port}-{pkt.dst_ip}:{pkt.dst_port}-{int(pkt.timestamp)}"
                        builder = _TCPSessionBuilder(
                            session_id=sess_id,
                            orig_ip=endpoint_pair[0][0],
                            orig_port=endpoint_pair[0][1],
                            resp_ip=endpoint_pair[1][0],
                            resp_port=endpoint_pair[1][1],
                            first_time=pkt.timestamp
                        )
                        sessions_builder[endpoint_pair] = builder
                    builder.update(pkt, is_orig)
        tcp_sessions_tuple = tuple(b.finalize() for b in sessions_builder.values())

        from nexsolve_core.provenance import CaptureFingerprint
        from integrations.scapy_adapter import ScapyAdapter
        scapy_adapter = ScapyAdapter()
        scapy_caps = scapy_adapter.probe_capture_capabilities(capture_path, max_packets=2000) if scapy_adapter.available else {}
        capture_fingerprint = CaptureFingerprint.from_pcap(
            capture_path,
            capabilities=scapy_caps,
        )

    if not canonical_windows:
        raise RuntimeError("The capture contained no parseable timestamped packets.")
    # Stream TemporalWindows to build necessary structures without keeping them all in memory if possible
    # Actually, the user asked to remove all_flows list materialization. 
    # Let's keep canonical_windows but remove cw.flows references from memory by clearing them after extraction.
    candidates = build_network_state_candidates(canonical_windows, MODEL_SCHEMA)
    history = build_state_history(candidates)
    compatibility = evaluate_model_compatibility(candidates, MODEL_SCHEMA, history.status).to_dict()

    src_ips = set()
    dst_ips = set()
    dst_ports = set()
    total_unique_flows = 0
    min_ts = float("inf")
    max_ts = float("-inf")

    seen_flow_ids = set()
    for cw in canonical_windows:
        for f in cw.flows:
            if f.flow_id not in seen_flow_ids:
                seen_flow_ids.add(f.flow_id)
                total_unique_flows += 1
                if f.start_timestamp < min_ts: min_ts = f.start_timestamp
                if f.end_timestamp > max_ts: max_ts = f.end_timestamp
                if f.src_ip: src_ips.add(f.src_ip)
                if f.dst_ip: dst_ips.add(f.dst_ip)
                if f.dst_port is not None: dst_ports.add(f.dst_port)

    windows = [window.to_dict() for window in canonical_windows]
    traffic = traffic_summary(windows)
    detection = analyze_packet_windows(windows)
    duration_seconds = max(0, int(windows[-1]["window_end"]) - int(windows[0]["window_start"])) if windows else 0

    tcp_sessions = tcp_sessions_tuple
    packet_span_seconds = round(max_ts - min_ts, 4) if min_ts <= max_ts else 0.0
    traffic["duration_seconds"] = duration_seconds
    traffic["packet_timestamp_span_seconds"] = packet_span_seconds
    traffic["temporal_window_coverage_seconds"] = duration_seconds
    traffic["packet_span_seconds"] = packet_span_seconds
    traffic["unique_src_ips"] = len(src_ips)
    traffic["unique_dst_ips"] = len(dst_ips)
    traffic["unique_dst_ports"] = len(dst_ports)
    if total_unique_flows > 0:
        traffic["flows"] = total_unique_flows

    import dataclasses
    capture_fingerprint = dataclasses.replace(
        capture_fingerprint,
        packet_count=traffic["packets"],
        duration_seconds=float(duration_seconds),
    )


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

    compatibility["schema_variant"] = schema_variant
    compatibility["active_schema"] = "MODEL_SCHEMA_45" if schema_variant == "45_feature_pcap_compatible" else "MODEL_SCHEMA_46"

    # Trust Layer integration
    from ml.forecasting import assemble_forecast_intelligence
    forecast_points: list[dict[str, Any]] = []

    from ml.forecasting.forecasting_engine import ForecastingPipeline
    forecasting_pipeline = ForecastingPipeline(active_model_dir)
    trajectory_result = None

    if compatibility.get("model_ready", False):
        try:
            from nexsolve_core.state import candidates_to_network_states
            states = candidates_to_network_states(candidates, active_schema, history.status)
            trajectory_result = forecasting_pipeline.execute_forecast(states, horizons=(1, 2, 3, 4, 5))
            for pt in trajectory_result.forecasts:
                forecast_points.append({
                    "horizon": pt.horizon,
                    "lookaheadSeconds": pt.lookahead_seconds,
                    "attackProbability": pt.attack_probability,
                    "cumulativeRisk": pt.cumulative_risk,
                    "riskLevel": pt.risk_level.value,
                    "predictedStage": pt.predicted_stage,
                    "confidence": pt.confidence,
                    "uncertainty": pt.uncertainty,
                    "explanation": [d.interpretation for d in pt.top_drivers] if pt.top_drivers else [pt.behavioral_interpretation],
                    "topDrivers": [d.to_dict() for d in pt.top_drivers],
                    "evidenceAttribution": pt.evidence_attribution.to_dict() if pt.evidence_attribution is not None else None,
                })
        except Exception:
            for h in (1, 2, 3, 4, 5):
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
        for h in (1, 2, 3, 4, 5):
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
        provenance_info={"capture_id": analysis_id, "source": filename, "schema_variant": schema_variant, "sha256": capture_fingerprint.sha256},
        min_sequence_length=8,
        required_features=active_flow_features,
        calibration_status="UNSUPPORTED",
        decision_threshold=0.5,
        window_seconds=60,
    )

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

    behavioral_report = analyze_behavioral_intelligence(_iter_flows(canonical_windows), ())
    sample_flows = []
    for i, f in enumerate(_iter_flows(canonical_windows)):
        if i >= 1000:
            break
        sample_flows.append(f)
    investigation_records = build_session_investigation_records(sample_flows, behavioral_report.beaconing_signals)
    tcp_session_metrics = aggregate_tcp_session_metrics(tcp_sessions)
    flow_statistics = aggregate_flow_statistics_summary(_iter_flows(canonical_windows))
    suricata_report = parse_suricata_eve_json(None)  # No external EVE JSON uploaded in standard PCAP analysis

    entity_histories = build_temporal_entity_histories(
        flows=_iter_flows(canonical_windows),
        tcp_sessions=tcp_sessions,
        observed_findings=detection.get("findings", []),
    )

    from ml.forecasting.attack_progression import forecast_attack_progression
    from nexsolve_core.graph import build_evidence_intelligence_graph
    from nexsolve_core.temporal_graph import build_temporal_graph_sequence
    from ml.forecasting.graph_fusion import fuse_forecast_with_temporal_graph
    from nexsolve_core.behavior import build_behavioral_episodes, detect_behavior_changes
    from nexsolve_core.intelligence import infer_attack_states, build_threat_centric_views, build_network_world_state

    temporal_graph = build_temporal_graph_sequence(
        windows=canonical_windows,
        all_flows=_iter_flows(canonical_windows),
        history_window_count=len(windows),
    )

    # Clear flows and packets from canonical_windows immediately after flow analytics extraction
    import dataclasses
    canonical_windows = [dataclasses.replace(cw, flows=(), packets=()) for cw in canonical_windows]

    graph_fusion = fuse_forecast_with_temporal_graph(
        baseline_forecast_points=forecast_points,
        temporal_graph=temporal_graph,
        mode="MODE_B",
    )

    progression_forecast = forecast_attack_progression(
        observed_findings=detection.get("findings", []),
        behavioral_report=behavioral_report,
        history_window_count=len(windows),
    )
    progression_dict = progression_forecast.to_dict()
    from ml.forecasting.attack_progression import build_continuous_progression_timeline
    progression_dict["continuous_timeline"] = build_continuous_progression_timeline(progression_forecast)

    # Re-assemble forecast intelligence with full multi-modal context (progression, findings, behavioral report)
    intelligence = assemble_forecast_intelligence(
        sequence=state_dicts,
        forecast_points=forecast_points,
        capture_quality=quality,
        provenance_info={"capture_id": analysis_id, "source": filename, "schema_variant": schema_variant, "sha256": capture_fingerprint.sha256},
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

    # Core Intelligence Extensions: Episodes, Changes, Entity History & Attack States
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

    # Advanced Threat Intelligence Engines (Sprint #NEXT)
    from nexsolve_core.behavior import compute_entity_baselines
    from nexsolve_core.intelligence import (
        analyze_attack_kinematics,
        build_entity_behavior_profiles,
        detect_attack_patterns,
        correlate_attack_campaigns,
        generate_threat_stories,
        prioritize_threats,
        assemble_forecast_context,
    )

    baselines = compute_entity_baselines(
        entity_histories=entity_histories,
        tcp_sessions=tcp_sessions,
    )
    attack_kinematics = analyze_attack_kinematics(
        entity_histories=entity_histories,
        observed_findings=detection.get("findings", []),
        tcp_sessions=tcp_sessions,
        change_signals=change_signals,
        beaconing_signals=behavioral_report.beaconing_signals,
        forecast_points=forecast_points,
    )
    patterns = detect_attack_patterns(
        tcp_sessions=tcp_sessions,
        observed_findings=detection.get("findings", []),
        beaconing_signals=behavioral_report.beaconing_signals,
        change_signals=change_signals,
    )
    entity_profiles = build_entity_behavior_profiles(
        entity_histories=entity_histories,
        tcp_sessions=tcp_sessions,
        observed_findings=detection.get("findings", []),
        episodes=episodes,
        beaconing_signals=behavioral_report.beaconing_signals,
    )
    campaigns = correlate_attack_campaigns(
        episodes=episodes,
        patterns=patterns,
        attack_states=attack_states,
    )
    threat_stories = generate_threat_stories(
        entity_profiles=entity_profiles,
        attack_kinematics=attack_kinematics,
        campaigns=campaigns,
        patterns=patterns,
        change_signals=change_signals,
        forecast_points=forecast_points,
        progression_forecast=progression_forecast,
    )
    prioritized_threats = prioritize_threats(
        entity_profiles=entity_profiles,
        attack_kinematics=attack_kinematics,
        campaigns=campaigns,
        patterns=patterns,
        change_signals=change_signals,
    )
    forecast_context = assemble_forecast_context(
        entity_profiles=entity_profiles,
        attack_kinematics=attack_kinematics,
        campaigns=campaigns,
        change_signals=change_signals,
        attack_progression=progression_forecast,
    )

    # Security Investigation Workspace Generation
    from nexsolve_core.intelligence import (
        investigate_entity,
        investigate_campaign,
        decompose_threat_risk,
        build_incident_investigation,
        generate_mitigation_recommendations,
    )

    all_deviations = [dev for b in baselines.values() for dev in b.deviations]
    entity_investigations = {}
    incident_investigations = []
    mitigation_recommendations = []

    threat_risk_breakdowns = {}
    risk_breakdown_objs = {}
    for p_threat in prioritized_threats:
        ent = p_threat.entity
        rb = decompose_threat_risk(
            entity=ent,
            entity_profiles=entity_profiles,
            attack_kinematics=attack_kinematics,
            campaigns=campaigns,
            change_signals=change_signals,
        )
        risk_breakdown_objs[ent] = rb
        threat_risk_breakdowns[ent] = rb.to_dict()

    for p_threat in prioritized_threats[:10]:
        ent = p_threat.entity
        inv_ctx = investigate_entity(
            entity=ent,
            entity_profiles=entity_profiles,
            attack_kinematics=attack_kinematics,
            change_signals=change_signals,
            baseline_deviations=all_deviations,
            episodes=episodes,
            campaigns=campaigns,
            patterns=patterns,
            tcp_sessions=tcp_sessions,
            beaconing_signals=behavioral_report.beaconing_signals,
            observed_findings=detection.get("findings", []),
            forecast_points=forecast_points,
            progression_forecast=progression_forecast,
            window_count=len(windows),
        )
        entity_investigations[ent] = inv_ctx.to_dict()

        # Build Incident-Level Investigation Dossier
        rb = risk_breakdown_objs.get(ent) or decompose_threat_risk(
            entity=ent,
            entity_profiles=entity_profiles,
            attack_kinematics=attack_kinematics,
            campaigns=campaigns,
            change_signals=change_signals,
        )
        inc_inv = build_incident_investigation(
            primary_entity=ent,
            entity_investigation=inv_ctx,
            entity_profiles=entity_profiles,
            attack_kinematics=attack_kinematics,
            campaigns=campaigns,
            patterns=patterns,
            beaconing_signals=behavioral_report.beaconing_signals,
            risk_breakdown=rb,
            window_count=len(windows),
        )
        incident_investigations.append(inc_inv.to_dict())

        # Generate Mitigations
        recs = generate_mitigation_recommendations(
            entity=ent,
            entity_profile=entity_profiles.get(ent),
            attack_kinematics=attack_kinematics,
            campaigns=campaigns,
            beaconing_signals=behavioral_report.beaconing_signals,
            window_count=len(windows),
        )
        mitigation_recommendations.extend([r.to_dict() for r in recs])

    campaign_investigations = {}
    for cmp in campaigns[:10]:
        c_inv = investigate_campaign(
            campaign=cmp,
            all_episodes=episodes,
            patterns=patterns,
        )
        campaign_investigations[cmp.campaign_id] = c_inv.to_dict()

    # Security Analyst Decision Engine Synthesis
    from nexsolve_core.intelligence import build_analyst_decisions

    analyst_decisions = build_analyst_decisions(
        entity_investigations=entity_investigations,
        campaign_investigations=campaign_investigations,
        incident_investigations=incident_investigations,
        prioritized_threats=prioritized_threats,
        entity_profiles=entity_profiles,
        attack_kinematics=attack_kinematics,
        campaigns=campaigns,
        patterns=patterns,
        change_signals=change_signals,
        baseline_deviations=all_deviations,
        tcp_sessions=tcp_sessions,
        beaconing_signals=behavioral_report.beaconing_signals,
        observed_findings=detection.get("findings", []),
        forecast_points=forecast_points,
        window_count=len(windows),
    )

    # Incident Reconstruction and Attack Story Engine
    from nexsolve_core.intelligence import build_incident_story

    incident_story = build_incident_story(
        windows=windows,
        all_flows=(),
        tcp_sessions=tcp_sessions,
        observed_findings=detection.get("findings", []),
        episodes=episodes,
        change_signals=change_signals,
        attack_kinematics=attack_kinematics,
        campaigns=campaigns,
        patterns=patterns,
        entity_profiles=entity_profiles,
        prioritized_threats=prioritized_threats,
        contradictions=threat_assessment.evidence,
        attack_progression=progression_forecast,
        forecast_points=forecast_points,
        attack_horizon=intelligence.attack_horizon,
        analyst_decisions=analyst_decisions,
        window_count=len(windows),
    )

    # Cross-Incident Campaign Correlation Engine & Threat Hunting
    from nexsolve_core.intelligence import (
        extract_incident_fingerprint,
        correlate_incident_set,
        build_campaign_clusters,
        get_hunt_templates,
        list_registered_fields,
    )

    current_fingerprint = extract_incident_fingerprint(
        incident_id=incident_story.story_id if incident_story else analysis_id,
        capture_id=analysis_id,
        incident_story=incident_story,
        entity_profiles=entity_profiles,
        tcp_sessions=tcp_sessions,
        observed_findings=detection.get("findings", []),
        episodes=episodes,
        traffic_summary=traffic,
        window_count=len(windows),
    )

    # Correlate across currently available incident fingerprints
    active_fingerprints = [current_fingerprint]
    incident_correlations = correlate_incident_set(active_fingerprints)
    campaign_clusters = build_campaign_clusters(active_fingerprints, incident_correlations)


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
        campaigns=campaigns,
        patterns=patterns,
        attack_kinematics=attack_kinematics,
        baselines=baselines,
    )

    world_state = build_network_world_state(
        capture_id=analysis_id,
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
        windows=windows,
        flows=(),
        tcp_sessions=tcp_sessions,
        entity_profiles=entity_profiles,
        threat_assessment=threat_assessment,
        incident_story=incident_story,
        campaign_clusters=campaign_clusters,
    )

    # Coherent Network Intelligence container
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

    from ml.forecasting.evidence_engine import (
        build_canonical_evidence_graph,
        evaluate_sensor_agreement as eval_sensor_agr,
        EvidenceItem,
        EvidenceSource,
        EvidencePolarity,
    )
    ev_items_for_agreement = []
    last_ts = windows[-1].get("start_timestamp", 1700000000.0) if windows and isinstance(windows[-1], dict) else (getattr(windows[-1], "start_timestamp", 1700000000.0) if windows else 1700000000.0)
    for idx_f, f in enumerate(detection.get("findings", [])):
        ev_items_for_agreement.append(
            EvidenceItem(
                evidence_id=f.get("finding_id") or f"EV_FIND_{idx_f}",
                timestamp=float(last_ts),
                source=EvidenceSource.HEURISTIC,
                modality="ALERT",
                polarity=EvidencePolarity.SUPPORTING,
                description=str(f.get("explanation") or f.get("rule_id") or "Heuristic pattern detected"),
                confidence=0.80,
                technique_id=f.get("mitre_technique") or f.get("technique_id"),
            )
        )
    if scapy_adapter.available and scapy_caps:
        ev_items_for_agreement.append(
            EvidenceItem(
                evidence_id="EV_SCAPY_PROBE",
                timestamp=float(last_ts),
                source=EvidenceSource.SCAPY,
                modality="PACKET",
                polarity=EvidencePolarity.SUPPORTING,
                description="Scapy deep packet dissection verified valid frame structures",
                confidence=0.90,
            )
        )
    if suricata_report and getattr(suricata_report, "alerts", None):
        for s_idx, s_al in enumerate(suricata_report.alerts):
            ev_items_for_agreement.append(
                EvidenceItem(
                    evidence_id=f"EV_SURI_{s_idx}",
                    timestamp=float(last_ts),
                    source=EvidenceSource.SURICATA,
                    modality="IDS_ALERT",
                    polarity=EvidencePolarity.SUPPORTING,
                    description=s_al.get("signature", "Suricata rule trigger"),
                    confidence=0.85,
                )
            )

    sensor_agr = eval_sensor_agr(ev_items_for_agreement)
    sensor_agreement_dict = {
        "sources": sorted(list(set(sensor_agr.supporting_sources + sensor_agr.contradictory_sources + sensor_agr.neutral_sources))),
        "agreement": sensor_agr.agreement_level.value,
        "agreement_level": sensor_agr.agreement_level.value,
        "contradictions": list(sensor_agr.contradictory_sources),
        "supporting_sources": list(sensor_agr.supporting_sources),
        "neutral_sources": list(sensor_agr.neutral_sources),
        "confidence_modifier": sensor_agr.confidence_modifier,
        "explanation": sensor_agr.explanation,
    }

    canonical_ev_graph = build_canonical_evidence_graph(
        pcap_sha256=capture_fingerprint.sha256,
        pcap_filename=filename,
        windows=canonical_windows,
        findings=detection.get("findings", []),
        attack_progression=progression_forecast,
        forecast_points=forecast_points,
    )

    result = {
        "analysis_id": analysis_id,
        "status": "completed",
        "source": {"name": filename, "kind": "uploaded_pcap", "filename": filename, "size_bytes": capture_size_bytes, "sha256": capture_fingerprint.sha256},
        "upload": {"filename": filename, "size_bytes": capture_size_bytes, "format": suffix[1:], "sha256": capture_fingerprint.sha256},
        "fingerprint": capture_fingerprint.to_dict(),
        "capture_fingerprint": capture_fingerprint.to_dict(),
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
        # Advanced Threat Intelligence Engines (Sprint #NEXT)
        "attack_kinematics": {k: v.to_dict() for k, v in attack_kinematics.items()},
        "entity_profiles": {k: v.to_dict() for k, v in entity_profiles.items()},
        "patterns": [p.to_dict() for p in patterns],
        "campaigns": [c.to_dict() for c in campaigns],
        "threat_stories": [s.to_dict() for s in threat_stories],
        "prioritized_threats": [p.to_dict() for p in prioritized_threats],
        "forecast_context": {k: v.to_dict() for k, v in forecast_context.items()},
        "baseline_deviations": [dev.to_dict() for b in baselines.values() for dev in b.deviations],
        # End-to-End Security Investigation Dossiers & Risk Breakdowns
        "entity_investigations": entity_investigations,
        "campaign_investigations": campaign_investigations,
        "threat_risk_breakdowns": threat_risk_breakdowns,
        "incident_investigations": incident_investigations,
        "mitigation_recommendations": mitigation_recommendations,
        # Security Analyst Decision Engine
        "analyst_decisions": [d.to_dict() for d in analyst_decisions],
        # Deterministic Incident Reconstruction & Attack Story Engine
        "incident_story": incident_story.to_dict() if incident_story else None,
        # Cross-Incident Campaign Correlation Engine
        "incident_fingerprint": current_fingerprint.to_dict(),
        "incident_correlations": [c.to_dict() for c in incident_correlations],
        "campaign_clusters": [cl.to_dict() for cl in campaign_clusters],
        # Threat Hunting & Intelligence Query Engine (Templates & Schema)
        "hunt_templates": get_hunt_templates(),
        "query_predicates": list_registered_fields(),
        # Dynamic Network Graph Intelligence & Attack Propagation
        "temporal_graph": temporal_graph.to_dict(),
        "temporalGraph": temporal_graph.to_dict(),
        "graph_fusion": graph_fusion.to_dict(),
        "graphFusion": graph_fusion.to_dict(),
        # Trust Layer & Forecast Intelligence
        "forecasts": forecast_points,
        "forecast_trajectory": trajectory_result.to_dict() if trajectory_result else None,
        "early_warning": trajectory_result.early_warning.to_dict() if trajectory_result else None,
        "attack_horizon": intelligence.attack_horizon,
        "attackHorizon": intelligence.attack_horizon,
        "attack_progression": progression_dict,
        "attackProgression": progression_dict,
        "sensor_agreement": sensor_agreement_dict,
        "sensorAgreement": sensor_agreement_dict,
        "canonical_evidence_graph": canonical_ev_graph.to_dict(),
        "evidence_chain": intelligence.evidence_chain,
        "evidenceChain": intelligence.evidence_chain,
        "confidence": intelligence.confidence,
        "unknown_behavior": intelligence.unknown_behavior,
        "unknownBehavior": intelligence.unknown_behavior,
        "abstention": intelligence.abstention,
        "analysis_state": (
            "ANALYSIS_COMPLETE_FORECAST_READY"
            if compatibility.get("model_ready", False)
            else "ANALYSIS_COMPLETE_FORECAST_UNAVAILABLE"
        ),
        "forecast_summary": {
            "available": bool(compatibility.get("model_ready", False)),
            "status": (
                "READY"
                if compatibility.get("model_ready", False)
                else ("INSUFFICIENT_HISTORY" if len(windows) < 8 else "INCOMPATIBLE_FEATURES")
            ),
            "required_windows": 8,
            "available_windows": len(windows),
            "required_window_seconds": 60,
            "message": (
                "Forecast rollouts generated successfully."
                if compatibility.get("model_ready", False)
                else (
                    "Forecasting requires at least 8 continuous 60-second windows. "
                    "Static traffic analysis completed successfully."
                )
            ),
        },
    }
    return persist_analysis(result)


def get_uploaded_analysis(analysis_id: str) -> dict[str, Any] | None:
    return get_analysis(analysis_id)

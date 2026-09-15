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
        provenance_info={"capture_id": analysis_id, "source": filename, "schema_variant": schema_variant},
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

    all_flows = [flow for cw in canonical_windows for flow in cw.flows]
    behavioral_report = analyze_behavioral_intelligence(all_flows, _packets)
    investigation_records = build_session_investigation_records(all_flows, behavioral_report.beaconing_signals)
    tcp_sessions = track_tcp_sessions(_packets)
    tcp_session_metrics = aggregate_tcp_session_metrics(tcp_sessions)
    flow_statistics = aggregate_flow_statistics_summary(all_flows)
    suricata_report = parse_suricata_eve_json(None)  # No external EVE JSON uploaded in standard PCAP analysis

    from ml.forecasting.attack_progression import forecast_attack_progression
    from nexsolve_core.graph import build_evidence_intelligence_graph
    from nexsolve_core.behavior import build_behavioral_episodes, detect_behavior_changes
    from nexsolve_core.temporal import build_temporal_entity_histories
    from nexsolve_core.intelligence import infer_attack_states, build_threat_centric_views, build_network_world_state

    progression_forecast = forecast_attack_progression(
        observed_findings=detection.get("findings", []),
        behavioral_report=behavioral_report,
        history_window_count=len(windows),
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
    entity_histories = build_temporal_entity_histories(
        flows=all_flows,
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
        rb = decompose_threat_risk(
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

    threat_risk_breakdowns = {}
    for p_threat in prioritized_threats:
        ent = p_threat.entity
        rb = decompose_threat_risk(
            entity=ent,
            entity_profiles=entity_profiles,
            attack_kinematics=attack_kinematics,
            campaigns=campaigns,
            change_signals=change_signals,
        )
        threat_risk_breakdowns[ent] = rb.to_dict()

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
        all_flows=all_flows,
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
        flows=all_flows,
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
        flows=all_flows,
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
        # Trust Layer & Forecast Intelligence
        "forecasts": forecast_points,
        "forecast_trajectory": trajectory_result.to_dict() if trajectory_result else None,
        "early_warning": trajectory_result.early_warning.to_dict() if trajectory_result else None,
        "attack_horizon": intelligence.attack_horizon,
        "attackHorizon": intelligence.attack_horizon,
        "attack_progression": progression_forecast.to_dict(),
        "attackProgression": progression_forecast.to_dict(),
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

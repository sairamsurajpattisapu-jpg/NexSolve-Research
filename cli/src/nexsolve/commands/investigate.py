"""NexSolve Analyst Investigation Command.

Provides a 360-degree forensic and predictive state overview for a given analysis:
- Capture identity and integrity metrics
- Current threat posture and risk score
- Attack lifecycle state and separated confidences
- Dynamic attack progression (observed vs inferred vs forecast)
- Multi-horizon forecast schedule (T+1 .. T+5)
- Evidentiary signals (supporting, contradictory, neutral)
- Grounded MITRE ATT&CK techniques and tactics
- Uncertainty calibration and abstention disclosures
- Direct report export links and web console URL
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from nexsolve.client.api import NexSolveClient
from nexsolve.config import DEFAULT_API_KEY, DEFAULT_API_URL, DEFAULT_WEB_URL
from nexsolve.errors import NexSolveError
from nexsolve.output.terminal import TerminalRenderer


def _load_or_fetch(target: str, client: NexSolveClient) -> dict[str, Any]:
    """Retrieve analysis payload from local file or backend server."""
    path = Path(target)
    if path.exists() and path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            raise NexSolveError(f"Failed to read local analysis file '{target}': {exc}")
    try:
        return client.get_results(target)
    except Exception as exc:
        raise NexSolveError(f"Failed to retrieve analysis for '{target}' from backend: {exc}")


def run_investigate(args: argparse.Namespace) -> int:
    """Execute comprehensive analyst investigation."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)
    server_url = getattr(args, "server", DEFAULT_API_URL)
    web_url = getattr(args, "web_url", DEFAULT_WEB_URL)
    api_key = getattr(args, "api_key", DEFAULT_API_KEY)

    client = NexSolveClient(base_url=server_url, api_key=api_key)
    data = _load_or_fetch(args.job_id, client)

    # 1. Capture Identity
    source = data.get("source", {})
    traffic = data.get("traffic", {})
    quality = data.get("quality", {})
    prov = data.get("provenance", {}) or data.get("provenance_info", {})
    sections = data.get("sections", {})

    job_id = data.get("analysis_id") or data.get("job_id") or getattr(args, "job_id", "unknown")
    filename = source.get("filename") or source.get("name") or prov.get("source_filename") or "capture.pcap"
    sha256 = prov.get("capture_hash") or data.get("capture_hash") or "N/A"
    file_size = source.get("file_size_bytes") or prov.get("file_size_bytes") or quality.get("file_size_bytes", 0)
    packets = traffic.get("packets") or quality.get("parsed_packets") or 0
    flows = traffic.get("flows") or traffic.get("flow_count") or 0
    duration = traffic.get("duration") or traffic.get("duration_seconds") or 0.0

    # 2. Current Threat
    detection = data.get("detection", {})
    threat_level = detection.get("threat_level") or detection.get("overall_threat_level") or data.get("threat_level") or "UNKNOWN"
    risk_score = detection.get("risk_score") or data.get("risk_score") or 0.0
    ah = data.get("attack_horizon") or data.get("attackHorizon") or sections.get("attack_horizon", {})
    early_warning_lead = ah.get("lead_time_seconds")
    early_warning_str = f"{early_warning_lead:.1f}s" if early_warning_lead is not None else "N/A"

    # 3. Attack State & Progression
    prog = data.get("attack_progression") or data.get("attackProgression") or sections.get("attack_progression", {})
    current_stage = prog.get("canonical_stage") or prog.get("current_stage") or prog.get("current_state") or "UNKNOWN"
    stage_conf = prog.get("stage_confidence", 0.0)
    tech_conf = prog.get("technique_confidence", 0.0)
    classification = prog.get("classification", "INFERRED")
    timeline = prog.get("timeline", [])
    transitions = prog.get("transitions", [])

    observed_stages = [ev["stage"] for ev in timeline if ev.get("classification") == "OBSERVED"]
    inferred_stages = [ev["stage"] for ev in timeline if ev.get("classification") == "INFERRED"]
    forecast_stages = [ev["stage"] for ev in timeline if ev.get("classification") == "FORECAST"]

    # 4. Forecast Horizons
    forecast_list = data.get("forecasts") or data.get("forecast_points") or sections.get("forecast", {}).get("forecast_points", [])
    forecast_map = {}
    for fp in forecast_list:
        h = fp.get("horizon") or fp.get("step") or fp.get("horizon_step")
        if h is not None:
            forecast_map[int(h)] = fp

    # 5. Evidence & Sensor Agreement
    ev_chain = data.get("evidence_chain") or data.get("evidenceChain") or sections.get("evidence_chain", {})
    supporting_ev = ev_chain.get("supporting_evidence", [])
    contradictory_ev = ev_chain.get("contradictory_evidence", [])
    neutral_ev = ev_chain.get("neutral_evidence", [])
    s_agr = data.get("sensor_agreement") or ev_chain.get("sensor_agreement", {})

    # 6. MITRE Grounding
    techniques = prog.get("observed_techniques") or []
    if not techniques:
        findings = data.get("findings") or detection.get("findings", [])
        for f in findings:
            if isinstance(f, dict) and "technique_id" in f:
                techniques.append(f["technique_id"])
    techniques = sorted(list(set(techniques)))

    # 7. Uncertainty & Abstention
    conf_dict = data.get("confidence") or sections.get("confidence", {})
    abs_dict = data.get("abstention") or sections.get("abstention", {})
    lim_dict = data.get("limitations") or sections.get("limitations", {})

    confidence_val = conf_dict.get("confidence_value")
    confidence_state = conf_dict.get("confidence_state", "UNSUPPORTED")
    is_abstained = abs_dict.get("abstained", False)

    # 8. Report & Console URLs
    html_url = f"{server_url.rstrip('/')}/jobs/{job_id}/report.html"
    json_url = f"{server_url.rstrip('/')}/jobs/{job_id}/result"
    md_url = f"{server_url.rstrip('/')}/jobs/{job_id}/report.md"
    console_url = f"{web_url.rstrip('/')}/console/analyze?job_id={job_id}"

    # Pure JSON Output
    if getattr(args, "json", False):
        payload = {
            "capture": {
                "filename": filename,
                "sha256": sha256,
                "file_size_bytes": file_size,
                "duration_seconds": duration,
                "packet_count": packets,
                "flow_count": flows,
            },
            "threat": {
                "threat_level": threat_level,
                "risk_score": risk_score,
                "early_warning_lead_seconds": early_warning_lead,
            },
            "attack_state": {
                "stage": current_stage,
                "classification": classification,
                "stage_confidence": stage_conf,
                "technique_confidence": tech_conf,
            },
            "progression": {
                "observed_stages": observed_stages,
                "inferred_stages": inferred_stages,
                "forecast_stages": forecast_stages,
                "transitions_count": len(transitions),
            },
            "forecast": {
                f"T+{h}": forecast_map.get(h, {"status": "ABSTAINED"}) for h in range(1, 6)
            },
            "evidence": {
                "supporting_count": len(supporting_ev),
                "contradictory_count": len(contradictory_ev),
                "neutral_count": len(neutral_ev),
                "sensor_agreement": s_agr.get("agreement_level") or s_agr.get("agreement", "UNKNOWN"),
            },
            "mitre": {
                "techniques": techniques,
            },
            "uncertainty": {
                "confidence_state": confidence_state,
                "confidence_value": confidence_val,
                "abstained": is_abstained,
                "abstention_reason": abs_dict.get("reason"),
            },
            "reports": {
                "html": html_url,
                "json": json_url,
                "markdown": md_url,
            },
            "web_console": console_url,
        }
        print(json.dumps(payload, indent=2, default=str))
        return 0

    # Human-Readable Terminal Dashboard
    term.print_banner()
    print(f"{term.C_CYAN}{term.C_BOLD}NEXSOLVE 360-DEGREE ANALYST INVESTIGATION{term.C_RESET}")
    print(f"{term.C_DIM}Full Forensic Telemetry, Threat State, Lifecycle Kinematics & Horizons{term.C_RESET}\n")

    # 1. Capture Identity
    print(f"{term.C_BOLD}[1] CAPTURE IDENTITY & INGESTION METRICS{term.C_RESET}")
    print(f"  Target File:     {term.C_WHITE}{filename}{term.C_RESET}")
    print(f"  SHA-256 Digest:  {term.C_DIM}{sha256}{term.C_RESET}")
    print(f"  File Size:       {file_size:,} bytes")
    print(f"  Duration Span:   {duration:.2f} seconds")
    print(f"  Traffic Volume:  {packets:,} packets | {flows:,} flows\n")

    # 2. Threat & Current State
    sev_color = term.C_RED if threat_level in ("CRITICAL", "HIGH", "ELEVATED") else term.C_GREEN
    print(f"{term.C_BOLD}[2] THREAT POSTURE & ATTACK STATE{term.C_RESET}")
    print(f"  Overall Threat:  {sev_color}{term.C_BOLD}{threat_level}{term.C_RESET} (Risk Score: {risk_score:.2f})")
    print(f"  Early Warning:   {early_warning_str} lead time")
    print(f"  Canonical Stage: {term.C_YELLOW}{term.C_BOLD}{current_stage}{term.C_RESET} [{classification}]")
    print(f"  Separated Conf:  Stage: {stage_conf:.1%} | Technique: {tech_conf:.1%}\n")

    # 3. Progression
    print(f"{term.C_BOLD}[3] ATTACK PROGRESSION & KINEMATICS{term.C_RESET}")
    print(f"  Observed Stages: {', '.join(observed_stages) if observed_stages else 'None'}")
    print(f"  Inferred Stages: {', '.join(inferred_stages) if inferred_stages else 'None'}")
    print(f"  Evaluated Kinematics: {len(transitions)} transitions evaluated\n")

    # 4. Multi-Horizon Forecast Schedule
    print(f"{term.C_BOLD}[4] MULTI-HORIZON ATTACK FORECAST (T+1 .. T+5){term.C_RESET}")
    print("  Horizon    Projected Stage        Prob       Conf       Uncertainty  Status")
    print("  ---------  --------------------   --------   --------   -----------  ----------------")
    for h in range(1, 6):
        fp = forecast_map.get(h)
        if fp and fp.get("attackProbability") is not None and not is_abstained:
            st = fp.get("predictedStage") or "UNKNOWN"
            prob = fp.get("attackProbability", 0.0)
            conf = fp.get("confidence", 0.0)
            uncert = fp.get("uncertainty", 0.0)
            print(f"  T+{h:<8} {st:<22} {prob:>6.1%}     {conf:>6.1%}     {uncert:>8.2f}     {term.C_GREEN}ACTIVE_FORECAST{term.C_RESET}")
        else:
            print(f"  T+{h:<8} {'UNKNOWN / ABSTAINED':<22} {'N/A':>6}     {'N/A':>6}     {'N/A':>8}     {term.C_YELLOW}ABSTAINED{term.C_RESET}")
    print()

    # 5. Evidence & Multi-Sensor Agreement
    print(f"{term.C_BOLD}[5] EVIDENTIARY CORROBORATION & SENSORS{term.C_RESET}")
    agr_level = s_agr.get("agreement_level") or s_agr.get("agreement", "UNKNOWN")
    agr_mod = s_agr.get("confidence_modifier", 1.0)
    print(f"  Multi-Sensor Agreement: {term.C_CYAN}[{agr_level}]{term.C_RESET} ({agr_mod:.2f}x confidence multiplier)")
    print(f"  Supporting Signals:     {term.C_GREEN}{len(supporting_ev)} items{term.C_RESET}")
    print(f"  Contradictory Signals:  {term.C_RED if contradictory_ev else term.C_WHITE}{len(contradictory_ev)} items{term.C_RESET}")
    print(f"  Neutral Telemetry:      {len(neutral_ev)} items")
    if supporting_ev:
        print("  Top Supporting Evidence:")
        for item in supporting_ev[:3]:
            feat = item.get("feature_name") or item.get("feature") or "Signal"
            expl = item.get("explanation") or ""
            print(f"    + {feat}: {expl}")
    print()

    # 6. MITRE ATT&CK Mapping
    print(f"{term.C_BOLD}[6] MITRE ATT&CK GROUNDING{term.C_RESET}")
    if techniques:
        print(f"  Verified Techniques: {term.C_WHITE}{', '.join(techniques)}{term.C_RESET}")
    else:
        print(f"  Verified Techniques: {term.C_DIM}Zero malicious techniques mapped to benign capture.{term.C_RESET}")
    print()

    # 7. Uncertainty & Limitations
    print(f"{term.C_BOLD}[7] UNCERTAINTY & ABSTENTION DISCLOSURES{term.C_RESET}")
    print(f"  Calibration Status:  {confidence_state}")
    print(f"  Forecast Abstained:  {'YES (' + str(abs_dict.get('reason')) + ')' if is_abstained else 'NO (Operational forecast active)'}")
    print()

    # 8. Forensic Artifacts & Web Console
    print(f"{term.C_BOLD}[8] FORENSIC REPORTS & VISUALIZATION{term.C_RESET}")
    print(f"  HTML Report:  {term.C_WHITE}{html_url}{term.C_RESET}")
    print(f"  Markdown:     {term.C_WHITE}{md_url}{term.C_RESET}")
    print(f"  JSON State:   {term.C_WHITE}{json_url}{term.C_RESET}")
    print(f"  Web Console:  {term.C_CYAN}{console_url}{term.C_RESET}\n")

    return 0

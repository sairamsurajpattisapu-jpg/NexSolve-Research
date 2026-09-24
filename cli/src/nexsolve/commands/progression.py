"""NexSolve Dynamic Attack Progression Command.

Displays 15-stage canonical attack lifecycle assessment, verified MITRE ATT&CK grounding,
temporal state transition kinematics, separated confidences, and progression timeline audit.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from nexsolve.client.api import NexSolveClient
from nexsolve.config import DEFAULT_API_KEY, DEFAULT_API_URL
from nexsolve.errors import NexSolveError
from nexsolve.output.terminal import TerminalRenderer


def _load_or_fetch(target: str, client: NexSolveClient) -> dict[str, Any]:
    """Retrieve analysis payload either from local JSON file or backend API."""
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


def run_progression(args: argparse.Namespace) -> int:
    """Execute attack progression inspection."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)
    server_url = getattr(args, "server", DEFAULT_API_URL)
    api_key = getattr(args, "api_key", DEFAULT_API_KEY)

    client = NexSolveClient(base_url=server_url, api_key=api_key)
    data = _load_or_fetch(args.job_id, client)

    # Extract progression payload
    progression = data.get("attack_progression") or data.get("attackProgression") or {}
    if not progression and "sections" in data:
        # Check if structured report format
        progression = data["sections"].get("attack_progression", {})

    if not progression:
        # Fallback: construct from findings if available
        findings = data.get("findings") or data.get("detection", {}).get("findings", [])
        from ml.forecasting.attack_progression import forecast_attack_progression
        history_cnt = data.get("window_count") or data.get("traffic", {}).get("windows", 8)
        p_fc = forecast_attack_progression(findings, history_window_count=history_cnt)
        progression = p_fc.to_dict()

    source = data.get("source", {})
    filename = source.get("filename") or source.get("name") or "Capture"
    job_id = data.get("analysis_id") or getattr(args, "job_id", "unknown")

    canonical_stage = progression.get("canonical_stage") or progression.get("current_stage") or progression.get("observed_state", "UNKNOWN")
    stage_conf = float(progression.get("stage_confidence", 0.0))
    timeline = progression.get("timeline", [])
    transitions = progression.get("transitions", [])
    forecast = progression.get("forecast") or progression.get("forecast_points", [])
    techniques = list(progression.get("observed_techniques", []))
    evidence = list(progression.get("supporting_evidence", []))
    contradictions = list(progression.get("contradictory_evidence", []))
    validation = progression.get("validation", {})
    uncertainty = round(1.0 - stage_conf, 4)

    if getattr(args, "json", False):
        json_output = {
            "capture": filename,
            "current_stage": canonical_stage,
            "stage_confidence": stage_conf,
            "timeline": timeline,
            "transitions": transitions,
            "forecast": forecast,
            "techniques": techniques,
            "evidence": evidence,
            "contradictions": contradictions,
            "uncertainty": uncertainty,
            "validation": validation,
            **progression,
        }
        print(json.dumps(json_output, indent=2))
        return 0

    if getattr(args, "quiet", False):
        print(canonical_stage)
        return 0

    # Render Terminal Presentation
    print(r"""
======================================================================
  _   _           ____        _            
 | \ | | _____  _/ ___|  ___ | |_   _____  
 |  \| |/ _ \ \/ \___ \ / _ \| \ \ / / _ \ 
 | |\  |  __/>  < ___) | (_) | |\ V /  __/ 
 |_| \_|\___/_/\_\____/ \___/|_| \_/ \___| 
                                           
 DYNAMIC ATTACK PROGRESSION & 15-STAGE LIFECYCLE ENGINE
 Grounded MITRE ATT&CK & Temporal Kinematics Verification
======================================================================
""")

    print(f"[*] Target Capture:   {filename}")
    print(f"[*] Analysis Job ID:  {job_id}")
    print(f"[*] Lifecycle Status: {progression.get('verdict', 'BASELINE_EQUILIBRIUM')}")

    # Section 1: Current Attack Stage & Grounding
    print("\n--- [1] CURRENT OBSERVED / INFERRED STAGE ---")
    classification = progression.get("classification", "INFERRED")
    tech_conf = progression.get("technique_confidence", 0.0)

    print(f"  Canonical Stage:       {term.bold(canonical_stage)}")
    print(f"  Stage Classification:  [{term.cyan(classification)}]")
    print(f"  Stage Confidence:      {stage_conf:.4f} (Corroborated Telemetry)")
    print(f"  Technique Confidence:  {tech_conf:.4f} (Sensor Match Certainty)")
    print(f"  Uncertainty:           {uncertainty:.4f}")
    if techniques:
        print(f"  MITRE Techniques:      {term.yellow(', '.join(techniques))}")
    else:
        print("  MITRE Techniques:      None (Zero active technique signatures observed)")

    # Section 2: Progression Timeline Across Horizons
    print("\n--- [2] MULTI-HORIZON PROGRESSION TIMELINE ---")
    if not timeline:
        print("  No discrete timeline events recorded for this capture.")
    else:
        print(f"  {'Horizon':<12} {'Stage':<22} {'Class':<12} {'Techniques':<16} {'Confidence':<14} {'Evidence'}")
        print(f"  {'-'*11:<12} {'-'*20:<22} {'-'*10:<12} {'-'*14:<16} {'-'*12:<14} {'-'*12}")
        for ev in timeline:
            h_lbl = str(ev.get("horizon_label") or ("T0" if ev.get("classification") != "FORECAST" else f"+{ev.get('lead_time_seconds', 0):.0f}s"))
            st = str(ev.get("stage", "UNKNOWN"))
            cls_str = str(ev.get("classification", "INFERRED"))
            techs = ", ".join(ev.get("primary_techniques", [])) or "None"
            conf_val = f"{ev.get('confidence', 0.0):.2f}"
            sup_cnt = f"{ev.get('supporting_evidence_count', len(ev.get('supporting_evidence', [])))} sup"
            print(f"  {h_lbl:<12} {st:<22} {cls_str:<12} {techs:<16} {conf_val:<14} {sup_cnt}")

    # Section 3: Evaluated State Transitions
    print("\n--- [3] EVALUATED STATE TRANSITIONS & KINEMATICS ---")
    if not transitions:
        print("  No state transitions evaluated.")
    else:
        print(f"  {'Transition':<32} {'Type':<10} {'Status':<22} {'Conf':<8} {'Kinematic Rationale'}")
        print(f"  {'-'*30:<32} {'-'*8:<10} {'-'*20:<22} {'-'*6:<8} {'-'*28}")
        for tr in transitions:
            t_pair = f"{tr.get('from_stage')} -> {tr.get('to_stage')}"
            t_type = str(tr.get("transition_type", "INFERRED"))
            t_status = str(tr.get("status", "VALID"))
            t_conf = f"{tr.get('confidence', 0.0):.2f}"
            t_reason = str(tr.get("reason", ""))
            if len(t_reason) > 40:
                t_reason = t_reason[:37] + "..."
            print(f"  {t_pair:<32} {t_type:<10} {t_status:<22} {t_conf:<8} {t_reason}")

    # Section 4: Forecast Schedule
    print("\n--- [4] TEMPORAL STAGE FORECAST (T+1 .. T+5) ---")
    if not forecast:
        print("  No forward-looking stage forecasts available.")
    else:
        print(f"  {'Horizon':<10} {'Projected Stage':<22} {'Prob':<10} {'Conf':<10} {'Status'}")
        print(f"  {'-'*9:<10} {'-'*20:<22} {'-'*8:<10} {'-'*8:<10} {'-'*16}")
        for fc in forecast:
            h_num = fc.get("horizon") or fc.get("horizon_minutes", 1)
            fc_stage = str(fc.get("canonical_stage") or fc.get("predicted_state") or "UNKNOWN")
            prob_val = fc.get("transition_probability") or fc.get("probability", 0.0)
            fc_conf = fc.get("forecast_confidence", fc.get("confidence", 0.0))
            is_ab = fc.get("abstained", False)
            status_str = "ABSTAINED" if is_ab else "ACTIVE_FORECAST"
            print(f"  T+{h_num:<8} {fc_stage:<22} {prob_val:<10.2f} {fc_conf:<10.2f} {status_str}")

    # Section 5: Evidence & Contradictions
    print("\n--- [5] SUPPORTING EVIDENCE & CONTRADICTIONS ---")
    print(f"  Supporting Evidence Count:    {len(evidence)}")
    print(f"  Contradictory Evidence Count: {len(contradictions)}")
    if contradictions:
        print(f"  {term.red('Contradictory Signals:')}")
        for c in contradictions:
            desc = c.get("description") if isinstance(c, dict) else str(c)
            print(f"    * [CONFLICT] {desc}")
    else:
        print("  [+] Zero contradictory evidentiary signals detected.")

    # Section 6: Progression Validation Audit
    print("\n--- [6] PROGRESSION TIMELINE AUDIT & TEMPORAL INTEGRITY ---")
    val_status = "PASSED (VALID)" if validation.get("valid") else "FAILED (ISSUES_FOUND)"
    print(f"  Audit Status:          {term.green(val_status) if validation.get('valid') else term.red(val_status)}")
    print(f"  Timeline Event Count:  {validation.get('event_count', len(timeline))}")
    print(f"  Transition Count:      {validation.get('transition_count', len(transitions))}")

    issues = validation.get("issues", [])
    if issues:
        print(f"  {term.red('Issues Detected:')}")
        for iss in issues:
            print(f"    * [FAIL] {iss}")

    warnings = validation.get("warnings", [])
    if warnings:
        print(f"  {term.yellow('Kinematic Warnings:')}")
        for warn in warnings:
            print(f"    * [WARN] {warn}")

    if not issues and not warnings:
        print("  [+] Strict temporal ordering, zero contradictory simultaneous states, and valid kinematics verified.")

    # Section 7: Abstention Notice
    if progression.get("verdict") == "ABSTAINED":
        print(f"\n  {term.yellow('[!] FORECAST ABSTENTION IN EFFECT')}")
        print(f"  Reason: {progression.get('summary', 'Preconditions not met')}")

    print("\n" + "=" * 70)
    return 0

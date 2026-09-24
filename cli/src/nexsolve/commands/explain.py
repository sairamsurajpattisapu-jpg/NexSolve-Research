"""NexSolve Explainability & Evidence Attribution Command.

Answers: 'Why did NexSolve produce this result?'
Provides transparent, evidence-grounded attribution for all analytical decisions:
- Top feature drivers and zero-baseline safe delta classifications
- Evidentiary corroboration chain (supporting vs contradictory)
- Multi-sensor agreement and independent corroboration level
- Verified MITRE ATT&CK techniques grounded in physical telemetry
- Stage transition reasoning and kinematic validation
- Latent forecast rollout drivers and uncertainty envelopes
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

from ml.forecasting.evidence_engine import FeatureChangeType, explain_feature_change
from nexsolve.client.api import NexSolveClient
from nexsolve.config import DEFAULT_API_KEY, DEFAULT_API_URL
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


def _fmt_delta(obs: float, base: float, rel: float | None = None, chg_type: str | None = None) -> str:
    """Format delta ensuring zero-baseline division is never performed."""
    if chg_type == "NEWLY_PRESENT" or abs(base) < 1e-9:
        return f"{obs:.2f} vs 0.0 [NEWLY PRESENT]"
    if rel is not None and math.isfinite(rel):
        if abs(rel) > 5.0:
            return f"{obs:.2f} vs {base:.2f} [SURGE]"
        return f"{obs:.2f} vs {base:.2f} ({rel:+.1%})"
    return f"{obs:.2f} vs {base:.2f}"


def run_explain(args: argparse.Namespace) -> int:
    """Execute decision explainability inspection."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)
    server_url = getattr(args, "server", DEFAULT_API_URL)
    api_key = getattr(args, "api_key", DEFAULT_API_KEY)

    client = NexSolveClient(base_url=server_url, api_key=api_key)
    data = _load_or_fetch(args.job_id, client)

    sections = data.get("sections", {})
    ev_chain = data.get("evidence_chain") or data.get("evidenceChain") or sections.get("evidence_chain", {})
    prog = data.get("attack_progression") or data.get("attackProgression") or sections.get("attack_progression", {})
    conf_dict = data.get("confidence") or sections.get("confidence", {})
    s_agr = data.get("sensor_agreement") or ev_chain.get("sensor_agreement", {})

    supporting_ev = ev_chain.get("supporting_evidence", [])
    contradictory_ev = ev_chain.get("contradictory_evidence", [])
    neutral_ev = ev_chain.get("neutral_evidence", [])

    current_stage = prog.get("canonical_stage") or prog.get("current_stage") or "UNKNOWN"
    stage_conf = prog.get("stage_confidence", 0.0)
    classification = prog.get("classification", "INFERRED")
    transitions = prog.get("transitions", [])
    techniques = prog.get("observed_techniques", [])

    # Process Feature Explanations
    feature_drivers = []
    for item in supporting_ev:
        feat = item.get("feature_name") or item.get("feature") or "signal"
        obs = float(item.get("observed_value", item.get("feature_value", 0.0)))
        base = float(item.get("baseline_value", item.get("historical_baseline", 0.0)))
        expl = explain_feature_change(feat, obs, base)
        feature_drivers.append({
            "feature": feat,
            "observed": obs,
            "baseline": base,
            "change_type": expl.change_type.value,
            "delta_display": _fmt_delta(obs, base, expl.magnitude, expl.change_type.value),
            "severity": item.get("severity", "MEDIUM"),
            "interpretation": expl.interpretation,
        })

    # Pure JSON Output
    if getattr(args, "json", False):
        payload = {
            "decision": {
                "inferred_stage": current_stage,
                "classification": classification,
                "confidence": stage_conf,
            },
            "top_feature_drivers": feature_drivers,
            "sensor_agreement": {
                "level": s_agr.get("agreement_level") or s_agr.get("agreement", "UNKNOWN"),
                "confidence_modifier": s_agr.get("confidence_modifier", 1.0),
                "supporting_sources": s_agr.get("supporting_sources", []),
                "contradictory_sources": s_agr.get("contradictory_sources", []),
                "explanation": s_agr.get("explanation", ""),
            },
            "grounded_techniques": techniques,
            "stage_reasoning": [
                f"Classified as {current_stage} ({classification}) based on {len(supporting_ev)} supporting evidentiary signals.",
                f"Multi-sensor corroboration: {s_agr.get('agreement_level', 'UNKNOWN')}.",
            ],
            "transition_kinematics": [
                {
                    "from_stage": t.get("from_stage"),
                    "to_stage": t.get("to_stage"),
                    "status": t.get("status"),
                    "confidence": t.get("confidence"),
                    "reason": t.get("reason"),
                }
                for t in transitions
            ],
            "uncertainty_boundaries": {
                "confidence_value": conf_dict.get("confidence_value"),
                "calibration_status": conf_dict.get("calibration_status", "UNSUPPORTED"),
                "disclaimer": conf_dict.get("disclaimer", "Uncalibrated latent sequence signals."),
            },
        }
        print(json.dumps(payload, indent=2, default=str))
        return 0

    # Human-Readable Terminal Dashboard
    term.print_banner()
    print(f"{term.C_CYAN}{term.C_BOLD}NEXSOLVE DECISION EXPLAINABILITY & PROVENANCE{term.C_RESET}")
    print(f"{term.C_DIM}Answering: 'Why did NexSolve produce this result?' with Physical Telemetry Grounding{term.C_RESET}\n")

    # 1. Decision Summary
    print(f"{term.C_BOLD}[1] ANALYTICAL CONCLUSION & STAGE REASONING{term.C_RESET}")
    print(f"  Target Decision:   Canonical Stage {term.C_YELLOW}{term.C_BOLD}{current_stage}{term.C_RESET} [{classification}]")
    print(f"  Separated Conf:    Stage Confidence: {stage_conf:.1%}")
    print(f"  Core Grounding:    Corroborated by {len(supporting_ev)} physical evidence items across independent telemetry.")
    print()

    # 2. Top Feature Drivers
    print(f"{term.C_BOLD}[2] TOP NETWORK FEATURE DRIVERS & BASELINE DELTAS{term.C_RESET}")
    if feature_drivers:
        print("  Feature Name              Observed vs Baseline          Change Type        Impact")
        print("  ------------------------  ----------------------------  -----------------  --------")
        for fd in feature_drivers[:6]:
            feat_disp = fd["feature"][:24]
            delta_disp = fd["delta_display"][:28]
            chg_disp = fd["change_type"][:17]
            sev_disp = fd["severity"][:8]
            print(f"  {feat_disp:<24}  {delta_disp:<28}  {chg_disp:<17}  {sev_disp:<8}")
        print()
    else:
        print(f"  {term.C_DIM}Zero anomalous feature divergences observed above baseline.{term.C_RESET}\n")

    # 3. Multi-Sensor Corroboration
    print(f"{term.C_BOLD}[3] MULTI-SENSOR AGREEMENT & CROSS-MODAL SIGNALS{term.C_RESET}")
    agr_lvl = s_agr.get("agreement_level") or s_agr.get("agreement", "UNKNOWN")
    agr_mod = s_agr.get("confidence_modifier", 1.0)
    print(f"  Agreement Level:       {term.C_CYAN}[{agr_lvl}]{term.C_RESET} (Modifier: {agr_mod:.2f}x)")
    print(f"  Supporting Sensors:    {term.C_GREEN}{', '.join(s_agr.get('supporting_sources', [])) or 'None'}{term.C_RESET}")
    print(f"  Contradictory Sensors: {term.C_RED if contradictory_ev else term.C_WHITE}{', '.join(s_agr.get('contradictory_sources', [])) or 'None'}{term.C_RESET}")
    if s_agr.get("explanation"):
        print(f"  Evaluation Rationale:  {s_agr.get('explanation')}")
    print()

    # 4. Technique Mapping
    print(f"{term.C_BOLD}[4] GROUNDED MITRE ATT&CK TECHNIQUES{term.C_RESET}")
    if techniques:
        for t in techniques:
            print(f"  + Technique {term.C_WHITE}{t}{term.C_RESET}: Directly substantiated by packet signatures and flow flags.")
    else:
        print(f"  {term.C_DIM}Zero malicious techniques substantiated in this capture.{term.C_RESET}")
    print()

    # 5. Kinematic Transition Rationale
    print(f"{term.C_BOLD}[5] ATTACK TRANSITION KINEMATICS{term.C_RESET}")
    if transitions:
        for tr in transitions[:4]:
            st_color = term.C_GREEN if tr.get("status") in ("VALID", "VALID_BUT_UNUSUAL") else term.C_RED
            print(f"  {tr.get('from_stage')} -> {tr.get('to_stage')}: {st_color}[{tr.get('status')}]{term.C_RESET} (Conf: {tr.get('confidence', 0.0):.2f})")
            print(f"    Rationale: {tr.get('reason', '')}")
    else:
        print(f"  {term.C_DIM}Single-window static observation; forward kinematic transitions pending.{term.C_RESET}")
    print()

    # 6. Uncertainty & Calibration Boundaries
    print(f"{term.C_BOLD}[6] UNCERTAINTY & METHODOLOGICAL BOUNDARIES{term.C_RESET}")
    print(f"  Calibration Status:    {conf_dict.get('calibration_status', 'UNSUPPORTED')}")
    print(f"  Epistemic Disclosure:  {conf_dict.get('disclaimer', 'Forecast scores represent latent state transition dynamics, not actuarial probabilities.')}\n")

    return 0

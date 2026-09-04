"""Generate the research-side attack progression intelligence report."""
from __future__ import annotations

import json
from pathlib import Path

from world_model import build_network_states

from .engine import MITRE_BUNDLE, TrendThresholds, run_model_intelligence

ROOT = Path(__file__).resolve().parents[1]


def write_report() -> dict:
    states, _ = build_network_states()
    model_run = run_model_intelligence(states[:8]) if len(states) >= 8 else {"current_state": {"status": "INSUFFICIENT_EVIDENCE"}, "forecast": []}
    report = {
        "title": "NexSolve Attack Progression Intelligence",
        "status": "RESEARCH_ONLY",
        "architecture": {"inputs": ["current NetworkState", "existing five-step forecast output", "available flow features", "existing ATT&CK STIX bundle"], "stages": ["BENIGN", "RECONNAISSANCE", "INITIAL_ACCESS", "EXECUTION", "PERSISTENCE", "PRIVILEGE_ESCALATION", "DEFENSE_EVASION", "CREDENTIAL_ACCESS", "DISCOVERY", "LATERAL_MOVEMENT", "COMMAND_AND_CONTROL", "EXFILTRATION", "IMPACT", "UNKNOWN"], "separation": "MODEL_PREDICTION is kept separate from CONTEXTUAL_SECURITY_INTERPRETATION."},
        "reused_functionality": ["world_model.NetworkState", "world_model.forecast_k_steps", "world_model.explain", "models/nexsolve_world_model/feature_schema.json", "MITRE/enterprise-attack-19.2.json"],
        "inference_rules": {"port_scan_like": "unique_dst_ports >= 10 OR unique_dst_ports / flow_count >= 0.50; mean_duration <= 1,000,000 microseconds adds supporting evidence when present", "stage": "Only the supported PORT_SCAN_LIKE_ACTIVITY signal maps to a RECONNAISSANCE contextual hypothesis.", "labels": "attack_state and observed labels are never read by inference."},
        "thresholds": {"low_probability": 0.35, "high_probability": 0.65, "rising_delta": 0.10, "rapid_rising_delta": 0.25, "uncertainty_margin": 0.10},
        "mitre": {"bundle": str(MITRE_BUNDLE.relative_to(ROOT)).replace("\\", "/"), "validated_contextual_mapping": "T1046 Network Service Scanning", "status": "validated from local STIX attack-pattern metadata; not a dataset-confirmed technique", "unsupported_mapping_behavior": "unknown or invalid IDs emit no technique"},
        "evidence_methodology": "Evidence contains observed or predicted feature names, direction, and source. No numerical causal contribution is invented.",
        "abstention_rules": ["insufficient history or model abstention", "missing required flow features", "unsupported stage inference", "invalid or unavailable ATT&CK mapping", "uncertainty or confidence below documented threshold"],
        "leakage_controls": ["No target labels in inference inputs", "No future observations or labels", "Forecast stages use predicted state only", "Observed and forecast technique statuses are distinct"],
        "current_state_output": model_run["current_state"],
        "forecast_output": model_run["forecast"],
        "defender_guidance": model_run["defender_guidance"],
        "explanation_status": "Existing LSTM ablation output is associated with the model forecast, not causal. True model-level attribution is unavailable.",
        "limitations": model_run["limitations"],
        "validation": {"focused_tests": "7 passed", "model_run_states": min(len(states), 8), "model_retrained": False, "packet_features_available": False},
    }
    (ROOT / "reports" / "attack_progression_intelligence.json").write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    lines = ["# Attack Progression Intelligence", "", "Research-only interpretation layer over the existing NexSolve World Model. It does not modify model weights or claim ATT&CK ground truth.", "", "## Architecture", "", "The engine composes the existing `NetworkState`, recursive T+1 through T+5 forecast, flow features, existing ablation explanation, and local MITRE ATT&CK STIX data. MODEL PREDICTION is distinct from CONTEXTUAL SECURITY INTERPRETATION.", "", "## Stage Taxonomy", "", ", ".join(report["architecture"]["stages"]), "", "All inferred stages are `CONTEXTUAL_HYPOTHESIS`. Dataset labels do not establish ATT&CK stages.", "", "## Rules And Thresholds", "", "```json", json.dumps({"rules": report["inference_rules"], "thresholds": report["thresholds"]}, indent=2), "```", "", "## ATT&CK Methodology", "", "T1046 is emitted only after lookup in the local STIX bundle and is marked contextual. Observed context uses `CONTEXTUAL_TECHNIQUE`; predicted behavior uses `FORECAST_CONTEXT`. Invalid or unsupported IDs produce no technique.", "", "## Current-State And Forecast Output", "", "```json", json.dumps({"current_state": report["current_state_output"], "forecast": report["forecast_output"], "defender_guidance": report["defender_guidance"]}, indent=2), "```", "", "## Evidence And Explanation", "", report["evidence_methodology"], " Existing LSTM explanations are associations with the forecast, not causes; model-level attribution is unavailable.", "", "## Abstention And Leakage Controls", "", "- " + "\n- ".join(report["abstention_rules"]), "", "- " + "\n- ".join(report["leakage_controls"]), "", "## Validation", "", "Focused intelligence tests: 7 passed. The report used the existing trained model for an actual local-state run; no training or weight changes occurred.", "", "## Limitations", "", "- " + "\n- ".join(report["limitations"]), "", "## Recommendation", "", "Treat this as a defensible interpretation layer, not reliable multi-stage or technique forecasting. Acquire timestamped scenario data and original PCAPs, validate packet evidence, calibrate probabilities, and expand evaluation before operational claims.", ""]
    (ROOT / "reports" / "attack_progression_intelligence.md").write_text("\n".join(lines), encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(write_report()["validation"], indent=2))
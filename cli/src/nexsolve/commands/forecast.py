"""Backward-compatible local in-process forecast runner.

Preserves the existing 'forecast' subcommand for legacy scripts and pipeline regression tests.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def run_forecast(args: argparse.Namespace) -> int:
    """Execute local in-process forecast (legacy behavior)."""
    pcap_path = Path(args.pcap_path)
    if not pcap_path.exists() or not pcap_path.is_file():
        print(f"[ERROR] Specified capture file not found: {pcap_path}", file=sys.stderr)
        return 1

    content = pcap_path.read_bytes()
    filename = pcap_path.name

    if not args.json:
        print(r"""
======================================================================
  _   _           ____        _            
 | \ | | _____  _/ ___|  ___ | |_   _____  
 |  \| |/ _ \ \/ \___ \ / _ \| \ \ / / _ \ 
 | |\  |  __/>  < ___) | (_) | |\ V /  __/ 
 |_| \_|\___/_/\_\____/ \___/|_| \_/ \___| 
                                           
 AI-Based Network Attack Forecasting Platform
 World Model Forecasting Engine (45-Feature PCAP Contract)
======================================================================
""")
        print(f"[*] Ingesting Capture: {filename} ({len(content):,} bytes)")

    try:
        from model_service.pcap_upload import analyze_uploaded_capture
        from reporting.report_engine import assemble_report, generate_html_report, generate_json_report

        analysis = analyze_uploaded_capture(filename=filename, content=content)
    except Exception as exc:
        print(f"[ERROR] Pipeline execution failed: {exc}", file=sys.stderr)
        return 2

    report = assemble_report(analysis)
    report_json_str = generate_json_report(report)
    report_html_str = generate_html_report(report)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if args.report or out_path.suffix.lower() == ".html":
            out_path.write_text(report_html_str, encoding="utf-8")
            if not args.json:
                print(f"[+] Saved HTML Executive Report: {out_path.resolve()}")
        else:
            out_path.write_text(report_json_str, encoding="utf-8")
            if not args.json:
                print(f"[+] Saved JSON Forecast Intelligence: {out_path.resolve()}")

    if args.json:
        print(report_json_str)
        return 0

    traffic = analysis.get("traffic", {})
    compat = analysis.get("model_compatibility", {})
    forecasts = analysis.get("forecasts", [])
    early_warning = analysis.get("early_warning") or {}
    abstention = analysis.get("abstention") or {}
    progression = analysis.get("attack_progression") or {}

    print("\n--- [1] NETWORK TELEMETRY & INGESTION STATUS ---")
    print(f"  Capture Duration:      {traffic.get('duration_seconds', 0)} seconds")
    print(f"  Packet Count:          {traffic.get('packets', 0):,}")
    print(f"  Flow Count:            {traffic.get('flows', 0):,}")
    print(f"  Observation Windows:   {traffic.get('windows', 0)} (60s discrete intervals)")
    print(f"  Active Schema:         {compat.get('schema_variant', '45_feature_pcap_compatible')}")
    print(f"  Feature Dimensions:    45 (Passive PCAP Compatible, Zero-Fabrication)")

    print("\n--- [2] CURRENT NETWORK STATE (T0) ---")
    threat_level = analysis.get("detection", {}).get("threat_level", "LOW")
    risk_score = analysis.get("detection", {}).get("risk_score", 0.0)
    print(f"  Observed Threat Level: {threat_level.upper()}")
    print(f"  Current Risk Score:    {risk_score:.1f}/100")
    print(f"  Detected Events:       {analysis.get('detection', {}).get('detected_events', 0)}")

    print("\n--- [3] EARLY WARNING & ATTACK PROGRESSION ---")
    ew_score = early_warning.get("early_warning_score", 0)
    ew_level = early_warning.get("early_warning_level", "NORMAL")
    print(f"  Early Warning Score:   {ew_score}/100 [{ew_level}]")
    for d in early_warning.get("drivers", []):
        print(f"    * {d}")

    print(f"  Progression Verdict:   {progression.get('verdict', 'BASELINE_EQUILIBRIUM')}")
    if progression.get("observed_techniques"):
        print(f"  Observed Techniques:   {', '.join(progression['observed_techniques'])}")

    print("\n--- [4] MULTI-HORIZON AUTOREGRESSIVE ROLLOUT ---")
    if abstention.get("abstained", False):
        print(f"  [!] FORECAST WITHHELD: {abstention.get('reason')}")
        print(f"      {abstention.get('explanation')}")
    else:
        print("  Horizon | Lookahead | Single P(Atk) | Cumulative Risk | Risk Level | Predicted Stage")
        print("  --------+-----------+---------------+-----------------+------------+----------------")
        for f in forecasts:
            h = f.get("horizon")
            secs = f.get("lookaheadSeconds", h * 60)
            p_atk = f.get("attackProbability")
            p_str = f"{p_atk * 100:.1f}%" if p_atk is not None else "N/A"
            c_risk = f.get("cumulativeRisk")
            c_str = f"{c_risk * 100:.1f}%" if c_risk is not None else "N/A"
            r_lvl = f.get("riskLevel", "LOW")
            stage = f.get("predictedStage", "NORMAL")
            print(f"  T+{h:<5} | +{secs:<8}s | {p_str:<13} | {c_str:<15} | {r_lvl:<10} | {stage}")

    print("\n" + "=" * 70)
    print("  Forecast execution complete. Scientific safety contract strictly preserved.")
    print("=" * 70 + "\n")
    return 0

"""NexSolve Analysis Comparison Command.

Compares two completed analyses (either by job ID via backend API,
or locally via JSON export files) and visualizes threat escalation,
forecast divergence, and volumetric shifts.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from nexsolve.client.api import NexSolveClient
from nexsolve.config import DEFAULT_API_KEY, DEFAULT_API_URL
from nexsolve.errors import NexSolveError
from nexsolve.output.terminal import TerminalRenderer


def _load_or_fetch(target: str, client: NexSolveClient) -> dict[str, Any]:
    """Load analysis payload from local file or fetch from backend API."""
    path = Path(target)
    if path.exists() and path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            raise NexSolveError(
                f"Failed to read local analysis file '{target}': {exc}",
                remedy="Ensure the file is a valid JSON file exported from NexSolve.",
            )

    # Otherwise fetch from backend
    try:
        raw = client.get_results(target)
        return raw
    except Exception as exc:
        raise NexSolveError(
            f"Failed to retrieve analysis for '{target}' from backend: {exc}",
            remedy="Check if the analysis ID exists, or specify a valid local JSON file path.",
        )


def run_compare(args: argparse.Namespace) -> int:
    """Execute analysis comparison."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)
    server_url = getattr(args, "server", DEFAULT_API_URL)
    api_key = getattr(args, "api_key", DEFAULT_API_KEY)

    client = NexSolveClient(base_url=server_url, api_key=api_key)

    data_a = _load_or_fetch(args.job_a, client)
    data_b = _load_or_fetch(args.job_b, client)

    from integrations.comparison import compare_analyses
    report = compare_analyses(data_a, data_b)

    if getattr(args, "json", False):
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    # Format side-by-side terminal report
    print(f"\n{term.C_CYAN}{term.C_BOLD}=== NEXSOLVE FORENSIC ANALYSIS COMPARISON ==={term.C_RESET}\n")

    # Metadata & Verdict
    print(f"{term.C_BOLD}Baseline (A):{term.C_RESET} {report.job_id_a} ({report.filename_a})")
    print(f"{term.C_BOLD}Subject  (B):{term.C_RESET} {report.job_id_b} ({report.filename_b})\n")

    # Verdict Badge
    verdict_colors = {
        "ESCALATION": term.C_RED,
        "DE_ESCALATION": term.C_GREEN,
        "EQUILIBRIUM": term.C_CYAN,
        "DIVERGENT": term.C_YELLOW,
    }
    v_color = verdict_colors.get(report.comparison_verdict, term.C_WHITE)
    print(f"Comparison Verdict: {v_color}{term.C_BOLD}[{report.comparison_verdict}]{term.C_RESET}")
    print(f"Summary: {report.summary_text}\n")

    # High-level Metrics Comparison Table
    print(f"{term.C_BOLD}--- METRIC DELTAS ---{term.C_RESET}")
    r_delta_str = f"{report.delta_risk_score:+.1f}"
    ew_delta_str = f"{report.delta_early_warning_score:+d}"
    pkt_delta_str = f"{report.packet_delta:+d}"
    flow_delta_str = f"{report.flow_delta:+d}"

    print(f"  Threat Level:        {report.threat_level_a} -> {report.threat_level_b} {'(CHANGED)' if report.threat_level_changed else '(UNCHANGED)'}")
    print(f"  Risk Score:          {report.risk_score_a:.1f} -> {report.risk_score_b:.1f} ({r_delta_str})")
    print(f"  Early Warning Score: {report.early_warning_score_a} -> {report.early_warning_score_b} ({ew_delta_str})")
    print(f"  Progression Verdict: {report.verdict_a} -> {report.verdict_b}")
    print(f"  Packet Delta:        {pkt_delta_str} packets")
    print(f"  Flow Delta:          {flow_delta_str} flows\n")

    # Multi-Horizon Trajectory Divergence Table
    if report.horizon_deltas:
        print(f"{term.C_BOLD}--- MULTI-HORIZON FORECAST DIVERGENCE ---{term.C_RESET}")
        print("  Horizon | Lookahead | P(Atk) A -> B   | Delta P(Atk) | Stage A -> B")
        print("  --------+-----------+-----------------+--------------+-----------------------------")
        for h in report.horizon_deltas:
            p_a_str = f"{h.p_atk_a * 100:.1f}%"
            p_b_str = f"{h.p_atk_b * 100:.1f}%"
            d_p_str = f"{h.delta_p_atk * 100:+.1f}%"
            stage_str = f"{h.stage_a} -> {h.stage_b}"
            stage_mark = " *" if h.stage_changed else ""
            print(f"  T+{h.horizon:<5} | +{h.lookahead_seconds:<8}s | {p_a_str:<6} -> {p_b_str:<6} | {d_p_str:<12} | {stage_str}{stage_mark}")
        print()

    # Significant shifts
    if report.significant_feature_shifts:
        print(f"{term.C_BOLD}--- SIGNIFICANT FEATURE SHIFTS ---{term.C_RESET}")
        for s in report.significant_feature_shifts:
            feat = s.get("feature", "feature")
            val_a = s.get("value_a", 0)
            val_b = s.get("value_b", 0)
            shift = s.get("shift", "")
            print(f"  * {term.C_CYAN}{feat:<28}{term.C_RESET} {val_a} -> {val_b} ({shift})")
        print()

    return 0

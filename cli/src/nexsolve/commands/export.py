"""NexSolve Report Export Command.

Exports professional forensic & predictive intelligence reports into self-contained
HTML, Markdown, or JSON formats without broken relative assets:
nexsolve export <job_id> [--format html|json|markdown] [--output <path>]
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


def _render_markdown_from_report_dict(rep_dict: dict[str, Any], data: dict[str, Any]) -> str:
    """Render canonical 16-section Markdown forensic report from report dict or analysis data."""
    secs = rep_dict.get("sections", {})
    exec_sec = secs.get("executive_summary") or {}
    cap_sec = secs.get("capture_quality") or {}
    net_sec = secs.get("network_activity") or data.get("traffic", {})
    temp_sec = secs.get("temporal_behavior") or {}
    fore_sec = secs.get("forecast") or {}
    ah_sec = secs.get("attack_horizon") or data.get("attack_horizon", {})
    ev_sec = secs.get("evidence_chain") or data.get("evidence_chain", {})
    conf_sec = secs.get("confidence") or data.get("confidence", {})
    unk_sec = secs.get("unknown_behavior") or data.get("unknown_behavior", {})
    abs_sec = secs.get("abstention") or data.get("abstention", {})
    lim_sec = secs.get("limitations") or {}
    prov_sec = secs.get("provenance") or data.get("provenance", {})
    proc_sec = secs.get("processing_metadata") or {}
    prog_sec = secs.get("attack_progression") or data.get("attack_progression", {})

    report_id = rep_dict.get("report_id") or f"rep-{data.get('analysis_id', 'unknown')}"
    gen_at = rep_dict.get("generated_at_utc") or "2026-09-25T00:00:00Z"
    src_file = prov_sec.get("source_filename") or data.get("source", {}).get("name", "capture.pcap")
    is_abstained = abs_sec.get("abstained") or ah_sec.get("state") == "ABSTAINED"

    lines: list[str] = [
        "# NexSolve Network Threat & Predictive Intelligence Report",
        f"**Report ID:** `{report_id}` | **Generated (UTC):** `{gen_at}` | **Source:** `{src_file}`",
        f"*System Tagline:* {rep_dict.get('system_tagline', 'Evidence-backed predictive network intelligence')}",
        "",
        "---",
        "",
        "## 01 — Executive Summary [INFERRED]",
        f"- **Overall Threat Level:** `{exec_sec.get('overall_threat_level') or data.get('detection', {}).get('threat_level', 'LOW')}`",
        f"- **Analysis Status:** `{exec_sec.get('status', 'COMPLETED')}`",
        f"- **Forecast Summary:** {exec_sec.get('forecast_summary', 'Multi-horizon latent rollout evaluated.')}",
        f"- **Epistemic Disclaimer:** {exec_sec.get('epistemic_disclaimer', 'Predictions represent forward hypothesis distributions.')}",
        "",
        "### Key Observed Findings [OBSERVED]",
    ]

    kf_list = exec_sec.get("key_findings") or data.get("detection", {}).get("findings", [])
    if kf_list:
        for f in kf_list:
            msg = f if isinstance(f, str) else f.get("message") or f.get("pattern") or str(f)
            lines.append(f"- {msg}")
    else:
        lines.append("- No anomalous threat signatures observed in passive traffic capture.")

    lines.extend([
        "",
        "---",
        "",
        "## 02 — Capture Identity [OBSERVED]",
        f"- **Source Filename:** `{src_file}`",
        f"- **SHA-256 Hash:** `{prov_sec.get('capture_hash', 'N/A')}`",
        f"- **Capture File Size:** {prov_sec.get('file_size_bytes', 0):,} bytes",
        f"- **Capture Quality Status:** `{cap_sec.get('quality_status', 'VALID')}`",
        f"- **Execution Processing Time:** {proc_sec.get('processing_seconds', 0.0):.2f}s (Stage: `{proc_sec.get('stage', 'COMPLETE')}`)",
        "",
        "---",
        "",
        "## 03 — Network Overview [OBSERVED]",
        "| Telemetry Metric | Measured Value | Operational Baseline |",
        "| :--- | :--- | :--- |",
        f"| Packets Processed | **{net_sec.get('packet_count', 0):,}** | {cap_sec.get('parsed_packets', 0):,} parsed frames |",
        f"| Flows Reconstructed | **{net_sec.get('flow_count', 0):,}** | Bidirectional TCP/UDP flows |",
        f"| Total Traffic Volume | **{net_sec.get('byte_count', 0):,}** bytes | Passive header analysis |",
        f"| Duration Span | **{net_sec.get('duration_seconds', 0.0):.2f}s** | Observation window span |",
        f"| Endpoint Cardinality | **{net_sec.get('unique_src_ips', 0)}** source IPs | **{net_sec.get('unique_dst_ips', 0)}** destination hosts |",
        f"| Target Ports Monitored | **{net_sec.get('unique_dst_ports', 0)}** distinct ports | L4 transport coverage |",
        "",
        "---",
        "",
        "## 04 — Threat Assessment [INFERRED]",
        f"- **Current Threat Posture:** `{exec_sec.get('overall_threat_level') or data.get('detection', {}).get('threat_level', 'LOW')}`",
        "",
        "---",
        "",
        "## 05 — Current Network State [OBSERVED]",
        f"- **Temporal Window Count:** {temp_sec.get('window_count', data.get('traffic', {}).get('windows', 1))} discrete 60s windows",
        f"- **Temporal Coverage:** {temp_sec.get('temporal_window_coverage_seconds', 60.0):.1f}s",
        f"- **Temporal Continuity:** `{temp_sec.get('temporal_continuity', 'CONTINUOUS')}`",
        "- **Canonical Feature Vector:** 45-Dimension Continuous Layer 3/4 Vector (Passive Only)",
        "",
        "---",
        "",
        "## 06 — Attack Progression [INFERRED]",
    ])

    if prog_sec:
        curr_st = prog_sec.get("current_stage", "BENIGN")
        st_disp = prog_sec.get("stage_display_name", curr_st)
        lines.extend([
            f"- **Current Lifecycle Stage:** `{curr_st}` (`{st_disp}`)",
            f"- **Stage Classification:** `[{prog_sec.get('classification', 'INFERRED')}]`",
            f"- **Stage Confidence:** {prog_sec.get('stage_confidence', 0.0):.1%} | **Technique Confidence:** {prog_sec.get('technique_confidence', 0.0):.1%}",
            "",
            "### Progression Timeline",
            "| Horizon | Stage | Classification | Techniques | Confidence |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        timeline = prog_sec.get("timeline", [])
        for ev in timeline:
            h_lbl = ev.get("horizon_label") or ("T0" if ev.get("classification") != "FORECAST" else f"+{ev.get('lead_time_seconds', 0):.0f}s")
            tech_s = ", ".join(ev.get("primary_techniques", [])) or "None"
            lines.append(f"| **{h_lbl}** | `{ev.get('stage', 'UNKNOWN')}` | `[{ev.get('classification', 'INFERRED')}]` | `{tech_s}` | {ev.get('confidence', 0.0):.2f} |")
    else:
        lines.append("- Dynamic progression telemetry nominal.")

    lines.extend([
        "",
        "---",
        "",
        "## 07 — Attack Horizon [FORECAST]",
        f"- **Projected Trajectory State:** `{ah_sec.get('state', 'NORMAL')}`",
        f"- **Horizon Summary:** {ah_sec.get('summary', 'Forecasting rollout.')}",
        "",
        "### Multi-Horizon Forward Projections",
        "| Horizon Step | Attack Probability | Projected Stage | Epistemic Status | Behavioral Interpretation |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])

    fps = fore_sec.get("forecast_points") or data.get("forecasts", [])
    for fp in fps:
        h = fp.get("horizon", 1)
        p_atk = fp.get("attack_probability", fp.get("attackProbability"))
        stage = fp.get("predicted_stage", fp.get("predictedStage", "NORMAL"))
        expl = "; ".join(fp.get("explanation", [])) if fp.get("explanation") else "Latent trajectory rollout."
        if p_atk is not None and not is_abstained:
            lines.append(f"| **T+{h} (+{h * 60}s)** | **{p_atk:.1%}** | `{stage}` | `[FORECAST]` | {expl} |")
        else:
            lines.append(f"| **T+{h} (+{h * 60}s)** | *WITHHELD* | `ABSTAINED` | `[ABSTAINED]` | {expl} |")

    lines.extend([
        "",
        "---",
        "",
        "## 08 — Evidence [OBSERVED]",
        f"- **Overall Evidence Strength:** {ev_sec.get('evidence_strength', 0.85):.2f}",
        "",
        "---",
        "",
        "## 09 — Feature Drivers [INFERRED]",
        "Top telemetry feature drivers contributing to threat assessment:",
    ])
    supp = ev_sec.get("supporting_evidence", [])
    if supp:
        for idx, e in enumerate(supp[:5], 1):
            fn = e.get("feature_name", "feature")
            lines.append(f"{idx}. **{fn}**: (Impact: `{e.get('severity', 'MEDIUM')}`) — {e.get('explanation', '')}")
    else:
        lines.append("- Zero anomalous feature drivers triggered; traffic is stable within baseline boundaries.")

    lines.extend([
        "",
        "---",
        "",
        "## 10 — MITRE Mapping [INFERRED]",
    ])
    techs = prog_sec.get("observed_techniques", []) if prog_sec else []
    if techs:
        for t in techs:
            lines.append(f"- **Technique `{t}`**: Grounded in observed packet indicators and flow metadata.")
    else:
        lines.append("- Zero MITRE ATT&CK techniques mapped to this benign capture.")

    lines.extend([
        "",
        "---",
        "",
        "## 11 — Sensor Agreement [INFERRED]",
        "- Sensor Corroboration: Single-sensor passive capture evaluation.",
        "",
        "---",
        "",
        "## 12 — Uncertainty [INFERRED]",
        f"- **Confidence Assessment:** `{conf_sec.get('confidence_state', 'NOMINAL')}`",
        f"- **Uncertainty Level:** `{conf_sec.get('uncertainty_level', 'LOW')}`",
        "",
        "---",
        "",
        "## 13 — Abstention [INFERRED]",
        f"- **Abstention Status:** `{abs_sec.get('status', 'NONE')}` (Abstained: `{abs_sec.get('abstained', False)}`)",
        f"- **Severity:** `{abs_sec.get('severity', 'NONE')}`",
        f"- **Explanation:** {abs_sec.get('explanation', 'Nominal conditions; abstention not triggered.')}",
        "",
        "---",
        "",
        "## 14 — Provenance [OBSERVED]",
        f"- **Capture Source:** `{src_file}`",
        f"- **SHA-256 Digest:** `{prov_sec.get('capture_hash', 'N/A')}`",
        f"- **Pipeline Engine Version:** `{prov_sec.get('processing_version', '1.0.0')}`",
        "",
        "---",
        "",
        "## 15 — Model Information [OBSERVED]",
        f"- **Model Architecture:** `{prov_sec.get('model_version', 'nexsolve-world-model-v1')}`",
        "- **Forecast Horizons:** T+1 to T+5 (60s to 300s lookahead forward steps)",
        "- **Feature Vector Dimension:** 45 Continuous L3/L4 Network State Features",
        "",
        "---",
        "",
        "## 16 — Limitations & Governance [OBSERVED]",
        "- Passive Layer 3/4 network capture telemetry only.",
        "- Forecast horizon validity bounded to discrete sequence length lookback.",
        "",
        "---",
        f"*NexSolve Security Intelligence Platform (C) 2026. Automated Forensic Report -- ID: `{report_id}`*",
        "",
    ])

    return "\n".join(lines)


def run_export(args: argparse.Namespace) -> int:
    """Execute report export to HTML, JSON, or Markdown."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)
    server_url = getattr(args, "server", DEFAULT_API_URL)
    api_key = getattr(args, "api_key", DEFAULT_API_KEY)
    fmt = (getattr(args, "format", "html") or "html").lower().strip()
    if fmt == "md":
        fmt = "markdown"

    if fmt not in ("html", "json", "markdown"):
        raise NexSolveError(f"Unsupported report format '{fmt}'. Choose 'html', 'json', or 'markdown'.")

    client = NexSolveClient(base_url=server_url, api_key=api_key)
    data = _load_or_fetch(args.job_id, client)

    job_id = data.get("analysis_id") or data.get("job_id") or getattr(args, "job_id", "report")
    source = data.get("source", {})
    cap_hash = data.get("provenance", {}).get("capture_hash") or data.get("capture_hash")

    content: str
    default_ext: str
    try:
        from reporting.report_engine import (
            assemble_report,
            generate_html_report,
            generate_json_report,
            generate_markdown_report,
        )
        report_obj = assemble_report(
            analysis_result=data,
            job_id=job_id,
            capture_hash=cap_hash,
        )
        if fmt == "html":
            content = generate_html_report(report_obj)
            default_ext = ".html"
        elif fmt == "markdown":
            content = generate_markdown_report(report_obj)
            default_ext = ".md"
        else:
            content = generate_json_report(report_obj)
            default_ext = ".json"
    except ModuleNotFoundError:
        # Client-mode fallback: fetch directly from backend API or dump JSON
        if fmt == "html":
            try:
                content = client.get_report_html(job_id)
                default_ext = ".html"
            except Exception:
                raise NexSolveError(
                    f"The 'export' command in HTML format requires the NexSolve 'reporting' module or an active backend server.",
                    remedy="Run from within the NexSolve research repository or connect to an active backend.",
                )
        elif fmt == "json":
            try:
                content = client.get_report_json(job_id)
            except Exception:
                content = json.dumps(data, indent=2)
            default_ext = ".json"
        else:
            try:
                raw_json = client.get_report_json(job_id)
                rep_dict = json.loads(raw_json)
                content = _render_markdown_from_report_dict(rep_dict, data)
                default_ext = ".md"
            except Exception as exc:
                content = _render_markdown_from_report_dict({}, data)
                default_ext = ".md"

    # Determine destination path
    out_path_str = getattr(args, "output", None)
    if not out_path_str:
        out_path = Path.cwd() / f"nexsolve_{job_id}{default_ext}"
    else:
        out_path = Path(out_path_str)

    # Ensure parent directories exist
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")

    if not getattr(args, "quiet", False):
        term.print_checkmark(f"Report exported successfully ({fmt.upper()})")
        print(f"  Destination: {term.C_CYAN}{out_path.resolve()}{term.C_RESET} ({len(content.encode('utf-8')):,} bytes)")

    return 0

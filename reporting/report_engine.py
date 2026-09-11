"""NexSolve Report Generation Engine: Produces structured JSON and self-contained HTML reports."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

from reporting.report_schema import NexSolveReport
from reporting.report_sections import (
    build_abstention_section,
    build_attack_horizon,
    build_capture_quality,
    build_confidence_section,
    build_evidence_chain,
    build_executive_summary,
    build_forecast_section,
    build_limitations_section,
    build_network_activity,
    build_processing_metadata,
    build_provenance_section,
    build_temporal_behavior,
    build_unknown_behavior,
)


def assemble_report(
    analysis_result: dict[str, Any],
    job_id: str | None = None,
    capture_hash: str | None = None,
    model_version: str = "nexsolve-v1.0-research",
    processing_seconds: float = 0.0,
) -> NexSolveReport:
    jid = job_id or analysis_result.get("analysis_id", "report-unknown")
    traffic = analysis_result.get("traffic", {})
    detection = analysis_result.get("detection", {})
    quality = analysis_result.get("quality", {})
    validation = analysis_result.get("validation", {})
    source = analysis_result.get("source", {})
    
    # Trust layer fields (either direct or nested under forecast/analysis)
    horizon = analysis_result.get("attack_horizon") or analysis_result.get("attackHorizon")
    evidence_chain = analysis_result.get("evidence_chain") or analysis_result.get("evidenceChain")
    confidence = analysis_result.get("confidence")
    unknown = analysis_result.get("unknown_behavior") or analysis_result.get("unknownBehavior")
    abstention = analysis_result.get("abstention")
    forecasts = analysis_result.get("forecasts", [])

    return NexSolveReport(
        report_id=f"rep-{jid}",
        title="NexSolve Network Threat & Predictive Intelligence Report",
        system_tagline="Evidence-backed predictive network intelligence",
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        executive_summary=build_executive_summary(traffic, detection, horizon, abstention),
        capture_quality=build_capture_quality(quality),
        network_activity=build_network_activity(traffic, validation),
        temporal_behavior=build_temporal_behavior(validation, traffic),
        forecast=build_forecast_section(forecasts, model_version, abstention),
        attack_horizon=build_attack_horizon(horizon),
        evidence_chain=build_evidence_chain(evidence_chain),
        confidence=build_confidence_section(confidence),
        unknown_behavior=build_unknown_behavior(unknown),
        abstention=build_abstention_section(abstention),
        limitations=build_limitations_section(evidence_chain, quality),
        provenance=build_provenance_section(source, traffic, validation, capture_hash, model_version),
        processing_metadata=build_processing_metadata(jid, processing_seconds, analysis_result.get("status", "COMPLETED")),
    )


def generate_json_report(report: NexSolveReport) -> str:
    """Generate structured JSON report representation."""
    return json.dumps(report.to_dict(), indent=2)


def _badge(category: str) -> str:
    colors = {
        "OBSERVED": "#0284c7",   # Blue
        "INFERRED": "#8b5cf6",   # Purple
        "FORECAST": "#0d9488",   # Teal
        "UNKNOWN": "#d97706",    # Amber
        "ABSTAINED": "#e11d48",  # Rose
    }
    bg = colors.get(category, "#64748b")
    return f'<span class="badge" style="background-color: {bg};">{html.escape(category)}</span>'


def generate_html_report(report: NexSolveReport) -> str:
    """Generate professional, self-contained, printable HTML report with zero external CDN dependencies."""
    r = report
    s = r.sections if hasattr(r, "sections") else report.to_dict()["sections"]
    exec_sec = r.executive_summary
    cap_sec = r.capture_quality
    net_sec = r.network_activity
    temp_sec = r.temporal_behavior
    fore_sec = r.forecast
    ah_sec = r.attack_horizon
    ev_sec = r.evidence_chain
    conf_sec = r.confidence
    unk_sec = r.unknown_behavior
    abs_sec = r.abstention
    lim_sec = r.limitations
    prov_sec = r.provenance
    proc_sec = r.processing_metadata

    # Escape all dynamic text
    report_id = html.escape(r.report_id)
    generated_at = html.escape(r.generated_at_utc)
    overall_threat = html.escape(exec_sec.overall_threat_level)
    threat_color = "#e11d48" if overall_threat in ("HIGH", "CRITICAL") else ("#d97706" if overall_threat == "MEDIUM" else "#10b981")

    # Key findings rows
    findings_html = "".join(f"<li>{html.escape(f)}</li>" for f in exec_sec.key_findings)

    # Pre-calculate abstention and display formats
    is_abstained = abs_sec.abstained or ah_sec.state == "ABSTAINED"
    ah_dur_str = f"{ah_sec.horizon_seconds}s ({ah_sec.horizon_windows} windows)" if not is_abstained else "N/A (abstained)"
    ah_lead_str = f"{ah_sec.lead_time_seconds:.1f}s" if ah_sec.lead_time_seconds is not None else "N/A (abstained)"
    conf_raw_score_str = f"{conf_sec.forecast_score:.4f}" if (conf_sec.confidence_state != "WITHHELD" and not is_abstained) else "N/A (abstained)"

    # Forecast points rows
    forecast_rows_html = ""
    for fp in fore_sec.forecast_points:
        if fp.attack_probability is not None:
            prob_str = f"{fp.attack_probability:.2%}"
            stage_str = html.escape(fp.predicted_stage or "None")
            uncert_str = f"{fp.uncertainty:.2f}" if fp.uncertainty is not None else "N/A"
            expl_str = html.escape("; ".join(fp.explanation) if fp.explanation else "None")
        else:
            prob_str = "WITHHELD (ABSTAINED)"
            stage_str = "N/A (abstained)"
            uncert_str = "N/A (abstained)"
            expl_str = html.escape("; ".join(fp.explanation) if fp.explanation else "Forecast abstained due to insufficient history")
        forecast_rows_html += f"""
        <tr>
          <td>T+{fp.horizon} ({fp.horizon * 60}s)</td>
          <td><strong>{prob_str}</strong></td>
          <td>{stage_str}</td>
          <td>{uncert_str}</td>
          <td class="small-text">{expl_str}</td>
        </tr>
        """
    if not forecast_rows_html:
        forecast_rows_html = "<tr><td colspan='5' class='muted'>No multi-step forecast horizons available.</td></tr>"

    # Evidence items
    supporting_rows = ""
    for e in ev_sec.supporting_evidence:
        supporting_rows += f"""
        <tr class="supp-row">
          <td><span class="pill pill-green">SUPPORTING</span></td>
          <td>{html.escape(e.feature_name)}</td>
          <td>{e.observed_value:.1f} vs {e.baseline_value:.1f} ({e.relative_change:+.1%})</td>
          <td>{html.escape(e.severity)}</td>
          <td>{html.escape(e.explanation)}</td>
        </tr>
        """
    contradictory_rows = ""
    for e in ev_sec.contradictory_evidence:
        contradictory_rows += f"""
        <tr class="contra-row">
          <td><span class="pill pill-red">CONTRADICTORY</span></td>
          <td>{html.escape(e.feature_name)}</td>
          <td>{e.observed_value:.1f} vs {e.baseline_value:.1f} ({e.relative_change:+.1%})</td>
          <td>{html.escape(e.severity)}</td>
          <td>{html.escape(e.explanation)}</td>
        </tr>
        """
    evidence_rows = supporting_rows + contradictory_rows
    if not evidence_rows:
        evidence_rows = "<tr><td colspan='5' class='muted'>No evidence items triggered for this capture.</td></tr>"

    # Limitations items
    def _format_lim_item(lim: Any) -> str:
        if isinstance(lim, dict):
            desc = lim.get("description") or lim.get("message") or str(lim)
            lim_type = lim.get("type")
            text = f"{lim_type}: {desc}" if lim_type else desc
            return html.escape(str(text))
        return html.escape(str(lim))

    limitations_html = "".join(f"<li>{_format_lim_item(lim)}</li>" for lim in (lim_sec.limitations + lim_sec.capture_limitations + lim_sec.calibration_caveats))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NexSolve Report - {report_id}</title>
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f293d;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --accent: #0d9488;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      line-height: 1.5;
      padding: 24px;
    }}
    .container {{
      max-width: 1040px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 2px solid var(--border);
      padding-bottom: 16px;
    }}
    .brand {{
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .brand h1 {{
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #38bdf8;
    }}
    .brand p {{
      font-size: 13px;
      color: var(--text-muted);
    }}
    .meta-box {{
      text-align: right;
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-muted);
    }}
    .section {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px 20px;
    }}
    .section-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }}
    .section-title {{
      font-size: 15px;
      font-weight: 600;
      color: #f8fafc;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-family: var(--font-mono);
      font-size: 10px;
      font-weight: 700;
      color: #ffffff;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .pill {{
      padding: 2px 6px;
      border-radius: 3px;
      font-size: 10px;
      font-family: var(--font-mono);
      font-weight: 600;
    }}
    .pill-green {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid #059669; }}
    .pill-red {{ background: rgba(225, 29, 72, 0.15); color: #fb7185; border: 1px solid #e11d48; }}
    .grid-2 {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }}
    .grid-4 {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
    }}
    .stat-card {{
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 10px 12px;
    }}
    .stat-label {{
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .stat-value {{
      font-size: 18px;
      font-weight: 700;
      font-family: var(--font-mono);
      color: #f1f5f9;
      margin-top: 4px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-top: 8px;
    }}
    th {{
      text-align: left;
      padding: 8px;
      border-bottom: 1px solid var(--border);
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-size: 11px;
    }}
    td {{
      padding: 8px;
      border-bottom: 1px solid rgba(31, 41, 61, 0.5);
    }}
    .small-text {{ font-size: 11px; color: var(--text-muted); }}
    .alert-box {{
      border-left: 4px solid var(--accent);
      background: rgba(13, 148, 136, 0.08);
      padding: 10px 14px;
      border-radius: 0 4px 4px 0;
      font-size: 12px;
      margin-top: 8px;
    }}
    .alert-warn {{
      border-color: #d97706;
      background: rgba(217, 119, 6, 0.08);
    }}
    ul {{ padding-left: 20px; font-size: 13px; }}
    li {{ margin-bottom: 4px; }}
    footer {{
      border-top: 1px solid var(--border);
      padding-top: 16px;
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      color: var(--text-muted);
    }}
    @media print {{
      body {{ background: #ffffff; color: #0f172a; padding: 0; }}
      .section {{ border: 1px solid #cbd5e1; background: #ffffff; page-break-inside: avoid; }}
      .stat-card {{ background: #f8fafc; border: 1px solid #cbd5e1; }}
      .stat-value {{ color: #0f172a; }}
      .alert-box {{ background: #f1f5f9; color: #0f172a; border-left-color: #0d9488; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <h1>NEXSOLVE</h1>
        <p>Evidence-backed predictive network intelligence</p>
      </div>
      <div class="meta-box">
        <div><strong>REPORT ID:</strong> {report_id}</div>
        <div><strong>GENERATED:</strong> {generated_at}</div>
        <div><strong>SOURCE:</strong> {html.escape(prov_sec.source_filename)}</div>
      </div>
    </header>

    <!-- 1. Executive Summary -->
    <section class="section">
      <div class="section-header">
        <h2 class="section-title">1. Executive Summary</h2>
        {_badge(exec_sec.category)}
      </div>
      <div class="grid-2">
        <div>
          <div class="stat-card" style="border-left: 4px solid {threat_color};">
            <div class="stat-label">Observed Threat Level</div>
            <div class="stat-value" style="color: {threat_color};">{overall_threat}</div>
          </div>
          <div style="margin-top: 10px;">
            <p style="font-size: 13px; font-weight: 600; margin-bottom: 4px;">Key Observed Findings:</p>
            <ul>{findings_html}</ul>
          </div>
        </div>
        <div>
          <div class="stat-card" style="border-left: 4px solid #0d9488;">
            <div class="stat-label">Attack Horizon & Forecast Status</div>
            <div class="stat-value" style="font-size: 14px; font-family: var(--font-sans);">{html.escape(exec_sec.forecast_summary)}</div>
          </div>
          <div class="alert-box alert-warn" style="margin-top: 10px;">
            <strong>Epistemic Policy:</strong> {html.escape(exec_sec.epistemic_disclaimer)}
          </div>
        </div>
      </div>
    </section>

    <!-- 2 & 3. Capture Quality & Activity Summary -->
    <div class="grid-2">
      <section class="section">
        <div class="section-header">
          <h2 class="section-title">2. Capture Quality</h2>
          {_badge(cap_sec.category)}
        </div>
        <div class="grid-2">
          <div class="stat-card">
            <div class="stat-label">Parsed / Total</div>
            <div class="stat-value">{cap_sec.parsed_packets} / {cap_sec.total_packets_observed}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Quality Status</div>
            <div class="stat-value">{html.escape(cap_sec.quality_status)}</div>
          </div>
        </div>
        <table style="margin-top: 10px;">
          <tr><td>Malformed Packets</td><td><strong>{cap_sec.malformed_packets}</strong></td></tr>
          <tr><td>Truncated Packets</td><td><strong>{cap_sec.truncated_packets}</strong></td></tr>
          <tr><td>Packet Loss Ratio</td><td><strong>{cap_sec.packet_loss_ratio:.2%}</strong></td></tr>
          <tr><td>Reordered Packets</td><td><strong>{cap_sec.reordered_packets}</strong></td></tr>
        </table>
      </section>

      <section class="section">
        <div class="section-header">
          <h2 class="section-title">3. Network Activity Summary</h2>
          {_badge(net_sec.category)}
        </div>
        <div class="grid-2">
          <div class="stat-card">
            <div class="stat-label">Total Volume</div>
            <div class="stat-value">{net_sec.packet_count:,} pkts</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Temporal Window Coverage</div>
            <div class="stat-value">{net_sec.temporal_window_coverage_seconds:.1f}s</div>
            <div class="small-text" style="margin-top: 4px;">Packet Timestamp Span: {net_sec.packet_timestamp_span_seconds:.2f}s</div>
          </div>
        </div>
        <table style="margin-top: 10px;">
          <tr><td>Reconstructed Flows</td><td><strong>{net_sec.flow_count:,}</strong></td></tr>
          <tr><td>Unique Host Pairs</td><td><strong>{net_sec.unique_src_ips} src &rarr; {net_sec.unique_dst_ips} dst</strong></td></tr>
          <tr><td>Destination Ports</td><td><strong>{net_sec.unique_dst_ports}</strong></td></tr>
          <tr><td>Protocols</td><td><strong>{html.escape(", ".join(f"{k}: {v}" for k, v in net_sec.protocol_distribution.items()))}</strong></td></tr>
        </table>
      </section>
    </div>

    <!-- 4. Temporal Behavior -->
    <section class="section">
      <div class="section-header">
        <h2 class="section-title">4. Temporal Behavior</h2>
        {_badge(temp_sec.category)}
      </div>
      <div class="grid-4">
        <div class="stat-card"><div class="stat-label">Windows (60s)</div><div class="stat-value">{temp_sec.window_count}</div></div>
        <div class="stat-card"><div class="stat-label">Continuity</div><div class="stat-value">{html.escape(temp_sec.temporal_continuity)}</div></div>
        <div class="stat-card"><div class="stat-label">Rate Trend</div><div class="stat-value">{html.escape(temp_sec.packet_rate_trend)}</div></div>
        <div class="stat-card"><div class="stat-label">Flow Churn</div><div class="stat-value">{html.escape(temp_sec.flow_churn_trend)}</div></div>
      </div>
    </section>

    <!-- 5 & 6. Forecast Rollout & Attack Horizon -->
    <section class="section">
      <div class="section-header">
        <h2 class="section-title">5. Multi-Horizon Forecast Rollout & Attack Horizon</h2>
        {_badge(fore_sec.category)}
      </div>
      <div class="grid-2" style="margin-bottom: 12px;">
        <div class="stat-card">
          <div class="stat-label">Attack Horizon State</div>
          <div class="stat-value" style="color: #38bdf8;">{html.escape(ah_sec.state)}</div>
          <div class="small-text" style="margin-top: 4px;">{html.escape(ah_sec.summary)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Horizon Duration & Lead Time</div>
          <div class="stat-value">{ah_dur_str}</div>
          <div class="small-text" style="margin-top: 4px;">Lead Time: {ah_lead_str}</div>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Horizon</th>
            <th>Predicted Score</th>
            <th>Predicted Stage</th>
            <th>Uncertainty</th>
            <th>Top Contributing Signal</th>
          </tr>
        </thead>
        <tbody>
          {forecast_rows_html}
        </tbody>
      </table>
    </section>

    <!-- 7. Evidence Chain (Why This Forecast) -->
    <section class="section">
      <div class="section-header">
        <h2 class="section-title">6. Evidence Chain (Observable Corroboration)</h2>
        {_badge(ev_sec.category)}
      </div>
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <div><strong>Evidence Strength:</strong> {ev_sec.evidence_strength:.2f} ({html.escape(ev_sec.evidence_quality)} Quality)</div>
        <div class="small-text">{html.escape(ev_sec.explanation)}</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Alignment</th>
            <th>Feature</th>
            <th>Observed vs Baseline</th>
            <th>Severity</th>
            <th>Physical Telemetry Rationale</th>
          </tr>
        </thead>
        <tbody>
          {evidence_rows}
        </tbody>
      </table>
    </section>

    <!-- 8, 9, 10. Confidence, Unknown Behavior & Abstention -->
    <div class="grid-2">
      <section class="section">
        <div class="section-header">
          <h2 class="section-title">7. Confidence & Unknown Behavior</h2>
          {_badge(conf_sec.category)}
        </div>
        <div class="alert-box alert-warn" style="margin-bottom: 10px;">
          <strong>Calibration Disclaimer:</strong> {html.escape(conf_sec.disclaimer)}
        </div>
        <table style="margin-bottom: 12px;">
          <tr><td>Raw Model Score</td><td><strong>{conf_raw_score_str}</strong></td></tr>
          <tr><td>Calibrated Confidence</td><td><strong>{conf_sec.confidence_value if conf_sec.confidence_value is not None else 'WITHHELD (UNSUPPORTED)'}</strong></td></tr>
          <tr><td>Uncertainty Level</td><td><strong>{html.escape(conf_sec.uncertainty_level)}</strong></td></tr>
        </table>
        <div style="border-top: 1px solid var(--border); padding-top: 8px;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-size: 13px; font-weight: 600;">Behavior Classification:</span>
            <span class="badge" style="background-color: {'#10b981' if unk_sec.classification == 'KNOWN_PATTERN' else '#d97706'};">{html.escape(unk_sec.classification)}</span>
          </div>
          <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">{html.escape(unk_sec.reason)}</p>
          <div class="small-text" style="margin-top: 4px;">Coverage: {unk_sec.coverage:.1%} · Abstain Recommended: {unk_sec.abstain_recommended}</div>
        </div>
      </section>

      <section class="section">
        <div class="section-header">
          <h2 class="section-title">8. Abstention Status & Preconditions</h2>
          {_badge(abs_sec.category)}
        </div>
        <div class="stat-card" style="margin-bottom: 10px;">
          <div class="stat-label">Availability Gate Status</div>
          <div class="stat-value" style="font-size: 14px; font-family: var(--font-mono); color: {'#34d399' if not abs_sec.abstained else '#fb7185'};">{html.escape(abs_sec.status)}</div>
        </div>
        <p style="font-size: 12px; margin-bottom: 6px;">{html.escape(abs_sec.explanation)}</p>
        {f'<div class="alert-box alert-warn"><strong>Missing Requirements:</strong> {html.escape(", ".join(abs_sec.missing_requirements))}</div>' if abs_sec.missing_requirements else ''}
      </section>
    </div>

    <!-- 11 & 12. Limitations & Provenance -->
    <div class="grid-2">
      <section class="section">
        <div class="section-header">
          <h2 class="section-title">9. Operational Limitations</h2>
          {_badge(lim_sec.category)}
        </div>
        <ul>{limitations_html}</ul>
      </section>

      <section class="section">
        <div class="section-header">
          <h2 class="section-title">10. Provenance & Auditability</h2>
          {_badge(prov_sec.category)}
        </div>
        <table class="small-text">
          <tr><td>Source File</td><td>{html.escape(prov_sec.source_filename)} ({prov_sec.file_size_bytes:,} bytes)</td></tr>
          <tr><td>SHA-256 Hash</td><td style="font-family: var(--font-mono);">{html.escape(prov_sec.capture_hash or 'N/A')}</td></tr>
          <tr><td>Model Version</td><td>{html.escape(prov_sec.model_version)}</td></tr>
          <tr><td>Processing Version</td><td>{html.escape(prov_sec.processing_version)}</td></tr>
          <tr><td>Execution Time</td><td>{proc_sec.processing_seconds:.2f}s (Stage: {html.escape(proc_sec.stage)})</td></tr>
        </table>
      </section>
    </div>

    <footer>
      <div>NexSolve Security Intelligence Platform &copy; 2026. All rights reserved.</div>
      <div>Confidential &middot; Automated Forensic & Predictive Report</div>
    </footer>
  </div>
</body>
</html>
"""

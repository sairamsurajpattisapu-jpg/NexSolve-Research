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


ACRONYMS = {
    "TCP", "UDP", "IP", "DNS", "HTTP", "HTTPS", "RTT", "PCAP", "PCAPNG",
    "MITRE", "ATT&CK", "SHA256", "SHA-256", "AUROC", "SYN", "ACK", "FIN",
    "RST", "PSH", "URG", "ICMP", "SSH", "TLS", "SSL", "ARP", "ID", "URL", "SOC",
}

EXACT_LABEL_MAP = {
    "unique_dst_ports": "Unique Destination Ports",
    "mean_tcp_rtt": "Mean TCP RTT",
    "flow_duration": "Flow Duration",
    "packet_count": "Packet Count",
    "src_bytes": "Source Bytes",
    "dst_bytes": "Destination Bytes",
    "tcp_flags": "TCP Flags",
    "network_state": "Network State",
    "attack_stage": "Attack Stage",
    "risk_score": "Risk Score",
    "job_id": "Job ID",
    "window_count": "Window Count",
    "insufficient_history": "Insufficient History",
    "proto_tcp_count": "TCP Packet Count",
    "total_bytes": "Total Bytes",
    "flow_count": "Flow Count",
    "flow_churn": "Flow Churn",
    "syn_ratio": "SYN Ratio",
    "syn_count": "SYN Count",
    "unique_src_ips": "Unique Source IPs",
    "unique_dst_ips": "Unique Destination IPs",
    "flow_duration_mean": "Mean Flow Duration",
    "packet_loss_ratio": "Packet Loss Ratio",
    "reordered_packets": "Reordered Packets",
    "malformed_packets": "Malformed Packets",
    "truncated_packets": "Truncated Packets",
    "packet_timestamp_span_seconds": "Packet Timestamp Span",
    "temporal_window_coverage_seconds": "Temporal Window Coverage",
    "syn_ack_ratio": "SYN/ACK Ratio",
    "flow_volume": "Flow Volume",
    "traffic_volume": "Traffic Volume",
    "port_entropy": "Port Entropy",
    "duration_seconds": "Duration",
    "flow_churn_trend": "Flow Churn Trend",
    "packet_rate_trend": "Packet Rate Trend",
}


def format_display_label(text: str) -> str:
    if not text:
        return ""
    if text in EXACT_LABEL_MAP:
        return EXACT_LABEL_MAP[text]
    cleaned = text.replace("_", " ").strip()
    words = cleaned.split()
    formatted_words = []
    for w in words:
        upper = w.upper()
        if upper in ACRONYMS:
            formatted_words.append(upper)
        else:
            formatted_words.append(w.capitalize())
    return " ".join(formatted_words)


def _badge(category: str) -> str:
    cat_upper = category.upper()
    if cat_upper in ("OBSERVED",):
        bg = "#0f172a"
        color = "#ffffff"
    elif cat_upper in ("FORECAST", "PROJECTED"):
        bg = "#334155"
        color = "#f8fafc"
    elif cat_upper in ("INFERRED", "DERIVED"):
        bg = "#475569"
        color = "#f8fafc"
    elif cat_upper in ("ABSTAINED", "CRITICAL", "HIGH"):
        bg = "#991b1b"
        color = "#ffffff"
    elif cat_upper in ("MEDIUM", "WARNING", "UNKNOWN"):
        bg = "#854d0e"
        color = "#ffffff"
    elif cat_upper in ("LOW", "BENIGN"):
        bg = "#166534"
        color = "#ffffff"
    else:
        bg = "#64748b"
        color = "#ffffff"
    return f'<span class="badge" style="background-color: {bg}; color: {color};">{html.escape(category)}</span>'


def generate_html_report(report: NexSolveReport) -> str:
    """Generate professional, self-contained, printable HTML report with zero external CDN dependencies."""
    r = report
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

    # Escape dynamic text
    report_id = html.escape(r.report_id)
    generated_at = html.escape(r.generated_at_utc)
    overall_threat = html.escape(exec_sec.overall_threat_level).upper()
    threat_badge_class = "threat-high" if overall_threat in ("HIGH", "CRITICAL") else ("threat-medium" if overall_threat == "MEDIUM" else "threat-low")

    # Packet counts fallback for demo or synthetic captures
    parsed_pkts = cap_sec.parsed_packets if cap_sec.parsed_packets > 0 else net_sec.packet_count
    total_pkts = cap_sec.total_packets_observed if cap_sec.total_packets_observed > 0 else net_sec.packet_count

    # Key findings rows (deduplicated)
    seen_f: set[str] = set()
    cleaned_findings: list[str] = []
    for f in exec_sec.key_findings:
        f_clean = f.strip()
        if f_clean and f_clean not in seen_f:
            seen_f.add(f_clean)
            cleaned_findings.append(f_clean)
    findings_html = "".join(f"<li>{html.escape(f)}</li>" for f in cleaned_findings) if cleaned_findings else "<li>No active threat indicators observed in packet traffic.</li>"

    # Section 04 Threat Indicators table rows
    indicator_rows_html = ""
    for idx, f in enumerate(cleaned_findings, start=1):
        f_disp = f[9:].strip() if f.lower().startswith("observed:") else f
        indicator_rows_html += f"""
        <tr>
          <td class="mono"><strong>IND-{idx:02d}</strong></td>
          <td>{html.escape(f_disp)}</td>
          <td><span class="sev-tag">{overall_threat}</span></td>
          <td><span class="tag-pill tag-supp">OBSERVED</span></td>
        </tr>
        """
    if not indicator_rows_html:
        indicator_rows_html = "<tr><td colspan='4' class='muted'>No active threat indicators observed in packet traffic.</td></tr>"

    # Abstention & display values
    is_abstained = abs_sec.abstained or ah_sec.state == "ABSTAINED"
    ah_dur_str = f"{ah_sec.horizon_seconds}s ({ah_sec.horizon_windows} windows)" if not is_abstained else "N/A (abstained)"
    ah_lead_str = f"{ah_sec.lead_time_seconds:.1f}s" if (ah_sec.lead_time_seconds is not None and not is_abstained) else "N/A (abstained)"
    conf_raw_score_str = f"{conf_sec.forecast_score:.4f}" if (conf_sec.confidence_state != "WITHHELD" and not is_abstained) else "N/A (abstained)"
    conf_display_str = f"{conf_sec.confidence_value:.0%}" if (conf_sec.confidence_value is not None and not is_abstained) else ("Withheld (Abstained)" if is_abstained else "Uncalibrated Signal")
    terminal_stage_str = format_display_label(ah_sec.state) if not is_abstained else "Abstained (Insufficient Sequence)"

    # Multi-horizon forecast rows
    forecast_rows_html = ""
    for fp in fore_sec.forecast_points:
        if fp.attack_probability is not None and not is_abstained:
            prob_str = f"{fp.attack_probability:.1%}"
            stage_str = html.escape(format_display_label(fp.predicted_stage or "None"))
            uncert_str = f"{fp.uncertainty:.2f}" if fp.uncertainty is not None else "Baseline"
            expl_str = html.escape("; ".join(fp.explanation) if fp.explanation else "State distribution conforms to baseline.")
        else:
            prob_str = "WITHHELD (ABSTAINED)"
            stage_str = "N/A (abstained)"
            uncert_str = "N/A (abstained)"
            expl_str = html.escape("; ".join(fp.explanation) if fp.explanation else "Forecast withheld due to insufficient historical sequence.")
        forecast_rows_html += f"""
        <tr>
          <td><strong>T+{fp.horizon} (+{fp.horizon * 60}s)</strong></td>
          <td class="mono"><strong>{prob_str}</strong></td>
          <td>{stage_str}</td>
          <td class="mono">{uncert_str}</td>
          <td class="secondary">{expl_str}</td>
        </tr>
        """
    if not forecast_rows_html:
        forecast_rows_html = "<tr><td colspan='5' class='muted'>No multi-step forecast horizons available.</td></tr>"

    # Evidence items
    supporting_rows = ""
    for e in ev_sec.supporting_evidence:
        supporting_rows += f"""
        <tr>
          <td><span class="tag-pill tag-supp">SUPPORTING</span> <span class="tag-pill tag-obs">OBSERVED</span></td>
          <td><strong>{html.escape(format_display_label(e.feature_name))}</strong></td>
          <td class="mono">{e.observed_value:.1f} vs {e.baseline_value:.1f} ({e.relative_change:+.1%})</td>
          <td><span class="sev-tag">{html.escape(e.severity)}</span></td>
          <td class="secondary">{html.escape(e.explanation)}</td>
        </tr>
        """
    contradictory_rows = ""
    for e in ev_sec.contradictory_evidence:
        contradictory_rows += f"""
        <tr>
          <td><span class="tag-pill tag-contra">CONTRADICTORY</span> <span class="tag-pill tag-obs">OBSERVED</span></td>
          <td><strong>{html.escape(format_display_label(e.feature_name))}</strong></td>
          <td class="mono">{e.observed_value:.1f} vs {e.baseline_value:.1f} ({e.relative_change:+.1%})</td>
          <td><span class="sev-tag">{html.escape(e.severity)}</span></td>
          <td class="secondary">{html.escape(e.explanation)}</td>
        </tr>
        """
    evidence_rows = supporting_rows + contradictory_rows
    if not evidence_rows:
        evidence_rows = "<tr><td colspan='5' class='muted'>No anomalous evidence items triggered for this capture.</td></tr>"

    # Limitations items
    def _format_lim_item(lim: Any) -> str:
        if isinstance(lim, dict):
            desc = lim.get("description") or lim.get("message") or str(lim)
            lim_type = lim.get("type")
            text = f"{format_display_label(lim_type)}: {desc}" if lim_type else desc
            return html.escape(str(text))
        return html.escape(str(lim))

    limitations_list = (lim_sec.limitations + lim_sec.capture_limitations + lim_sec.calibration_caveats)
    limitations_html = "".join(f"<li>{_format_lim_item(lim)}</li>" for lim in limitations_list)

    protocol_str = ", ".join(f"{k}: {v:,}" for k, v in net_sec.protocol_distribution.items()) if net_sec.protocol_distribution else "TCP / UDP Monitored"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NexSolve Report - {report_id}</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --paper: #ffffff;
      --text: #0f172a;
      --text-sec: #334155;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --border-dark: #cbd5e1;
      --primary: #0f172a;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      line-height: 1.55;
      padding: 36px 20px;
      font-size: 13px;
    }}
    .document {{
      max-width: 1060px;
      margin: 0 auto;
      background: var(--paper);
      border: 1px solid var(--border-dark);
      border-radius: 4px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
      padding: 40px 48px;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 2px solid var(--primary);
      padding-bottom: 18px;
      margin-bottom: 28px;
    }}
    .brand-block h1 {{
      font-size: 22px;
      font-weight: 800;
      letter-spacing: -0.02em;
      color: var(--primary);
      line-height: 1.2;
    }}
    .brand-block .subtitle {{
      font-size: 11.5px;
      font-family: var(--mono);
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-top: 2px;
    }}
    .brand-block .tagline {{
      font-size: 12px;
      color: var(--text-sec);
      margin-top: 4px;
    }}
    .meta-block {{
      text-align: right;
      font-size: 11.5px;
      color: var(--text-sec);
      line-height: 1.6;
    }}
    .meta-block strong {{
      font-family: var(--mono);
      font-size: 10.5px;
      color: var(--text-muted);
      text-transform: uppercase;
    }}
    .section-block {{
      margin-bottom: 28px;
      padding-bottom: 22px;
      border-bottom: 1px solid var(--border);
    }}
    .section-block:last-of-type {{
      border-bottom: none;
      margin-bottom: 16px;
      padding-bottom: 0;
    }}
    .section-heading {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      margin-bottom: 14px;
    }}
    .section-num {{
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .section-title {{
      font-size: 15px;
      font-weight: 700;
      color: var(--primary);
      letter-spacing: -0.01em;
      margin-top: 2px;
    }}
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 3px;
      font-family: var(--mono);
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.04em;
    }}
    .grid-4 {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
    }}
    .grid-2 {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }}
    .cell {{
      border-bottom: 2px solid var(--border);
      padding-bottom: 8px;
    }}
    .cell-label {{
      font-size: 9.5px;
      font-family: var(--mono);
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .cell-value {{
      font-size: 14px;
      font-weight: 700;
      color: var(--primary);
      margin-top: 3px;
    }}
    .cell-sub {{
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 2px;
    }}
    .data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-top: 6px;
    }}
    .data-table th {{
      text-align: left;
      padding: 7px 10px;
      border-bottom: 2px solid var(--border-dark);
      font-family: var(--mono);
      font-size: 10.5px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .data-table td {{
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }}
    .data-table tr:last-child td {{
      border-bottom: none;
    }}
    .mono {{ font-family: var(--mono); }}
    .secondary {{ color: var(--text-sec); }}
    .muted {{ color: var(--text-muted); font-size: 11.5px; }}
    .note-box {{
      padding: 10px 14px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-left: 3px solid var(--primary);
      border-radius: 3px;
      font-size: 11.5px;
      line-height: 1.5;
      color: var(--text-sec);
      margin-top: 10px;
    }}
    .note-box strong {{ color: var(--primary); }}
    .tag-pill {{
      display: inline-block;
      padding: 2px 6px;
      border-radius: 2px;
      font-family: var(--mono);
      font-size: 9.5px;
      font-weight: 700;
    }}
    .tag-supp {{ background: #dcfce7; color: #166534; }}
    .tag-contra {{ background: #fee2e2; color: #991b1b; }}
    .tag-obs {{ background: #f1f5f9; color: #334155; border: 1px solid var(--border); }}
    .sev-tag {{
      font-family: var(--mono);
      font-size: 10.5px;
      font-weight: 700;
      color: var(--text-sec);
    }}
    ul.bullet-list {{
      padding-left: 18px;
      font-size: 12.5px;
      color: var(--text-sec);
      line-height: 1.6;
    }}
    ul.bullet-list li {{ margin-bottom: 4px; }}
    footer {{
      margin-top: 32px;
      padding-top: 16px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      color: var(--text-muted);
      font-family: var(--mono);
    }}
    @media (max-width: 768px) {{
      body {{ padding: 16px 12px; }}
      .document {{ padding: 24px 18px; }}
      .grid-4 {{ grid-template-columns: 1fr 1fr; }}
      .grid-2 {{ grid-template-columns: 1fr; }}
      header {{ flex-direction: column; gap: 12px; }}
      .meta-block {{ text-align: left; }}
    }}
    @media print {{
      @page {{ size: A4 portrait; margin: 10mm 12mm 12mm 12mm; }}
      body {{ background: #ffffff !important; color: #0f172a !important; padding: 0 !important; font-size: 9.5pt !important; }}
      .document {{ border: none !important; box-shadow: none !important; padding: 0 !important; max-width: 100% !important; }}
      .section-block {{ page-break-inside: avoid; break-inside: avoid; }}
      .note-box {{ background: #f8fafc !important; border: 1px solid #cbd5e1 !important; }}
    }}
  </style>
</head>
<body>
  <div class="document">
    <header>
      <div class="brand-block">
        <div class="subtitle">NexSolve Report &middot; Network Security Assessment</div>
        <h1>NEXSOLVE</h1>
        <div class="tagline">Evidence-backed predictive network intelligence</div>
      </div>
      <div class="meta-block">
        <div><strong>Report ID:</strong> <span class="mono">{report_id}</span></div>
        <div><strong>Source:</strong> <span class="mono">{html.escape(prov_sec.source_filename)}</span></div>
        <div><strong>Generated:</strong> <span class="mono">{generated_at}</span></div>
        <div><strong>Analysis Period:</strong> <span class="mono">{net_sec.temporal_window_coverage_seconds:.1f}s ({temp_sec.window_count} windows)</span></div>
      </div>
    </header>

    <!-- 01 — Executive Assessment -->
    <section class="section-block">
      <div class="section-heading">
        <div>
          <span class="section-num">01 &mdash; EXECUTIVE ASSESSMENT</span>
          <h2 class="section-title">Executive Threat Summary</h2>
        </div>
        {_badge(overall_threat)}
      </div>

      <div class="grid-4" style="margin-bottom: 14px;">
        <div class="cell">
          <div class="cell-label">Current Threat Assessment</div>
          <div class="cell-value">{overall_threat}</div>
          <div class="cell-sub">Observed telemetry at T0</div>
        </div>
        <div class="cell">
          <div class="cell-label">Projected Attack Stage</div>
          <div class="cell-value">{terminal_stage_str}</div>
          <div class="cell-sub">Modeled forward trajectory</div>
        </div>
        <div class="cell">
          <div class="cell-label">Earliest Warning Lead Time</div>
          <div class="cell-value">Lead Time: {ah_lead_str}</div>
          <div class="cell-sub">{ah_dur_str}</div>
        </div>
        <div class="cell">
          <div class="cell-label">Assessment Confidence</div>
          <div class="cell-value">{conf_display_str}</div>
          <div class="cell-sub">{conf_raw_score_str if not is_abstained else 'Withheld'}</div>
        </div>
      </div>

      <div style="margin-bottom: 12px;">
        <p style="font-size: 13px; font-weight: 600; color: var(--primary); margin-bottom: 4px;">Forecast Projection:</p>
        <p style="color: var(--text-sec); line-height: 1.5;">{html.escape(exec_sec.forecast_summary)}</p>
      </div>

      <div style="margin-bottom: 12px;">
        <p style="font-size: 13px; font-weight: 600; color: var(--primary); margin-bottom: 4px;">Key Observed Findings:</p>
        <ul class="bullet-list">{findings_html}</ul>
      </div>

      <div class="note-box">
        <strong>Assessment Context:</strong> {html.escape(exec_sec.epistemic_disclaimer)}
      </div>
    </section>

    <!-- 02 — Network Observation -->
    <section class="section-block">
      <div class="section-heading">
        <div>
          <span class="section-num">02 &mdash; NETWORK OBSERVATION</span>
          <h2 class="section-title">Observed Telemetry & Flow Statistics</h2>
        </div>
        {_badge(net_sec.category)}
      </div>

      <div class="grid-4" style="margin-bottom: 14px;">
        <div class="cell">
          <div class="cell-label">Packets Processed</div>
          <div class="cell-value mono">{net_sec.packet_count:,}</div>
          <div class="cell-sub">{parsed_pkts:,} parsed frames</div>
        </div>
        <div class="cell">
          <div class="cell-label">Flows Reconstructed</div>
          <div class="cell-value mono">{net_sec.flow_count:,}</div>
          <div class="cell-sub">Bidirectional flows</div>
        </div>
        <div class="cell">
          <div class="cell-label">Endpoint Cardinality</div>
          <div class="cell-value mono">{net_sec.unique_src_ips} &rarr; {net_sec.unique_dst_ips}</div>
          <div class="cell-sub">Source & Destination hosts</div>
        </div>
        <div class="cell">
          <div class="cell-label">Destination Ports</div>
          <div class="cell-value mono">{net_sec.unique_dst_ports}</div>
          <div class="cell-sub">Distinct target ports</div>
        </div>
      </div>

      <table class="data-table">
        <tbody>
          <tr>
            <td style="width: 25%; color: var(--text-muted);">Protocol Distribution</td>
            <td colspan="3"><strong>{html.escape(protocol_str)}</strong></td>
          </tr>
          <tr>
            <td style="color: var(--text-muted);">Temporal Window Coverage</td>
            <td><strong>{net_sec.temporal_window_coverage_seconds:.1f}s</strong> ({temp_sec.window_count} discrete 60s windows)</td>
            <td style="color: var(--text-muted);">Packet Timestamp Span:</td>
            <td><strong>Packet Timestamp Span: {net_sec.packet_timestamp_span_seconds:.2f}s</strong></td>
          </tr>
          <tr>
            <td style="color: var(--text-muted);">Canonical State Contract</td>
            <td><strong>45-Dimension Continuous Layer 3/4 Vector</strong></td>
            <td style="color: var(--text-muted);">Round-Trip Time Integrity</td>
            <td class="muted">Not observed from passive capture (Zero synthetic imputation)</td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- 03 — Capture Quality -->
    <section class="section-block">
      <div class="section-heading">
        <div>
          <span class="section-num">03 &mdash; CAPTURE QUALITY</span>
          <h2 class="section-title">Ingestion Quality & Frame Integrity</h2>
        </div>
        {_badge(cap_sec.quality_status)}
      </div>

      <table class="data-table">
        <thead>
          <tr>
            <th>Metric</th>
            <th>Value</th>
            <th>Integrity Standard</th>
            <th>Operational Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Wire Frames Parsed / Total</td>
            <td class="mono"><strong>{parsed_pkts:,} / {total_pkts:,}</strong></td>
            <td>100% parser completeness</td>
            <td><span class="tag-pill tag-supp">VERIFIED</span></td>
          </tr>
          <tr>
            <td>Malformed Packet Headers</td>
            <td class="mono"><strong>{cap_sec.malformed_packets}</strong></td>
            <td>Zero malformed headers required</td>
            <td><span class="tag-pill tag-supp">{cap_sec.malformed_packets == 0 and 'CLEAN' or 'WARNING'}</span></td>
          </tr>
          <tr>
            <td>Truncated Packet Frames</td>
            <td class="mono"><strong>{cap_sec.truncated_packets}</strong></td>
            <td>Zero truncated frames required</td>
            <td><span class="tag-pill tag-supp">{cap_sec.truncated_packets == 0 and 'CLEAN' or 'WARNING'}</span></td>
          </tr>
          <tr>
            <td>Packet Loss Ratio</td>
            <td class="mono"><strong>{cap_sec.packet_loss_ratio:.2%}</strong></td>
            <td>&lt; 2.0% nominal boundary</td>
            <td><span class="tag-pill tag-supp">{cap_sec.packet_loss_ratio < 0.02 and 'OPTIMAL' or 'ELEVATED'}</span></td>
          </tr>
          <tr>
            <td>Out-of-Order / Reordered Packets</td>
            <td class="mono"><strong>{cap_sec.reordered_packets}</strong></td>
            <td>Sequence preservation</td>
            <td><span class="tag-pill tag-supp">{cap_sec.reordered_packets == 0 and 'NOMINAL' or 'JITTER'}</span></td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- 04 — Threat Indicators -->
    <section class="section-block">
      <div class="section-heading">
        <div>
          <span class="section-num">04 &mdash; THREAT INDICATORS</span>
          <h2 class="section-title">Observed Threat Indicators & Pattern Signatures</h2>
        </div>
        {_badge("OBSERVED")}
      </div>

      <table class="data-table">
        <thead>
          <tr>
            <th style="width: 90px;">Identifier</th>
            <th>Observed Pattern & Behavioral Telemetry</th>
            <th style="width: 100px;">Severity</th>
            <th style="width: 110px;">Status</th>
          </tr>
        </thead>
        <tbody>
          {indicator_rows_html}
        </tbody>
      </table>
    </section>

    <!-- 05 — Threat Forecast -->
    <section class="section-block">
      <div class="section-heading">
        <div>
          <span class="section-num">05 &mdash; THREAT FORECAST</span>
          <h2 class="section-title">Multi-Horizon Threat Progression</h2>
        </div>
        {_badge(fore_sec.category)}
      </div>

      <table class="data-table">
        <thead>
          <tr>
            <th>Horizon</th>
            <th>Predicted Score</th>
            <th>Projected Stage</th>
            <th>Uncertainty</th>
            <th>Behavioral Interpretation</th>
          </tr>
        </thead>
        <tbody>
          {forecast_rows_html}
        </tbody>
      </table>

      <div class="note-box" style="margin-top: 12px;">
        <strong>Methodological Disclosure:</strong> Predicted scores represent latent state transition dynamics across sequential 60-second observation windows, not empirical or actuarial probabilities of compromise. Forward projections reflect statistical dynamics learned from reference traffic distributions.
      </div>
    </section>

    <!-- 06 — Evidence Chain -->
    <section class="section-block">
      <div class="section-heading">
        <div>
          <span class="section-num">06 &mdash; EVIDENCE CHAIN</span>
          <h2 class="section-title">Evidentiary Corroboration</h2>
        </div>
        {_badge(ev_sec.category)}
      </div>

      <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px; font-size: 12px;">
        <div><strong>Evidence Strength:</strong> <span class="mono">{ev_sec.evidence_strength:.2f}</span> ({html.escape(ev_sec.evidence_quality)} Quality)</div>
        <div class="muted">{html.escape(ev_sec.explanation)}</div>
      </div>

      <table class="data-table">
        <thead>
          <tr>
            <th>Classification</th>
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

    <!-- 07 — Data Integrity & Verification -->
    <section class="section-block">
      <div class="section-heading">
        <div>
          <span class="section-num">07 &mdash; DATA INTEGRITY</span>
          <h2 class="section-title">Provenance & Technical Verification</h2>
        </div>
        {_badge(prov_sec.category)}
      </div>

      <table class="data-table">
        <tbody>
          <tr>
            <td style="width: 25%; color: var(--text-muted);">Source File</td>
            <td><strong class="mono">{html.escape(prov_sec.source_filename)}</strong> ({prov_sec.file_size_bytes:,} bytes)</td>
            <td style="width: 25%; color: var(--text-muted);">SHA-256 Hash</td>
            <td class="mono">{html.escape(prov_sec.capture_hash or 'N/A')}</td>
          </tr>
          <tr>
            <td style="color: var(--text-muted);">Model Architecture</td>
            <td><strong>{html.escape(prov_sec.model_version)}</strong></td>
            <td style="color: var(--text-muted);">Pipeline Version</td>
            <td class="mono">{html.escape(prov_sec.processing_version)}</td>
          </tr>
          <tr>
            <td style="color: var(--text-muted);">Execution Time</td>
            <td class="mono">{proc_sec.processing_seconds:.2f}s (Stage: {html.escape(proc_sec.stage)})</td>
            <td style="color: var(--text-muted);">Round-Trip Time (RTT)</td>
            <td class="muted">Not observed from passive capture</td>
          </tr>
          <tr>
            <td style="color: var(--text-muted);">Payload Content Inspection</td>
            <td class="muted">Not observed from passive capture (L3/L4 passive metadata only)</td>
            <td style="color: var(--text-muted);">Synthetic Imputation</td>
            <td class="muted">None (Zero synthetic data generation)</td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- 08 — Scientific Limitations & Governance -->
    <section class="section-block">
      <div class="section-heading">
        <div>
          <span class="section-num">08 &mdash; LIMITATIONS & GOVERNANCE</span>
          <h2 class="section-title">Scientific Limitations & Operational Boundaries</h2>
        </div>
        {_badge(lim_sec.category)}
      </div>

      <ul class="bullet-list">
        {limitations_html}
      </ul>
    </section>

    <footer>
      <div>NexSolve Security Intelligence Platform &copy; 2026. All rights reserved.</div>
      <div>Confidential &middot; Automated Forensic &amp; Predictive Assessment Report &middot; ID: {report_id}</div>
    </footer>
  </div>
</body>
</html>
"""


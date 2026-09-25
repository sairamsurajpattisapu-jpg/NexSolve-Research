"""Implementation of the 'nexsolve analyze' command."""
from __future__ import annotations

import argparse
import json
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any

from nexsolve.client.api import NexSolveClient
from nexsolve.client.models import AnalysisSummary, JobStatus
from nexsolve.config import (
    DEFAULT_API_KEY,
    DEFAULT_API_URL,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_TIMEOUT,
    DEFAULT_WEB_URL,
    STAGE_DESCRIPTIONS,
)
from nexsolve.errors import CancelledError, NexSolveError
from nexsolve.output.terminal import TerminalRenderer

# Canonical stage ordering
STAGE_ORDER = [
    "INGESTION",
    "PARSING",
    "FLOW_RECONSTRUCTION",
    "WINDOWING",
    "NETWORK_STATE",
    "FORECAST",
    "EVIDENCE",
    "REPORT",
    "COMPLETE",
]

STAGE_CHECKMARKS = {
    "INGESTION": "Capture ingestion completed",
    "PARSING": "Packet parsing completed",
    "FLOW_RECONSTRUCTION": "Flow reconstruction completed",
    "WINDOWING": "Temporal windowing completed",
    "NETWORK_STATE": "Network state assembled",
    "FORECAST": "Attack forecast simulated",
    "EVIDENCE": "Evidence chain evaluated",
    "REPORT": "Security report compiled",
}


def run_analyze(args: argparse.Namespace) -> int:
    """Execute the end-to-end PCAP analysis flow."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)

    raw_pcap_path = getattr(args, "pcap_path", None)
    if not raw_pcap_path:
        from nexsolve.picker import open_pcap_picker
        selected = open_pcap_picker()
        if not selected:
            print("No PCAP selected. Analysis cancelled.")
            return 0
        raw_pcap_path = selected
        args.pcap_path = selected
        if not getattr(args, "json", False) and not getattr(args, "quiet", False):
            print(f"\nSelected:\n  {selected}\n")
            print(f"Selected capture:\n  {Path(selected).name}\n")

    pcap_path = Path(raw_pcap_path)
    server_url = (getattr(args, "server", None) or DEFAULT_API_URL).rstrip("/")
    web_url = (getattr(args, "web_url", None) or DEFAULT_WEB_URL).rstrip("/")
    api_key = getattr(args, "api_key", None) or DEFAULT_API_KEY
    timeout = float(getattr(args, "timeout", None) or DEFAULT_TIMEOUT)
    poll_interval = float(getattr(args, "poll_interval", None) or DEFAULT_POLL_INTERVAL)
    json_output = getattr(args, "json", False)
    quiet = getattr(args, "quiet", False)
    verbose = getattr(args, "verbose", False)
    open_browser = getattr(args, "open", False)
    report_out = getattr(args, "report_out", None)

    client = NexSolveClient(base_url=server_url, api_key=api_key, timeout=timeout)

    # 1. Local validation
    meta = client.validate_local_pcap(pcap_path)

    if verbose:
        print(f"[DEBUG] Local PCAP verified: {meta['path']} ({meta['size_bytes']} bytes, format={meta['format']}, magic={meta['magic']})", file=sys.stderr)

    if not json_output and not quiet:
        term.print_banner()
        term.print_file_info(meta["filename"], meta["size_bytes"], meta["format"])
        term.print_stage_start("ANALYSIS")
        term.print_checkmark("PCAP validated")

    # 2. Server connectivity check
    if verbose:
        print(f"[DEBUG] Checking connectivity to NexSolve API: {server_url}/health", file=sys.stderr)
    client.check_health()

    # 3. Stream upload
    if verbose:
        print(f"[DEBUG] Uploading capture payload to {server_url}/jobs", file=sys.stderr)
    initial_job = client.upload_pcap(pcap_path)
    job_id = initial_job.job_id

    if verbose:
        print(f"[DEBUG] Job registered with ID: {job_id}, status: {initial_job.status}", file=sys.stderr)

    if not json_output and not quiet:
        term.print_checkmark("Upload completed")
        term.print_checkmark(f"Analysis started ({job_id})")

    # 4. Status polling with truthful progress
    start_time = time.monotonic()
    completed_stages: set[str] = set()
    last_reported_stage: str = ""

    def on_progress(job: JobStatus) -> None:
        nonlocal last_reported_stage
        elapsed = time.monotonic() - start_time

        if verbose:
            print(f"[DEBUG] Poll update (+{elapsed:.1f}s): stage={job.stage}, progress={job.progress*100:.1f}%, pkts={job.packets_processed}", file=sys.stderr)

        if json_output or quiet:
            return

        current_stage = job.stage

        # If we have advanced past previous stages, print their checkmarks
        if current_stage in STAGE_ORDER:
            curr_idx = STAGE_ORDER.index(current_stage)
            for prev_stage in STAGE_ORDER[:curr_idx]:
                if prev_stage not in completed_stages and prev_stage in STAGE_CHECKMARKS:
                    term.clear_live_progress()
                    term.print_checkmark(STAGE_CHECKMARKS[prev_stage])
                    completed_stages.add(prev_stage)

        if current_stage != "COMPLETE":
            term.print_live_progress(current_stage, job.progress, elapsed)

    try:
        final_job = client.poll_job(
            job_id=job_id,
            timeout=timeout,
            interval=poll_interval,
            on_progress=on_progress,
        )
    except KeyboardInterrupt:
        if not json_output and not quiet:
            term.clear_live_progress()
        client.cancel_job(job_id)
        raise CancelledError(f"Analysis cancelled by user (job: {job_id}).", job_id=job_id)

    if not json_output and not quiet:
        term.clear_live_progress()
        # Mark all remaining intermediate stages as checked
        for stage in STAGE_ORDER:
            if stage not in completed_stages and stage in STAGE_CHECKMARKS:
                term.print_checkmark(STAGE_CHECKMARKS[stage])
                completed_stages.add(stage)

    # 5. Result retrieval
    result = client.get_job_result(job_id)
    summary = AnalysisSummary.from_result(result, web_base_url=web_url)

    # 6. Optional report download
    if report_out:
        out_path = Path(report_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.suffix.lower() == ".html":
            html_text = client.get_report_html(job_id)
            out_path.write_text(html_text, encoding="utf-8")
        else:
            json_text = client.get_report_json(job_id)
            out_path.write_text(json_text, encoding="utf-8")

        if not json_output:
            term.print_checkmark(f"Saved forensic report: {out_path.resolve()}")

    # 7. Output presentation
    if json_output:
        print(json.dumps(result, indent=2))
        return 0

    term.print_soc_summary(summary)

    report_location = str(Path(report_out).resolve()) if report_out else summary.report_url
    print(f"\n{term.C_GREEN}{term.C_BOLD}Analysis complete.{term.C_RESET}\n")
    print(f"  Job ID:            {term.C_WHITE}{job_id}{term.C_RESET}")
    print(f"  Threat assessment: {term.C_WHITE}{summary.threat_level}{term.C_RESET} (Risk score: {summary.risk_score:.1f}/100)")
    print(f"  Forecast:          {term.C_CYAN}{summary.progression_verdict}{term.C_RESET}")
    print(f"  Report:            {term.C_WHITE}{report_location}{term.C_RESET}")

    term.print_visualization_box(job_id, summary.visualization_url, summary.report_url)

    # 8. Browser launch if requested
    if open_browser:
        try:
            print(f"[*] Opening investigation console in browser: {summary.visualization_url}")
            webbrowser.open(summary.visualization_url)
        except Exception as exc:
            print(f"[!] Unable to launch browser automatically: {exc}", file=sys.stderr)

    return 0

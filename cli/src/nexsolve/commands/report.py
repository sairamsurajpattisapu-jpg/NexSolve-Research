"""Implementation of the 'nexsolve report' command."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from nexsolve.client.api import NexSolveClient
from nexsolve.config import DEFAULT_API_KEY, DEFAULT_API_URL, DEFAULT_WEB_URL
from nexsolve.output.terminal import TerminalRenderer


def run_report(args: argparse.Namespace) -> int:
    """Download or display report for a completed analysis job."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)

    job_id = args.job_id
    server_url = (getattr(args, "server", None) or DEFAULT_API_URL).rstrip("/")
    web_url = (getattr(args, "web_url", None) or DEFAULT_WEB_URL).rstrip("/")
    api_key = getattr(args, "api_key", None) or DEFAULT_API_KEY
    output_path = getattr(args, "output", None)
    report_format = getattr(args, "format", "html").lower()
    quiet = getattr(args, "quiet", False)
    verbose = getattr(args, "verbose", False)

    client = NexSolveClient(base_url=server_url, api_key=api_key)

    # If output file specified, determine format by extension or flag
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.suffix.lower() == ".json" or report_format == "json":
            content = client.get_report_json(job_id)
            out.write_text(content, encoding="utf-8")
        else:
            content = client.get_report_html(job_id)
            out.write_text(content, encoding="utf-8")
        if not quiet:
            print(f"{term.C_GREEN}✓{term.C_RESET} Saved report: {term.C_BOLD}{out.resolve()}{term.C_RESET}")
        else:
            print(str(out.resolve()))
        return 0

    if report_format == "json" or getattr(args, "json", False):
        content = client.get_report_json(job_id)
        print(content)
        return 0

    # Display report metadata and URLs
    job = client.get_job_status(job_id)
    rep_url = f"{web_url}/console/reports/{job_id}"
    vis_url = f"{web_url}/console/forecast/{job_id}"

    if quiet:
        print(f"Interactive: {vis_url}")
        print(f"Report:      {rep_url}")
        return 0

    print(f"\n{term.C_BOLD}NEXSOLVE FORENSIC REPORT{term.C_RESET}")
    print(f"  {term.C_DIM}Job ID:{term.C_RESET}     {term.C_CYAN}{job_id}{term.C_RESET}")
    print(f"  {term.C_DIM}Capture:{term.C_RESET}    {job.filename or 'N/A'}")
    print(f"  {term.C_DIM}Status:{term.C_RESET}     {job.status}")

    print(f"\n{term.C_BOLD}Report Access Links:{term.C_RESET}")
    print(f"  Interactive Console: {term.C_CYAN}{vis_url}{term.C_RESET}")
    print(f"  Executive Report:    {term.C_CYAN}{rep_url}{term.C_RESET}")
    print(f"\n{term.C_DIM}To download the standalone HTML report to disk:{term.C_RESET}")
    print(f"  nexsolve report {job_id} --output report.html\n")

    return 0

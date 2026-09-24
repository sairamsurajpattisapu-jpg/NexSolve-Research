"""Implementation of the 'nexsolve status' command."""
from __future__ import annotations

import argparse
import json
import sys

from nexsolve.client.api import NexSolveClient
from nexsolve.config import DEFAULT_API_KEY, DEFAULT_API_URL, DEFAULT_WEB_URL, STAGE_DESCRIPTIONS
from nexsolve.output.terminal import TerminalRenderer


def run_status(args: argparse.Namespace) -> int:
    """Query and display processing status for an existing analysis job."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)

    job_id = args.job_id
    server_url = (getattr(args, "server", None) or DEFAULT_API_URL).rstrip("/")
    web_url = (getattr(args, "web_url", None) or DEFAULT_WEB_URL).rstrip("/")
    api_key = getattr(args, "api_key", None) or DEFAULT_API_KEY
    json_output = getattr(args, "json", False)
    quiet = getattr(args, "quiet", False)
    verbose = getattr(args, "verbose", False)

    client = NexSolveClient(base_url=server_url, api_key=api_key)
    job = client.get_job_status(job_id)

    if json_output:
        raw_dict = {
            "job_id": job.job_id,
            "filename": job.filename,
            "status": job.status,
            "stage": job.stage,
            "progress": job.progress,
            "packets_processed": job.packets_processed,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "error": job.error,
            "processing_statistics": job.processing_statistics,
            "visualization_url": f"{web_url}/console/forecast/{job.job_id}" if job.is_complete else None,
        }
        print(json.dumps(raw_dict, indent=2))
        return 0

    if quiet:
        print(f"{job.job_id} {job.status} {job.stage} {int(job.progress * 100)}%")
        return 0

    print(f"\n{term.C_BOLD}NEXSOLVE JOB STATUS{term.C_RESET}")
    print(f"  {term.C_DIM}Job ID:{term.C_RESET}     {term.C_CYAN}{job.job_id}{term.C_RESET}")
    print(f"  {term.C_DIM}Capture:{term.C_RESET}    {job.filename or 'N/A'}")

    status_color = term.C_GREEN if job.is_complete else (term.C_RED if job.is_failed else term.C_YELLOW)
    print(f"  {term.C_DIM}Status:{term.C_RESET}     {status_color}{term.C_BOLD}{job.status}{term.C_RESET}")
    print(f"  {term.C_DIM}Stage:{term.C_RESET}      {job.stage} ({STAGE_DESCRIPTIONS.get(job.stage, 'Processing')})")
    print(f"  {term.C_DIM}Progress:{term.C_RESET}   {int(job.progress * 100)}%")

    if job.packets_processed > 0:
        print(f"  {term.C_DIM}Packets:{term.C_RESET}    {job.packets_processed:,}")
    if job.created_at:
        print(f"  {term.C_DIM}Created:{term.C_RESET}    {job.created_at}")
    if job.completed_at:
        print(f"  {term.C_DIM}Completed:{term.C_RESET}  {job.completed_at}")

    if job.error:
        print(f"\n  {term.C_RED}[!] Error:{term.C_RESET} {job.error}")

    if job.is_complete:
        vis_url = f"{web_url}/console/forecast/{job.job_id}"
        rep_url = f"{web_url}/console/reports/{job.job_id}"
        term.print_visualization_box(job.job_id, vis_url, rep_url)

    return 0

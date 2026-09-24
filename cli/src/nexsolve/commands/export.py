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
from reporting.report_engine import (
    assemble_report,
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
)


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

    # Assemble structured report object
    report_obj = assemble_report(
        analysis_result=data,
        job_id=job_id,
        capture_hash=cap_hash,
    )

    # Render target format
    if fmt == "html":
        content = generate_html_report(report_obj)
        default_ext = ".html"
    elif fmt == "markdown":
        content = generate_markdown_report(report_obj)
        default_ext = ".md"
    else:  # json
        content = generate_json_report(report_obj)
        default_ext = ".json"

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

"""NexSolve Command-Line Interface Dispatcher and Entry Point."""
from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

from nexsolve.config import (
    CLI_VERSION,
    DEFAULT_API_KEY,
    DEFAULT_API_URL,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_TIMEOUT,
    DEFAULT_WEB_URL,
)
from nexsolve.errors import NexSolveError
from nexsolve.output.terminal import TerminalRenderer

# Reconfigure stdout/stderr for robust Windows encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser for NexSolve CLI."""
    parser = argparse.ArgumentParser(
        prog="nexsolve",
        description="NexSolve: AI-Based Network Attack Forecasting Platform",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"nexsolve {CLI_VERSION}",
        help="Show program's version number and exit",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. 'analyze' command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Upload PCAP capture to NexSolve analysis platform, monitor progress, and obtain visualization URL",
    )
    analyze_parser.add_argument(
        "pcap_path",
        nargs="?",
        default=None,
        help="Path to .pcap or .pcapng network capture file (omit to open native file picker)",
    )
    analyze_parser.add_argument(
        "--server",
        default=DEFAULT_API_URL,
        help=f"NexSolve API backend base URL (default: {DEFAULT_API_URL} or $NEXSOLVE_API_URL)",
    )
    analyze_parser.add_argument(
        "--web-url",
        default=DEFAULT_WEB_URL,
        help=f"NexSolve Web Console base URL (default: {DEFAULT_WEB_URL} or $NEXSOLVE_WEB_URL)",
    )
    analyze_parser.add_argument(
        "--api-key",
        default=DEFAULT_API_KEY,
        help="Optional API key for authenticated backend endpoints",
    )
    analyze_parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help=f"Status polling interval in seconds (default: {DEFAULT_POLL_INTERVAL}s)",
    )
    analyze_parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Maximum wait timeout in seconds (default: {DEFAULT_TIMEOUT}s)",
    )
    analyze_parser.add_argument(
        "--open",
        action="store_true",
        help="Automatically open the completed analysis visualization URL in the default web browser",
    )
    analyze_parser.add_argument(
        "--headless",
        action="store_true",
        help="Run in headless non-interactive mode without opening browser or prompting",
    )
    analyze_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw completed analysis JSON result to stdout",
    )
    analyze_parser.add_argument(
        "-o", "--report-out",
        dest="report_out",
        help="Download and save the printable HTML or JSON forensic report to the specified file path",
    )
    analyze_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and intermediate progress updates; display only final SOC summary and URLs",
    )
    analyze_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Display detailed diagnostic telemetry and request timing to stderr",
    )
    analyze_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    # 2. 'status' command
    status_parser = subparsers.add_parser(
        "status",
        help="Check current processing status and stage of an analysis job",
    )
    status_parser.add_argument("job_id", help="The NexSolve job/analysis ID (e.g. job-a1b2c3d4e5f6)")
    status_parser.add_argument(
        "--server",
        default=DEFAULT_API_URL,
        help=f"NexSolve API backend base URL (default: {DEFAULT_API_URL})",
    )
    status_parser.add_argument(
        "--web-url",
        default=DEFAULT_WEB_URL,
        help=f"NexSolve Web Console base URL (default: {DEFAULT_WEB_URL})",
    )
    status_parser.add_argument(
        "--api-key",
        default=DEFAULT_API_KEY,
        help="Optional API key for authenticated backend endpoints",
    )
    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw status record as JSON",
    )
    status_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode: print minimal status summary line",
    )
    status_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose mode: print detailed job statistics and diagnostic fields",
    )
    status_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    # 3. 'report' command
    report_parser = subparsers.add_parser(
        "report",
        help="Retrieve, download, or view forensic report for a completed analysis",
    )
    report_parser.add_argument("job_id", help="The NexSolve job/analysis ID")
    report_parser.add_argument(
        "-o", "--output",
        help="Destination path to save the downloaded report file",
    )
    report_parser.add_argument(
        "--format",
        choices=["html", "json"],
        default="html",
        help="Report format to download: 'html' (standalone printable) or 'json' (raw intelligence)",
    )
    report_parser.add_argument(
        "--server",
        default=DEFAULT_API_URL,
        help=f"NexSolve API backend base URL (default: {DEFAULT_API_URL})",
    )
    report_parser.add_argument(
        "--web-url",
        default=DEFAULT_WEB_URL,
        help=f"NexSolve Web Console base URL (default: {DEFAULT_WEB_URL})",
    )
    report_parser.add_argument(
        "--api-key",
        default=DEFAULT_API_KEY,
        help="Optional API key for authenticated backend endpoints",
    )
    report_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw report JSON directly to stdout",
    )
    report_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode: suppress headers and decoration",
    )
    report_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose mode: display report retrieval telemetry",
    )
    report_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    # 4. 'forecast' command (backward-compatible legacy runner)
    forecast_parser = subparsers.add_parser(
        "forecast",
        help="[Legacy] Analyze PCAP capture locally in-process without backend connection",
    )
    forecast_parser.add_argument("pcap_path", help="Path to .pcap or .pcapng network capture file")
    forecast_parser.add_argument("--horizon", type=int, default=5, help="Forecast horizon steps (default: 5)")
    forecast_parser.add_argument("--json", action="store_true", help="Output raw JSON intelligence report")
    forecast_parser.add_argument("--report", action="store_true", help="Generate standalone HTML security report")
    forecast_parser.add_argument("-o", "--output", help="Output file path for generated JSON or HTML report")

    # 5. 'doctor' command
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Verify runtime environment, installed ML/packet libraries, sensors, and backend connectivity",
    )
    doctor_parser.add_argument(
        "--server",
        default=DEFAULT_API_URL,
        help=f"NexSolve API backend base URL (default: {DEFAULT_API_URL})",
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw diagnostics JSON to stdout",
    )
    doctor_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    # 6. 'compare' command
    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare two completed analyses (by job ID or local JSON file) for threat escalation and forecast divergence",
    )
    compare_parser.add_argument("job_a", help="Baseline analysis ID or path to JSON analysis file")
    compare_parser.add_argument("job_b", help="Subject analysis ID or path to JSON analysis file")
    compare_parser.add_argument(
        "--server",
        default=DEFAULT_API_URL,
        help=f"NexSolve API backend base URL (default: {DEFAULT_API_URL})",
    )
    compare_parser.add_argument(
        "--api-key",
        default=DEFAULT_API_KEY,
        help="Optional API key for authenticated backend endpoints",
    )
    compare_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw comparison report as JSON to stdout",
    )
    compare_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    # 7. 'evidence' command
    evidence_parser = subparsers.add_parser(
        "evidence",
        help="Inspect cryptographic capture fingerprint, protocol capabilities, and multi-signal evidence fusion",
    )
    evidence_parser.add_argument("job_id", help="The NexSolve job ID or path to local analysis JSON file")
    evidence_parser.add_argument(
        "--server",
        default=DEFAULT_API_URL,
        help=f"NexSolve API backend base URL (default: {DEFAULT_API_URL})",
    )
    evidence_parser.add_argument(
        "--api-key",
        default=DEFAULT_API_KEY,
        help="Optional API key for authenticated backend endpoints",
    )
    evidence_parser.add_argument(
        "--entity",
        help="Filter evidence and investigation dossier to a specific IP entity",
    )
    evidence_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw evidence records as JSON to stdout",
    )
    evidence_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    # 8. 'evaluate' command
    evaluate_parser = subparsers.add_parser(
        "evaluate",
        help="Evaluate model forecasting performance across discrete horizons (T+1 to T+5, T+10)",
        description="Evaluate model forecasting performance across discrete horizons (T+1 to T+5, T+10)",
    )
    evaluate_parser.add_argument("dataset", help="Target benchmark dataset name ('unsw', 'cic', 'toniot') or data file path")
    evaluate_parser.add_argument("--model", help="Path to World Model checkpoint directory")
    evaluate_parser.add_argument("--horizons", default="1,2,3,5", help="Comma-separated forecast horizons (default: '1,2,3,5')")
    evaluate_parser.add_argument("--embargo-seconds", type=float, default=60.0, help="Embargo gap seconds between temporal splits (default: 60.0s)")
    evaluate_parser.add_argument("--holdout-family", help="Attack family name to hold out for out-of-distribution evaluation")
    evaluate_parser.add_argument("-o", "--output", help="Directory path to save experiment reproducibility artifacts")
    evaluate_parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility (default: 42)")
    evaluate_parser.add_argument("--json", action="store_true", help="Output raw evaluation results as JSON")
    evaluate_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color codes in terminal output")

    # 9. 'benchmark' command
    benchmark_parser = subparsers.add_parser(
        "benchmark",
        help="Run standardized input-parity benchmark comparing World Model against Persistence and Logistic Regression",
        description="Run standardized input-parity benchmark comparing World Model against Persistence and Logistic Regression",
    )
    benchmark_parser.add_argument("dataset", help="Target benchmark dataset name ('unsw', 'cic', 'toniot') or data file path")
    benchmark_parser.add_argument("--model", help="Path to World Model checkpoint directory")
    benchmark_parser.add_argument("--horizons", default="1,2,3,5", help="Comma-separated forecast horizons (default: '1,2,3,5')")
    benchmark_parser.add_argument("--embargo-seconds", type=float, default=60.0, help="Embargo gap seconds between temporal splits (default: 60.0s)")
    benchmark_parser.add_argument("--holdout-family", help="Attack family name to hold out for out-of-distribution evaluation")
    benchmark_parser.add_argument("-o", "--output", help="Directory path to save experiment reproducibility artifacts")
    benchmark_parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility (default: 42)")
    benchmark_parser.add_argument("--json", action="store_true", help="Output raw benchmark report as JSON")
    benchmark_parser.add_argument("--no-color", action="store_true", help="Disable ANSI color codes in terminal output")

    # 10. 'progression' command
    progression_parser = subparsers.add_parser(
        "progression",
        help="Inspect 15-stage canonical attack progression, MITRE ATT&CK techniques, transitions, and timeline validation",
        description="Inspect 15-stage canonical attack progression, MITRE ATT&CK techniques, transitions, and timeline validation",
    )
    progression_parser.add_argument("job_id", help="The NexSolve job ID or path to local analysis JSON file")
    progression_parser.add_argument(
        "--server",
        default=DEFAULT_API_URL,
        help=f"NexSolve API backend base URL (default: {DEFAULT_API_URL})",
    )
    progression_parser.add_argument(
        "--api-key",
        default=DEFAULT_API_KEY,
        help="Optional API key for authenticated backend endpoints",
    )
    progression_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw attack progression payload as JSON to stdout",
    )
    progression_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )
    progression_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode; print only current canonical attack stage",
    )

    # 11. 'investigate' command
    investigate_parser = subparsers.add_parser(
        "investigate",
        help="Comprehensive 360-degree forensic state, attack progression, forecast horizons, and evidence investigation",
        description="Comprehensive 360-degree forensic state, attack progression, forecast horizons, and evidence investigation",
    )
    investigate_parser.add_argument("job_id", help="The NexSolve job ID or path to local analysis JSON file")
    investigate_parser.add_argument(
        "--server",
        default=DEFAULT_API_URL,
        help=f"NexSolve API backend base URL (default: {DEFAULT_API_URL})",
    )
    investigate_parser.add_argument(
        "--web-url",
        default=DEFAULT_WEB_URL,
        help=f"NexSolve Web Console base URL (default: {DEFAULT_WEB_URL})",
    )
    investigate_parser.add_argument(
        "--api-key",
        default=DEFAULT_API_KEY,
        help="Optional API key for authenticated backend endpoints",
    )
    investigate_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw investigation payload as JSON to stdout",
    )
    investigate_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    # 12. 'explain' command
    explain_parser = subparsers.add_parser(
        "explain",
        help="Explain analytical decisions with physical telemetry, feature drivers, sensor agreement, and MITRE grounding",
        description="Explain analytical decisions with physical telemetry, feature drivers, sensor agreement, and MITRE grounding",
    )
    explain_parser.add_argument("job_id", help="The NexSolve job ID or path to local analysis JSON file")
    explain_parser.add_argument(
        "--server",
        default=DEFAULT_API_URL,
        help=f"NexSolve API backend base URL (default: {DEFAULT_API_URL})",
    )
    explain_parser.add_argument(
        "--api-key",
        default=DEFAULT_API_KEY,
        help="Optional API key for authenticated backend endpoints",
    )
    explain_parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw explainability payload as JSON to stdout",
    )
    explain_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    # 13. 'export' command
    export_parser = subparsers.add_parser(
        "export",
        help="Export comprehensive forensic & predictive report to self-contained HTML, Markdown, or JSON",
        description="Export comprehensive forensic & predictive report to self-contained HTML, Markdown, or JSON",
    )
    export_parser.add_argument("job_id", help="The NexSolve job ID or path to local analysis JSON file")
    export_parser.add_argument(
        "--format",
        choices=["html", "json", "markdown", "md"],
        default="html",
        help="Target report format: 'html', 'json', or 'markdown' (default: 'html')",
    )
    export_parser.add_argument(
        "-o", "--output",
        help="Destination file path for exported report",
    )
    export_parser.add_argument(
        "--server",
        default=DEFAULT_API_URL,
        help=f"NexSolve API backend base URL (default: {DEFAULT_API_URL})",
    )
    export_parser.add_argument(
        "--api-key",
        default=DEFAULT_API_KEY,
        help="Optional API key for authenticated backend endpoints",
    )
    export_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress interactive confirmation messages",
    )
    export_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    # 14. 'version' command
    version_parser = subparsers.add_parser(
        "version",
        help="Show NexSolve platform, CLI, model, and feature schema version details",
        description="Show NexSolve platform, CLI, model, and feature schema version details",
    )
    version_parser.add_argument(
        "--json",
        action="store_true",
        help="Output version details as JSON to stdout",
    )
    version_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )

    return parser


_COMMAND_HANDLERS: dict[str, tuple[str, str]] = {
    "analyze": ("nexsolve.commands.analyze", "run_analyze"),
    "status": ("nexsolve.commands.status", "run_status"),
    "report": ("nexsolve.commands.report", "run_report"),
    "forecast": ("nexsolve.commands.forecast", "run_forecast"),
    "doctor": ("nexsolve.commands.doctor", "run_doctor"),
    "compare": ("nexsolve.commands.compare", "run_compare"),
    "evidence": ("nexsolve.commands.evidence", "run_evidence"),
    "evaluate": ("nexsolve.commands.evaluate", "run_evaluate"),
    "benchmark": ("nexsolve.commands.benchmark", "run_benchmark"),
    "progression": ("nexsolve.commands.progression", "run_progression"),
    "investigate": ("nexsolve.commands.investigate", "run_investigate"),
    "explain": ("nexsolve.commands.explain", "run_explain"),
    "export": ("nexsolve.commands.export", "run_export"),
    "version": ("nexsolve.commands.version", "run_version"),
}


def _dispatch_command(cmd_name: str, args: argparse.Namespace) -> int:
    """Dynamically load and execute only the invoked subcommand."""
    entry = _COMMAND_HANDLERS.get(cmd_name)
    if not entry:
        return 0
    mod_name, func_name = entry
    mod = importlib.import_module(mod_name)
    handler = getattr(mod, func_name)
    return handler(args)


def run_interactive_menu(term: TerminalRenderer) -> int:
    """Provide a clean interactive terminal menu when nexsolve is invoked without arguments."""
    menu_text = (
        f"\n{term.C_CYAN}{term.C_BOLD}NexSolve{term.C_RESET}\n"
        f"{term.C_DIM}AI Network Attack Forecasting{term.C_RESET}\n\n"
        f"What would you like to do?\n\n"
        f"  1. Analyze a PCAP\n"
        f"  2. Investigate an existing job\n"
        f"  3. Run diagnostics\n"
        f"  4. View version\n"
        f"  5. Exit\n"
    )
    print(menu_text)

    while True:
        try:
            choice = input("Select an option: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting NexSolve.")
            return 0

        if not choice:
            continue

        if choice in ("1", "analyze", "analyze a pcap"):
            from nexsolve.picker import open_pcap_picker
            selected = open_pcap_picker()
            if not selected:
                print("No PCAP selected. Analysis cancelled.")
                return 0

            print(f"\nSelected:\n  {selected}\n")
            print(f"Selected capture:\n  {Path(selected).name}\n")

            open_browser = False
            try:
                open_prompt = input("Open web investigation console in browser when complete? [Y/n]: ").strip().lower()
                if open_prompt in ("", "y", "yes"):
                    open_browser = True
            except (EOFError, KeyboardInterrupt):
                open_browser = False

            analyze_args = argparse.Namespace(
                pcap_path=selected,
                server=DEFAULT_API_URL,
                web_url=DEFAULT_WEB_URL,
                api_key=DEFAULT_API_KEY,
                poll_interval=DEFAULT_POLL_INTERVAL,
                timeout=DEFAULT_TIMEOUT,
                open=open_browser,
                headless=False,
                json=False,
                report_out=None,
                quiet=False,
                verbose=False,
                no_color=not term.color_enabled,
            )
            return _dispatch_command("analyze", analyze_args)

        elif choice in ("2", "investigate", "investigate an existing job", "investigate a job"):
            try:
                job_id = input("Enter Job ID (e.g. job-a1b2c3d4e5f6) or path to analysis JSON: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nInvestigation cancelled.")
                return 0

            if not job_id:
                print("No job ID provided. Investigation cancelled.")
                return 0

            inv_args = argparse.Namespace(
                job_id=job_id,
                server=DEFAULT_API_URL,
                web_url=DEFAULT_WEB_URL,
                api_key=DEFAULT_API_KEY,
                json=False,
                no_color=not term.color_enabled,
            )
            return _dispatch_command("investigate", inv_args)

        elif choice in ("3", "doctor", "diagnostics", "run diagnostics"):
            doc_args = argparse.Namespace(
                server=DEFAULT_API_URL,
                json=False,
                no_color=not term.color_enabled,
            )
            return _dispatch_command("doctor", doc_args)

        elif choice in ("4", "version", "view version"):
            ver_args = argparse.Namespace(
                json=False,
                no_color=not term.color_enabled,
            )
            return _dispatch_command("version", ver_args)

        elif choice in ("5", "exit", "quit", "q"):
            print("Exiting NexSolve.")
            return 0

        else:
            print("Invalid option. Please select a number from 1 to 5.")


def main(argv: list[str] | None = None) -> int:
    """Main CLI execution routine."""
    parser = build_parser()
    args = parser.parse_args(argv)

    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)

    try:
        if not args.command:
            return run_interactive_menu(term)
        elif args.command in _COMMAND_HANDLERS:
            return _dispatch_command(args.command, args)
        else:
            parser.print_help()
            return 0
    except NexSolveError as err:
        term.print_error(err)
        return err.exit_code
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"\n[ERROR] An unexpected error occurred: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

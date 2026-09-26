"""Terminal presentation and styling utilities for the NexSolve CLI."""
from __future__ import annotations

import os
import sys
from typing import Any

from nexsolve.client.models import AnalysisSummary, JobStatus
from nexsolve.config import STAGE_DESCRIPTIONS


def _can_encode(char: str) -> bool:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        char.encode(encoding)
        return True
    except Exception:
        return False


class TerminalRenderer:
    """Handles ANSI colors, spinners, progress updates, and SOC report formatting."""

    def __init__(self, use_color: bool = True) -> None:
        # Check if color is supported and enabled
        is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        no_color_env = bool(os.getenv("NO_COLOR"))
        self.color_enabled = use_color and is_tty and not no_color_env

        # Unicode encoding support check
        self.supports_unicode = _can_encode("✓")
        self.CHECKMARK = "✓" if self.supports_unicode else "[+]"
        self.ARROW = "➜" if self.supports_unicode else "->"
        self.BOX_TL = "┌" if self.supports_unicode else "+"
        self.BOX_TR = "┐" if self.supports_unicode else "+"
        self.BOX_BL = "└" if self.supports_unicode else "+"
        self.BOX_BR = "┘" if self.supports_unicode else "+"
        self.BOX_H = "─" if self.supports_unicode else "-"
        self.BOX_V = "│" if self.supports_unicode else "|"

        # ANSI escape codes
        self.C_RESET = "\033[0m" if self.color_enabled else ""
        self.C_BOLD = "\033[1m" if self.color_enabled else ""
        self.C_DIM = "\033[2m" if self.color_enabled else ""
        self.C_RED = "\033[91m" if self.color_enabled else ""
        self.C_GREEN = "\033[92m" if self.color_enabled else ""
        self.C_YELLOW = "\033[93m" if self.color_enabled else ""
        self.C_BLUE = "\033[94m" if self.color_enabled else ""
        self.C_MAGENTA = "\033[95m" if self.color_enabled else ""
        self.C_CYAN = "\033[96m" if self.color_enabled else ""
        self.C_WHITE = "\033[97m" if self.color_enabled else ""

    def bold(self, text: Any) -> str:
        return f"{self.C_BOLD}{text}{self.C_RESET}"

    def green(self, text: Any) -> str:
        return f"{self.C_GREEN}{text}{self.C_RESET}"

    def red(self, text: Any) -> str:
        return f"{self.C_RED}{text}{self.C_RESET}"

    def yellow(self, text: Any) -> str:
        return f"{self.C_YELLOW}{text}{self.C_RESET}"

    def cyan(self, text: Any) -> str:
        return f"{self.C_CYAN}{text}{self.C_RESET}"

    def dim(self, text: Any) -> str:
        return f"{self.C_DIM}{text}{self.C_RESET}"

    def format_size(self, size_bytes: int) -> str:
        """Format bytes to human-readable size string."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def print_banner(self) -> None:
        banner = rf"""{self.C_CYAN}{self.C_BOLD}
======================================================================
  _   _           ____        _            
 | \ | | _____  _/ ___|  ___ | |_   _____  
 |  \| |/ _ \ \/ \___ \ / _ \| \ \ / / _ \ 
 | |\  |  __/>  < ___) | (_) | |\ V /  __/ 
 |_| \_|\___/_/\_\____/ \___/|_| \_/ \___| 
                                           
 NexSolve
 AI-Based Network Attack Forecasting Platform
======================================================================{self.C_RESET}"""
        print(banner)

    def print_file_info(self, filename: str, size_bytes: int, format_name: str) -> None:
        fmt = format_name.upper().lstrip(".")
        print(f"\n{self.C_BOLD}CAPTURE{self.C_RESET}\n")
        print(f"  {self.C_DIM}File:{self.C_RESET}     {self.C_WHITE}{filename}{self.C_RESET}")
        print(f"  {self.C_DIM}Size:{self.C_RESET}     {self.C_WHITE}{self.format_size(size_bytes)}{self.C_RESET}")
        print(f"  {self.C_DIM}Format:{self.C_RESET}   {self.C_WHITE}{fmt}{self.C_RESET}\n")

    def print_stage_start(self, title: str = "ANALYSIS") -> None:
        print(f"{self.C_BOLD}{title}{self.C_RESET}")

    def print_header(self, text: str) -> None:
        print(f"\n{self.C_CYAN}{self.C_BOLD}=== {text} ==={self.C_RESET}\n")

    def print_info(self, text: str) -> None:
        print(f"  {self.C_CYAN}[*]{self.C_RESET} {text}")

    def print_success(self, text: str) -> None:
        print(f"\n  {self.C_GREEN}{self.CHECKMARK}{self.C_RESET} {self.C_BOLD}{text}{self.C_RESET}")

    def print_checkmark(self, label: str) -> None:
        print(f"  {self.C_GREEN}{self.CHECKMARK}{self.C_RESET} {label}")

    def print_live_progress(self, stage: str, progress: float, elapsed_seconds: float) -> None:
        description = STAGE_DESCRIPTIONS.get(stage, "Processing telemetry")
        pct = int(progress * 100)
        # Clear current line and write progress
        sys.stdout.write(f"\r  {self.C_CYAN}{self.ARROW}{self.C_RESET} [{stage}] {description}... {self.C_BOLD}{pct}%{self.C_RESET} ({elapsed_seconds:.1f}s)    ")
        sys.stdout.flush()

    def clear_live_progress(self) -> None:
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    def print_soc_summary(self, summary: AnalysisSummary) -> None:
        print(f"\n{self.C_BOLD}--- CURRENT NETWORK STATE (T0) ---{self.C_RESET}")
        threat_color = self.C_RED if summary.threat_level in ("HIGH", "CRITICAL") else (self.C_YELLOW if summary.threat_level == "ELEVATED" else self.C_GREEN)
        print(f"  Observed Threat Level: {threat_color}{self.C_BOLD}{summary.threat_level}{self.C_RESET}")
        print(f"  Current Risk Score:    {summary.risk_score:.1f} / 100")
        print(f"  Detected Events:       {summary.detected_events}")
        print(f"  Packets / Flows:       {summary.packet_count:,} pkts / {summary.flow_count:,} flows")

        print(f"\n{self.C_BOLD}--- EARLY WARNING & ATTACK PROGRESSION ---{self.C_RESET}")
        ew_color = self.C_RED if summary.early_warning_level in ("HIGH", "CRITICAL") else (self.C_YELLOW if summary.early_warning_level == "ELEVATED" else self.C_GREEN)
        print(f"  Early Warning Score:   {ew_color}{self.C_BOLD}{summary.early_warning_score} / 100 [{summary.early_warning_level}]{self.C_RESET}")
        print(f"  Progression Verdict:   {self.C_CYAN}{summary.progression_verdict}{self.C_RESET}")

        print(f"\n{self.C_BOLD}--- MULTI-HORIZON AUTOREGRESSIVE ROLLOUT ---{self.C_RESET}")
        if summary.abstention and summary.abstention.get("abstained"):
            reason = summary.abstention.get("reason", "INSUFFICIENT_HISTORY")
            expl = summary.abstention.get("explanation", "Insufficient continuous temporal windows.")
            print(f"  {self.C_YELLOW}[!] FORECAST WITHHELD: {reason}{self.C_RESET}")
            print(f"      {expl}")
        elif summary.forecast_points:
            print("  Horizon | Lookahead | Single P(Atk) | Cumulative Risk | Risk Level | Predicted Stage")
            print("  --------+-----------+---------------+-----------------+------------+----------------")
            for f in summary.forecast_points:
                h = f.get("horizon", 1)
                secs = f.get("lookaheadSeconds", h * 60)
                p_atk = f.get("attackProbability")
                p_str = f"{p_atk * 100:.1f}%" if p_atk is not None else "N/A"
                c_risk = f.get("cumulativeRisk")
                c_str = f"{c_risk * 100:.1f}%" if c_risk is not None else "N/A"
                r_lvl = f.get("riskLevel", "LOW")
                stage = f.get("predictedStage", "NORMAL")
                print(f"  T+{h:<5} | +{secs:<8}s | {p_str:<13} | {c_str:<15} | {r_lvl:<10} | {stage}")

        if summary.top_drivers:
            print(f"\n{self.C_BOLD}--- TOP ATTRIBUTION DRIVERS ---{self.C_RESET}")
            for d in summary.top_drivers[:3]:
                feat = d.get("feature", "feature")
                direction = d.get("direction", "up").upper()
                cur_val = d.get("current_value", "")
                pred_val = d.get("predicted_value", "")
                interp = d.get("interpretation", "")
                if ("by " in interp and "%" in interp) and (cur_val == 0 or cur_val == 0.0 or str(cur_val) in ("0", "0.0")):
                    interp = f"Feature '{feat}' newly present in forecast ({cur_val} -> {pred_val})"
                print(f"  * {self.C_CYAN}{feat:<24}{self.C_RESET} | {direction} ({cur_val} -> {pred_val})")
                if interp:
                    print(f"    --> {self.C_DIM}{interp}{self.C_RESET}")

    def print_concise_summary(self, summary: AnalysisSummary, pcap_name: str) -> None:
        arrow = "→" if self.supports_unicode else "->"
        print(f"\n{self.C_GREEN}{self.C_BOLD}ANALYSIS COMPLETE{self.C_RESET}\n")

        if summary.is_abstained:
            print(f"{self.C_BOLD}Capture{self.C_RESET}\n  {pcap_name}\n")
            print(f"{self.C_BOLD}Status{self.C_RESET}\n  COMPLETED\n")
            print(f"{self.C_BOLD}Forecast{self.C_RESET}\n  {self.C_YELLOW}ABSTAINED{self.C_RESET}\n")
            print(f"{self.C_BOLD}Reason{self.C_RESET}\n  {summary.abstention_reason_text}\n")
            print(f"{self.C_BOLD}Observed{self.C_RESET}\n  {summary.abstention_observed_windows} windows\n")
            print(f"{self.C_BOLD}Required{self.C_RESET}\n  {summary.abstention_required_windows} windows\n")
            print(f"{self.C_BOLD}Report{self.C_RESET}\n  AVAILABLE\n")
        else:
            if summary.forecast_points:
                h_min = min(pt.get("horizon", 1) for pt in summary.forecast_points)
                h_max = max(pt.get("horizon", len(summary.forecast_points)) for pt in summary.forecast_points)
                horizons_str = f"T+{h_min} {arrow} T+{h_max}"
            else:
                horizons_str = f"T+1 {arrow} T+5"

            print(f"{self.C_BOLD}Capture{self.C_RESET}\n  {pcap_name}\n")
            print(f"{self.C_BOLD}Status{self.C_RESET}\n  COMPLETED\n")
            print(f"{self.C_BOLD}Forecast{self.C_RESET}\n  {self.C_CYAN}AVAILABLE{self.C_RESET}\n")
            print(f"{self.C_BOLD}Horizons{self.C_RESET}\n  {horizons_str}\n")
            print(f"{self.C_BOLD}Evidence{self.C_RESET}\n  AVAILABLE\n")
            print(f"{self.C_BOLD}Report{self.C_RESET}\n  AVAILABLE\n")

    def print_visualization_box(self, job_id: str, vis_url: str, report_url: str) -> None:
        print(f"{self.C_BOLD}Analysis ID:{self.C_RESET}")
        print(f"  {self.C_CYAN}{job_id}{self.C_RESET}\n")

        border = self.BOX_H * 70
        print(f"{self.C_CYAN}{self.BOX_TL}{border}{self.BOX_TR}{self.C_RESET}")
        print(f"{self.C_CYAN}{self.BOX_V}{self.C_RESET} {self.C_BOLD}VIEW INTERACTIVE ATTACKS, FORECAST & EVIDENCE IN WEB UI:{self.C_RESET}")
        print(f"{self.C_CYAN}{self.BOX_V}{self.C_RESET}   {self.C_GREEN}{self.C_BOLD}{vis_url}{self.C_RESET}")
        print(f"{self.C_CYAN}{self.BOX_V}{self.C_RESET}")
        print(f"{self.C_CYAN}{self.BOX_V}{self.C_RESET} {self.C_BOLD}VIEW OR EXPORT PRINTABLE EXECUTIVE REPORT:{self.C_RESET}")
        print(f"{self.C_CYAN}{self.BOX_V}{self.C_RESET}   {self.C_CYAN}{report_url}{self.C_RESET}")
        print(f"{self.C_CYAN}{self.BOX_BL}{border}{self.BOX_BR}{self.C_RESET}\n")

    def print_error(self, exc: Exception) -> None:
        msg = getattr(exc, "message", str(exc))
        reason = getattr(exc, "reason", None)
        next_step = getattr(exc, "next_step", None)
        remedy = getattr(exc, "remedy", "")

        print(f"\n{self.C_RED}{self.C_BOLD}[ERROR]{self.C_RESET} {msg}", file=sys.stderr)
        if reason:
            print(f"\n{self.C_BOLD}Reason:{self.C_RESET}\n  {reason}", file=sys.stderr)
        if next_step:
            print(f"\n{self.C_BOLD}Possible next step:{self.C_RESET}\n  {next_step}\n", file=sys.stderr)
        elif remedy:
            print(f"{self.C_YELLOW}{self.C_BOLD}[REMEDY]{self.C_RESET} {remedy}\n", file=sys.stderr)

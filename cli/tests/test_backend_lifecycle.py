"""Comprehensive test suite for CLI Branding, Backend Lifecycle, and UX (Prompt Requirements A-H)."""
from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from nexsolve.errors import EngineStartupError, ServerConnectionError
from nexsolve.main import build_parser, main
from nexsolve.output.terminal import TerminalRenderer
from nexsolve.service import (
    check_engine_health,
    ensure_backend_ready,
    find_project_root,
    is_local_endpoint,
    is_port_bound,
)


@pytest.fixture
def sample_pcap(tmp_path: Path) -> Path:
    pcap = tmp_path / "valid_sample.pcap"
    header = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
    pcap.write_bytes(header)
    return pcap


# =============================================================================
# Requirement A: SIH strings do NOT appear in production CLI output
# =============================================================================

def test_sih_references_absent_from_help(capsys):
    """Verify that --help produces clean, product-focused output free of SIH references."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr().out

    for forbidden in ["SIH", "Smart India", "26153", "Problem Statement"]:
        assert forbidden.lower() not in captured.lower(), f"Forbidden string '{forbidden}' found in --help"
    assert "NexSolve: AI-Based Network Attack Forecasting Platform" in captured


def test_sih_references_absent_from_analyze_help(capsys):
    """Verify that 'analyze --help' does not display any SIH branding."""
    with pytest.raises(SystemExit) as exc_info:
        main(["analyze", "--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr().out

    for forbidden in ["SIH", "Smart India", "26153", "Problem Statement"]:
        assert forbidden.lower() not in captured.lower(), f"Forbidden string '{forbidden}' found in analyze --help"


def test_sih_references_absent_from_banner(capsys):
    """Verify that TerminalRenderer.print_banner() outputs clean NexSolve product identity."""
    renderer = TerminalRenderer(use_color=False)
    renderer.print_banner()
    captured = capsys.readouterr().out

    for forbidden in ["SIH", "Smart India", "26153", "Problem Statement"]:
        assert forbidden.lower() not in captured.lower(), f"Forbidden string '{forbidden}' found in banner"
    assert "NexSolve" in captured
    assert "AI-Based Network Attack Forecasting Platform" in captured


# =============================================================================
# Requirement B & G: Existing backend is preserved and used without restarting/killing
# =============================================================================

def test_existing_backend_used_immediately_without_restart():
    """When backend is already healthy, ensure_backend_ready returns immediately."""
    with patch("nexsolve.service.check_engine_health", return_value=True) as mock_health, \
         patch("subprocess.Popen") as mock_popen:
        ensure_backend_ready("http://127.0.0.1:8001")
        mock_health.assert_called_once()
        mock_popen.assert_not_called()


# =============================================================================
# Requirement C & D: Backend unavailable -> Automatic startup succeeds and analysis continues
# =============================================================================

def test_backend_unavailable_triggers_autostart_and_waits_for_readiness():
    """When engine is unavailable, CLI starts local process and waits for health readiness."""
    health_calls = 0

    def mock_health_check(url, timeout=1.0):
        nonlocal health_calls
        health_calls += 1
        return health_calls >= 3  # Becomes ready on 3rd poll

    mock_process = MagicMock()
    mock_process.poll.return_value = None  # Running normally

    term = TerminalRenderer(use_color=False)

    with patch("nexsolve.service.check_engine_health", side_effect=mock_health_check), \
         patch("nexsolve.service.is_port_bound", return_value=False), \
         patch("subprocess.Popen", return_value=mock_process) as mock_popen, \
         patch("time.sleep", return_value=None):
        ensure_backend_ready("http://127.0.0.1:8001", term=term, startup_timeout=10.0)

        assert mock_popen.called
        assert health_calls >= 3


# =============================================================================
# Requirement E: Backend startup fails -> Useful diagnostic with Reason and Next Step
# =============================================================================

def test_backend_startup_failure_reports_clear_diagnostic(capsys):
    """When startup process terminates prematurely, EngineStartupError provides actionable guidance."""
    mock_process = MagicMock()
    mock_process.poll.return_value = 1  # Exited with error

    with patch("nexsolve.service.check_engine_health", return_value=False), \
         patch("nexsolve.service.is_port_bound", return_value=False), \
         patch("nexsolve.service.read_recent_engine_log", return_value="Address already in use: 127.0.0.1:8001"), \
         patch("subprocess.Popen", return_value=mock_process):
        with pytest.raises(EngineStartupError) as exc_info:
            ensure_backend_ready("http://127.0.0.1:8001", startup_timeout=5.0)

        err = exc_info.value
        assert "Analysis engine could not be started" in str(err)
        assert err.reason != ""
        assert err.next_step != ""

        term = TerminalRenderer(use_color=False)
        term.print_error(err)
        captured = capsys.readouterr().err
        assert "[ERROR] Analysis engine could not be started" in captured
        assert "Reason:" in captured
        assert "Possible next step:" in captured


def test_port_already_bound_by_foreign_process_reports_conflict():
    """If port 8001 is already bound by an alien service, fail immediately with clear diagnostic."""
    with patch("nexsolve.service.check_engine_health", return_value=False), \
         patch("nexsolve.service.is_port_bound", return_value=True):
        with pytest.raises(EngineStartupError) as exc_info:
            ensure_backend_ready("http://127.0.0.1:8001")

        err = exc_info.value
        assert "already in use" in err.reason.lower()
        assert "terminate the conflicting process" in err.next_step.lower()


# =============================================================================
# Requirement F: Wrong API URL -> Useful diagnostic without spawning useless server
# =============================================================================

def test_wrong_api_url_provides_useful_diagnostic(sample_pcap: Path, capsys):
    """Explicitly providing an unreachable custom server URL fails fast with diagnostic."""
    ret = main(["analyze", str(sample_pcap), "--server", "http://127.0.0.1:59999", "--no-color"])
    assert ret == 3
    captured = capsys.readouterr().err
    assert "[ERROR]" in captured
    assert "59999" in captured
    assert "Reason:" in captured or "REMEDY" in captured


# =============================================================================
# Requirement H: Local PCAP validation continues to work strictly
# =============================================================================

def test_pcap_validation_still_enforced(capsys):
    """File validation rejects non-existent and corrupt files before any network interaction."""
    ret_not_found = main(["analyze", "ghost_file_missing.pcap"])
    assert ret_not_found == 2
    captured = capsys.readouterr().err
    assert "[ERROR]" in captured
    assert "not found" in captured.lower()


# =============================================================================
# Requirements 1-16: End-to-End Workflow, Headless, Open, Abstention, Paths
# =============================================================================

def test_analyze_headless_flag_suppresses_browser_and_prompt(sample_pcap: Path, mock_server: str, capsys):
    """--headless never opens browser, never prompts interactively, and exits 0."""
    with patch("webbrowser.open") as mock_open, \
         patch("builtins.input") as mock_input:
        ret = main([
            "analyze",
            str(sample_pcap),
            "--server", mock_server,
            "--headless",
            "--poll-interval", "0.05",
            "--no-color",
        ])
        assert ret == 0
        mock_open.assert_not_called()
        mock_input.assert_not_called()
        captured = capsys.readouterr().out
        assert "ANALYSIS COMPLETE" in captured
        assert "COMPLETED" in captured


def test_analyze_open_flag_launches_browser_automatically(sample_pcap: Path, mock_server: str, capsys):
    """--open automatically opens browser to visualization URL without prompting."""
    with patch("webbrowser.open", return_value=True) as mock_open, \
         patch("builtins.input") as mock_input:
        ret = main([
            "analyze",
            str(sample_pcap),
            "--server", mock_server,
            "--open",
            "--poll-interval", "0.05",
            "--no-color",
        ])
        assert ret == 0
        mock_input.assert_not_called()
        mock_open.assert_called_once()
        opened_url = mock_open.call_args[0][0]
        assert "/console/forecast/job-test123456" in opened_url


def test_analyze_interactive_prompt_yes_opens_browser(sample_pcap: Path, mock_server: str, capsys):
    """In interactive mode, answering 'y' opens the web investigation console."""
    with patch("webbrowser.open", return_value=True) as mock_open, \
         patch("sys.stdin.isatty", return_value=True), \
         patch("builtins.input", return_value="y") as mock_input:
        ret = main([
            "analyze",
            str(sample_pcap),
            "--server", mock_server,
            "--poll-interval", "0.05",
            "--no-color",
        ])
        assert ret == 0
        mock_input.assert_called_once()
        mock_open.assert_called_once()


def test_analyze_interactive_prompt_no_does_not_open_browser(sample_pcap: Path, mock_server: str, capsys):
    """In interactive mode, answering 'n' skips opening the browser."""
    with patch("webbrowser.open") as mock_open, \
         patch("sys.stdin.isatty", return_value=True), \
         patch("builtins.input", return_value="n") as mock_input:
        ret = main([
            "analyze",
            str(sample_pcap),
            "--server", mock_server,
            "--poll-interval", "0.05",
            "--no-color",
        ])
        assert ret == 0
        mock_input.assert_called_once()
        mock_open.assert_not_called()


def test_analyze_browser_open_failure_shows_url_and_succeeds(sample_pcap: Path, mock_server: str, capsys):
    """If browser launch fails, analysis does not fail and displays console URL cleanly."""
    with patch("webbrowser.open", side_effect=Exception("No display available")):
        ret = main([
            "analyze",
            str(sample_pcap),
            "--server", mock_server,
            "--open",
            "--poll-interval", "0.05",
            "--no-color",
        ])
        assert ret == 0
        captured = capsys.readouterr().out
        assert "Analysis completed successfully." in captured
        assert "Could not open the browser automatically." in captured
        assert "Console URL:" in captured
        assert "/console/forecast/job-test123456" in captured


def test_analyze_abstention_displays_abstained_and_exits_zero(tmp_path: Path, mock_server: str, capsys):
    """Capture with insufficient temporal history displays ABSTAINED and exits code 0."""
    abstain_pcap = tmp_path / "abstain_sample.pcap"
    header = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
    abstain_pcap.write_bytes(header)

    ret = main([
        "analyze",
        str(abstain_pcap),
        "--server", mock_server,
        "--headless",
        "--poll-interval", "0.05",
        "--no-color",
    ])
    assert ret == 0
    captured = capsys.readouterr().out
    assert "ANALYSIS COMPLETE" in captured
    assert "ABSTAINED" in captured
    assert "Insufficient temporal history" in captured
    assert "2 windows" in captured
    assert "8 windows" in captured
    assert "AVAILABLE" in captured


def test_analyze_windows_path_with_spaces(tmp_path: Path, mock_server: str, capsys):
    """Windows paths containing spaces and nested subdirectories are handled cleanly."""
    spaces_dir = tmp_path / "My Captures" / "Security Team"
    spaces_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = spaces_dir / "test space capture.pcap"
    header = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
    pcap_path.write_bytes(header)

    ret = main([
        "analyze",
        str(pcap_path),
        "--server", mock_server,
        "--headless",
        "--poll-interval", "0.05",
        "--no-color",
    ])
    assert ret == 0
    captured = capsys.readouterr().out
    assert "test space capture.pcap" in captured
    assert "ANALYSIS COMPLETE" in captured


def test_analyze_invalid_extension_fails_fast(tmp_path: Path, capsys):
    """Providing a file with unsupported extension (e.g. .txt) fails validation with non-zero exit."""
    bad_file = tmp_path / "capture.txt"
    bad_file.write_text("not a pcap")

    ret = main(["analyze", str(bad_file), "--no-color"])
    assert ret == 2
    captured = capsys.readouterr().err
    assert "[ERROR]" in captured
    assert "unsupported" in captured.lower()


"""Tests for NexSolve interactive CLI mode, native file picker, and packaging boundaries."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from nexsolve.main import main, run_interactive_menu
from nexsolve.output.terminal import TerminalRenderer
from nexsolve.picker import open_pcap_picker


@pytest.fixture
def sample_pcap(tmp_path: Path) -> Path:
    pcap = tmp_path / "sample.pcap"
    header = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
    pcap.write_bytes(header)
    return pcap


@pytest.fixture
def sample_pcapng(tmp_path: Path) -> Path:
    pcapng = tmp_path / "sample.pcapng"
    # Section Header Block (SHB) with 0a0d0d0a magic
    header = bytes.fromhex("0a0d0d0a1c0000004d3cb2a101000000ffffffffffffffff1c000000")
    pcapng.write_bytes(header)
    return pcapng


# 1. Interactive menu tests

def test_interactive_menu_exit(capsys: pytest.CaptureFixture):
    term = TerminalRenderer(use_color=False)
    with patch("builtins.input", return_value="5"):
        code = run_interactive_menu(term)
    assert code == 0
    captured = capsys.readouterr()
    assert "Exiting NexSolve." in captured.out


def test_interactive_menu_version(capsys: pytest.CaptureFixture):
    term = TerminalRenderer(use_color=False)
    with patch("builtins.input", return_value="4"):
        code = run_interactive_menu(term)
    assert code == 0
    captured = capsys.readouterr()
    assert "NEXSOLVE PLATFORM & SYSTEM VERSION" in captured.out


def test_interactive_menu_doctor(capsys: pytest.CaptureFixture):
    term = TerminalRenderer(use_color=False)
    with patch("builtins.input", return_value="3"):
        code = run_interactive_menu(term)
    assert code in (0, 1)  # Depends on sensor/backend presence
    captured = capsys.readouterr()
    assert "NEXSOLVE SYSTEM DIAGNOSTICS & DOCTOR" in captured.out


def test_interactive_menu_investigate_cancel(capsys: pytest.CaptureFixture):
    term = TerminalRenderer(use_color=False)
    inputs = iter(["2", ""])
    with patch("builtins.input", lambda prompt="": next(inputs)):
        code = run_interactive_menu(term)
    assert code == 0
    captured = capsys.readouterr()
    assert "Investigation cancelled." in captured.out


def test_interactive_menu_analyze_cancel(capsys: pytest.CaptureFixture):
    term = TerminalRenderer(use_color=False)
    with patch("builtins.input", return_value="1"), \
         patch("nexsolve.picker.open_pcap_picker", return_value=None):
        code = run_interactive_menu(term)
    assert code == 0
    captured = capsys.readouterr()
    assert "No PCAP selected. Analysis cancelled." in captured.out


def test_interactive_menu_analyze_select(sample_pcap: Path, mock_server: str, capsys: pytest.CaptureFixture):
    term = TerminalRenderer(use_color=False)
    inputs = iter(["1", "n"])
    with patch("builtins.input", lambda prompt="": next(inputs)), \
         patch("nexsolve.picker.open_pcap_picker", return_value=str(sample_pcap)), \
         patch("nexsolve.main.DEFAULT_API_URL", mock_server):
        code = run_interactive_menu(term)
    assert code == 0
    captured = capsys.readouterr()
    assert "Selected capture:" in captured.out
    assert "sample.pcap" in captured.out
    assert "Analysis complete." in captured.out
    assert "Job ID:            job-test123456" in captured.out
    assert "Threat assessment: ELEVATED" in captured.out
    assert "Forecast:          RECONNAISSANCE_SCAN" in captured.out


# 2. 'nexsolve analyze' without path tests

def test_analyze_no_path_picker_cancellation(capsys: pytest.CaptureFixture):
    with patch("nexsolve.picker.open_pcap_picker", return_value=None):
        code = main(["analyze"])
    assert code == 0
    captured = capsys.readouterr()
    assert "No PCAP selected. Analysis cancelled." in captured.out


def test_analyze_no_path_picker_selection(sample_pcap: Path, mock_server: str, capsys: pytest.CaptureFixture):
    with patch("nexsolve.picker.open_pcap_picker", return_value=str(sample_pcap)):
        code = main(["analyze", "--server", mock_server])
    assert code == 0
    captured = capsys.readouterr()
    assert "Selected:" in captured.out
    assert "Selected capture:" in captured.out
    assert "sample.pcap" in captured.out
    assert "Analysis complete." in captured.out
    assert "Job ID:            job-test123456" in captured.out
    assert "Threat assessment: ELEVATED" in captured.out
    assert "Forecast:          RECONNAISSANCE_SCAN" in captured.out


# 3. Direct path analysis tests

def test_analyze_direct_path_skips_picker(sample_pcap: Path, mock_server: str, capsys: pytest.CaptureFixture):
    picker_mock = MagicMock()
    with patch("nexsolve.picker.open_pcap_picker", picker_mock):
        code = main(["analyze", str(sample_pcap), "--server", mock_server])
    assert code == 0
    picker_mock.assert_not_called()
    captured = capsys.readouterr()
    assert "Analysis complete." in captured.out
    assert "Job ID:            job-test123456" in captured.out


def test_analyze_pcapng_direct_path(sample_pcapng: Path, mock_server: str, capsys: pytest.CaptureFixture):
    code = main(["analyze", str(sample_pcapng), "--server", mock_server])
    assert code == 0
    captured = capsys.readouterr()
    assert "sample.pcapng" in captured.out
    assert "Analysis complete." in captured.out


def test_analyze_open_browser_flag(sample_pcap: Path, mock_server: str, capsys: pytest.CaptureFixture):
    opened_urls: list[str] = []
    with patch("webbrowser.open", lambda url: opened_urls.append(url)):
        code = main(["analyze", str(sample_pcap), "--server", mock_server, "--open"])
    assert code == 0
    assert len(opened_urls) == 1
    assert "job-test123456" in opened_urls[0]
    captured = capsys.readouterr()
    assert "Opening investigation console in browser:" in captured.out


# 4. File validation tests

def test_analyze_validation_nonexistent_file(capsys: pytest.CaptureFixture):
    code = main(["analyze", "nonexistent_file_xyz_123.pcap"])
    assert code == 2
    captured = capsys.readouterr()
    assert "File does not exist" in (captured.err + captured.out)


def test_analyze_validation_unsupported_extension(tmp_path: Path, capsys: pytest.CaptureFixture):
    txt_file = tmp_path / "traffic.txt"
    txt_file.write_text("not a pcap")
    code = main(["analyze", str(txt_file)])
    assert code == 2
    captured = capsys.readouterr()
    assert "Unsupported capture format" in (captured.err + captured.out)


# 5. Native picker implementation & fallback tests

def test_open_pcap_picker_tkinter_select(tmp_path: Path):
    target = tmp_path / "picked.pcap"
    target.touch()

    with patch("tkinter.Tk") as mock_tk, \
         patch("tkinter.filedialog.askopenfilename", return_value=str(target)):
        result = open_pcap_picker()

    assert result == str(target.resolve())


def test_open_pcap_picker_tkinter_cancel():
    with patch("tkinter.Tk") as mock_tk, \
         patch("tkinter.filedialog.askopenfilename", return_value=""):
        result = open_pcap_picker()

    assert result is None


def test_open_pcap_picker_fallback_on_tkinter_error(tmp_path: Path):
    target = tmp_path / "fallback.pcap"
    target.touch()

    with patch("tkinter.Tk", side_effect=Exception("No DISPLAY available")), \
         patch("builtins.input", return_value=f'"{str(target)}"'):
        result = open_pcap_picker()

    assert result == str(target.resolve())


def test_open_pcap_picker_fallback_cancel():
    with patch("tkinter.Tk", side_effect=Exception("No DISPLAY available")), \
         patch("builtins.input", return_value=""):
        result = open_pcap_picker()

    assert result is None


# 6. Packaging & import boundary tests

def test_packaging_no_eager_ml_imports():
    """Verify that importing CLI modules does not eagerly require repo-local 'ml' module."""
    # Temporarily hide 'ml' from sys.modules
    original_ml = sys.modules.pop("ml", None)
    try:
        import nexsolve.main
        import nexsolve.picker
        import nexsolve.commands.version
        import nexsolve.commands.doctor
        import nexsolve.commands.analyze
        import nexsolve.commands.status
        import nexsolve.commands.report
        
        # Verify bare help and version commands work cleanly
        with pytest.raises(SystemExit) as exc:
            nexsolve.main.main(["--version"])
        assert exc.value.code == 0
    finally:
        if original_ml is not None:
            sys.modules["ml"] = original_ml

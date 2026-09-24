"""Unit tests for the NexSolve API client and local validators."""
from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from nexsolve.client.api import NexSolveClient, StreamingMultipartReader
from nexsolve.errors import ServerConnectionError, ValidationError


@pytest.fixture
def valid_pcap_file(tmp_path: Path) -> Path:
    """Create a minimal valid PCAP file with microsecond magic bytes."""
    pcap = tmp_path / "valid.pcap"
    # PCAP header: magic d4 c3 b2 a1, version 2.4, etc.
    header = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
    pcap.write_bytes(header)
    return pcap


def test_validate_local_pcap_success(valid_pcap_file: Path):
    client = NexSolveClient()
    meta = client.validate_local_pcap(valid_pcap_file)
    assert meta["filename"] == "valid.pcap"
    assert meta["size_bytes"] == 24
    assert meta["format"] == "pcap"
    assert meta["magic"] == "d4c3b2a1"


def test_validate_local_pcap_not_found():
    client = NexSolveClient()
    with pytest.raises(ValidationError) as exc_info:
        client.validate_local_pcap("nonexistent_file_12345.pcap")
    assert "not found" in exc_info.value.message.lower()
    assert exc_info.value.exit_code == 2


def test_validate_local_pcap_is_directory(tmp_path: Path):
    client = NexSolveClient()
    with pytest.raises(ValidationError) as exc_info:
        client.validate_local_pcap(tmp_path)
    assert "not a regular file" in exc_info.value.message.lower()
    assert exc_info.value.exit_code == 2


def test_validate_local_pcap_invalid_extension(tmp_path: Path):
    bad_ext = tmp_path / "capture.txt"
    bad_ext.write_text("hello")
    client = NexSolveClient()
    with pytest.raises(ValidationError) as exc_info:
        client.validate_local_pcap(bad_ext)
    assert "unsupported capture extension" in exc_info.value.message.lower()
    assert exc_info.value.exit_code == 2


def test_validate_local_pcap_empty(tmp_path: Path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    client = NexSolveClient()
    with pytest.raises(ValidationError) as exc_info:
        client.validate_local_pcap(empty)
    assert "empty" in exc_info.value.message.lower()
    assert exc_info.value.exit_code == 2


def test_validate_local_pcap_corrupt_magic(tmp_path: Path):
    corrupt = tmp_path / "corrupt.pcap"
    corrupt.write_bytes(b"INVALID_HEADER_BYTES_12345")
    client = NexSolveClient()
    with pytest.raises(ValidationError) as exc_info:
        client.validate_local_pcap(corrupt)
    assert "not a valid pcap/pcapng" in exc_info.value.message.lower()
    assert exc_info.value.exit_code == 2


def test_check_health_connection_error():
    # Attempt connecting to an unused localhost port
    client = NexSolveClient(base_url="http://127.0.0.1:59999")
    with pytest.raises(ServerConnectionError) as exc_info:
        client.check_health()
    assert "cannot connect" in exc_info.value.message.lower()
    assert exc_info.value.exit_code == 3


def test_streaming_multipart_reader(tmp_path: Path):
    test_file = tmp_path / "sample.pcap"
    test_content = b"0123456789" * 1000
    test_file.write_bytes(test_content)

    header = b"--BOUNDARY\r\nContent-Disposition: form-data\r\n\r\n"
    footer = b"\r\n--BOUNDARY--\r\n"

    reader = StreamingMultipartReader(header, test_file, footer)
    assert len(reader) == len(header) + len(test_content) + len(footer)

    streamed_data = reader.read()
    reader.close()

    assert streamed_data == header + test_content + footer

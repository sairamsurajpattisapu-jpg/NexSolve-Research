"""NexSolve CLI configuration and defaults."""
from __future__ import annotations

import os

# Software version
CLI_VERSION = "1.0.0"

# Service endpoints (configurable via environment variables with safe localhost defaults)
DEFAULT_API_URL: str = os.getenv("NEXSOLVE_API_URL", "http://127.0.0.1:8001").rstrip("/")
DEFAULT_WEB_URL: str = os.getenv("NEXSOLVE_WEB_URL", "http://localhost:5173").rstrip("/")
DEFAULT_API_KEY: str = os.getenv("NEXSOLVE_API_KEY", "")

# Operational defaults
DEFAULT_POLL_INTERVAL: float = float(os.getenv("NEXSOLVE_POLL_INTERVAL", "0.5"))
DEFAULT_TIMEOUT: float = float(os.getenv("NEXSOLVE_TIMEOUT", "180.0"))

# Safety limits matching the NexSolve server contract
MAX_UPLOAD_BYTES: int = 1024 * 1024 * 1024  # 1 GiB
MAX_PACKETS: int = 500000
MAX_FLOWS: int = 100000
MAX_PROCESSING_DURATION_SECONDS: int = 300
ALLOWED_EXTENSIONS: tuple[str, ...] = (".pcap", ".pcapng")

# Supported PCAP / PCAPNG magic numbers (first 4 bytes)
PCAP_MAGICS: tuple[bytes, ...] = (
    bytes.fromhex("0a0d0d0a"),  # PCAP-NG
    bytes.fromhex("d4c3b2a1"),  # PCAP microsecond (little-endian)
    bytes.fromhex("a1b2c3d4"),  # PCAP microsecond (big-endian)
    bytes.fromhex("4d3cb2a1"),  # PCAP nanosecond (little-endian)
    bytes.fromhex("a1b23c4d"),  # PCAP nanosecond (big-endian)
)

# Canonical pipeline stage descriptions matching the NexSolve frontend visualizer
STAGE_DESCRIPTIONS: dict[str, str] = {
    "INGESTION": "Reading captured network telemetry",
    "PARSING": "Decoding packet headers and protocol metadata",
    "FLOW_RECONSTRUCTION": "Reconstructing bidirectional network conversations",
    "WINDOWING": "Segmenting behavior into temporal network states",
    "NETWORK_STATE": "Assembling canonical feature representation",
    "FORECAST": "Simulating future network states",
    "EVIDENCE": "Evaluating forecast drivers and supporting evidence",
    "REPORT": "Compiling analysis record",
    "COMPLETE": "Analysis complete. Forecast ready",
}

"""Central configuration constants, resource limits, and sanitization utilities for NexSolve."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except ImportError:
    pass

# =============================================================================
# SERVER CONFIGURATION (Configurable via environment variables with safe defaults)
# =============================================================================

NEXSOLVE_HOST: str = os.getenv("NEXSOLVE_HOST", "0.0.0.0")
NEXSOLVE_PORT: int = int(os.getenv("NEXSOLVE_PORT", "8001"))
NEXSOLVE_ENV: str = os.getenv("NEXSOLVE_ENV", "production")
NEXSOLVE_LOG_LEVEL: str = os.getenv("NEXSOLVE_LOG_LEVEL", "info")

# =============================================================================
# RESOURCE LIMITS (Configurable via environment variables with safe defaults)
# =============================================================================

# Maximum file size for uploaded PCAP/PCAPNG (default: 1 GiB = 1,073,741,824 bytes)
MAX_PCAP_UPLOAD_BYTES: int = int(os.getenv("NEXSOLVE_MAX_UPLOAD_BYTES", 1024 * 1024 * 1024))
MAX_UPLOAD_BYTES: int = MAX_PCAP_UPLOAD_BYTES
MAX_PCAP_UPLOAD_SIZE: str = "1 GiB"

# Maximum packets processed per single capture to prevent memory exhaustion (default: 100,000)
MAX_PACKETS: int = int(os.getenv("NEXSOLVE_MAX_PACKETS", 100_000))

# Maximum flows reconstructed per capture (default: 20,000)
MAX_FLOWS: int = int(os.getenv("NEXSOLVE_MAX_FLOWS", 20_000))

# Maximum temporal windows generated per capture (default: 500)
MAX_TEMPORAL_WINDOWS: int = int(os.getenv("NEXSOLVE_MAX_TEMPORAL_WINDOWS", 500))

# Maximum time allowed for processing a single capture (seconds, default: 120s)
MAX_PROCESSING_DURATION_SECONDS: float = float(os.getenv("NEXSOLVE_MAX_PROCESSING_SECONDS", 120.0))

# Maximum number of concurrent async processing jobs (default: 4)
MAX_CONCURRENT_JOBS: int = int(os.getenv("NEXSOLVE_MAX_CONCURRENT_JOBS", 4))

# Maximum report size in bytes (default: 10 MB)
MAX_REPORT_SIZE_BYTES: int = int(os.getenv("NEXSOLVE_MAX_REPORT_SIZE_BYTES", 10 * 1024 * 1024))

# Maximum lookback sequence length for forecasting
MAX_LOOKBACK_WINDOWS: int = int(os.getenv("NEXSOLVE_MAX_LOOKBACK_WINDOWS", 256))

# Allowed capture extensions (strict allowlist)
ALLOWED_EXTENSIONS: tuple[str, ...] = (".pcap", ".pcapng")

# Supported PCAP / PCAPNG magic numbers (first 4 bytes)
PCAP_MAGICS: tuple[bytes, ...] = (
    bytes.fromhex("0a0d0d0a"),  # PCAP-NG
    bytes.fromhex("d4c3b2a1"),  # PCAP microsecond (little-endian)
    bytes.fromhex("a1b2c3d4"),  # PCAP microsecond (big-endian)
    bytes.fromhex("4d3cb2a1"),  # PCAP nanosecond (little-endian)
    bytes.fromhex("a1b23c4d"),  # PCAP nanosecond (big-endian)
)


# =============================================================================
# RESOURCE LIMIT EXCEPTION
# =============================================================================

@dataclass
class ResourceLimitDetails:
    status: str = "RESOURCE_LIMIT_EXCEEDED"
    resource: str = ""
    observed: int | float = 0
    limit: int | float = 0
    recoverable: bool = False
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "resource": self.resource,
            "observed": self.observed,
            "limit": self.limit,
            "recoverable": self.recoverable,
            "explanation": self.explanation,
        }


class ResourceLimitExceededError(Exception):
    """Raised when an operation exceeds pre-configured safety resource bounds."""

    def __init__(
        self,
        resource: str,
        observed: int | float,
        limit: int | float,
        explanation: str,
        recoverable: bool = False,
    ):
        self.details = ResourceLimitDetails(
            status="RESOURCE_LIMIT_EXCEEDED",
            resource=resource,
            observed=observed,
            limit=limit,
            recoverable=recoverable,
            explanation=explanation,
        )
        super().__init__(explanation)

    @property
    def resource(self) -> str:
        return self.details.resource

    @property
    def observed(self) -> int | float:
        return self.details.observed

    @property
    def limit(self) -> int | float:
        return self.details.limit

    @property
    def recoverable(self) -> bool:
        return self.details.recoverable

    @property
    def explanation(self) -> str:
        return self.details.explanation

    def to_dict(self) -> dict[str, Any]:
        return self.details.to_dict()


# =============================================================================
# SECURITY SANITIZATION UTILITIES
# =============================================================================

_SAFE_FILENAME_PATTERN = re.compile(r"[^a-zA-Z0-9_.-]")


def sanitize_filename(filename: str | None, default_stem: str = "capture") -> str:
    """Sanitize client-provided filename to prevent path traversal and injection.
    
    - Extracts the pure filename component (stripping directory parts).
    - Removes null bytes and forbidden path traversal sequences.
    - Filters to alphanumeric, dash, dot, and underscore characters.
    - Limits total length to 128 characters.
    - Validates that extension is within ALLOWED_EXTENSIONS.
    """
    if not filename:
        return f"{default_stem}.pcap"

    # Strip directory components regardless of OS separators
    base_name = Path(filename).name
    # Strip null bytes and control chars
    base_name = base_name.replace("\x00", "").strip()

    # Split suffix
    dot_index = base_name.rfind(".")
    if dot_index == -1:
        suffix = ".pcap"
        stem = base_name
    else:
        suffix = base_name[dot_index:].lower()
        stem = base_name[:dot_index]

    if suffix not in ALLOWED_EXTENSIONS:
        # Default to .pcap if invalid extension
        suffix = ".pcap"

    # Sanitize stem
    clean_stem = _SAFE_FILENAME_PATTERN.sub("_", stem).strip("._-")
    if not clean_stem:
        clean_stem = default_stem

    # Limit stem length
    if len(clean_stem) > 100:
        clean_stem = clean_stem[:100]

    return f"{clean_stem}{suffix}"


def sanitize_error_message(message: str) -> str:
    """Remove absolute local filesystem paths from error messages before client response."""
    # Pattern to match Windows paths (e.g. C:\Users\... or C:/Users/...)
    message = re.sub(r"[a-zA-Z]:[/\\](?:[^/\\:\*\?\"<>|\r\n]+[/\\])*[^/\\:\*\?\"<>|\r\n]*", "[REDACTED_PATH]", message)
    # Pattern to match Unix-style absolute paths (e.g. /home/... or /tmp/...)
    message = re.sub(r"(?:/[a-zA-Z0-9_.-]+){2,}", "[REDACTED_PATH]", message)
    return message


# Standardized, user-facing error dictionary
ERROR_DESCRIPTIONS: dict[str, str] = {
    "INVALID_PCAP": "The capture file format is unsupported or empty.",
    "INVALID_PCAP_MAGIC": "The file does not contain a valid PCAP or PCAP-NG magic byte signature.",
    "MALFORMED_CAPTURE": "The packet data contains corrupted frame headers or unparseable timestamps.",
    "RESOURCE_LIMIT_EXCEEDED": "The capture size or complexity exceeds pre-configured safety execution bounds.",
    "CONCURRENT_JOB_LIMIT_EXCEEDED": "System capacity limit reached. Too many captures are being processed concurrently.",
    "PROCESSING_TIMEOUT": "Capture processing exceeded maximum allowed duration.",
    "INSUFFICIENT_HISTORY": "Lookback sequence contains insufficient contiguous temporal windows for forecasting.",
    "GAPPED_HISTORY": "Temporal observation history contains significant timestamp discontinuities.",
    "MISSING_FEATURES": "Network state does not supply the feature semantics required by the model contract.",
    "FORECAST_UNAVAILABLE": "Forecasting was withheld by the epistemic safety gate due to data or uncertainty limitations.",
    "UNKNOWN_BEHAVIOR": "Observed traffic falls outside supported feature distributions (out-of-distribution anomaly).",
}


def get_user_friendly_error(code: str, fallback: str = "An unexpected error occurred.") -> str:
    """Return user-safe description for an error code without technical internals."""
    return ERROR_DESCRIPTIONS.get(code, sanitize_error_message(fallback))

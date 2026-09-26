"""NexSolve CLI structured error hierarchy with actionable remedies."""
from __future__ import annotations

from typing import Any


class NexSolveError(Exception):
    """Base error for all NexSolve CLI exceptions."""

    def __init__(self, message: str, remedy: str = "", exit_code: int = 1) -> None:
        super().__init__(message)
        self.message = message
        self.remedy = remedy
        self.exit_code = exit_code

    def __str__(self) -> str:
        return self.message


class ValidationError(NexSolveError):
    """Raised when local input file validation fails before submission."""

    def __init__(self, message: str, remedy: str = "") -> None:
        default_remedy = remedy or "Verify that the file path is correct, readable, and is a valid .pcap or .pcapng network capture."
        super().__init__(message=message, remedy=default_remedy, exit_code=2)


class ServerConnectionError(NexSolveError):
    """Raised when the CLI cannot connect to the NexSolve API server."""

    def __init__(self, message: str, remedy: str = "", reason: str = "", next_step: str = "") -> None:
        self.reason = reason
        self.next_step = next_step
        default_remedy = remedy or "Verify the NexSolve backend is running (e.g. via ./start_backend.ps1) and reachable at the configured --server URL."
        super().__init__(message=message, remedy=default_remedy, exit_code=3)


class EngineStartupError(NexSolveError):
    """Raised when the local analysis engine cannot be started automatically."""

    def __init__(self, reason: str = "", next_step: str = "", message: str = "Analysis engine could not be started.") -> None:
        self.reason = reason
        self.next_step = next_step
        remedy = f"Reason:\n  {reason}\n\nPossible next step:\n  {next_step}" if reason else (next_step or "")
        super().__init__(message=message, remedy=remedy, exit_code=3)


class AuthenticationError(NexSolveError):
    """Raised when API credentials or tokens are rejected (HTTP 401/403)."""

    def __init__(self, message: str, remedy: str = "") -> None:
        default_remedy = remedy or "Provide a valid API key using --api-key or set the NEXSOLVE_API_KEY environment variable."
        super().__init__(message=message, remedy=default_remedy, exit_code=4)


class UploadError(NexSolveError):
    """Raised when file upload fails during transmission or server validation."""

    def __init__(self, message: str, remedy: str = "") -> None:
        default_remedy = remedy or "Check network connectivity and ensure the capture does not exceed size limits."
        super().__init__(message=message, remedy=default_remedy, exit_code=5)


class JobError(NexSolveError):
    """Raised when server-side job processing fails."""

    def __init__(self, message: str, job_id: str = "", error_details: dict[str, Any] | None = None, remedy: str = "") -> None:
        self.job_id = job_id
        self.error_details = error_details or {}
        default_remedy = remedy or "Check the backend service logs or re-run with a different PCAP capture file."
        super().__init__(message=message, remedy=default_remedy, exit_code=6)


class ResourceLimitError(JobError):
    """Raised when analysis exceeds safety bounds (packet count, flow count, timeout)."""

    def __init__(self, message: str, job_id: str = "", error_details: dict[str, Any] | None = None, remedy: str = "") -> None:
        default_remedy = remedy or (
            "The capture file exceeds safety limits (max 100,000 packets or 20,000 flows). "
            "Filter the capture using Wireshark or tcpdump to create a focused slice."
        )
        super().__init__(message=message, job_id=job_id, error_details=error_details, remedy=default_remedy)
        self.exit_code = 7


class JobTimeoutError(NexSolveError):
    """Raised when job polling exceeds the specified timeout."""

    def __init__(self, message: str, job_id: str = "", remedy: str = "") -> None:
        self.job_id = job_id
        default_remedy = remedy or f"The job is still processing on the server. Increase --timeout or check status later using: nexsolve status {job_id}"
        super().__init__(message=message, remedy=default_remedy, exit_code=8)


class NotFoundError(NexSolveError):
    """Raised when an analysis ID or report cannot be found (HTTP 404)."""

    def __init__(self, message: str, remedy: str = "") -> None:
        default_remedy = remedy or "Verify that the analysis/job ID was typed correctly and that the job has not expired."
        super().__init__(message=message, remedy=default_remedy, exit_code=9)


class CancelledError(NexSolveError):
    """Raised when analysis is cancelled by the user via SIGINT (Ctrl+C)."""

    def __init__(self, message: str = "Analysis cancelled by user.", job_id: str = "") -> None:
        self.job_id = job_id
        super().__init__(message=message, remedy="You can check or resume monitoring with: nexsolve status <job_id>", exit_code=130)

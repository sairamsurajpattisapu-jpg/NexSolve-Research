"""Zero-dependency HTTP API client for the NexSolve platform."""
from __future__ import annotations

import io
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

from nexsolve.config import (
    ALLOWED_EXTENSIONS,
    DEFAULT_API_URL,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_TIMEOUT,
    MAX_UPLOAD_BYTES,
    PCAP_MAGICS,
)
from nexsolve.errors import (
    AuthenticationError,
    JobError,
    JobTimeoutError,
    NotFoundError,
    ResourceLimitError,
    ServerConnectionError,
    UploadError,
    ValidationError,
)
from nexsolve.client.models import JobStatus


class StreamingMultipartReader(io.RawIOBase):
    """Memory-efficient streaming composite reader for multipart/form-data upload.
    
    Streams header bytes, raw file bytes from disk in chunks, and footer bytes
    without buffering the entire PCAP payload into memory.
    """

    def __init__(self, header: bytes, file_path: Path, footer: bytes) -> None:
        super().__init__()
        self._header = io.BytesIO(header)
        self._file = open(file_path, "rb")
        self._footer = io.BytesIO(footer)
        self._total_size = len(header) + file_path.stat().st_size + len(footer)
        self._bytes_read = 0

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            buf = bytearray()
            while chunk := self.read(65536):
                buf.extend(chunk)
            return bytes(buf)

        buf = bytearray()
        while len(buf) < size:
            needed = size - len(buf)
            data = self._header.read(needed)
            if data:
                buf.extend(data)
                continue
            data = self._file.read(needed)
            if data:
                buf.extend(data)
                continue
            data = self._footer.read(needed)
            if data:
                buf.extend(data)
                continue
            break

        self._bytes_read += len(buf)
        return bytes(buf)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def close(self) -> None:
        try:
            self._file.close()
        finally:
            super().close()

    def __len__(self) -> int:
        return self._total_size


class NexSolveClient:
    """Production client for interacting with the NexSolve backend service."""

    def __init__(
        self,
        base_url: str = DEFAULT_API_URL,
        api_key: str = "",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self, additional: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "NexSolve-CLI/1.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if additional:
            headers.update(additional)
        return headers

    def check_health(self) -> dict[str, Any]:
        """Verify service connectivity and readiness."""
        url = f"{self.base_url}/health"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                raw = resp.read()
                try:
                    return json.loads(raw.decode("utf-8"))
                except (json.JSONDecodeError, ValueError) as json_err:
                    raise ServerConnectionError(
                        f"Server returned invalid JSON on /health: {raw[:100]!r}",
                        remedy=f"Verify backend service is running and healthy at {self.base_url}.",
                    ) from json_err
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthenticationError(f"Authentication failed (HTTP {exc.code})") from exc
            raise ServerConnectionError(
                f"NexSolve health check failed: HTTP {exc.code} {exc.reason}",
                remedy=f"Verify backend service is running and healthy at {self.base_url}.",
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ServerConnectionError(
                f"Cannot connect to NexSolve API at {self.base_url}",
                remedy=f"Ensure backend is running (e.g. via ./start_backend.ps1 or docker-compose) and listening at {self.base_url}.",
            ) from exc

    def validate_local_pcap(self, path: Path | str) -> dict[str, Any]:
        """Perform strict pre-flight validation on local PCAP before upload."""
        target_path = Path(path)
        if not target_path.exists():
            raise ValidationError(
                f"Capture file not found: {target_path}",
                remedy="Check the file path and verify that the file exists.",
            )
        if not target_path.is_file():
            raise ValidationError(
                f"Path is not a regular file: {target_path}",
                remedy="Provide a path to a regular .pcap or .pcapng capture file.",
            )

        suffix = target_path.suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            raise ValidationError(
                f"Unsupported capture extension '{suffix}'",
                remedy="NexSolve requires .pcap or .pcapng network capture files.",
            )

        file_size = target_path.stat().st_size
        if file_size == 0:
            raise ValidationError(
                f"Capture file is empty (0 bytes): {target_path.name}",
                remedy="Provide a valid, non-empty network capture containing packets.",
            )
        if file_size > MAX_UPLOAD_BYTES:
            raise ValidationError(
                f"Capture exceeds maximum allowed upload size (1 GiB): {file_size:,} bytes",
                remedy="Capture size exceeds 1 GiB. Slice the capture into smaller time windows using tcpdump or editcap.",
            )

        try:
            with open(target_path, "rb") as f:
                magic = f.read(4)
        except OSError as exc:
            raise ValidationError(
                f"Cannot read capture file: {exc}",
                remedy="Verify file permissions and that the file is not locked by another process.",
            ) from exc

        if magic not in PCAP_MAGICS:
            raise ValidationError(
                f"File '{target_path.name}' is not a valid PCAP/PCAPNG capture (invalid magic header: {magic.hex()})",
                remedy="Ensure the file was generated by Wireshark, tcpdump, or equivalent network capture tools.",
            )

        return {
            "path": target_path,
            "filename": target_path.name,
            "size_bytes": file_size,
            "format": suffix[1:],
            "magic": magic.hex(),
        }

    def upload_pcap(self, pcap_path: Path | str) -> JobStatus:
        """Stream capture file to /jobs endpoint as multipart/form-data."""
        meta = self.validate_local_pcap(pcap_path)
        path = meta["path"]
        filename = meta["filename"]

        boundary = f"----NexSolveBoundary{uuid.uuid4().hex}"
        header = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/vnd.tcpdump.pcap\r\n\r\n"
        ).encode("utf-8")
        footer = f"\r\n--{boundary}--\r\n".encode("utf-8")

        reader = StreamingMultipartReader(header, path, footer)
        url = f"{self.base_url}/jobs"
        req = urllib.request.Request(
            url,
            data=reader,
            headers=self._headers({
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(reader)),
            }),
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_bytes = resp.read()
                try:
                    data = json.loads(raw_bytes.decode("utf-8"))
                except (json.JSONDecodeError, ValueError) as json_err:
                    raise ServerConnectionError(
                        f"Server returned invalid JSON on upload response: {raw_bytes[:100]!r}",
                        remedy="Verify backend server endpoint and version.",
                    ) from json_err
                return JobStatus.from_dict(data)
        except urllib.error.HTTPError as exc:
            reader.close()
            error_body = exc.read().decode("utf-8", errors="replace")
            parsed_err = None
            try:
                parsed_err = json.loads(error_body)
            except Exception:
                pass

            msg = parsed_err.get("detail") if parsed_err and isinstance(parsed_err, dict) else error_body
            if exc.code == 400:
                raise ValidationError(
                    f"Upload rejected (Bad Request): {msg}",
                    remedy="Verify the capture file and upload parameters.",
                ) from exc
            if exc.code == 413:
                raise UploadError(
                    f"Upload rejected: capture exceeds server upload limit ({msg})",
                    remedy="Slice the capture into smaller intervals under 1 GiB.",
                ) from exc
            if exc.code == 415:
                raise UploadError(
                    f"Upload rejected: unsupported file type ({msg})",
                    remedy="Only .pcap and .pcapng files are supported.",
                ) from exc
            if exc.code == 422:
                raise UploadError(
                    f"Upload rejected: invalid or corrupted capture ({msg})",
                    remedy="Verify capture integrity using wireshark or capinfos.",
                ) from exc
            if exc.code in (401, 403):
                raise AuthenticationError(f"Upload unauthorized (HTTP {exc.code})") from exc
            if exc.code == 500:
                raise ServerConnectionError(
                    f"Server internal error during upload (HTTP 500): {msg}",
                    remedy="Check backend service logs.",
                ) from exc
            raise UploadError(f"Server returned HTTP {exc.code} during upload: {msg}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reader.close()
            raise ServerConnectionError(
                f"Connection failed during PCAP upload to {url}: {exc}",
                remedy=f"Verify network connectivity and that {self.base_url} is reachable.",
            ) from exc
        finally:
            reader.close()

    def get_job_status(self, job_id: str) -> JobStatus:
        """Poll the current processing status for a job."""
        url = f"{self.base_url}/jobs/{job_id}"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_bytes = resp.read()
                try:
                    data = json.loads(raw_bytes.decode("utf-8"))
                except (json.JSONDecodeError, ValueError) as json_err:
                    raise ServerConnectionError(
                        f"Server returned invalid JSON for job {job_id}: {raw_bytes[:100]!r}",
                        remedy="Check server health and endpoint validity.",
                    ) from json_err
                return JobStatus.from_dict(data)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NotFoundError(
                    f"Job not found: {job_id}",
                    remedy="Verify that the job ID is correct and has not expired.",
                ) from exc
            if exc.code in (401, 403):
                raise AuthenticationError(f"Unauthorized (HTTP {exc.code})") from exc
            if exc.code == 400:
                raise ValidationError(
                    f"Bad Request querying job status (HTTP 400): {job_id}",
                    remedy="Verify job ID format.",
                ) from exc
            if exc.code == 500:
                raise ServerConnectionError(
                    f"Server error querying job {job_id} (HTTP 500)",
                    remedy="Check backend service logs.",
                ) from exc
            raise ServerConnectionError(f"Failed to query job status (HTTP {exc.code})") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ServerConnectionError(f"Connection lost while polling job {job_id}: {exc}") from exc

    def poll_job(
        self,
        job_id: str,
        timeout: float = DEFAULT_TIMEOUT,
        interval: float = DEFAULT_POLL_INTERVAL,
        on_progress: Callable[[JobStatus], None] | None = None,
    ) -> JobStatus:
        """Poll job until completion, failure, or timeout with truthful progress updates."""
        start_time = time.monotonic()
        retry_count = 0
        max_transient_retries = 3

        while True:
            elapsed = time.monotonic() - start_time
            if elapsed > timeout:
                raise JobTimeoutError(
                    f"Analysis exceeded timeout limit ({timeout:.0f}s).",
                    job_id=job_id,
                )

            try:
                status = self.get_job_status(job_id)
                retry_count = 0  # reset on successful poll
            except ServerConnectionError as exc:
                retry_count += 1
                if retry_count > max_transient_retries:
                    raise exc
                time.sleep(interval)
                continue

            if on_progress:
                on_progress(status)

            if status.is_complete:
                return status

            if status.is_resource_limit_exceeded:
                err_dict = status.error or {}
                explanation = err_dict.get("explanation") or f"Resource limit exceeded on {err_dict.get('resource', 'processing')}."
                raise ResourceLimitError(explanation, job_id=job_id, error_details=err_dict)

            if status.is_failed:
                err_dict = status.error or {}
                msg = err_dict.get("message") or err_dict.get("detail") or "Analysis pipeline failed on server."
                raise JobError(msg, job_id=job_id, error_details=err_dict)

            time.sleep(interval)

    def get_job_result(self, job_id: str) -> dict[str, Any]:
        """Fetch completed analysis result payload."""
        url = f"{self.base_url}/jobs/{job_id}/result"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_bytes = resp.read()
                try:
                    return json.loads(raw_bytes.decode("utf-8"))
                except (json.JSONDecodeError, ValueError) as json_err:
                    raise ServerConnectionError(
                        f"Server returned invalid JSON for job result {job_id}: {raw_bytes[:100]!r}",
                        remedy="Check server health and endpoint validity.",
                    ) from json_err
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NotFoundError(f"Analysis result not found for job: {job_id}") from exc
            if exc.code in (401, 403):
                raise AuthenticationError(f"Unauthorized (HTTP {exc.code})") from exc
            if exc.code == 400:
                raise ValidationError(f"Invalid request for job result (HTTP 400): {job_id}") from exc
            if exc.code == 409:
                raise JobError(f"Analysis is still processing for job: {job_id}") from exc
            if exc.code == 422:
                body = exc.read().decode("utf-8", errors="replace")
                raise JobError(f"Job terminated with failure: {body}", job_id=job_id) from exc
            if exc.code == 500:
                raise ServerConnectionError(f"Server error generating result for job {job_id} (HTTP 500)") from exc
            raise ServerConnectionError(f"Failed to fetch job result (HTTP {exc.code})") from exc

    get_results = get_job_result

    def get_report_json(self, job_id: str) -> str:
        """Download structured JSON report."""
        url = f"{self.base_url}/jobs/{job_id}/report.json"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NotFoundError(f"Report not found for job: {job_id}") from exc
            if exc.code in (401, 403):
                raise AuthenticationError(f"Unauthorized (HTTP {exc.code})") from exc
            if exc.code == 500:
                raise ServerConnectionError(f"Server error generating JSON report (HTTP 500)") from exc
            raise ServerConnectionError(f"Failed to download JSON report (HTTP {exc.code})") from exc

    def get_report_html(self, job_id: str) -> str:
        """Download standalone printable HTML report."""
        url = f"{self.base_url}/jobs/{job_id}/report.html"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NotFoundError(f"HTML report not found for job: {job_id}") from exc
            if exc.code in (401, 403):
                raise AuthenticationError(f"Unauthorized (HTTP {exc.code})") from exc
            if exc.code == 500:
                raise ServerConnectionError(f"Server error generating HTML report (HTTP 500)") from exc
            raise ServerConnectionError(f"Failed to download HTML report (HTTP {exc.code})") from exc

    def cancel_job(self, job_id: str) -> bool:
        """Request cancellation of an active processing job."""
        url = f"{self.base_url}/api/jobs/{job_id}"
        req = urllib.request.Request(url, headers=self._headers(), method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status == 204
        except Exception:
            return False

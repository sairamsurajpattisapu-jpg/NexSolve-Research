# NexSolve Production Security & Resource Safety Specification

**Status**: PRODUCTION SPECIFICATION  
**Modules**: `nexsolve_core/config.py`, `model_service/jobs.py`, `model_service/pcap_upload.py`  
**Endpoints**: `POST /jobs`, `POST /api/pcap/analyze`, `GET /jobs/{job_id}/*`  
**SIH Problem Statement**: SIH26153 — AI based Network Attack Forecasting from Network Traffic Data  

---

## 1. Threat Model & Security Boundaries

Operating a network forensic and attack forecasting platform requires handling potentially hostile, malformed, or weaponized network telemetry. The NexSolve API is hardened against arbitrary file execution, denial of service (DoS), path traversal, parser exploitation, and sensitive data leakage.

### Core Security Principles
1. **Zero Client Trust**: Filenames, MIME types, extensions, and headers supplied by HTTP clients are treated as untrusted user input.
2. **Double Verification**: File extension allowlisting is backed by deep magic byte inspection.
3. **Fail-Closed Processing**: Any parser anomaly or resource boundary trip terminates processing gracefully with a structured diagnostic error without exposing internal stack traces or filesystem paths.
4. **Isolated Transient Runtime**: Uploaded captures are processed in ephemeral, dynamically created temporary sandboxes guaranteed to be unlinked in `finally` blocks.
5. **No Local Path Leakage**: All absolute filesystem paths (e.g. `C:\Users\...` or `/home/...`) are sanitized and redacted prior to client serialization.

---

## 2. Input Validation & File Handling

### 2.1 Extension and Magic Number Verification
* **Allowlist**: Only `.pcap` and `.pcapng` extensions are accepted (`ALLOWED_EXTENSIONS`).
* **Magic Header Verification (`PCAP_MAGICS`)**:
  * `0a 0d 0d 0a`: PCAP-NG block header.
  * `d4 c3 b2 a1`: Classic PCAP microsecond (little-endian).
  * `a1 b2 c3 d4`: Classic PCAP microsecond (big-endian).
  * `4d 3c b2 a1`: Classic PCAP nanosecond (little-endian).
  * `a1 b2 3c 4d`: Classic PCAP nanosecond (big-endian).
* Uploads failing header checks are rejected with HTTP 422 (`The file could not be parsed as a supported PCAP/PCAPNG capture.`).

### 2.2 Filename Sanitization & Traversal Prevention
Client filenames are passed through `sanitize_filename()`:
* Directory traversal sequences (`..`, `/`, `\`) are stripped.
* Null bytes (`\x00`) and control characters are removed.
* Non-alphanumeric characters (outside `_`, `-`, `.`) are substituted.
* File stem is constrained to a maximum of 100 characters.

---

## 3. Resource Safety & Boundary Limits

To prevent memory exhaustion and CPU starvations during live demonstrations or local deployments, central limits are enforced across every processing stage:

| Resource Parameter | Default Limit | Environment Variable | Action on Breach |
| :--- | :---: | :--- | :--- |
| **Max Upload Bytes** | `64 MB` | `NEXSOLVE_MAX_UPLOAD_BYTES` | HTTP 413 Upload Limit Exceeded |
| **Max Packets** | `100,000` | `NEXSOLVE_MAX_PACKETS` | Job status: `RESOURCE_LIMIT_EXCEEDED` |
| **Max Flows** | `20,000` | `NEXSOLVE_MAX_FLOWS` | Job status: `RESOURCE_LIMIT_EXCEEDED` |
| **Max Temporal Windows** | `500` | `NEXSOLVE_MAX_TEMPORAL_WINDOWS` | Job status: `RESOURCE_LIMIT_EXCEEDED` |
| **Max Processing Duration** | `120.0s` | `NEXSOLVE_MAX_PROCESSING_SECONDS` | Job status: `RESOURCE_LIMIT_EXCEEDED` |
| **Max Concurrent Jobs** | `4` | `NEXSOLVE_MAX_CONCURRENT_JOBS` | Queue worker pool throttling |
| **Max Report Size** | `10 MB` | `NEXSOLVE_MAX_REPORT_SIZE_BYTES` | Serializer boundary enforcement |

### 3.1 Structured Limit Exceeded Response
When a boundary is reached, NexSolve does **not** silently truncate data and pretend processing was successful. It returns a structured `RESOURCE_LIMIT_EXCEEDED` contract:

```json
{
  "status": "RESOURCE_LIMIT_EXCEEDED",
  "resource": "packet_count",
  "observed": 142000,
  "limit": 100000,
  "recoverable": false,
  "explanation": "Observed packet count (142,000) exceeds maximum limit of 100,000."
}
```

---

## 4. Sandbox Isolation & Temporary Files

1. Every uploaded capture is allocated a dedicated directory under `runtime/nexsolve-job-<id>-<uuid>/`.
2. Processing runs strictly inside this isolated subtree.
3. Upon job completion, abortion, or failure, the entire directory is recursively purged using `shutil.rmtree(..., ignore_errors=True)`.
4. Tests verify that `runtime/` remains clean after job execution.

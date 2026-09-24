# NexSolve CLI Reference & Architecture Manual

**AI-Based Network Attack Forecasting Platform**  
*Smart India Hackathon 2026 · Problem Statement ID: 26153*

---

## 1. Architectural Overview

The NexSolve CLI (`nexsolve`) operates as a lightweight, zero-external-dependency terminal client and orchestration interface for the NexSolve attack forecasting platform.

```text
┌─────────────────────────────────────────────────────────────┐
│                      NexSolve CLI                           │
│   (nexsolve analyze / nexsolve status / nexsolve report)   │
└──────────────────────────────┬──────────────────────────────┘
                               │
            1. Fast local pre-flight validation
            (format, magic bytes, max 1 GiB limit)
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                     NexSolve REST API                       │
│           (FastAPI Uvicorn on http://127.0.0.1:8001)        │
└──────────────────────────────┬──────────────────────────────┘
                               │
            2. Stream multipart/form-data (/jobs)
            3. ThreadPoolExecutor Async Job Pipeline
               - INGESTION (10%)
               - PARSING (25%)
               - FLOW_RECONSTRUCTION (40%)
               - WINDOWING (55%)
               - NETWORK_STATE (70%)
               - FORECAST (80%)
               - EVIDENCE (90%)
               - REPORT (95%)
               - COMPLETE (100%)
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                NexSolve Web Visualization                   │
│   http://localhost:5173/console/forecast/{job_id}           │
└─────────────────────────────────────────────────────────────┘
```

The CLI strictly avoids duplicating the underlying machine learning models, PCAP parsing engines, or feature extraction matrices locally. Instead, it interacts directly with the production backend API via streaming multipart uploads and bounded polling.

---

## 2. Installation & Quick Start

### Python Environment
Ensure Python 3.10+ is available. From the repository root:

```bash
# Editable development install
pip install -e ./cli

# Verify installation
nexsolve --version
nexsolve --help
```

### Direct Monorepo Execution
Without installing into the Python environment, the CLI can also be executed directly:

```bash
python -m nexsolve --help
```

---

## 3. Command Reference

### `nexsolve analyze <pcap_path>`
Submits a `.pcap` or `.pcapng` network capture file to the NexSolve platform, streams truthful stage progression in the terminal, displays an immediate SOC summary upon completion, and presents the clickable URL to visualize the full attack trajectory in the web UI.

```bash
nexsolve analyze <pcap_path> [options]
```

#### Arguments
- `pcap_path`: Path to a valid `.pcap` or `.pcapng` capture file (up to 1 GiB).

#### Options
- `--server <URL>`: Backend API base URL (default: `http://127.0.0.1:8001` or `$NEXSOLVE_API_URL`).
- `--web-url <URL>`: Frontend web console base URL (default: `http://localhost:5173` or `$NEXSOLVE_WEB_URL`).
- `--api-key <KEY>`: Optional bearer token for authenticated endpoints (default: `$NEXSOLVE_API_KEY`).
- `--poll-interval <SEC>`: Polling cadence in seconds (default: `0.5`).
- `--timeout <SEC>`: Maximum wait timeout in seconds (default: `180.0`).
- `--open`: Automatically opens the analysis in the default web browser upon completion.
- `--json`: Outputs the complete analysis payload as JSON to `stdout`.
- `-o, --report-out <PATH>`: Downloads and saves the standalone printable HTML or JSON report to disk.
- `-q, --quiet`: Quiet mode: suppresses promotional banner and intermediate live step logs; prints only the final SOC summary and URLs.
- `--verbose`: Verbose mode: prints detailed diagnostic telemetry and request timings to `stderr`.
- `--no-color`: Disables ANSI terminal coloring.

#### Example Usage
```bash
# Standard analysis with interactive web console link
nexsolve analyze data/test_slices/friday_10windows_slice.pcap

# Analyze and automatically open browser
nexsolve analyze capture.pcap --open

# Download standalone HTML executive report
nexsolve analyze capture.pcap --report-out reports/executive_audit.html

# Headless CI/CD JSON extraction
nexsolve analyze capture.pcap --json > analysis_result.json
```

---

### `nexsolve status <job_id>`
Queries the live status, current processing stage, and packet metrics for an active or completed job.

```bash
nexsolve status <job_id> [options]
```

#### Options
- `--json`: Outputs raw job status record as JSON to `stdout`.
- `-q, --quiet`: Quiet mode: prints minimal single-line status record (`<job_id> <status> <stage> <pct>%`).
- `--verbose`: Verbose mode: prints detailed job metrics and processing statistics.
- `--server <URL>`: API backend URL (default: `http://127.0.0.1:8001`).
- `--api-key <KEY>`: Optional API key.

#### Example Usage
```bash
nexsolve status job-88f7b12080e5
nexsolve status job-88f7b12080e5 -q
nexsolve status job-88f7b12080e5 --json
```

---

### `nexsolve report <job_id>`
Retrieves and downloads the cryptographic forensic report for a completed analysis.

```bash
nexsolve report <job_id> [options]
```

#### Options
- `-o, --output <PATH>`: Destination path to save the report file.
- `--format {html,json}`: Report format (default: `html`).
- `--json`: Outputs raw JSON forensic report directly to `stdout`.
- `-q, --quiet`: Suppress decorative banners; prints only the saved file path or access URLs.
- `--verbose`: Verbose mode: displays retrieval diagnostics to `stderr`.
- `--server <URL>`: API backend URL (default: `http://127.0.0.1:8001`).
- `--api-key <KEY>`: Optional API key.

#### Example Usage
```bash
# View report summary and web links
nexsolve report job-88f7b12080e5

# Download standalone printable HTML report
nexsolve report job-88f7b12080e5 --output reports/audit.html

# Download raw JSON forensic report
nexsolve report job-88f7b12080e5 --output reports/intelligence.json --format json
```

---

### `nexsolve doctor`
Runs comprehensive system diagnostics on the local host environment, Python runtime, machine learning frameworks (`torch`, `fastapi`, `uvicorn`), packet processing libraries (`scapy`, `dpkt`), external security sensors (`zeek`, `suricata`, `tshark`), world model weights, and live backend connectivity.

```bash
nexsolve doctor [--server <URL>] [--json] [--no-color]
```

#### Example Output
```text
=== NEXSOLVE SYSTEM DIAGNOSTICS & DOCTOR ===

1. Host Environment:
   Python:     3.14.3 (C:\Users\saira\...\.venv\Scripts\python.exe)
   OS:         Windows 11 (AMD64)

2. Core Engine Libraries:
   [PASS] torch        v2.14.0+cpu
   [PASS] scapy        v2.7.0
   [PASS] dpkt         v1.9.8
   [PASS] fastapi      v0.141.1
   [PASS] uvicorn      v0.52.4

3. Deep Forensics & External Sensors:
   [OPTIONAL] zeek         Not found in PATH (NexSolve native fallback active)
   [OPTIONAL] suricata     Not found in PATH (NexSolve native fallback active)
   [OPTIONAL] tshark       Not found in PATH (NexSolve native fallback active)

4. Predictive Models & Checkpoints:
   [PASS] World Model: Canonical 46-feature verified
   [PASS] PCAP-Compatible 45-feature Model: Available

5. NexSolve Backend Service (http://127.0.0.1:8001):
   [PASS] Connected (2.4ms) - Model loaded: True

Diagnostic Verdict:
  [OK] NexSolve engine is healthy and operational.
```

---

### `nexsolve compare <job_a> <job_b>`
Performs a comparative evaluation between two analyses to determine threat escalation, forecast divergence, and volumetric shifts. Operates either online via backend job IDs or offline using local exported JSON reports.

```bash
nexsolve compare <job_a> <job_b> [--server <URL>] [--json] [--no-color]
```

#### Example Usage
```bash
# Compare two backend analysis jobs
nexsolve compare job-baseline-001 job-incident-002

# Compare two exported JSON forensic reports offline
nexsolve compare ./reports/baseline.json ./reports/incident.json
```

---

### `nexsolve evidence <job_id>`
Displays the cryptographic capture fingerprint (SHA-256, link type, protocol breakdown), probed hardware/software capabilities, multi-modal evidence fusion (supporting vs. contradictory indicators), MITRE ATT&CK techniques, and entity investigation dossiers.

```bash
nexsolve evidence <job_id> [--server <URL>] [--entity <IP>] [--json] [--no-color]
```

#### Example Usage
```bash
# Inspect all evidence and cryptographic fingerprint
nexsolve evidence job-88f7b12080e5

# Filter investigation dossier to a specific entity
nexsolve evidence job-88f7b12080e5 --entity 192.168.1.100
```

---

### `nexsolve investigate <job_id>`
Provides a 360-degree forensic and predictive state overview for a given analysis:
- Capture identity and integrity metrics
- Current threat posture and risk score
- Attack lifecycle state and separated confidences
- Dynamic attack progression (observed vs inferred vs forecast)
- Multi-horizon forecast schedule (T+1 .. T+5)
- Evidentiary signals (supporting, contradictory, neutral)
- Grounded MITRE ATT&CK techniques and tactics
- Uncertainty calibration and abstention disclosures
- Direct report export links and web console URL

```bash
nexsolve investigate <job_id> [--server <URL>] [--web-url <URL>] [--json] [--no-color]
```

---

### `nexsolve explain <job_id>`
Answers: "Why did NexSolve produce this result?"
Provides transparent, evidence-grounded attribution for analytical decisions:
- Top network feature drivers and zero-baseline safe delta classifications
- Evidentiary corroboration chain (supporting vs contradictory)
- Multi-sensor agreement and independent corroboration level
- Verified MITRE ATT&CK techniques grounded in physical telemetry
- Stage transition reasoning and kinematic validation
- Latent forecast rollout drivers and uncertainty envelopes

```bash
nexsolve explain <job_id> [--server <URL>] [--json] [--no-color]
```

---

### `nexsolve export <job_id>`
Exports professional forensic & predictive intelligence reports into self-contained HTML, Markdown, or JSON formats without broken relative asset paths:

```bash
nexsolve export <job_id> [--format html|json|markdown] [-o <path>] [--server <URL>] [--quiet]
```

---

### `nexsolve progression <job_id>`
Inspects the 15-stage canonical attack progression lifecycle, MITRE ATT&CK techniques, transitions, and timeline validation:

```bash
nexsolve progression <job_id> [--server <URL>] [--json] [--quiet] [--no-color]
```

---

### `nexsolve version`
Displays platform version, CLI version, model architecture, feature schema versions, and runtime environment without exposing sensitive configuration or secrets:

```bash
nexsolve version [--json] [--no-color]
```

---

### `nexsolve forecast <pcap_path>` [Legacy]
Retained for 100% backward compatibility with earlier air-gapped demo scripts. Runs the entire 45-feature extraction and world model rollout locally in-process without requiring a running backend service.

```bash
nexsolve forecast capture.pcap [--horizon 5] [--json] [--report] [-o output.html]
```

---

## 4. Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `NEXSOLVE_API_URL` | NexSolve backend REST API base URL | `http://127.0.0.1:8001` |
| `NEXSOLVE_WEB_URL` | NexSolve Web Console base URL | `http://localhost:5173` |
| `NEXSOLVE_API_KEY` | Optional authorization bearer token | `""` |
| `NEXSOLVE_POLL_INTERVAL` | Status polling interval in seconds | `0.5` |
| `NEXSOLVE_TIMEOUT` | Analysis polling timeout in seconds | `180.0` |
| `NO_COLOR` | Standard flag to disable terminal colors | Unset |

---

## 5. Exit Codes

The CLI returns standard Unix-compliant exit codes for reliable CI/CD automation:

| Code | Meaning | Actionable Resolution |
| :---: | :--- | :--- |
| `0` | Success | Analysis completed and report ready |
| `1` | Unexpected Error | Review error message |
| `2` | Local Validation Error | Verify file exists, is non-empty, and has valid magic bytes |
| `3` | Server Connection Error | Verify backend is running via `./start_backend.ps1` |
| `4` | Authentication Error | Provide valid API key |
| `5` | Upload Error | Ensure capture does not exceed 1 GiB |
| `6` | Server Job Failure | Inspect backend error details |
| `7` | Resource Limit Exceeded | Slice capture under 100k packets / 20k flows |
| `8` | Polling Timeout | Increase `--timeout` |
| `9` | Not Found | Verify job ID |
| `130` | Cancelled by User | Graceful termination on Ctrl+C (SIGINT) |

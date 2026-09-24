# NexSolve CLI

**NexSolve AI Network Attack Forecasting Command-Line Interface**  
*SIH 2026 Problem Statement ID: 26153*

The NexSolve CLI provides SOC analysts, automated ingestion agents, and CI/CD pipelines with direct terminal access to the NexSolve World Model attack forecasting system.

---

## Installation

### Development / Editable Install
From the repository root or `cli/` directory:
```bash
pip install -e ./cli
```

### Direct Execution Without Installation
```bash
python -m nexsolve --help
```

---

## Commands

### 1. `nexsolve analyze`
Submit a raw `.pcap` or `.pcapng` capture to the running NexSolve analysis platform, monitor progress across all 9 deterministic stages, and obtain the interactive web visualization link.

```bash
# Analyze a network capture and display the terminal SOC forecast table
nexsolve analyze data/test_slices/friday_10windows_slice.pcap

# Analyze and automatically open the interactive visualization in your browser
nexsolve analyze capture.pcap --open

# Output completed analysis directly as JSON
nexsolve analyze capture.pcap --json

# Save the printable standalone forensic report to disk
nexsolve analyze capture.pcap --report-out reports/executive_audit.html

# Target a remote or containerized NexSolve server
nexsolve analyze capture.pcap --server http://remote-host:8001 --web-url http://remote-host:5173
```

### 2. `nexsolve status`
Query the real-time processing status, current stage, and elapsed metrics of an active or completed job.

```bash
nexsolve status job-a1b2c3d4e5f6

# Output status as JSON
nexsolve status job-a1b2c3d4e5f6 --json
```

### 3. `nexsolve report`
Retrieve, view, or download the comprehensive forensic report for a completed analysis.

```bash
# View report summary and web access links
nexsolve report job-a1b2c3d4e5f6

# Download standalone HTML report
nexsolve report job-a1b2c3d4e5f6 --output reports/audit_report.html

# Download structured JSON intelligence report
nexsolve report job-a1b2c3d4e5f6 --output reports/forecast.json --format json
```

### 4. `nexsolve forecast` [Legacy]
Analyze PCAP captures locally in-process without an active backend server (for air-gapped terminal analysis and regression test suites).

```bash
nexsolve forecast capture.pcap
```

---

## Configuration & Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `NEXSOLVE_API_URL` | NexSolve FastAPI backend base URL | `http://127.0.0.1:8001` |
| `NEXSOLVE_WEB_URL` | NexSolve Web Console base URL | `http://localhost:5173` |
| `NEXSOLVE_API_KEY` | Optional bearer authentication token | `""` |
| `NEXSOLVE_POLL_INTERVAL` | Status polling frequency in seconds | `0.5` |
| `NEXSOLVE_TIMEOUT` | Maximum wait timeout in seconds | `180.0` |
| `NO_COLOR` | Disable terminal ANSI colors | Unset |

---

## Exit Codes

- `0`: Success
- `1`: Generic / unexpected error
- `2`: Validation error (invalid file, wrong format, file empty)
- `3`: Connection error (backend server unreachable)
- `4`: Authentication error (invalid credentials)
- `5`: Upload error (server rejected payload)
- `6`: Server-side job processing failure
- `7`: Resource limit exceeded (packets > 100,000, flows > 20,000)
- `8`: Polling timeout
- `9`: Not found (job ID not found or expired)
- `130`: Cancelled by user (Ctrl+C)

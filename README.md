# NexSolve

> **AI-Powered Network Attack Forecasting & Early-Warning Platform**  
> **Smart India Hackathon 2026** · Problem Statement ID: **26153**  
> **Title**: "AI based Network Attack Forecasting from Network Traffic Data"  
> **Scientific Model**: Autoregressive LSTM World Model (`45_feature_pcap_compatible`) · 100% Offline Edge Execution

---

## Why NexSolve?

Traditional intrusion detection systems (IDS/IPS, NIDS, and standard ML classifiers) operate in a fundamentally reactive posture:
```
Traditional IDS:  Observe traffic -> Match rule/signature -> Alert on breach (T0) -> Predictive Lead Time = 0s
NexSolve:         Observe traffic -> Model temporal state -> Simulate future -> Forecast attack risk -> Explain WHY
```
When an attack occurs, defending networks need **lead time** to trigger automated egress isolation, rate-limiting, and quarantine policies *during early reconnaissance* before data exfiltration or denial-of-service impacts the perimeter.

NexSolve models the evolving state of a computer network from passive traffic telemetry and predicts the likelihood and progression of malicious activity across future discrete time windows ($T+1$ through $T+5$).

---

## Core Workflow

```
NETWORK TRAFFIC (PCAP/PCAPNG)
        ↓
TEMPORAL NETWORK STATE (45 Passive Features · 60s Windows)
        ↓
FUTURE STATE SIMULATION (Autoregressive LSTM World Model)
        ↓
MULTI-HORIZON ATTACK RISK (Single P(Atk) & Monotonic Cumulative Risk)
        ↓
ATTACK PROGRESSION (Markovian Behavioral Stage Transitions)
        ↓
MITRE BEHAVIORAL INTERPRETATION (T1046, T1071, T1190, T1498)
        ↓
EXPLAINABLE EARLY WARNING (Top Feature Drivers & 0-100 Score)
        ↓
SOC COMMAND CENTER & STANDALONE AUDIT REPORTS (HTML / JSON)
```


```text
+-------------------------------------------------------------------------------+
|                             NEXSOLVE ARCHITECTURE                             |
+-------------------------------------------------------------------------------+
                                        │
                         Raw Capture (.pcap / .pcapng)
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │       STAGE 1: Ingestion & Upload Validation        │
             │   (Magic bytes, size limits, SHA-256 fingerprint)   │
             └──────────────────────────┬──────────────────────────┘
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │            STAGE 2: Safe PCAP Parsing               │
             │    (Scapy streaming, layer validation, sanitizing)  │
             └──────────────────────────┬──────────────────────────┘
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │         STAGE 3: Canonical Flow Reconstruction      │
             │    (5-tuple bidirectional tracking, TCP handshakes) │
             └──────────────────────────┬──────────────────────────┘
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │         STAGE 4: Temporal Window Generation         │
             │     (Strict chronological 60s non-overlapping bins) │
             └──────────────────────────┬──────────────────────────┘
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │       STAGE 5: NetworkState Candidate Extraction    │
             │   (46-feature registry, past-only, zero fabrication)│
             └──────────────────────────┬──────────────────────────┘
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │        STAGE 6: Forecasting & Attack Horizon        │
             │  (Persistence baseline champion, T+1..T+5 rollouts)│
             └──────────────────────────┬──────────────────────────┘
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │         STAGE 7: Evidence Intelligence Engine       │
             │  (Supporting / Contradictory metrics, MITRE mapping)│
             └──────────────────────────┬──────────────────────────┘
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │        STAGE 8: Forensic Reporting & Artifacts      │
             │    (Cryptographic audit trail, standalone HTML)     │
             └──────────────────────────┬──────────────────────────┘
                                        ▼
        ┌───────────────────────────────┴───────────────────────────────┐
        ▼                                                               ▼
FastAPI Async REST API                                     Vite + React 19 SOC Dashboard
(Streaming status, jobs, reports)                          (Timeline, Horizon, Evidence, Demo)
```

---

## 5. 8-Stage Processing Pipeline (Empirical Latencies)

Every capture processed by NexSolve undergoes an 8-stage verifiable transformation. Processing metrics are tracked with microsecond resolution and exposed in the API and UI:

| Stage | Name | Description | Empirical Timing (100 pkts) |
| :---: | :--- | :--- | :---: |
| **1** | **Upload & File Validation** | Validates magic bytes, enforces 64MB cap, verifies packet count, computes SHA-256 | ~21.9 ms |
| **2** | **PCAP Ingestion & Parsing** | Zero-copy packet header extraction, layer dissection (IPv4, IPv6, TCP, UDP, ICMP) | ~30.9 ms |
| **3** | **Flow Reconstruction** | Bidirectional 5-tuple tracking, TCP state machine validation (SYN/ACK/FIN/RST) | ~0.02 ms |
| **4** | **Temporal Windowing** | 60-second time-bin partitioning, timestamp monotonicity & jitter check | < 0.01 ms |
| **5** | **Network State Extraction** | 46-feature group-qualified state extraction using past-only history | ~0.86 ms |
| **6** | **Forecasting Head** | $T+1 \dots T+5$ recursive multi-horizon forecast & attack horizon calculation | ~0.01 ms |
| **7** | **Evidence & Attribution** | Baseline comparison, contradictory indicator analysis, MITRE ATT&CK mapping | ~0.37 ms |
| **8** | **Forensic Report Generation** | Standalone cryptographic HTML & JSON forensic report serialization | ~0.32 ms |
| **Total** | **End-to-End Latency** | **Full ingestion to forensic report generation** | **~32.6 ms** |

---

## 6. Forecasting Methodology & Benchmark Reality

### The Phase 5 Benchmark Reality

NexSolve adheres strictly to scientific honesty. In rigorous temporal evaluations across contiguous time episodes:

1. **The Production Champion**: The **Persistence Baseline** ($Y_{t+k} = Y_t$) remains the strongest, most reliable forecasting model on real contiguous network episodes.
2. **Evaluated ML Candidates**:
   - `Candidate V1` (NumPy Recursive LSTM: 46 inputs, 24 hidden units, seq length 8)
   - `Candidate V2` (Direct Multi-Horizon Logistic Regression with flattened lookback)
3. **Scientific Promotion Decision: `HOLD`**:
   - In cross-episode temporal testing, candidate neural and linear models failed to reliably beat persistence across all 5 forward horizons without exhibiting variance inflation or sensitivity to unseen traffic patterns.
   - Consequently, **Candidate ML models remain gated as research-only**.
   - NexSolve serves the empirical persistence baseline in production while providing candidate projections explicitly tagged as `UNCALIBRATED`.

---

## 7. Attack Horizon Concept & UX

Instead of a binary alert, NexSolve computes an **Attack Horizon**:

- **Horizon Window**: Identifies the precise future time window $[T_{start}, T_{end}]$ during which attack severity will cross defensive thresholds (e.g., $T+1$ through $T+4$).
- **Peak Attack Step**: Forecasts the exact future window where peak malicious volume or disruption will culminate.
- **Estimated Time to Impact (ETI)**: Concrete seconds remaining until defensive thresholds are breached.
- **Horizon Severity**: Categorized as `NONE`, `IMMINENT`, `ACCELERATING`, `SUSTAINED`, or `DECAYING`.
- **Confidence Calibration**: Explicitly marked with an `UNCALIBRATED` indicator to prevent false certainty in SOC operations.

```text
  t0 [Observed]        T+1 (+60s)         T+2 (+120s)        T+3 (+180s)        T+4 (+240s)        T+5 (+300s)
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ Attack: 0.85 │──▶│ Attack: 0.88 │──▶│ Attack: 0.94 │──▶│ Attack: 0.95 │──▶│ Attack: 0.89 │──▶│ Attack: 0.72 │
│ Vol: 12.4k/s │   │ IN HORIZON   │   │ IN HORIZON   │   │ PEAK STEP ★  │   │ IN HORIZON   │   │ OUT OF HORIZ │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

---

## 8. Evidence Intelligence Engine

NexSolve refuses to output ungrounded forecasts. Every prediction is justified through a tripartite evidence chain:

1. **Supporting Evidence**: Measured traffic metrics that corroborate the threat (e.g., *SYN packet ratio observed at 88.4% vs 4.1% baseline, +2056% increase*).
2. **Contradictory Evidence**: Observed metrics that challenge or moderate the attack hypothesis (e.g., *Total byte volume dropped 34% below saturation threshold; zero outbound C2 beaconing detected*). Contradictory evidence directly dampens forecast confidence.
3. **Capture Limitations**: Quality impairments in the capture file that constrain analytical certainty (e.g., *14% packet truncation detected; non-monotonic timestamp jitter observed*).

---

## 9. Unknown Behavior & Novelty Detection

When network traffic exhibits structural anomalies that do not match known attack signatures:

- **Novelty Scoring**: Statistical distance from verified normal baseline state space.
- **Behavior Categorization**: Flagged as `UNKNOWN_BEHAVIOR` or `NOVEL_PATTERN`.
- **Hypothesis Formulation**: Proposes mapped MITRE ATT&CK techniques with an explicit `CONTEXTUAL_HYPOTHESIS` tag, alerting analysts to inspect rather than asserting guaranteed attribution.

---

## 10. Explicit Forecast Abstention (`FORECAST WITHHELD`)

When capture quality is degraded or historical temporal context is insufficient, NexSolve exercises **deliberate safety abstention**:

- **Why Abstain?**: Forecasting without sufficient history ($< 3$ consecutive windows) or on captures with severe packet loss ($> 20\%$) produces dangerous hallucinations.
- **How It Appears**: The system returns `FORECAST_ABSTAINED` / `FORECAST WITHHELD`.
- **Transparency**: The response clearly articulates:
  - **Reason**: Specific condition triggering abstention.
  - **Missing Prerequisites**: Data points required before forecasting can safely resume.
  - **Recommended Action**: Concrete operational guidance for the defender.

---

## 11. Dataset & Evaluation Methodology

### Chronological Splits & Leakage Prevention

- **UNSW-NB15**: Primary temporal benchmark domain. Evaluated strictly as timestamp-contiguous episodes. No random shuffling. Train, validation, and test episodes remain strictly segregated.
- **TON-IoT (`Network_dataset_23`)**: Retained as an independent cross-domain temporal check. Never joined or merged with UNSW.
- **CIC-IDS2017 Audit**: Rejected for temporal attack forecasting because flow CSVs lack event timestamps, preventing verifiable time-series reconstruction. The CIC packet branch is retained strictly as an unlabeled 60-second window baseline artifact.

---

## 12. Scientific Limitations (Honest Disclosure)

1. **No Guaranteed Future Prediction**: Network forecasts represent statistical extrapolations under current trajectory assumptions; adversaries can alter behavior at any time.
2. **Dataset Domain Shift**: Models calibrated on academic captures (UNSW-NB15) experience distribution shift when applied to enterprise production traffic.
3. **Packet Loss Sensitivity**: Severe capture truncation or packet dropping degrades feature fidelity.
4. **Single-Class Validation Bottleneck**: Academic datasets with benign-only validation splits prevent formal Platt scaling or isotonic calibration, requiring explicit `UNCALIBRATED` tagging.

---

## Complete End-to-End Product Workflow

NexSolve provides a unified, continuous analyst workflow from raw ingestion to forensic export:

```text
OPEN NEXSOLVE (http://localhost:5173)
       │
       ▼
LAUNCH CONSOLE (/console/analyze)
       │
       ▼
UPLOAD DATA (.pcap / .pcapng / .csv)
       │
       ▼
ANALYZE & PROCESS (8-Stage Real-Time Execution Tracking)
       │
       ▼
FORECAST (Multi-Horizon Rollout T+1 .. T+5 with Distinct Step vs Cumulative Risk)
       │
       ▼
EXPLAIN (Counterfactual Perturbation Feature Influence & Top Drivers)
       │
       ▼
SHOW ATTACK PROGRESSION (Empirical Markovian Behavioral Stage Transitions)
       │
       ▼
SHOW MITRE INTERPRETATION (Behavioral ATT&CK Discovery & Exploitation Mapping)
       │
       ▼
SHOW EVIDENCE (Supporting vs Contradictory Indicators & Quality Constraints)
       │
       ▼
EXPORT RESULT (Cryptographic JSON Forensic Payload & Standalone HTML Audit Report)
```

---

## Installation & Quick Start

### Prerequisites
- **Python 3.10+** (Tested on Python 3.11 – 3.14) with virtual environment at `.venv`
- **Node.js 18+** and **npm**
- **Windows PowerShell** / **Linux bash**

### 1. One-Command Full Stack Launcher (PowerShell)
```powershell
# In root directory: launches FastAPI backend (8001) and Vite console (5173)
.\start-dev.ps1
```
*(Optionally pass `-BackendOnly` or `-FrontendOnly` to isolate services).*

### 2. Modular Service Startup
```powershell
# Terminal 1 - Backend FastAPI Service (http://127.0.0.1:8001)
.\start_backend.ps1

# Terminal 2 - Frontend Forecast Console (http://localhost:5173)
.\start_frontend.ps1
```

---

## Running Real PCAP & CSV Analysis

1. Open the console at `http://localhost:5173/console/analyze` (or click **Analyze** in the top navigation).
2. Drag and drop any `.pcap`, `.pcapng`, or 60-second windowed `.csv` file (e.g. `data/test_slices/friday_10windows_slice.pcap`).
3. Click **Start Security Forecast Analysis**.
4. The console automatically redirects to `/console/forecast/:jobId` and streams real deterministic processing stages:
   `INGESTION` $\to$ `PARSING` $\to$ `FLOW_RECONSTRUCTION` $\to$ `WINDOWING` $\to$ `NETWORK_STATE` $\to$ `FORECAST` $\to$ `EVIDENCE` $\to$ `REPORT` $\to$ `COMPLETE`.
5. Upon completion, the interactive **Forecast Console** renders:
   - **Primary Visualization**: Observed trajectory ($T_0$) with forward rollout projections ($T+1 \dots T+5$).
   - **Two Distinct Risk Panels**: Point Attack Probability $P(\text{attack at } T+K)$ vs Monotonic Cumulative Future Risk $P(\text{attack } \le T+K)$.
   - **Early Warning Composite**: Score (0–100), lead time, and dynamic onset indicator.
   - **Attacker Progression**: Sequential reconnaissance and exploitation stages with transition probabilities.
   - **Behavioral MITRE ATT&CK Matrix**: Grounded mapping to techniques (e.g. T1046, T1498).
   - **45-Feature Vector Inspection**: [View Full Feature Vector (45-dim)] modal with complete semantic dictionary.
   - **Explainability Drivers**: [View All Features] modal with counterfactual perturbation attribution.
   - **Forensic Export**: Immediate links to download machine-readable JSON and printable HTML forensic reports.

---

## Running Deterministic SIH Demos

For judges, evaluators, and presentation environments:
- **Web UI**: Navigate to `http://localhost:5173/console/demo` (or click **SIH Demo** in the top header). Select any of the 7 pre-computed deterministic scenarios (e.g. *Normal Baseline*, *Early Reconnaissance Signal*, *Sustained Volumetric Attack*, *Contradictory Evidence*, *Forecast Abstained*).
- **Presentation Mode**: Click **Presentation Mode** in the console header for a high-contrast, uncluttered view suitable for projectors and live demonstrations.
- **Terminal E2E Runner**:
  ```bash
  python scripts/run_demo.py
  ```

---

## Command-Line Interface (CLI)

NexSolve includes a unified CLI runner for air-gapped terminal analysis and automated CI/CD pipelines:

```bash
# Analyze PCAP and print SOC terminal forecast table
python -m nexsolve forecast data/test_slices/friday_10windows_slice.pcap

# Export machine-readable JSON intelligence report
python -m nexsolve forecast capture.pcap --json -o reports/forecast.json

# Generate standalone printable HTML security audit report
python -m nexsolve forecast capture.pcap --report -o reports/audit_report.html
```

---

## Deterministic Live Demo Runner

Run the end-to-end user journey in under 5 seconds with zero mock data:

```bash
python scripts/run_demo.py
```
This script executes the entire 16-step user journey:
1. Ingests real 10-window capture (`friday_10windows_slice.pcap`).
2. Reconstructs 283 directional 5-tuple flows across 2,277 packets.
3. Groups telemetry into discrete 60s windows without fabricating `mean_tcp_rtt`.
4. Evaluates 45-feature state vector compatibility.
5. Executes autoregressive LSTM rollout across horizons $T+1 \dots T+5$.
6. Calculates single-step risk and monotonic cumulative exposure.
7. Computes Early Warning Score (0–100) and maps behavioral MITRE techniques.
8. Generates self-contained HTML and JSON reports in `reports/`.

---

## Automated Verification & Test Suite

NexSolve maintains strict test coverage across scientific safety contracts, world model rollouts, and frontend components:

```powershell
# 1. Run Complete Scientific Validation Suite (Contracts, Rollouts, PCAP pipeline)
python scripts/validate_system.py

# 2. Run End-to-End PCAP Demo & CLI Test Suite
pytest tests/test_pcap_demo_pipeline.py -v

# 3. Run Frontend Unit & Integration Tests (15 suites, 65 tests)
cd frontend
npm test -- --run
npm run typecheck
```


---

## 14. Production Deployment Guide

NexSolve is engineered for containerized and bare-metal production environments with zero external black-box cloud dependencies.

### Option A: Docker Compose (Recommended Production Deployment)

Docker Compose provisions an enterprise-grade stack with an isolated network, persistent volume storage, and automated health checks:
- **`postgres`**: PostgreSQL 16 database with health check and persistent volume (`postgres_data`)
- **`backend`**: FastAPI ASGI service with non-root security (`nexsolve` UID 10001), 64 MB upload cap, and 120s timeouts
- **`frontend`**: Nginx Alpine reverse proxy routing `/api/`, `/jobs/`, `/health`, and `/ready` to backend, serving optimized production assets

```bash
# Copy and customize environment variables
cp .env.example .env
cp frontend/.env.example frontend/.env

# Build and start all services in detached mode
docker-compose up --build -d

# Verify service logs
docker-compose logs -f
```

The application is immediately available at:
- **Frontend Dashboard**: `http://localhost:3000` (or configured port)
- **Backend API**: `http://localhost:8001`
- **Readiness Probe**: `http://localhost:8001/ready`

To stop the services gracefully:
```bash
docker-compose down
```

---

### Option B: Bare-Metal Production Deployment (Manual ASGI)

#### 1. Environment Configuration
Copy `.env.example` to `.env` in the repository root:
```bash
cp .env.example .env
```

Key production environment parameters:
| Variable | Production Default | Description |
| :--- | :--- | :--- |
| `NEXSOLVE_HOST` | `0.0.0.0` | Listen host interface |
| `NEXSOLVE_PORT` | `8001` | Service port |
| `NEXSOLVE_ENV` | `production` | Deployment mode (`production` / `development` / `testing`) |
| `NEXSOLVE_LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `DATABASE_URL` | `postgresql://nexsolve:nexsolve_secret@localhost:5432/nexsolve_db` | PostgreSQL connection string (falls back to SQLite if unset) |
| `NEXSOLVE_CORS_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Allowed CORS origins for browser security |
| `NEXSOLVE_MAX_UPLOAD_BYTES`| `67108864` (64 MB) | Hard upload payload ceiling |
| `NEXSOLVE_MAX_PACKETS` | `100000` | Maximum packets analyzed per capture to prevent memory exhaustion |
| `NEXSOLVE_PROCESSING_TIMEOUT_SECONDS` | `120` | Wall-clock timeout per analysis job |

#### 2. Database Setup & Initialization
NexSolve automatically creates its persistence tables on first launch via the application lifespan hook.
To verify or initialize PostgreSQL manually:
```bash
# Create user and database in PostgreSQL:
psql -U postgres -c "CREATE USER nexsolve WITH PASSWORD 'nexsolve_secret';"
psql -U postgres -c "CREATE DATABASE nexsolve_db OWNER nexsolve;"
```
*(If `DATABASE_URL` is omitted, NexSolve operates in verified SQLite persistence mode storing data in `runtime/nexsolve.db` without data loss).*

#### 3. Start Backend ASGI Service
Launch using `uvicorn` with production concurrency settings:
```powershell
uvicorn model_service.app:app --host 0.0.0.0 --port 8001 --workers 2 --proxy-headers
```

#### 4. Build and Serve Production Frontend
Build the optimized static bundle and serve via Nginx or Vite preview:
```powershell
cd frontend
npm install
npm run build
npm run preview -- --host 0.0.0.0 --port 3000
```

---

### Production Health & Readiness Verification

Run standard HTTP probes to verify production readiness:

```bash
# 1. Liveness Probe (verifies HTTP server & model weights loaded)
curl -s http://localhost:8001/health

# Expected response (200 OK):
# {"service_status":"ok","model_loaded":true,"model_version":"nexsolve-v1-persistence-champion",...}

# 2. Readiness Probe (verifies database persistence and pipeline operational)
curl -s http://localhost:8001/ready

# Expected response (200 OK):
# {"status":"ready","service":"nexsolve-backend","database":{"status":"healthy","mode":"database","detail":"connected"}}
```

---

## 15. SIH Demo Mode

NexSolve includes a built-in **Deterministic SIH Demo Suite** designed for judges and evaluators. Accessible directly from the top header navigation or the upload panel:

| Scenario | Mode / Threat | Expected Evaluation Behavior |
| :--- | :--- | :--- |
| **1. Normal Enterprise Traffic** | Benign baseline | Low risk score, stable baseline, no attack horizon predicted |
| **2. Early Attack Signal** | Reconnaissance / Port Scan | Low current attack, horizon forecasts breach starting at $T+2$ |
| **3. Sustained Attack Progression** | Volumetric SYN Flood / DDoS | High current attack, immediate sustained horizon across $T+1 \dots T+5$ |
| **4. Contradictory Evidence** | Volumetric surge with falling drops | High raw score moderated by contradictory indicators; lowered confidence |
| **5. Unknown / Novel Behavior** | Out-of-distribution protocol anomaly | Novelty score elevated; MITRE ATT&CK contextual hypothesis generated |
| **6. Forecast Abstained** | Insufficient history (< 3 windows) | Forecast deliberately withheld with safety abstention explanation |
| **7. Poor Capture Quality** | 42% packet loss / degraded capture | Capture quality flagged as DEGRADED; analytical limitations displayed |

*Note: Demo mode functions seamlessly both online via the FastAPI backend and 100% offline via pre-compiled client fixtures if network connectivity is unavailable.*

---

## 16. API Overview

### Core REST Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Liveness check, model loaded status, and schema feature count |
| `GET` | `/ready` | Readiness probe verifying database persistence and service operational status |
| `POST` | `/api/upload` | Upload `.pcap`/`.pcapng` capture for 8-stage asynchronous analysis |
| `GET` | `/api/jobs/{job_id}` | Poll asynchronous job processing status and stage metrics |
| `GET` | `/api/jobs/{job_id}/results` | Retrieve complete analysis payload (Horizon, Evidence, State) |
| `GET` | `/api/jobs/{job_id}/report.json`| Download structured forensic JSON report |
| `GET` | `/api/jobs/{job_id}/report.html`| Download standalone, self-contained forensic HTML report |
| `GET` | `/api/demo/scenarios` | List all 7 deterministic SIH evaluation scenarios |
| `GET` | `/api/demo/scenarios/{id}` | Retrieve pre-computed analysis payload for a scenario |
| `POST` | `/forecast` | Direct low-level temporal state forecasting endpoint |

---

## 17. Project Structure

```text
NexSolve-Research/
├── ml/                         # ML research, evaluation, and baseline models
│   ├── baseline/               # Persistence, majority, and heuristic models
│   ├── evaluation/             # Contiguous episode cross-horizon evaluators
│   └── models/                 # Model candidate definitions and trainers
├── nexsolve_core/              # Canonical data models, schemas, and state extraction
│   ├── schemas/                # PacketRecord, FlowRecord, TemporalWindow, Quality
│   └── state/                  # 46-feature group-qualified state builder
├── model_service/              # Production FastAPI asynchronous application
│   ├── app.py                  # API endpoints and route definitions
│   ├── jobs.py                 # 8-stage background pipeline processor
│   ├── reports.py              # Standalone forensic JSON/HTML report generator
│   └── pcap_service.py         # Streaming PCAP parser and flow extractor
├── demo/                       # SIH Demo scenarios and CLI runner
│   └── scenarios.py            # 7 deterministic scenario definitions and payloads
├── frontend/                   # Vite + React 19 + TypeScript SOC Dashboard
│   ├── src/components/         # AttackHorizonCard, EvidenceChain, DemoModeSelector
│   ├── src/fixtures/           # Offline demo scenario JSON payloads
│   └── src/pages/              # Dashboard, Threats, Traffic, Reports views
└── reports/                    # Comprehensive research and verification reports
```

---

## 18. License & Attribution

Developed for the **Smart India Hackathon 2026** (Problem Statement 26153).  
All benchmark claims and evaluations are fully reproducible using the commands in `reports/REPRODUCIBILITY.md`.

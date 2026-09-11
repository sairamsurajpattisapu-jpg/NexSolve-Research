# NexSolve: AI-Based Network Attack Forecasting

> **SIH 2026 Problem Statement 26153**: AI-Based Network Attack Forecasting from Network Traffic Data  
> **Repository Type**: Production-Grade Research & Predictive Network Intelligence System  
> **Status**: Production Software Foundation Complete | Scientific Model Baseline: Persistence Champion (`ML Promotion: HOLD`)

---

## 1. What NexSolve Is

**NexSolve** is a predictive network intelligence and forensic analysis platform. Rather than merely detecting intrusions after damage has occurred, NexSolve reconstructs ordered network packet captures into temporal network states and answers a forward-looking question:

> **"Given the network traffic observed up to time $t_0$, what is the attack trajectory and network state likely to look like across future horizons ($t+1$ to $t+5$), how far out is the attack window, and what evidence supports or contradicts this forecast?"**

NexSolve bridges raw packet-level forensic capture (`.pcap` / `.pcapng`) to forward-looking cyber defense, providing SOC analysts and incident responders with deterministic, auditable, and scientifically defensible decision support.

---

## 2. The Problem It Solves

Traditional network defense operates in an inherently reactive paradigm:

1. **Post-Incident Alert Overwhelm**: Intrusion Detection Systems (IDS/IPS) trigger alerts only after malicious payloads, signature matches, or volumetric spikes have already breached the network perimeter.
2. **Zero Temporal Horizon**: Standard security dashboards answer *"What just happened?"* or *"What is happening right now?"*, but fail to inform defenders about the trajectory of the threat over the next 1 to 5 minutes.
3. **Black-Box Hallucinations**: Many proposed AI/ML models output uncalibrated probabilities with no traceable evidence chain, creating analyst distrust and fatal alert fatigue.
4. **Data Leakage in Research**: Academic models often report artificially inflated >99% accuracies by randomly shuffling time-series data or mixing train/test packets from the same temporal flows, collapsing when deployed on continuous, out-of-distribution traffic.

NexSolve addresses SIH PS 26153 by establishing a chronologically strict, leakage-free pipeline that produces verifiable temporal network states, multi-step attack forecasts, explicit attack horizons, bidirectional evidence chains, and strict safety abstention when data quality or history is insufficient.

---

## 3. Why Existing Approaches Fail

| Vector | Traditional IDS / SIEM | Naive Academic ML | NexSolve System |
| :--- | :--- | :--- | :--- |
| **Paradigm** | Reactive / Signature / Retrospective | Unbounded Classification | Predictive Temporal Network Intelligence |
| **Temporal Horizon** | $t_0$ only (Past / Immediate) | Static slice ($t_0$) | Forward rollouts: $t+1$ through $t+5$ |
| **Evidence Basis** | Rule match or anomaly score | Opaque tensor / embedding | Bidirectional (Supporting + Contradictory) |
| **Evaluation** | Synthetic test benches | Random train/test split (Data Leakage) | Contiguous temporal episodes (Zero leakage) |
| **Degraded Data** | Silent misclassification / False alerts | Hallucinated confidence | Explicit Forecast Abstention (`FORECAST WITHHELD`) |
| **Operational Output** | Alert spam | Arbitrary label | Actionable Defender Horizon & Countermeasures |

---

## 4. Architecture

NexSolve decouples live packet forensic extraction, canonical state reconstruction, temporal forecasting, and forensic reporting into an asynchronous, auditable architecture:

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

## 13. How to Run Locally (Quickstart)

Get NexSolve running locally in 3 quick terminal steps:

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- (Optional) PostgreSQL 14+ (SQLite used automatically in test/local development modes)

### Step 1: Install Backend & Dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r model_service/requirements.txt
```

### Step 2: Start the Backend API
```powershell
python -m uvicorn model_service.app:app --host 127.0.0.1 --port 8001
```

### Step 3: Start the Frontend Application
```powershell
cd frontend
npm install
npm run dev
```

Visit **`http://localhost:5173`** in your browser.

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

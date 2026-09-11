# NexSolve — SIH 2026 Final Demo Readiness Report

**Smart India Hackathon 2026 — Problem Statement 26153**  
**Document**: `reports/SIH_FINAL_DEMO_READINESS.md`  
**Date**: September 2026  
**Evaluation Status**: FINAL DEMO READY (VERIFIED ON LIVE STACK)  
**Baseline Model**: Persistence Champion (`candidate_v1` and `candidate_v2` remain on `HOLD` for research)

---

## 1. Executive Demo Status
NexSolve is fully operational, hardened, and verified for live Smart India Hackathon jury evaluations. The system successfully demonstrates the critical paradigm shift from reactive detection ($T_0$) to multi-step predictive intelligence ($T+1 \dots T+5$), backed by bidirectional evidence chains, uncalibrated confidence disclosures, and explicit forecast abstention when evidence is insufficient.

---

## 2. Service & Endpoint Status

| Subsystem | Target Endpoint | HTTP Status | Measured Latency | Operational Health |
| :--- | :--- | :--- | :--- | :--- |
| **Frontend Dashboard** | `http://localhost:5173` | `200 OK` | < 10 ms | Production bundle active; SPA routing verified |
| **Backend API Root** | `http://localhost:8001` | `200 OK` | < 5 ms | FastAPI 1.0.0 ASGI running via Uvicorn |
| **Liveness Probe** | `http://localhost:8001/health` | `200 OK` | < 4 ms | 46 features, $K=5$, model loaded |
| **Readiness Probe** | `http://localhost:8001/ready` | `200 OK` | < 6 ms | Database connected, worker pool ready |
| **Demo Registry** | `http://localhost:8001/api/demo/scenarios` | `200 OK` | < 8 ms | All 7 deterministic scenarios accessible |

---

## 3. Database Persistence Status
- **Active Persistence Mode**: `DATABASE` mode backed by SQLite engine (`runtime/nexsolve.db`), conforming 1:1 with PostgreSQL production models.
- **Health Check**: `check_db_health()` verified `{"status": "HEALTHY", "mode": "DATABASE", "detail": "Database connection verified"}`.
- **Process Restart Persistence**: Verified. Analysis results, JSON reports, and HTML reports for completed jobs persist across complete server process restarts with zero in-memory dependency.

---

## 4. Real PCAP Workflow Status
- **Pipeline Stages**: Ingestion $\to$ Streaming Scapy Parse $\to$ 5-Tuple Flow Reconstruction $\to$ 60s Temporal Windowing $\to$ 46-Feature Extraction $\to$ Persistence Champion 5-Step Forecast ($T+1 \dots T+5$) $\to$ Evidence Chain $\to$ Report Engine.
- **Measured Processing Time**: Under 40 milliseconds for a 30-packet test capture.
- **Safety Boundaries**: Strictly enforces 64 MB upload ceiling, 100,000 packet budget, and 120s timeout.

---

## 5. SIH Demo Scenarios Conformance (7 / 7 Verified)

| Scenario ID | Name & Focus | Attack Horizon State | Evidence Signal | Epistemic Policy | Conformance |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `NORMAL_TRAFFIC` | Benign Baseline | `NO_ATTACK_FORECAST` | Baseline metrics stable | Zero alarms | **PASSED** |
| `EARLY_ATTACK_SIGNAL` | Port Reconnaissance | `EARLY_SIGNAL` (Onset: $T+2$) | Port diversity +64.2% | Lead time: 120s | **PASSED** |
| `SUSTAINED_ATTACK_FORECAST` | SYN Flood / DDoS | `SUSTAINED_ATTACK_FORECAST` | Heavy flow surge +62.8% | Spans $T+1 \dots T+3$ | **PASSED** |
| `CONTRADICTORY_EVIDENCE` | Signal Conflict | `UNCERTAIN_FORECAST` | Volumetric spike vs falling drops | High uncertainty flag | **PASSED** |
| `UNKNOWN_BEHAVIOR` | OOD Protocol Variation | Contextual Hypothesis | Novelty score: 0.84 | Never labeled benign | **PASSED** |
| `FORECAST_ABSTAINED` | Insufficient History | `ABSTAINED` | History length: 2 windows (< 3) | `FORECAST WITHHELD` | **PASSED** |
| `POOR_CAPTURE_QUALITY` | Degraded Telemetry | Quality: `DEGRADED` | 42% loss, 340 malformed pkts | Analytical limitations | **PASSED** |

---

## 6. Attack Horizon & Evidence Chain UI
- **Attack Horizon Card**: Visually displays forward rollout ($T+1 \dots T+5$), onset lead time, horizon depth, and narrative explanation.
- **Evidence Chain Card**: Clearly isolates supporting signals from contradictory signals with exact feature deltas against moving baselines.
- **Forecast Confidence Card**: Explicitly displays `UNCALIBRATED` in amber rather than fabricating fake probability percentages.
- **Abstention Banner**: Emphasizes *"When NexSolve does not have enough evidence, it explicitly abstains rather than hallucinating."*

---

## 7. Report Generation Status
- **Structured JSON Export**: Downloadable at `/jobs/{id}/report.json` with cryptographic SHA-256 capture provenance.
- **Standalone HTML Export**: Downloadable at `/jobs/{id}/report.html` with embedded offline styles, zero external CDNs, and zero local filesystem path leaks.

---

## 8. Security Hardening Status
- **Empty Upload**: Rejected with `HTTP 400 Bad Request`.
- **Malformed PCAP**: Rejected with `HTTP 422 Unprocessable Entity`.
- **Unsupported File Type**: Rejected with `HTTP 415 Unsupported Media Type`.
- **Path Traversal Filename**: Sanitized and rejected with `HTTP 415`.
- **Security Headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`.

---

## 9. Automated Verification Results

| Suite | Tests Executed | Passed | Failed | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Backend Test Suite** (`pytest -q`) | 194 | 194 | 0 | **100% PASSED** |
| **Frontend Vitest Suite** (`npm test -- --run`) | 32 | 32 | 0 | **100% PASSED** |
| **TypeScript Typecheck** (`tsc -b`) | 40 files | 0 errors | 0 | **100% PASSED** |
| **Linter** (`oxlint`) | 40 files | 0 errors | 0 | **100% PASSED** |
| **Frontend Production Build** (`vite build`) | 1,868 modules | Built (615ms) | 0 | **100% PASSED** |
| **Total Automated Tests** | **226** | **226** | **0** | **100% PASSED** |

---

## 10. Recommended Demo Scenario Order for Judges

For a smooth, impactful 5-minute presentation:
1. **Scenario 1 (`NORMAL_TRAFFIC`)**: Establish normal baseline state ($T_0$).
2. **Scenario 2 (`EARLY_ATTACK_SIGNAL`)**: Show early warning at $T+2$ (120s lead time) where traditional IDS fails to alert.
3. **Scenario 4 (`CONTRADICTORY_EVIDENCE`)**: Show epistemic maturity: contradictory signals prevent overconfidence.
4. **Scenario 6 (`FORECAST_ABSTAINED`)**: Show safety: system explicitly refuses to forecast on insufficient data (`FORECAST WITHHELD`).
5. **Live PCAP Upload**: Upload test file to demonstrate sub-second end-to-end processing and report generation.

---

## 11. Known Limitations & Disclosures
1. **Validated Model Baseline**: Persistence Champion is the current verified production baseline; candidate ML models (`candidate_v1`, `candidate_v2`) remain on `HOLD` for research.
2. **Confidence Calibration**: Forecast envelopes are labeled `UNCALIBRATED` due to single-class academic validation splits.
3. **Single-Node Ingestion Scope**: Bounded at 64 MB / 100,000 packets per capture file.

---

## 12. Exact Commands to Start the Demo Stack

### Terminal 1: Backend ASGI Service
```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn model_service.app:app --host 127.0.0.1 --port 8001
```

### Terminal 2: Production Frontend Preview
```powershell
cd frontend
npm run preview -- --host 127.0.0.1 --port 5173
```

**Live Demo URL**: `http://localhost:5173`

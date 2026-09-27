# NexSolve Release Readiness & Operational Deployment Guide

**Version**: 1.0.0-release-candidate  
**Date**: September 27, 2026  
**Status**: RELEASE CANDIDATE READY  
**Classification**: PRODUCTION DEFENSIVE RELEASE & RESEARCH BENCHMARK  

---

## 1. Executive Summary

NexSolve is an AI-based network attack forecasting platform delivering continuous, predictive visibility into network state transitions before attacks escalate into downstream impacts.

This release finalizes the dual-engine architecture:
1. **Production Engine (Authoritative Default)**: The bitwise-frozen, cryptographically verified `final_world_model` v3.0.0. All production inference, CLI operations, reports, and UI dashboards default strictly to this certified model.
2. **Research Engine (`multi_event_v1`)**: The next-generation temporal forecaster trained across 15 real-world attack onset events with 7 independent held-out evaluation events. It is clearly labeled with uncertified research badges and production weights remain completely protected.
3. **Rejected Candidates (`stealth_v1`)**: Permanently blocked at both the Central Forecast Gate and API validation layers due to unacceptable false positive rates (94.37% on benign traffic).

---

## 2. Cryptographic Asset Integrity (Golden Manifest)

All 7 production baseline files in `models/final_world_model/` have been verified bitwise identical against their golden SHA-256 digests. Zero bytes have been modified.

| Production Asset | SHA-256 Golden Digest (Uppercase Hex) | Verification Status |
|:---|:---|:---:|
| `config.json` | `98C55F8685478286264438B07DB7DCA72B3A42F1A41E0A4D26366654379AA1A1` | **MATCH (PASS)** |
| `feature_schema.json` | `2BB8714F2DA49F124C82209488E9DC1ECCFF3CA8F655079404BA7EFB27E4454B` | **MATCH (PASS)** |
| `manifest.json` | `75BEF97F0BE8C7310A9AF89D8F13046C9F7E3A12303A7A55582913996805CBF6` | **MATCH (PASS)** |
| `metadata.json` | `19816E54918779B1226DB88A0EA7319DAB7D831423B7D6A77181915F90A20093` | **MATCH (PASS)** |
| `metrics.json` | `8B2B395728BE2F8FFD80A66A2E120D634B2206CD2ABF2DB5AEC39FC65C4414B9` | **MATCH (PASS)** |
| `model.npz` | `5787B2ABD68B2243F45AE1290E24B2DAA5483E69405660CF3DE824FD8B498ECC` | **MATCH (PASS)** |
| `preprocessing.npz` | `E85D998324D7F45215494CA09D1C9388667F49B7E72D0A1511A1B64B0C72C6B3` | **MATCH (PASS)** |

---

## 3. Architecture & Engine Selection Matrix

All forecasting requests are mediated by the **Authoritative Central Forecast Gate** (`ml/forecasting/central_gate.py`).

```
                              [ Incoming PCAP / Flow Telemetry ]
                                              │
                                              ▼
                             [ Ingestion & Data Quality Gate ]
                               (Strict 1 GiB, PCAP/PCAPNG Magic)
                                              │
                                              ▼
                             [ 45-Feature Extraction & Windowing ]
                                              │
                                              ▼
                             [ Central Forecast Routing Gate ]
                                              │
              ┌───────────────────────────────┴───────────────────────────────┐
              │                                                               │
              ▼                                                               ▼
    [ Production Engine ]                                           [ Research Engine ]
    - final_world_model v3.0.0                                      - multi_event_v1
    - Status: Authoritative Default                                 - Status: Research Candidate
    - Bitwise Frozen npz weights                                    - Temporal GRU (15 events)
    - 45 PCAP Features                                              - Strict Research Notice
              │                                                               │
              └───────────────────────────────┬───────────────────────────────┘
                                              ▼
                                 [ Scientific Abstention Gate ]
                           (History < 8 windows? -> Forecast Withheld)
                                              │
                                              ▼
                                 [ Canonical Presentation ]
                           - Web Console (Dark Cyber-Forensic Theme)
                           - CLI Tooling (nexsolve analyze)
                           - Executive & Technical Forensic Reports
```

### Engine Selection Rules:
1. `production` (Default): Uses frozen World Model v3.0.0. Authoritative baseline with guaranteed calibration and stability.
2. `multi_event` (Research): Evaluates multi-event GRU model. Uncertified research candidate. Displays explicit research banner.
3. `stealth` / `stealth_v1` (REJECTED): Requests raise an explicit `ValueError` and are rejected with HTTP 400.

---

## 4. Scientific Rejection of `stealth_v1`

A targeted ML sprint investigated improving low-rate PortScan precursor sensitivity via topology-adaptive features (`port_novelty_zscore`, `fan_out_ratio`, `connection_dev_zscore`, `dst_growth_rate`, `syn_fan_in`).

### Findings & Rationale:
- **PortScan Sensitivity**: Detection lead time improved to 300s.
- **Catastrophic Generalization Failure**: False Positive Rate (FPR) surged from **4.23% to 94.37%** across benign test windows.
- **False Alarm Ratio**: Generated **335 false positive alerts on 355 benign windows**, causing precision to collapse from **73.08% to 6.69%**.
- **Formal Decision**: Candidate `stealth_v1` was formally and permanently rejected. In accordance with zero-leakage and operational safety invariants, no model that triggers 94% false alarms can be promoted to production or exposed to analysts.

---

## 5. Supported Network Inputs & Quality Boundaries

| Attribute | Specification / Limit | Enforcement Mechanism |
|:---|:---|:---|
| **Capture Formats** | Standard PCAP (`\xd4\xc3\xb2\xa1`), PCAPNG (`\x0a\x0d\x0d\x0a`) | Magic byte validation |
| **Max Upload Size** | 1024 MiB (1 GiB) | Streaming byte counters & chunked lifecycle |
| **Max Packets** | 100,000 packets per single upload | Pre-allocation limits |
| **Max Reconstructed Flows** | 20,000 flows | Flow table memory caps |
| **Temporal Window Size** | 60.0 seconds continuous | Canonical temporal windowing |
| **Minimum History Required** | 8 continuous windows (480 seconds) | Central Forecast Gate abstention rule |
| **Temporal Continuity** | Max allowable inter-window gap: 120s | Time-delta gap detection |

### Abstention & Integrity Guardrails:
When input telemetry fails quality boundaries:
- Captures with < 8 windows trigger `INSUFFICIENT_HISTORY` abstention.
- The static traffic heuristics and network state analysis succeed, but future forecast probabilities are set to `null` and future stages to `UNKNOWN`.
- Placeholder values, fake 0.85 confidence, or default reconnaissance summaries are strictly prohibited and scrubbed.

---

## 6. Verification & Test Suite Summary

All test suites executed with 100% pass rates:

1. **Backend Unit & Regression Suite**:
   - `tests/test_multi_event_forecasting.py`: 7/7 passed
   - `tests/test_forecast_engines.py`: 8/8 passed
   - `tests/test_forecast_abstention.py`: 7/7 passed
   - `tests/test_release_smoke.py`: 6/6 passed
   - `tests/test_security_hardening.py`: 12/12 passed
   - `tests/test_capture_correctness.py`: 6/6 passed
   - `tests/test_strict_1gb_upload_limits.py`: 15/15 passed
   - **Total Backend Tests Verified**: 61/61 passed (100%)

2. **Frontend Test Suite (Vitest)**:
   - 28 test files executed
   - 183 unit and integration tests passed (100%)
   - Zero test failures

3. **Frontend Production Build (`tsc -b && vite build`)**:
   - TypeScript compilation verified clean with zero type errors
   - Production bundle built cleanly (`dist/` generated)

4. **CLI End-to-End Verification**:
   - Verified `nexsolve doctor`: All sensors and backend connectivity verified.
   - Verified `nexsolve analyze` with `--engine production`: Complete SOC rollout, attribution drivers, and HTML report generated.
   - Verified `nexsolve analyze` with `--engine multi_event`: Research engine routing and research notices verified.
   - Verified `nexsolve analyze` with `insufficient_history.pcap`: Abstention behavior cleanly handled with informative output.
   - Verified `nexsolve analyze` with `malformed.pcap`: Rejected with exit code 1 and clean actionable error message.

---

## 7. Known Boundaries & Limitations

1. **PortScan Onset Sensitivity**: The production model and `multi_event_v1` candidate exhibit lower sensitivity on ultra-stealthy single-packet horizontal port scans than on volumetric attacks (DDoS, Botnet, Infiltration). Research models that improved PortScan sensitivity caused unacceptably high false alarm rates and were rejected.
2. **Temporal History Invariant**: Forecasters require at least 8 continuous 60-second windows (480s) to establish network kinematics. Short packet bursts cannot produce forward predictions and will be marked as `ABSTAINED`.
3. **Passive Telemetry Constraints**: Passive PCAP captures cannot measure TCP round-trip latency without active probes; `mean_tcp_rtt` is strictly excluded from feature extraction to prevent zero-filling or synthetic imputation.
4. **MITRE ATT&CK Attribution**: MITRE ATT&CK mappings represent contextual behavioral interpretations based on anomalous transport patterns and connection diversity, not direct neural classification labels.

---

## 8. SOC Deployment & Runbook

### Starting the Production Service:
```bash
# Start backend API on port 8001
python -m uvicorn model_service.app:app --host 0.0.0.0 --port 8001

# Serve frontend web console
npm run preview --prefix frontend
```

### CLI Analysis Workflow:
```bash
# Production analysis (Default, Authoritative)
nexsolve analyze /path/to/capture.pcap -o report.html

# Research evaluation (Uncertified candidate)
nexsolve analyze /path/to/capture.pcap --engine multi_event -o research_report.html

# Headless JSON export for SIEM integration
nexsolve analyze /path/to/capture.pcap --json > forecast.json
```

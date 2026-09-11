# NexSolve: SIH 2026 Judge Demonstration Script & Evaluation Checklist

> **Problem Statement**: SIH 2026 PS 26153 — AI-Based Network Attack Forecasting from Network Traffic Data  
> **Evaluation Mode**: Deterministic 7-Scenario SIH Evaluation Suite + Live PCAP Ingestion  
> **Duration**: ~5–7 minutes live demonstration

---

## Executive Summary for Judges

Traditional Intrusion Detection Systems (IDS) detect attacks *after* they hit the network. In academic research, machine learning models frequently claim 99%+ accuracy by cheating—randomly shuffling temporal packets and suffering from catastrophic time-series data leakage.

**NexSolve solves both problems:**
1. **Predictive Temporal Horizon**: It answers *"What will the network look like across future horizons $T+1$ through $T+5$?"* rather than merely alerting on what already occurred.
2. **Scientific Honesty & Zero Leakage**: We evaluate models on timestamp-contiguous, non-overlapping episodes. We rigorously audited baselines and discovered that the empirical Persistence baseline beats naive deep learning. As true engineers, we placed candidate ML on `HOLD` and serve validated, calibrated baselines.
3. **Evidence-Bounded Defense**: Every forecast produces supporting evidence, contradictory evidence, and capture limitations. If data quality is degraded or history is insufficient, the system exercises deliberate **Safety Abstention** (`FORECAST WITHHELD`).

---

## 10-Step Judge Walkthrough Script

### Step 1: Open Application & Initialize Demo Mode
- **Action**: Open browser to `http://localhost:5173`. Click the **"Demo Mode"** badge/toggle in the header or the **"Try Demo Scenarios"** button on the upload card.
- **UI State**: The 7-scenario interactive tab bar appears at the top of the dashboard.
- **What to Say**:
  > *"Judges, welcome to NexSolve. We have built a deterministic evaluation suite directly into the production interface, allowing you to stress-test our system across 7 real-world scenarios—from normal traffic to advanced attacks, contradictory evidence, unknown behavior, and safety abstentions."*
- **Key Point to Emphasize**: Transparent and reproducible deterministic evaluation.

---

### Step 2: Scenario 1 — Normal Enterprise Traffic (Benign Baseline)
- **Action**: Click tab **"1. Normal Traffic"**. Click **"Run Evaluation"**.
- **UI State**:
  - Risk Level: `LOW` (Green indicator, Risk Score 0.04).
  - Attack Horizon Card: Shows `Severity: NONE`. "No attack threshold breach projected."
  - Evidence Chain: Baseline traffic metrics show normal web/DNS browsing, low SYN ratio (3.8%), stable packet volume.
- **What to Say**:
  > *"Notice that on normal traffic, the system remains calm. It establishes a rolling baseline. The attack horizon confirms no projected breach over the next 5 time steps (300 seconds), avoiding false alarms on benign enterprise traffic."*
- **Key Point to Emphasize**: Stability and false-positive resistance during steady-state enterprise operations.

---

### Step 3: Scenario 2 — Early Attack Signal (Reconnaissance / Port Scan)
- **Action**: Click tab **"2. Early Signal"**. Click **"Run Evaluation"**.
- **UI State**:
  - Current state ($t_0$): Risk score is low (0.32), but...
  - **Attack Horizon**: Predicts attack breach starting at **$T+2$** and peaking at **$T+3$** (Severity: `ACCELERATING`, ETI: 120s).
  - Evidence Chain: Shows early horizontal port scan activity (+480% unique dest ports), while overall byte volume remains low.
- **What to Say**:
  > *"This is the core value proposition of NexSolve. At time $t_0$, traditional IDS triggers no critical alert because traffic volume is modest. But our temporal state model detects early reconnaissance and projects that an attack threshold breach will culminate 2 to 3 minutes into the future ($T+2$ to $T+3$). Defenders receive 120 seconds of actionable lead time before critical disruption."*
- **Key Point to Emphasize**: Predictive lead time (Estimated Time to Impact) before attack maturation.

---

### Step 4: Scenario 3 — Sustained Attack Progression (Volumetric SYN Flood / DDoS)
- **Action**: Click tab **"3. Sustained Attack"**. Click **"Run Evaluation"**.
- **UI State**:
  - Risk Level: `CRITICAL` (Red indicator, Risk Score 0.94).
  - Attack Horizon: Severity `SUSTAINED`. Active attack window spans $T+1$ through $T+5$. Peak step at $T+2$.
  - Timeline Cards: All forward steps ($T+1 \dots T+5$) marked `IN HORIZON`. Prominent `UNCALIBRATED` badge showing scientific calibration status.
- **What to Say**:
  > *"Here is a volumetric SYN flood. The attack horizon immediately highlights that the network will remain under sustained saturation for the entire 5-minute forecast horizon. Notice our transparency: each horizon card explicitly states 'UNCALIBRATED', alerting the SOC analyst that this is a raw empirical projection, avoiding dangerous false overconfidence."*
- **Key Point to Emphasize**: Multi-horizon trajectory rollout and scientific transparency (`UNCALIBRATED` label).

---

### Step 5: Scenario 4 — Contradictory Evidence (Attack Dampening)
- **Action**: Click tab **"4. Contradictory Evidence"**. Click **"Run Evaluation"**.
- **UI State**:
  - Top Metric: Elevated attack probability (0.78), but Forecast Confidence is marked `LOW / CONFLICTED`.
  - Evidence Chain:
    - *Supporting Evidence*: High SYN flags (76.2%), connection attempts elevated.
    - *Contradictory Evidence*: "Overall byte volume decreased by 34% below threshold; zero outbound C2 beaconing observed."
- **What to Say**:
  > *"In real SOC environments, raw metrics conflict. Notice how NexSolve handles contradictory evidence. While the SYN ratio is high, the overall byte volume is dropping and no egress traffic is observed. Rather than blindly screaming 'CRITICAL DDOS', our evidence engine surfaces contradictory signals and actively dampens the confidence score to prevent analyst panic."*
- **Key Point to Emphasize**: Bidirectional evidence evaluation (Supporting vs. Contradictory metrics).

---

### Step 6: Scenario 5 — Unknown / Novel Behavior (Out-of-Distribution Anomaly)
- **Action**: Click tab **"5. Unknown Behavior"**. Click **"Run Evaluation"**.
- **UI State**:
  - Classification: `UNKNOWN_BEHAVIOR` (Novelty Score: 0.88).
  - Finding: Flagged as `Novel Protocol Distribution Pattern`.
  - ATT&CK Context: Tagged with `CONTEXTUAL_HYPOTHESIS` (e.g., T1071.001 Web Protocols).
- **What to Say**:
  > *"When an adversary uses an unprecedented exploit, black-box models hallucinate an incorrect classification. NexSolve calculates the statistical distance from normal baseline states. It flags this as 'Unknown Behavior' with high novelty, and provides a contextual MITRE ATT&CK hypothesis for human triage rather than claiming certainty."*
- **Key Point to Emphasize**: Robust handling of zero-day/out-of-distribution traffic without hallucination.

---

### Step 7: Scenario 6 — Forecast Abstained (`FORECAST WITHHELD`)
- **Action**: Click tab **"6. Forecast Abstained"**. Click **"Run Evaluation"**.
- **UI State**:
  - Forecast Status: Big amber shield displaying **"FORECAST WITHHELD"**.
  - Reason: `INSUFFICIENT_TEMPORAL_HISTORY (< 3 consecutive 60s windows observed)`.
  - Missing Prerequisites: "Requires at least 3 contiguous historical temporal windows."
  - Recommended Action: "Continue monitoring packet stream until temporal baseline accumulates."
- **What to Say**:
  > *"This is our proudest engineering feature: Deliberate Safety Abstention. When a capture only contains 1 or 2 windows, any 5-step forecast would be pure fiction. Instead of hallucinating, NexSolve withholds the forecast, explains exactly what data is missing, and advises the defender on necessary action."*
- **Key Point to Emphasize**: Safety-first architecture—refusing to guess when evidence is insufficient.

---

### Step 8: Scenario 7 — Poor Capture Quality (Degraded Network Telemetry)
- **Action**: Click tab **"7. Poor Quality"**. Click **"Run Evaluation"**.
- **UI State**:
  - Capture Quality Badge: Marked in amber as `DEGRADED`.
  - Quality Metrics: 42% packet loss / truncation, non-monotonic timestamp jitter.
  - Limitations: Forensics engine flags that TCP reconstruction is partial (`INCOMPLETE`).
- **What to Say**:
  > *"Telemetry in the field is messy. When a SPAN port drops 42% of packets or truncation occurs, NexSolve flags capture quality as DEGRADED, warns the analyst, and bounds all derived conclusions."*
- **Key Point to Emphasize**: Telemetry-aware forensic resilience.

---

### Step 9: Downloadable Forensic Report (Cryptographic Audit Trail)
- **Action**: In the header or results action bar, click **"Export HTML Report"** (or view the JSON report).
- **UI State**: A standalone, self-contained HTML forensic document opens in a new tab.
- **What to Say**:
  > *"NexSolve generates standalone, cryptographically auditable forensic reports. This HTML file is 100% self-contained—zero external CDN dependencies, zero tracking scripts. It embeds the SHA-256 capture hash, stage latency breakdown, attack horizon projection, and full evidence chain, ready for chain-of-custody submission in legal and compliance audits."*
- **Key Point to Emphasize**: Air-gapped, zero-CDN standalone forensic auditability.

---

### Step 10: Real-Time PCAP Upload & 8-Stage Execution
- **Action**: Switch back to **"Upload Capture"**. Drag and drop a test capture file (e.g., `tests/fixtures/test_100packets.pcap`). Click **"Analyze capture"**.
- **UI State**:
  - The live progress tracker visually cycles through all 8 stages:
    `Upload Validation` -> `PCAP Parsing` -> `Flow Reconstruction` -> `Window Generation` -> `State Extraction` -> `Forecasting Head` -> `Evidence Engine` -> `Report Generation`.
  - Processing completes in under **35 milliseconds**.
  - Full results populate the dashboard.
- **What to Say**:
  > *"Finally, here is the live end-to-end pipeline. We upload a raw packet capture. The 8-stage asynchronous engine parses packets, reconstructs flows, creates temporal windows, extracts 46 state features, evaluates horizons, generates evidence, and compiles forensic reports in ~32 milliseconds. This is a fully functional, end-to-end system ready for deployment."*
- **Key Point to Emphasize**: Sub-second execution speed, end-to-end asynchronous pipeline, production readiness.

---

## Offline Fallback Demo (If Server/WiFi Fails)

If network connectivity, backend port binding, or server access is completely unavailable during the presentation:

1. **Pre-Compiled Client Fixtures**:
   - The frontend includes pre-bundled scenario payloads in `frontend/src/fixtures/demoScenarios.ts`.
   - The UI automatically falls back to local client fixtures if the backend API returns an error or is unreachable.
2. **Offline Browser Launch**:
   - Simply keep the frontend running (`npm run dev` at `http://localhost:5173`) or serve the pre-built `dist/` directory:
     ```powershell
     cd frontend
     npx serve dist -l 5173
     ```
3. **No External Network Dependencies**:
   - Both the frontend dashboard and exported HTML reports have zero internet requirements (all fonts, icons, styling, and charts are locally bundled).

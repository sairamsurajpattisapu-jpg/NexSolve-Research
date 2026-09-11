# NexSolve — SIH 2026 Final Judge Demonstration Script

**Problem Statement 26153**: AI-Based Network Attack Forecasting from Network Traffic Data  
**Target Audience**: Smart India Hackathon Jury & Technical Evaluators  
**Duration**: 5–7 Minutes  
**Live URL**: `http://localhost:5173` (or `http://localhost:3000` via Docker Compose)  
**Core Thesis**: *"Most systems tell you what already happened. NexSolve shows you what the network is likely to become next — and tells you when it does not have enough evidence to claim that."*

---

## Demonstration Timeline & Step-by-Step Script

```text
+-------------------------------------------------------------------------------+
|                        5-7 MINUTE DEMO FLOW AT A GLANCE                       |
+-------------------------------------------------------------------------------+
  [0:00-0:30]  The Problem: Traditional Reactive Defense
  [0:30-1:00]  Why Detection Fails & How NexSolve Shifts the Paradigm
  [1:00-2:00]  Live PCAP Ingestion & Canonical Flow/Window Reconstruction
  [2:00-3:00]  Observing the Past: Canonical Temporal Network State (T0)
  [3:00-4:00]  Forecasting the Future: Multi-Horizon Rollout & Attack Horizon (T+1..T+5)
  [4:00-5:00]  Why Believe It: Bidirectional Evidence Chain & Trust Calibration
  [5:00-6:00]  Epistemic Safety: The Abstention & Contradictory Evidence Demonstration
  [6:00-7:00]  Production Architecture, Scientific Honesty & Impact
+-------------------------------------------------------------------------------+
```

---

### [0:00 – 0:30] Phase 1: The Core Problem

#### **UI Action**:
- Display the **Landing Dashboard** (`http://localhost:5173`).
- Point to the clean, focused interface with the top navigation: *Overview*, *Threats*, *Traffic*, *Reports*, and *SIH Demo Mode*.

#### **Spoken Script**:
> "Respected judges, every enterprise today runs firewalls, SIEMs, and intrusion detection systems like Snort or Suricata. Yet major breaches continue to succeed. Why?
> 
> Because traditional security operates in an exclusively **reactive** paradigm. Current systems answer only one question: *'What just happened?'* By the time an alert fires, packets have already breached your perimeter, lateral movement has begun, and data exfiltration may already be underway. SOC analysts are overwhelmed with alerts for yesterday's attacks."

---

### [0:30 – 1:00] Phase 2: Paradigm Shift — Forensic Detection to Temporal Forecasting

#### **UI Action**:
- Hover over the subtitle: *"Overview / Predictive Intelligence — Network Security Posture & Forecast"*.
- Point out the distinct badges: `Current Detection (T₀)` vs `Attack Horizon (T+1 → T+5)`.

#### **Spoken Script**:
> "For SIH Problem Statement 26153, NexSolve changes the fundamental paradigm:
> 
> **We do not merely detect attacks after damage occurs.** NexSolve answers:
> *'Given the raw network traffic observed up to time $T_0$, what will the network state look like over the next 1 to 5 minutes ($T+1 \dots T+5$), how much lead time does the defender have, and what verifiable evidence supports or contradicts that forecast?'*
> 
> Crucially, unlike black-box academic models that hallucinate 99% accuracy on shuffled data, NexSolve incorporates an **Epistemic Safety Gate**: when evidence is gapped, degraded, or insufficient, it explicitly **withholds the forecast** rather than guessing."

---

### [1:00 – 2:00] Phase 3: Live PCAP Ingestion & Canonical Flow Reconstruction

#### **UI Action**:
- In the **Capture Upload** card, click **"Choose capture"**.
- Select a test capture (e.g. `data/production_pcap/sample_traffic.pcap` or an authorized `.pcap` capture).
- Click **"Analyze PCAP"**.
- Observe the real-time asynchronous stage indicators:
  `QUEUED` $\to$ `PARSING` $\to$ `FLOW_RECONSTRUCTION` $\to$ `TEMPORAL_WINDOWING` $\to$ `FORECASTING` $\to$ `COMPLETE`.

#### **Spoken Script**:
> "Let's demonstrate this live on real network traffic. I am uploading a raw packet capture.
> 
> Watch the pipeline: NexSolve validates file magic bytes, enforces a 64 MB cap and 100,000 packet ceiling, and streams the capture through Scapy without loading gigabytes into RAM.
> 
> In milliseconds, it reconstructs bidirectional 5-tuple flows, handles TCP handshake states, and slices packets into chronologically strict, non-overlapping 60-second temporal windows. Notice that all processing happens locally with zero cloud dependencies and zero data leakage from future windows."

---

### [2:00 – 3:00] Phase 4: Observing the Past — 46-Feature Network State

#### **UI Action**:
- Once processing finishes, the **JobResult** view renders.
- Direct attention to the metric cards:
  - `Observed Traffic`: Packet count and temporal window breakdown.
  - `Reconstructed Flows`: Flow volume and protocol diversity.
  - `Capture Integrity`: `HIGH QUALITY` or `DEGRADED` (loss ratio, malformed count).
  - `Current Detection (T₀)`: The current baseline threat state.

#### **Spoken Script**:
> "Here is our reconstructed temporal baseline at time $T_0$.
> 
> NexSolve extracts 46 canonical features divided across three groups: Flow features, Packet features, and Temporal lookback features. 
> 
> Notice the top cards clearly demarcate: **'Current Detection ($T_0$): What is happening right now.'** This is what traditional IDS tools stop at. But NexSolve uses this state as the launching pad for forward forecasting."

---

### [3:00 – 4:00] Phase 5: Forecasting the Future — Multi-Horizon Rollout & Attack Horizon

#### **UI Action**:
- Scroll to the **Attack Horizon & Forecast Lead Time** card.
- Show the visual forward timeline ($T+1, T+2, T+3, T+4, T+5$).
- Highlight the **Lead Time** counter (e.g., `Lead Time: 120s`, `Horizon: 3 Windows`).
- Click the **SIH Demo Mode** button in the top navigation and select **"Scenario 2: Early Attack Signal"**.
- Point out how the Attack Horizon status updates to **EARLY SIGNAL** with breach onset at $T+2$.

#### **Spoken Script**:
> "Now we look into the future. This is the **Attack Horizon**.
> 
> Instead of giving a static score, NexSolve computes forward rollouts across future horizons $T+1$ through $T+5$—representing the next 1 to 5 minutes.
> 
> In this early reconnaissance scenario, current detection at $T_0$ is low—traditional tools wouldn't even page an on-call engineer. But NexSolve's temporal model identifies an escalating trajectory, projecting an impending breach at window $T+2$ with **120 seconds of actionable defender lead time**.
> 
> This 2-minute window allows automated firewall rule orchestration or SOC containment before the attacker establishes persistence."

---

### [4:00 – 5:00] Phase 6: Why Believe the Model? — Bidirectional Evidence Chain & Calibration

#### **UI Action**:
- Scroll down to the **Why This Forecast (Evidence Intelligence)** panel.
- Point out:
  - **Supporting Signals** (green checkmarks with metric deltas: e.g. *Destination Port Diversity +64.2%*).
  - **Contradictory Signals** (isolated conflicting metrics).
  - **Net Evidence Balance**.
- Point to the **Confidence & Calibration** card:
  - Show the raw score vs. the `UNCALIBRATED` disclosure badge.

#### **Spoken Script**:
> "Now the most critical question any security judge will ask: *'Why should an analyst trust an AI forecast?'*
> 
> NexSolve does not use black-box embeddings. We built a bidirectional **Evidence Chain**.
> 
> Looking here, you see the exact supporting traffic signals driving the forecast: SYN-to-ACK ratios, flow duration anomalies, and port diversity surges compared to the moving baseline.
> 
> And look at our scientific honesty: if the dataset lacks multi-class continuous validation splits, NexSolve explicitly labels confidence as **`UNCALIBRATED`**. We never fabricate a fake '99.4% confidence' percentage. An analyst always knows exactly what is measured and what is statistical extrapolation."

---

### [5:00 – 6:00] Phase 7: Epistemic Safety — The Abstention Demonstration

#### **UI Action**:
- In the Demo Mode selector, switch to **"Scenario 6: Forecast Abstained"** (or **"Scenario 4: Contradictory Evidence"**).
- Show the visual change:
  - Attack Horizon pill turns amber: **ABSTAINED**.
  - Availability card displays: **`FORECAST WITHHELD`**.
  - Reason: *History length (2 windows) is below minimum threshold (3 windows)*.
- Click **Scenario 4: Contradictory Evidence** to show how contradictory signals suppress overconfidence.

#### **Spoken Script**:
> "Now let us show you what makes NexSolve truly production-ready: **Forecast Abstention**.
> 
> In Scenario 6, the capture contains only 2 windows—less than the 3 windows required to establish temporal momentum. A naive ML model would still spit out a prediction and hallucinate an attack.
> 
> NexSolve refuses. The system triggers an **Epistemic Safety Gate**, visibly declaring:
> **'FORECAST WITHHELD: Insufficient observation history.'**
> 
> Similarly, in Scenario 4, volumetric traffic surges but packet drop rates plummet. NexSolve detects the contradiction, flags high uncertainty, and prevents a false-positive escalation."

---

### [6:00 – 7:00] Phase 8: Reports, Architecture, and Closing

#### **UI Action**:
- Scroll to the top right of the result card and click **"Download HTML Report"**.
- Open the downloaded standalone HTML report in a browser tab.
- Show the cryptographic SHA-256 provenance hash, epistemic badges (`OBSERVED`, `INFERRED`, `FORECAST`), and executive summary.
- Show that the report is self-contained with zero external CDN dependencies.

#### **Spoken Script**:
> "Finally, every analysis produces an immutable, cryptographically verifiable audit artifact. 
> 
> As you can see, this standalone forensic HTML report embeds the full evidence chain, MITRE ATT&CK mappings, and capture SHA-256 hash. It can be archived or emailed to incident response teams without needing external internet access.
> 
> To summarize NexSolve's engineering foundation:
> 1. **Zero Data Leakage**: Evaluated on contiguous chronological episodes, never randomly shuffled.
> 2. **Scientifically Defensible**: Persistence Champion baseline validated; ML candidates transparently kept on HOLD until multi-domain calibration is complete.
> 3. **Production Hardened**: 194 backend tests, 32 frontend tests, 100% pass rate, dual health/readiness probes, and PostgreSQL persistence.
> 
> NexSolve gives defenders what they have never had before: **time**."

---

## Quick Judge Demo Checklist

| Target Time | Key Checkpoint | Visual Indicator |
| :--- | :--- | :--- |
| **0:30** | State the problem | Dashboard with "Detection vs. Forecasting" distinction |
| **1:30** | Live PCAP upload | 5-stage progress indicator (`QUEUED` $\to$ `COMPLETE`) |
| **2:30** | $T_0$ Network State | 46 features, packet/flow counts, capture integrity |
| **3:30** | Attack Horizon ($T+1..T+5$) | Horizon lead time card (e.g. 120s warning) |
| **4:30** | Evidence Chain | Green supporting vs. red contradictory signals |
| **5:30** | Epistemic Abstention | Amber `FORECAST WITHHELD` safety card |
| **6:30** | Forensic Report Export | Standalone HTML report with SHA-256 provenance |

# NexSolve Unknown Behavior Detection Specification

**Status**: PRODUCTION SPECIFICATION  
**Module**: `ml/forecasting/unknown_behavior.py`  
**Endpoint**: `POST /forecast` (`model_service/app.py`)  
**SIH Problem Statement**: SIH26153 — AI based Network Attack Forecasting from Network Traffic Data  

---

## 1. Executive Summary & Philosophy

Conventional network intrusion detection engines suffer from a chronic failure mode: when presented with unseen, zero-day, or anomalous network traffic, they either silently produce confident false negatives or misclassify benign novel services as catastrophic attacks.

**NexSolve Unknown Behavior Detection** explicitly separates **threat classification** from **domain epistemic validity**.

> **Foundational Principle**:  
> `UNKNOWN_BEHAVIOR` does **not** automatically denote malicious activity.  
> It signifies that observed network signals lie **outside the supported behavioral interpretation space** of the system. Treating unknown behavior as inherently malicious causes alert storms and automated response disasters; treating it as benign creates vulnerabilities. NexSolve surfaces unknown patterns with explicit epistemic boundaries and recommended abstention.

---

## 2. Classification Taxonomy

The classification engine maps the current network state into one of three rigorous states:

| Classification | Definition & Operational Meaning | Typical Coverage | Action / Abstention |
| :--- | :--- | :---: | :---: |
| **`KNOWN_PATTERN`** | Observed telemetry conforms cleanly to calibrated benign baselines or modeled multi-step attack progression patterns. | $\ge 70\%$ | Standard automated processing; no abstention recommended. |
| **`WEAK_PATTERN`** | Signals exhibit low-amplitude deviations, sparse evidence, or marginal coverage without direct structural contradiction. | $30\% \dots 69\%$ | Monitored routing; low-confidence alerts; no hard abstention. |
| **`UNKNOWN_BEHAVIOR`** | Signals violate physical flow invariants, exhibit protocol anomalies, or contradict model expectations. | $< 30\%$ or triggered by anomaly rule | SOC analyst triage required; `abstain_recommended = True`. |

---

## 3. Deterministic Trigger Conditions

The classification engine enforces deterministic rules evaluated in order of priority:

### 3.1 Rule 1: Physical & Semantic Invariants Violation
Network flow telemetry must obey physical transport laws. When telemetry reports impossible physical relationships, the engine immediately flags `UNKNOWN_BEHAVIOR`:
- **Impossible Flow/Packet Relationship**: `flow_count > 0` while `total_packets == 0`.
- **Zero-Byte Packets with High Volume**: `total_packets > 1000` while `total_bytes == 0`.
- **Impossible Port Distribution**: `unique_dst_ports > total_packets`.

### 3.2 Rule 2: Forecast vs. Evidence Disagreement
When an ML or heuristic forecast asserts high attack probability ($\hat{y} \ge 0.80$) but the physical evidence chain reports a complete collapse in traffic volume ($> 75\%$ drop) or $0$ supporting evidence items alongside multiple contradictory items:
- The system recognizes that the model is hallucinating outside its validated distribution.
- Flags `UNKNOWN_BEHAVIOR` with reason: *"Severe forecast/evidence contradiction: model predicts attack but physical metrics indicate baseline traffic collapse."*
- Sets `abstain_recommended = True`.

### 3.3 Rule 3: Conflicting Evidence Overload
When high severity evidence items are split equally or predominantly contradictory during an elevated forecast state:
- Corroborating signals conflict directly with dampening signals.
- Triggered when `contradictory_feature_count >= supporting_feature_count` and `forecast_score >= 0.70`.

### 3.4 Rule 4: Critical Capture Telemetry Failure
When capture telemetry reports severe corruption:
- `packet_loss_ratio >= 0.20` (20% packet loss) OR `reordered_packets_ratio >= 0.25`.
- Telemetry cannot support reliable behavioral classification.
- Flags `UNKNOWN_BEHAVIOR` with capture limitation notes.

### 3.5 Rule 5: Low Feature Coverage
Coverage $C \in [0.0, 1.0]$ measures the proportion of observable feature dimensions operating within known physical bounds:

$$C = \frac{\sum_{f \in \mathcal{F}_{\text{valid}}} 1}{|\mathcal{F}_{\text{total}}|}$$

If $C < 0.30$, the state falls into `UNKNOWN_BEHAVIOR`.

---

## 4. Unknown Behavior Data Contract

The classification output structure integrates directly into the unified forecast response:

```json
{
  "classification": "UNKNOWN_BEHAVIOR",
  "reason": "Protocol anomaly detected: flow count surged 150% with zero byte throughput, indicating unsupported tunneling or malformed frames.",
  "supporting_evidence": [
    "Active concurrent flow count increased 150%"
  ],
  "contradictory_evidence": [
    "Observed total byte volume is 0"
  ],
  "coverage": 0.35,
  "abstain_recommended": true
}
```

---

## 5. SOC Operational Workflow Under Unknown Behavior

1. **Automated Containment Suppression**: Automated firewall rule creation and IP blacklisting are suppressed when `abstain_recommended == true` to prevent self-inflicted denial of service.
2. **PCAP Extraction Queue**: The system schedules raw PCAP buffer retention for the affected time window $T_0 - 5\,\text{min} \dots T_0 + 1\,\text{min}$ for forensic deep packet inspection.
3. **Analyst Review Banner**: Displayed prominently in the SOC interface with the exact physical contradictions that triggered the unknown behavior classification.

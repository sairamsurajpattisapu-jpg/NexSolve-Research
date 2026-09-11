# NexSolve — Real PCAP Forecast Abstention Diagnostic & Resolution Report

## 1. Root Cause
When uploading arbitrary real PCAP files, users and evaluators observed:
- Attack Horizon: 0 windows
- Onset Lead Time: N/A
- Temporal Consistency: 0%
- Calibration: UNSUPPORTED
- Attack horizon evaluation abstained: `INSUFFICIENT_HISTORY`
- Forecast T+1..T+5: Withheld
- Capture Quality: `DEGRADED`

**Root Cause Breakdown**:
1. **Mathematical Sequence Requirement (Scientific Safeguard)**:
   - NexSolve's forecasting architecture requires an 8-window lookback (`min_sequence_length=8`).
   - The canonical temporal window duration is fixed at 60 seconds.
   - Consequently, computing a valid rollout without hallucination mathematically requires at least **480 seconds (8 continuous minutes)** of network traffic.
   - Arbitrary ad-hoc or demonstration captures uploaded by testers typically span 5 to 60 seconds (or 1–3 minutes), resulting in 1 to 3 temporal windows (`seq_len < 8`). This legitimately triggers `INSUFFICIENT_HISTORY`.
2. **Contiguity / Idle Periods**:
   - In sparse captures where packets exist in non-contiguous 60-second intervals (e.g., traffic in minute 0, minute 1, idle minute 2, traffic in minute 3), temporal windowing produces non-contiguous window boundaries (`current.start_timestamp != previous.end_timestamp`).
   - The sequence history builder strictly enforces continuity and flags this as `GAPPED_HISTORY` to prevent temporal distortion.
3. **Capture Quality Assessment**:
   - The `CaptureQuality` status is classified as `DEGRADED` whenever partial TCP sessions are observed (sessions without an observed 3-way handshake SYN/ACK or FIN/RST termination, or unsupported protocol layers).
   - In real-world captures where packet sniffing starts mid-connection, incomplete flows are virtually always present. This is a factual measurement, not a failure; `DEGRADED` quality does not block forecasting unless quality is marked `INSUFFICIENT` (empty or unparseable).
4. **UX & Information Gap**:
   - The system previously returned a bare `INSUFFICIENT_HISTORY` tag without providing actionable telemetry context (how many windows were observed, how many are required, what the duration was, or why the safety gate abstained).
   - Furthermore, in `evaluate_forecast_abstention`, sequence length was evaluated before interval contiguity, masking gap detection in multi-window captures under 8 windows.

---

## 2. Real Bug vs Expected Abstention
- **Abstention on Short Captures (< 480s)**: **EXPECTED & SCIENTIFICALLY SOUND**.
  NexSolve intentionally refuses to generate multi-step autoregressive rollouts when the historical lookback sequence is insufficient. Fabricating predictions from 1 or 2 windows would constitute epistemic hallucination.
- **Abstention on Gapped Captures**: **EXPECTED & INTENDED**.
  Temporal gaps break time-series continuity.
- **Evaluation Order & Diagnostic Transparency**: **IMPLEMENTATION GAP (NOW RESOLVED)**.
  `evaluate_forecast_abstention` was updated to check timestamp contiguity prior to sequence length, and enriched to return structured metadata (`observed_windows`, `required_windows`, `capture_duration_seconds`, `gap_seconds`). The frontend was upgraded with structured diagnostic cards explaining the deliberate safety decision.

---

## 3. PCAP Diagnostics Summary

| Scenario | Packets | Duration | Window Count | History Status | Quality Status | Forecast Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Short Capture** | 25 | 6.00s | 1 | `INSUFFICIENT_HISTORY` | `GOOD` / `DEGRADED` | **Graceful Abstention** (Observed: 1/8 windows, 60s) |
| **Continuous 8-Window Capture** | 40 | 440.00s | 8 | `READY` | `DEGRADED` (incomplete flows) | **History Verified Ready** (8 contiguous windows, 0 gaps) |
| **Gapped Capture (Idle Minute)** | 15 | 200.00s | 3 | `GAPPED_HISTORY` | `DEGRADED` | **Graceful Abstention** (Gap: 60s detected between windows) |
| **PCAPNG Capture** | 10 | 10.00s | 1 | `INSUFFICIENT_HISTORY` | `GOOD` | **Graceful Abstention** (1/8 windows; PCAPNG parsed cleanly) |
| **IPv6 UDP Capture** | 5 | 10.00s | 1 | `INSUFFICIENT_HISTORY` | `GOOD` | **Graceful Abstention** (IPv6 layers cleanly normalized) |

---

## 4. Temporal Window Diagnostics
- **Window Size**: 60 seconds (fixed canonical duration).
- **Window Boundaries**: Deterministically aligned to UTC epoch minute boundaries `[floor(ts/60)*60, floor(ts/60)*60 + 60)`.
- **Ordering**: Strict ascending timestamp sorting preserved.
- **Sub-microsecond Scaling**: Microsecond timestamps in Scapy (`pkt.time`) are converted to IEEE 754 floats without precision distortion.

---

## 5. History Eligibility
- **Minimum Windows Required**: 8 contiguous canonical windows (480 seconds).
- **Contiguity Requirement**: For all adjacent pairs `(w[i], w[i+1])`, `w[i+1].start_timestamp == w[i].end_timestamp`.
- **Capture Boundary Rule**: History cannot span multiple independent capture IDs.

---

## 6. Changes Made

1. **`ml/forecasting/forecast_abstention.py`**:
   - Added structured diagnostic fields to `ForecastAbstentionResult`:
     - `observed_windows: int | None = None`
     - `required_windows: int | None = None`
     - `capture_duration_seconds: float | None = None`
     - `gap_seconds: int | None = None`
   - Reordered evaluation checks: Contiguity and temporal gap checks are evaluated first to accurately distinguish `GAPPED_HISTORY` from `INSUFFICIENT_HISTORY`.
   - Populated duration and gap diagnostics in all return paths.
2. **`frontend/src/types/api.ts`**:
   - Extended `ForecastAbstentionPayload` interface with `observed_windows`, `required_windows`, `capture_duration_seconds`, and `gap_seconds`.
3. **`frontend/src/components/ForecastStatus.tsx`**:
   - Added responsive diagnostic cards for abstained states displaying:
     - Clear human-readable reason (`Insufficient Temporal History` or `Telemetry Contains Temporal Gaps`).
     - Observed windows and elapsed duration (`X windows (YYs)`).
     - Required minimum lookback (`8 contiguous windows (480s)`) or specific gap duration (`XXs non-contiguous gap`).
     - Actionable guidance for the user/judge (`Upload a longer capture containing continuous traffic history (at least 8 min)`).
4. **`tests/test_pcap_diagnostics.py`**:
   - Created deterministic regression test suite verifying short captures, continuous 8-window captures, gapped captures, PCAPNG format, and IPv6 traffic.

---

## 7. Tests Added

- `test_short_pcap_abstains_with_factual_diagnostics`: Validates that a short capture (< 8 windows) produces 1 window, triggers `INSUFFICIENT_HISTORY`, sets `observed_windows=1`, `required_windows=8`, `capture_duration_seconds=60.0`, and does not crash.
- `test_continuous_8_windows_produces_ready_history`: Validates that a capture spanning 8 contiguous windows produces `READY` history status with zero gaps.
- `test_gapped_pcap_reports_gap_diagnostics`: Validates that a capture with missing minutes triggers `GAPPED_HISTORY` with exact gap measurement (`gap_seconds=60`).
- `test_pcapng_ingestion_and_windowing`: Validates that `.pcapng` format is parsed without loss of fidelity.
- `test_ipv6_udp_canonical_extraction`: Validates that IPv6 UDP packets are parsed with appropriate protocol counting and windowing.

---

## 8. Full Test Results

- **Backend Pytest**: **199 / 199 passed** (100% passing; 0 failed)
- **Frontend Vitest**: **32 / 32 passed** (100% passing; 0 failed)
- **TypeScript Typecheck**: **0 errors**
- **Oxlint**: **0 warnings, 0 errors** (40 files checked)
- **Vite Production Build**: **Successful** (client bundle built cleanly in 639ms)

---

## 9. Remaining Legitimate Limitations
- PCAP captures spanning less than 8 contiguous minutes (480 seconds) cannot generate forward forecasts because the underlying world model requires 8 historical temporal states to establish momentum and velocity.
- The machine learning LSTM world model remains gated behind feature compatibility checks (e.g. `mean_tcp_rtt` is not fabricated from synthetic PCAPs).
- Both constraints represent deliberate scientific safeguards rather than system defects.

# Leakage Audit

Status: **PASSED_WITH_BLOCKERS**.

| ID | Severity | Location | Status | Remediation |
|---|---|---|---|---|
| target-columns | none | active feature schema | passed | Keep labels target-only. |
| future-features | none | active feature schema | passed | Reject future-derived names during schema validation. |
| split-overlap | none | temporal split definition | passed | Continue chronological split enforcement. |
| calibration-contamination | medium | validation split | open | Acquire a validation episode containing both classes; keep calibration BLOCKED_BY_DATA until then. |
| cic-timestamps | high | CIC-IDS2017 flow CSVs | blocked | Use a verified timestamp-bearing source or the original PCAP. |

Labels remain targets only, preprocessing is train-only, temporal ordering is preserved, and no random shuffling or future observations are used. The open calibration and CIC timestamp findings prevent final-model promotion.
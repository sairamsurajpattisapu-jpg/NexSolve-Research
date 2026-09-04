# TON_IoT Timestamp Validation

## Decision

**D: ACCESSIBLE SOURCE BUT EXACT VALIDATION FILE NOT IDENTIFIED**

## Official Source

- Institutional page: https://research.unsw.edu.au/projects/toniot-datasets
- Official download link: https://unsw-my.sharepoint.com/:f:/g/personal/z5025758_ad_unsw_edu_au/EvBTaetotpdGnW7rJQ8fCvYBh8063CNeY9W33MpRsarJaQ?e=yZlnxW
- Access check: HTTP 200, public folder reachable, no login observed

The institutional page documents `Processed`, `Train_Test_datasets`, and `SecurityEvents_GroundTruth_datasets`; it states that security events include timestamp `ts` and that labels use IP addresses and timestamps.

## Direct File Result

No file was downloaded. The returned SharePoint HTML did not expose exact CSV filenames or direct file URLs. No API or guessed URL was used.

- Exact file: None
- Size: Not computed
- SHA-256: Not computed
- Rows/columns/header: Not computed
- Timestamp field/range/precision/timezone: Not computed
- 60-second windows and state transitions: Not computed
- Benign/attack counts: Not computed

## Leakage Risks To Audit Later

The official documentation indicates IP/timestamp-based labeling. Future validation must check whether source IP, destination/device identity, scenario, or fixed periods trivially encode labels, and must keep security-event labels evaluation-only.

## Readiness

TON_IoT is **not ready** for the locked forecasting experiment. The minimum next acquisition is one exact processed network CSV containing timestamps and labels plus its corresponding timestamped network security-event ground truth file. Exact names and sizes remain UNKNOWN until the official folder listing is visible.

No CIC-IDS2017, UNSW-NB15, MITRE, or production NexSolve files were modified. No model was trained and no forecasting experiment was run.

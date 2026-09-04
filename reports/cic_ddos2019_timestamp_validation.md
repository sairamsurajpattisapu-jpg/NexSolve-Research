# CIC-DDoS2019 Timestamp Validation

## Result

**Decision D: TIMESTAMP CLAIM NOT VERIFIED**

No CIC-DDoS2019 generated flow CSV was downloaded or inspected.

## Official Source

- URL: https://cicresearch.ca/CICDataset/CICDDoS2019/
- Source: Official CIC/UNB CIC-DDoS2019 download endpoint
- HTTP status: 200
- Download date: 2026-09-03

The endpoint is a download form requiring personal identity fields. It does not expose a public directory listing or a direct generated-flow filename. No form was submitted because accurate user identity information was not available, and no identity was fabricated.

## File-Level Validation

- Exact file obtained: None
- File size: Not computed
- SHA-256: Not computed
- Row count: Not computed
- Schema/header: Not inspected
- Timestamp field, format, precision, timezone, range, ordering: Not computed
- Labels and attack categories: Not computed
- 60-second windows and transitions: Not computed
- Leakage checks: Not performed at file level

## Why Validation Stopped

Documentation-level evidence remains available in the dataset-selection report, but the requested direct validation requires an actual official generated flow CSV. The official endpoint requires a form submission and provides no browsable file inventory from which a smallest CSV can be selected safely.

## Additional Files Needed

The exact filename and size are **UNKNOWN** until the official listing is available after legitimate form access. The minimum useful acquisition is one official generated labeled flow CSV containing timestamps and both flow/label fields. PCAPs and the full distribution are not needed for this validation step.

## Safety Result

- Existing CIC-IDS2017 files: unchanged
- Existing UNSW-NB15 files: unchanged
- MITRE ATT&CK source: unchanged
- Production NexSolve repository: untouched
- Forecasting experiment: not run
- Advanced model: not trained

# Dataset Selection Decision

Run timestamp (UTC): `2026-09-03T10:49:46+00:00`

## Best Candidate

CIC-DDoS2019

## Backup Candidate

TON_IoT

## Winner Score

45

## Backup Score

42

## Winner Reasons

```json
[
  "Official UNB documentation explicitly states timestamp-based flow labeling.",
  "Source/destination IP, ports, and protocol fields are part of the documented label basis.",
  "Two documented capture days provide a chronological future-day design.",
  "Attack schedules include many distinct attack periods rather than one single block.",
  "Benign background traffic is explicitly described.",
  "Generated per-machine CSVs provide a practical first acquisition target.",
  "Official download, paper, license, and attack-time tables support reproducibility."
]
```

## Backup Not Selected

TON_IoT has explicit timestamped security-event ground truth and event diversity, but its heterogeneous multimodal packaging and IP/timestamp joins create more linkage and leakage complexity.

## Exact Next Download

```json
{
  "filename": "UNKNOWN: official directory listing must be inspected before selecting a smallest generated CSV",
  "source": "http://cicresearch.ca//CICDataset/CICDDoS2019/",
  "approximate_size": "UNKNOWN",
  "purpose": "Inspect one official generated flow CSV header and timestamp coverage before full acquisition."
}
```

## Forecasting Potential

HIGH

## Advanced Model

NOT JUSTIFIED YET

## Next Step

TON_IoT backup validation is also blocked at exact file identification: inspect the official public SharePoint folder listing and acquire one smallest processed network CSV plus its timestamped ground truth file; do not download the full dataset.

## Backup Validation Status

TON_IoT official page and public SharePoint folder are reachable, but the returned folder page exposed no exact CSV filenames or direct file URLs. No file was downloaded or guessed. See `reports/toniot_timestamp_validation.md`.

## TON_IoT Network 23 Update

The actual official `Network_dataset_23.csv` is now validated. It provides explicit timestamps, benign/attack labels, network flow features, 893 non-empty 60-second windows, 889 contiguous pairs, and both state transitions. Decision A for initial locked temporal evaluation; see `reports/toniot_network23_validation.md`. CIC-DDoS2019 remains unvalidated because its official download is gated.

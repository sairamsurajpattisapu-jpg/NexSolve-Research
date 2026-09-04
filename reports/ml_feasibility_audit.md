# NexSolve ML Feasibility Audit

Audit date: 2026-09-04

## Decision

**ML FEASIBILITY: NO for the current production path.**

Validated supervised ML is not currently feasible for the production packet-window detector. The production artifact is a read-only, unlabeled packet-window Parquet file. Available labeled sources are flow-level or event-ground-truth datasets with different schemas, aggregation semantics, and leakage risks. No source can be used as production ML training data without changing the inference contract or inventing packet/window labels.

**ML decision: future-ready, not implemented.** The active detector remains `traffic_heuristics` through `HeuristicDetector`. No ML score, probability, confidence, or attack label is exposed by the production analysis routes.

## Production input contract

`data/processed/cic_ids2017_packet_windows.parquet` was verified read-only:

- 484 rows, 48 columns, 60-second UTC packet aggregates.
- SHA-256: `de9c7a7c71512a9ee303de89ef4e314412fa45566296044fd10f536088745615`.
- Packet metrics include sizes, TTL, TCP flags/windows, IAT, fragmentation, retransmissions, endpoint cardinalities, and a traffic-derived port-scan score.
- No label, attack category, source ground-truth reference, or independent incident outcome is present.
- The production API reads this artifact and does not run PCAP extraction.

The protected research model contract is different: 46 numeric features over 8 historical 60-second states, comprising 18 flow features, 22 packet features, and 6 temporal features. Its packet fields are explicitly unavailable placeholders, and its UNSW-derived weights are not used for packet analysis.

## Dataset audit

| Dataset | Labels | Feature compatibility | Usable for production ML | Reason |
|---|---|---|---|---|
| CIC-IDS2017 flow CSVs, 8 files | Genuine `BENIGN` and attack labels; 225,711 to 286,096 valid rows per file | Flow-level aggregates; no exact event timestamp, source IP, protocol, or packet-level features. Cannot produce the production packet-window schema. | **No** | Existing Logistic Regression is a flow-only research baseline. Combining files chronologically is not defensible without timestamps; duplicates and malformed numeric rows require care. |
| UNSW-NB15 traffic CSVs | Genuine binary `Label` and attack categories; 4 x 700,000 data rows in the audited traffic files | Timestamped flow records and a protected 46-feature temporal research contract. Packet fields are unavailable in the source/model path and do not match production packet aggregates. | **No** | The NumPy LSTM is research-only, has limited evaluation, and cannot consume production packet windows. `attack_cat` is missing for benign rows; adjacent duplicates and temporal/scenario proxies require split controls. |
| TON-IoT `Network_dataset_23.csv` | Genuine `label`: 33,475 benign and 305,546 attack rows; `type` corroborates categories | Timestamped flow/network records with IPs, ports, protocol, duration, bytes, and packets. It is not the production packet-window schema. | **No** | It is a promising future flow/window research candidate, but transforming it into packet features would change semantics. IP/time/scenario proxies and duplicate keys require leakage-safe evaluation. |
| TON-IoT `GroundTruth_Network_18.csv` | Genuine attack-event categories only; 801,188 attack rows and no benign rows | Event ground truth with timestamps and tuples, but no bytes, packets, duration, or packet aggregates. | **No** | Corroboration metadata only. It cannot create benign labels or fill missing production features. |
| Production CIC packet-window Parquet | **No labels** | Exact production packet-window contract; 484 rows and 48 columns. | **No supervised ML** | There is no independent target or ground truth. Labeling it with heuristics would create circular validation. |
| Research world-model NPZ artifacts | No new labels; trained from UNSW-derived flow states | Exact research 46-feature state contract only. | **No** | A serialized artifact is not evidence of compatibility or production validation. Stored results show limited coverage and no promotion over persistence. |

## Label and leakage assessment

- CIC labels originate from the dataset's flow capture labeling, but the files do not preserve event chronology required for a temporal packet-window target.
- UNSW labels originate in the source traffic dataset and are genuine, but they describe flow records and attack categories rather than the production packet-window target.
- TON-IoT Network 23 has the strongest local combination of timestamps, benign/attack labels, and flow features. It remains a different dataset and contract; source/destination IPs, fixed capture periods, duplicate timestamp keys, and attack concentration are leakage risks.
- TON-IoT GroundTruth Network 18 is attack-only event metadata. It must not be used to fabricate benign traffic labels.
- No duplicate, temporal, or label handling can reconcile these sources with unlabeled production packet windows without changing the target definition.
- Heuristic output must not be converted into ML labels. That would be heuristic -> label -> ML -> validation circularity.

## Required data to enable production ML

1. Packet or packet-window records generated with the same 48-column production feature contract, or a deliberately versioned replacement contract used by both training and inference.
2. Independently sourced benign/attack labels for the same window target, with provenance and labeling rules.
3. Stable timestamps and capture/scenario identifiers sufficient for chronological, scenario-separated train/validation/test splits.
4. Duplicate and overlap checks at the packet, flow, tuple, and window levels.
5. A held-out test set untouched during preprocessing and model selection.
6. Calibration data and calibration evaluation before exposing probabilities as confidence.

## Future-ready architecture

`DetectionEngine` defines the stable analysis contract. `HeuristicDetector` is the only active production implementation. `MLDetector` is an explicit future implementation seam with `detection_method=validated_ml`; it is not instantiated or served until a compatible labeled dataset passes the promotion gates. A future `hybrid` mode must preserve separate evidence sources and must not imply that heuristic rules are model explanations.

## Current SIH positioning

**Current:** Explainable traffic heuristics over verified packet windows.

**Future:** Validated ML detector after compatible labeled packet/window data, leakage-safe evaluation, independent test metrics, and calibration evidence are available.

The product should not claim AI-powered threat detection, supervised attack classification, calibrated confidence, or model predictions for the current production dashboard.

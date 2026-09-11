# Phase 5 Temporal Dataset Audit

| Dataset | Source | Rows | Timestamp Field | Support | Episodes | Eligible 5-Horizon Cases | Decision |
|---|---|---|---|---|---|---|---|
| UNSW-NB15 | `UNSW-NB15/raw/UNSW-NB15_{1..4}.csv` | 2800000 | Stime (col 28) / Ltime (col 29) | **SUPPORTED** | 5 | 1 | primary research domain; Episode 0 train, Episode 1 val, Episode 2 test; Ep 3 and 4 are pure attack |
| TON-IoT Network_dataset_23 | `TON-IoT/validation/Network_dataset_23.csv` | 339021 | ts | **SUPPORTED** | 4 | 2 | external-domain evaluation; Ep 0 train, Ep 1 val, Ep 2 test; not merged with UNSW |
| TON-IoT GroundTruth_Network_18 | `TON-IoT/validation/GroundTruth_Network_18.csv` | 801188 | ts | **UNSUPPORTED_STANDALONE** | 0 | 0 | attack-only event log; not a standalone benign/attack forecasting dataset |
| CIC-IDS2017 flow CSVs | `CIC-IDS2017/MachineLearningCSV/MachineLearningCVE/*.csv` | 2830743 | none | **TEMPORAL_FORECASTING_UNSUPPORTED** | 0 | 0 | temporal forecasting blocked; no event timestamps |
| NF-UNSW-NB15-v2 | `Downloads archive fe6cb615d161452c_MOHANAD_A4706.zip` | audited archive (~441 MB CSV) | none | **TEMPORAL_FORECASTING_UNSUPPORTED** | 0 | 0 | temporal forecasting blocked without timestamps |
| CIC packet Parquet | `data/processed/cic_ids2017_packet_windows.parquet` | 484 | window_start | **DETECTION_ANALYTICS_ONLY** | 1 | 0 | detection evidence only; unlabeled and model-incompatible |

## Independent Episode Summary
- **UNSW-NB15 Independent Episodes:** 5 (Total Eligible Cases: 1381)
- **TON-IoT Independent Episodes:** 4 (Total Eligible Cases: 853)
- **Datasets Combined:** NO. Merging rows across capture or dataset boundaries is strictly forbidden.

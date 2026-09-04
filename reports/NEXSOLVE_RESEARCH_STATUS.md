# NexSolve Research Status

## SIH 26153 World Model Data Foundation

As of 2026-09-03, local inspection of `TON-IoT/`, `CIC-IDS2017/`, and `UNSW-NB15/` found no `.pcap`, `.pcapng`, Zeek `conn.log`, or packet-derived feature file. Existing local CSVs are flow/event tables. CIC flow CSVs contain packet and IAT aggregates, TCP flag counts, and initial window-byte fields, but these are not raw packet observations and do not verify TTL variance, payload distribution, fragment flags, or retransmission evidence.

The smallest practical official development source is the single CIC-IDS2017 scenario capture `Friday-WorkingHours-Afternoon-PortScan.pcap`, accessed through the official UNB/CIC download page. UNB documents Friday as 8.3 GB total, with normal traffic and attacks including Port Scan, but does not publish this scenario file's standalone byte size. Its exact local size, SHA-256, packet field coverage, and overlap with TON-IoT Network 23 remain unknown until acquisition. No correspondence may be assumed between CIC and TON-IoT files.

Design artifacts: `reports/sih_world_model_data_foundation.md`, `reports/sih_world_model_data_foundation.json`, `reports/packet_feature_specification.md`, `reports/packet_feature_specification.json`, `reports/world_model_design.md`, and `reports/world_model_design.json`. The proposed state is flow plus verified packet plus past-only temporal features. The proposed rollout is `K=5` contiguous 60-second steps. No model was trained, and CIC-IDS2017, UNSW-NB15, TON-IoT source CSVs, MITRE, and production NexSolve were not modified.

Run timestamp (UTC): `2026-09-03T10:49:46+00:00`

## Dataset Status

```json
{
  "CIC-IDS2017": "Inspected; quality computed.",
  "UNSW-NB15": "Inspected; all seven required files read and quality computed.",
  "MITRE": "Local enterprise ATT&CK 19.2 JSON inspected; 858 attack-pattern objects."
}
```

## Temporal Findings

```json
{
  "UNSW": "60-second timestamp windows computed.",
  "CIC": "Not available: the eight extracted CIC CSVs contain flow features and Label but no timestamp column.",
  "CIC_timestamp_source_state": "D"
}
```

## Forecast Definition

```json
{
  "observation_window": "One 60-second non-empty traffic window; 60 seconds is retained because it gives 1,441 windows and sufficient per-window traffic density.",
  "forecast_horizon": "The next contiguous 60-second window.",
  "forecast_unit": "One timestamp window per dataset, chronological order only.",
  "state_representation": "Binary observed security state: BENIGN (Label=0) or ATTACK (Label=1; attack_cat retained as descriptive metadata). MITRE lifecycle stages are not directly observed.",
  "target": "Binary security state of the immediately following contiguous 60-second window, evaluated only from future-window labels.",
  "minimum_evidence": "A candidate future episode must be contiguous, strictly after training, contain both states, and contain at least 20 valid adjacent forecast pairs. The current data provides one eligible episode with 24 pairs.",
  "prediction_time": "End of the observed window, before reading any target-window rows.",
  "probability_meaning": "A probability, when produced by a future model, must mean estimated probability of the target state conditional on information available through prediction time T; current baselines emit hard labels only.",
  "confidence": "Not implemented by current baselines; must not be inferred from hard-label accuracy.",
  "abstention": "Return insufficient evidence when history, traffic, state support, or training transition support is inadequate; report coverage and abstention separately.",
  "allowed_information": "Rows and aggregates timestamped at or before the observation-window end.",
  "forbidden_information": "Future-window rows, labels, attack categories, GT events, future-fitted preprocessing, future transition probabilities, and random shuffling.",
  "split": "Train and validation use the first two pre-test contiguous runs (80/20 chronologically); test is the first later complete contiguous run containing both states (2015-02-18 00:23-00:48 UTC). No randomization.",
  "metrics": "Macro-F1, per-class precision/recall/F1, balanced accuracy, confusion matrix, coverage, and abstention rate.",
  "detection_distinction": "Detection asks what is happening in the current observed window; forecasting asks what state occurs in the subsequent future window. Detection accuracy is not forecasting evidence."
}
```

## Detection Baseline

```json
{
  "dataset": "CIC-IDS2017",
  "model": "LogisticRegression",
  "features": "All numeric flow columns except Label; nonnumeric/nonfinite values replaced with 0.0.",
  "sampling": "Deterministic systematic sample, cap 50,000 valid rows per source file; source totals are also reported. Sampling bounds memory while preserving chronological file partitions.",
  "split": {
    "train": {
      "source_files": [
        "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Monday-WorkingHours.pcap_ISCX.csv",
        "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Tuesday-WorkingHours.pcap_ISCX.csv"
      ],
      "source_rows_total": 975827,
      "evaluated_samples": 97721,
      "label_distribution": {
        "0": 96194,
        "1": 1527
      }
    },
    "validation": {
      "source_files": [
        "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Wednesday-workingHours.pcap_ISCX.csv"
      ],
      "source_rows_total": 692703,
      "evaluated_samples": 49479,
      "label_distribution": {
        "0": 31396,
        "1": 18083
      }
    },
    "test": {
      "source_files": [
        "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Morning.pcap_ISCX.csv"
      ],
      "source_rows_total": 1162213,
      "evaluated_samples": 231346,
      "label_distribution": {
        "0": 178253,
        "1": 53093
      }
    }
  },
  "chronology": "Monday and Tuesday train, Wednesday validation, Thursday and Friday test. CIC files have no explicit timestamp, so chronology is available only at day-file granularity.",
  "preprocessing": "StandardScaler fitted on training samples only; class_weight=balanced fitted by the estimator using training labels only.",
  "parameters": {
    "solver": "liblinear",
    "max_iter": 100,
    "class_weight": "balanced",
    "random_state": 0
  },
  "validation_metrics": {
    "precision": 0.05526590198123045,
    "recall": 0.0029309296023889843,
    "f1": 0.005566642159437034,
    "macro_f1": 0.3843089229616946,
    "balanced_accuracy": 0.48703687517194233,
    "confusion_matrix": [
      [
        30490,
        906
      ],
      [
        18030,
        53
      ]
    ],
    "class_support": {
      "0": 31396,
      "1": 18083
    },
    "roc_auc": 0.3104770120918698,
    "pr_auc": 0.3842595411661054
  },
  "test_metrics": {
    "precision": 0.47944923962186603,
    "recall": 0.17576705027028044,
    "f1": 0.25723224499359126,
    "macro_f1": 0.5595464414889394,
    "balanced_accuracy": 0.5594632460935532,
    "confusion_matrix": [
      [
        168121,
        10132
      ],
      [
        43761,
        9332
      ]
    ],
    "class_support": {
      "0": 178253,
      "1": 53093
    },
    "roc_auc": 0.5392981881219244,
    "pr_auc": 0.3338916162413815
  },
  "limitations": [
    "No CIC event timestamp exists, so the chronological split is file/day based rather than flow-time based.",
    "Results are bounded deterministic samples, not full-row evaluation."
  ]
}
```

## Forecasting Baselines

```json
{
  "current_state": {
    "precision": 0.9285714285714286,
    "recall": 0.9285714285714286,
    "f1": 0.9285714285714286,
    "macro_f1": 0.9142857142857144,
    "balanced_accuracy": 0.9142857142857144,
    "confusion_matrix": [
      [
        9,
        1
      ],
      [
        1,
        13
      ]
    ],
    "class_support": {
      "1": 14,
      "0": 10
    },
    "roc_auc": "Not computed",
    "pr_auc": "Not computed",
    "forecast_cases": 24,
    "evaluated_cases": 24,
    "coverage": 1.0,
    "abstentions": 0,
    "abstention_rate": 0.0
  },
  "persistence": {
    "precision": 0.9285714285714286,
    "recall": 0.9285714285714286,
    "f1": 0.9285714285714286,
    "macro_f1": 0.9142857142857144,
    "balanced_accuracy": 0.9142857142857144,
    "confusion_matrix": [
      [
        9,
        1
      ],
      [
        1,
        13
      ]
    ],
    "class_support": {
      "1": 14,
      "0": 10
    },
    "roc_auc": "Not computed",
    "pr_auc": "Not computed",
    "forecast_cases": 24,
    "evaluated_cases": 24,
    "coverage": 1.0,
    "abstentions": 0,
    "abstention_rate": 0.0
  },
  "empirical_transition": {
    "precision": 0.9285714285714286,
    "recall": 0.9285714285714286,
    "f1": 0.9285714285714286,
    "macro_f1": 0.9142857142857144,
    "balanced_accuracy": 0.9142857142857144,
    "confusion_matrix": [
      [
        9,
        1
      ],
      [
        1,
        13
      ]
    ],
    "class_support": {
      "1": 14,
      "0": 10
    },
    "roc_auc": "Not computed",
    "pr_auc": "Not computed",
    "forecast_cases": 24,
    "evaluated_cases": 24,
    "coverage": 1.0,
    "abstentions": 0,
    "abstention_rate": 0.0
  }
}
```

## Coverage

```json
{
  "current_state": 1.0,
  "persistence": 1.0,
  "empirical_transition": 1.0
}
```

## Mitre

Unmapped.

## Explainability

Not computed.

## Cross Dataset

UNSW supports a small timestamped exploratory forecast; CIC supports detection benchmarking but not temporal forecasting from the available schema. CIC timestamp-source audit state: D.

## Model Decision

ADVANCED MODEL NOT JUSTIFIED: UNSW has one eligible future mixed-state episode and 24 pairs with tied baselines; CIC has no timestamp field.

## Expanded Forecast Evaluation

```json
{
  "eligible_episodes": 1,
  "total_forecast_cases": 24,
  "evidence_level": "extremely limited",
  "forecasting_value": "Not demonstrated: all three baselines tie on the sole eligible episode."
}
```

## Candidate Dataset Selection

```json
{
  "winner": "CIC-DDoS2019",
  "backup": "TON_IoT",
  "winner_score": 45,
  "backup_score": 42,
  "advanced_model": "NOT JUSTIFIED YET"
}
```

## Scientific Claim Boundary

## CIC-DDoS2019 Direct Validation

Decision D: **TIMESTAMP CLAIM NOT VERIFIED**. The official CIC/UNB endpoint requires a download-form submission and exposes no public generated-flow directory listing. No file was obtained, so file-level timestamp, schema, label, and join validation were not computed.

## TON_IoT Backup Validation

Decision D: **ACCESSIBLE SOURCE BUT EXACT VALIDATION FILE NOT IDENTIFIED**. The official UNSW page links to a public SharePoint folder and the folder is reachable, but its returned page exposed no exact CSV filenames or direct file URLs. No file was downloaded or guessed, so timestamp, schema, label, and 60-second window validation were not computed.

## TON_IoT Network 18 Validation

The first actual TON_IoT file, `TON-IoT/validation/GroundTruth_Network_18.csv`, is now validated. It contains 801,188 ordered Unix-second attack-event records from 2019-04-27T10:42:14Z through 2019-04-29T14:45:29Z, but no benign records, duration/bytes/packet features, or BENIGN-to-ATTACK transitions. Decision B: **TIMESTAMP EXISTS BUT MORE DATA REQUIRED**. A processed network traffic CSV with benign and attack flows is required before the locked forecasting experiment.

## TON_IoT Network 23 Validation

`TON-IoT/validation/Network_dataset_23.csv` is the first validated TON_IoT traffic file suitable for the locked feasibility setup. It contains 339,021 rows, 46 columns, explicit Unix-second `ts`, `label` values 0/1, flow duration/bytes/packet fields, 893 non-empty 60-second windows, and 889 contiguous forecast pairs. It has 30 benign and 863 attack windows, with 11 BENIGN-to-ATTACK and 12 ATTACK-to-BENIGN transitions. The file is not globally timestamp-sorted and must be grouped by `ts`; no forecasting model was run. Decision A: **READY FOR FULL TEMPORAL EVALUATION**.

```json
{
  "supported_now": [
    "Local network traffic ingestion and deterministic feature extraction",
    "CIC malicious/benign detection benchmarking",
    "UNSW timestamp-based temporal analysis",
    "Binary next-window baseline evaluation on one mixed-state future episode",
    "Local MITRE ATT&CK v19.2 data integration"
  ],
  "limited_evidence": [
    "UNSW attack-state forecasting: one eligible future episode and 24 forecast pairs",
    "Future transition prediction: baselines tie exactly",
    "Probability/confidence estimates: not produced by current hard-label baselines",
    "Explainability: no model contribution analysis computed"
  ],
  "not_supported_yet": [
    "High-confidence real-world attack prediction",
    "Generalization to arbitrary networks",
    "Multi-stage MITRE attack forecasting",
    "Production-grade forecasting accuracy",
    "Claims of beating advanced forecasting models",
    "Claims of preventing attacks",
    "CIC temporal forecasting from current files"
  ],
  "scientific_claim": "NexSolve currently demonstrates a leakage-audited research contract and limited UNSW next-state baseline evidence, not forecasting superiority or operational prediction."
}
```

## Product Prediction

Given network behavior observed through prediction time T, NexSolve may estimate the next contiguous 60-second UNSW security state as BENIGN or ATTACK; current baselines provide hard labels only and do not establish operational forecasting value.

## Conceptual Product Contract

Network traffic -> ingestion -> current detection -> temporal state -> forecast engine -> evidence-based ATT&CK context -> non-causal explanation -> alert/risk/recommended action.

## Limitations

```json
[
  "No existing research implementation was available.",
  "CIC has no flow timestamp, so its split is day-file based rather than flow-time based.",
  "Detection uses a deterministic cap of 50,000 sampled rows per CIC file.",
  "Global duplicate counts were not computed to avoid excessive memory use.",
  "UNSW forecast test has only 24 contiguous pairs, though both target states are present."
]
```

## Recommended Next Engineering Step

Inspect the official CIC-DDoS2019 directory and acquire one smallest generated flow CSV for timestamp/schema validation; do not download the full dataset.

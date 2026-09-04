# World Model Evaluation

```json
{
  "dataset": "UNSW-NB15",
  "feature_groups": {
    "flow": [
      "flow_count",
      "total_src_bytes",
      "total_dst_bytes",
      "total_packets",
      "mean_duration",
      "mean_flow_bytes",
      "mean_flow_packets",
      "mean_sttl",
      "mean_dttl",
      "mean_swin",
      "mean_dwin",
      "mean_iat",
      "mean_tcp_rtt",
      "unique_src_ports",
      "unique_dst_ports",
      "proto_tcp_count",
      "proto_udp_count",
      "proto_other_count"
    ],
    "packet": [
      "packet_count",
      "mean_packet_size",
      "std_packet_size",
      "min_packet_size",
      "max_packet_size",
      "mean_ttl",
      "std_ttl",
      "min_ttl",
      "max_ttl",
      "tcp_syn_count",
      "tcp_ack_count",
      "tcp_fin_count",
      "tcp_rst_count",
      "tcp_psh_count",
      "tcp_urg_count",
      "mean_tcp_window",
      "std_tcp_window",
      "fragment_count",
      "retransmission_count",
      "mean_iat",
      "std_iat",
      "max_iat"
    ],
    "temporal": [
      "delta_flow_count",
      "delta_total_bytes",
      "delta_total_packets",
      "delta_ports",
      "delta_iat",
      "rolling_total_bytes"
    ]
  },
  "split_definition": "Existing 60-second contiguous-run split: first two runs pre-test, 80/20 train/validation; first later mixed-state run untouched test.",
  "model": "LSTM trained only on train windows; packet interface currently unavailable and zero-filled with availability=false.",
  "training_results": {
    "source": "results/world_model_training.json"
  },
  "test_results": {
    "lstm": {
      "precision": 1.0,
      "recall": 0.36363636363636365,
      "f1": 0.5333333333333333,
      "macro_f1": 0.5607843137254902,
      "balanced_accuracy": 0.6818181818181819,
      "confusion_matrix": [
        [
          5,
          0
        ],
        [
          7,
          4
        ]
      ],
      "roc_auc": 0.6363636363636364,
      "pr_auc": 0.8485791985791986,
      "coverage": 0.6666666666666666,
      "abstention_rate": 0.3333333333333333,
      "forecast_cases": 24,
      "evaluated_cases": 16,
      "abstentions": 8
    },
    "temporal_persistence": {
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
      "roc_auc": 0.9142857142857144,
      "pr_auc": 0.9039115646258503,
      "coverage": 1.0,
      "abstention_rate": 0.0,
      "forecast_cases": 24
    }
  },
  "baseline_comparison": "No improvement claim is made without a measured advantage over persistence.",
  "existing_logistic_regression_baseline": {
    "source": "results/detection_baseline.json",
    "status": "Not directly comparable: it is a CIC-IDS2017 static detection baseline, while this is UNSW-NB15 next-window forecasting.",
    "preserved": true
  },
  "leakage_checks": [
    "labels used only as next-state targets",
    "attack_ratio, filenames, scenarios, IPs, and tuple identifiers excluded",
    "scaler fit on training windows only",
    "chronological split preserved",
    "test labels read only for scoring",
    "train/test time gap was not crossed for LSTM context"
  ],
  "limitations": [
    "One 24-pair mixed-state test episode",
    "LSTM abstains on the first eight test sources because contiguous test history is insufficient",
    "No raw PCAP is available yet",
    "Packet features are an explicit unavailable interface, not fabricated observations",
    "NumPy LSTM is a compact execution-critical prototype"
  ],
  "packet_audit_blocker": "Stop model work and audit the PCAP immediately when the Friday PCAP appears."
}
```

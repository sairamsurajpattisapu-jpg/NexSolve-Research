# CIC-IDS2017 Flow Audit

This audit covers only the eight ISCX flow CSVs. They are not packet captures.

## Executive Findings

- No file contains an exact timestamp, source/destination IP, source port, or protocol field.
- Flow aggregates are usable; packet-level and causal event-time features remain unavailable.
- The files cannot be combined chronologically without an external timestamp source.
- The adapter preserves source order and rejects malformed records; it does not retrain or modify the World Model.

## Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

- Size: 77123859 bytes
- Rows: 225745 (225711 valid)
- Columns: 79
- Timestamp: unavailable
- Timestamp range: {'min': None, 'max': None}
- Labels: `{"BENIGN": 97718, "DDOS": 128027}`
- Missing values: {'total_cells': 0, 'by_column': {}}
- Malformed values: {'total_rows': 34, 'wrong_width_rows': 0, 'non_numeric_rows': 34, 'by_column': {'Flow Bytes/s': 34, 'Flow Packets/s': 34}}
- Duplicate rows: 2633
- Source/destination IPs: unavailable / unavailable
- Source/destination ports: unavailable / Destination Port available
- Protocol: unavailable

### Exact Columns

```text
Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

### Feature Availability

```json
{
  "flow": {
    "bytes": [
      "Total Length of Fwd Packets",
      "Total Length of Bwd Packets",
      "Flow Bytes/s",
      "Fwd Packet Length Max",
      "Fwd Packet Length Min",
      "Fwd Packet Length Mean",
      "Fwd Packet Length Std",
      "Bwd Packet Length Max",
      "Bwd Packet Length Min",
      "Bwd Packet Length Mean",
      "Bwd Packet Length Std",
      "Min Packet Length",
      "Max Packet Length",
      "Packet Length Mean",
      "Packet Length Std",
      "Packet Length Variance",
      "Average Packet Size",
      "Avg Fwd Segment Size",
      "Avg Bwd Segment Size",
      "Subflow Fwd Bytes",
      "Subflow Bwd Bytes"
    ],
    "packets": [
      "Total Fwd Packets",
      "Total Backward Packets",
      "Flow Packets/s",
      "Fwd Packets/s",
      "Bwd Packets/s",
      "Subflow Fwd Packets",
      "Subflow Bwd Packets"
    ],
    "duration": [
      "Flow Duration",
      "Active Mean",
      "Active Std",
      "Active Max",
      "Active Min",
      "Idle Mean",
      "Idle Std",
      "Idle Max",
      "Idle Min"
    ],
    "tcp_flags": [
      "Fwd PSH Flags",
      "Bwd PSH Flags",
      "Fwd URG Flags",
      "Bwd URG Flags",
      "FIN Flag Count",
      "SYN Flag Count",
      "RST Flag Count",
      "PSH Flag Count",
      "ACK Flag Count",
      "URG Flag Count",
      "CWE Flag Count",
      "ECE Flag Count"
    ],
    "iat": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "flow_direction_and_other": [
      "Destination Port",
      "Down/Up Ratio",
      "Fwd Header Length",
      "Bwd Header Length",
      "Init_Win_bytes_forward",
      "Init_Win_bytes_backward",
      "act_data_pkt_fwd",
      "min_seg_size_forward"
    ]
  },
  "packet": {
    "ttl": {
      "available": false,
      "columns": []
    },
    "ttl_variance": {
      "available": false,
      "columns": []
    },
    "tcp_window_size": {
      "available": false,
      "columns": []
    },
    "fragmentation": {
      "available": false,
      "columns": []
    },
    "payload_size_distribution": {
      "available": false,
      "columns": []
    },
    "retransmission_indicators": {
      "available": false,
      "columns": []
    },
    "packet_level_timing": {
      "available": false,
      "columns": []
    },
    "packet_level_scan_signatures": {
      "available": false,
      "columns": []
    }
  },
  "temporal": {
    "within_flow_iat_columns": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "causal_event_timestamp": false,
    "causal_temporal_features_available": false
  }
}
```

## Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv

- Size: 76906168 bytes
- Rows: 286467 (286096 valid)
- Columns: 79
- Timestamp: unavailable
- Timestamp range: {'min': None, 'max': None}
- Labels: `{"BENIGN": 127537, "PORTSCAN": 158930}`
- Missing values: {'total_cells': 0, 'by_column': {}}
- Malformed values: {'total_rows': 371, 'wrong_width_rows': 0, 'non_numeric_rows': 371, 'by_column': {'Flow Bytes/s': 371, 'Flow Packets/s': 371}}
- Duplicate rows: 72353
- Source/destination IPs: unavailable / unavailable
- Source/destination ports: unavailable / Destination Port available
- Protocol: unavailable

### Exact Columns

```text
Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

### Feature Availability

```json
{
  "flow": {
    "bytes": [
      "Total Length of Fwd Packets",
      "Total Length of Bwd Packets",
      "Flow Bytes/s",
      "Fwd Packet Length Max",
      "Fwd Packet Length Min",
      "Fwd Packet Length Mean",
      "Fwd Packet Length Std",
      "Bwd Packet Length Max",
      "Bwd Packet Length Min",
      "Bwd Packet Length Mean",
      "Bwd Packet Length Std",
      "Min Packet Length",
      "Max Packet Length",
      "Packet Length Mean",
      "Packet Length Std",
      "Packet Length Variance",
      "Average Packet Size",
      "Avg Fwd Segment Size",
      "Avg Bwd Segment Size",
      "Subflow Fwd Bytes",
      "Subflow Bwd Bytes"
    ],
    "packets": [
      "Total Fwd Packets",
      "Total Backward Packets",
      "Flow Packets/s",
      "Fwd Packets/s",
      "Bwd Packets/s",
      "Subflow Fwd Packets",
      "Subflow Bwd Packets"
    ],
    "duration": [
      "Flow Duration",
      "Active Mean",
      "Active Std",
      "Active Max",
      "Active Min",
      "Idle Mean",
      "Idle Std",
      "Idle Max",
      "Idle Min"
    ],
    "tcp_flags": [
      "Fwd PSH Flags",
      "Bwd PSH Flags",
      "Fwd URG Flags",
      "Bwd URG Flags",
      "FIN Flag Count",
      "SYN Flag Count",
      "RST Flag Count",
      "PSH Flag Count",
      "ACK Flag Count",
      "URG Flag Count",
      "CWE Flag Count",
      "ECE Flag Count"
    ],
    "iat": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "flow_direction_and_other": [
      "Destination Port",
      "Down/Up Ratio",
      "Fwd Header Length",
      "Bwd Header Length",
      "Init_Win_bytes_forward",
      "Init_Win_bytes_backward",
      "act_data_pkt_fwd",
      "min_seg_size_forward"
    ]
  },
  "packet": {
    "ttl": {
      "available": false,
      "columns": []
    },
    "ttl_variance": {
      "available": false,
      "columns": []
    },
    "tcp_window_size": {
      "available": false,
      "columns": []
    },
    "fragmentation": {
      "available": false,
      "columns": []
    },
    "payload_size_distribution": {
      "available": false,
      "columns": []
    },
    "retransmission_indicators": {
      "available": false,
      "columns": []
    },
    "packet_level_timing": {
      "available": false,
      "columns": []
    },
    "packet_level_scan_signatures": {
      "available": false,
      "columns": []
    }
  },
  "temporal": {
    "within_flow_iat_columns": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "causal_event_timestamp": false,
    "causal_temporal_features_available": false
  }
}
```

## Friday-WorkingHours-Morning.pcap_ISCX.csv

- Size: 58316725 bytes
- Rows: 191033 (190911 valid)
- Columns: 79
- Timestamp: unavailable
- Timestamp range: {'min': None, 'max': None}
- Labels: `{"BENIGN": 189067, "BOT": 1966}`
- Missing values: {'total_cells': 0, 'by_column': {}}
- Malformed values: {'total_rows': 122, 'wrong_width_rows': 0, 'non_numeric_rows': 122, 'by_column': {'Flow Bytes/s': 122, 'Flow Packets/s': 122}}
- Duplicate rows: 6888
- Source/destination IPs: unavailable / unavailable
- Source/destination ports: unavailable / Destination Port available
- Protocol: unavailable

### Exact Columns

```text
Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

### Feature Availability

```json
{
  "flow": {
    "bytes": [
      "Total Length of Fwd Packets",
      "Total Length of Bwd Packets",
      "Flow Bytes/s",
      "Fwd Packet Length Max",
      "Fwd Packet Length Min",
      "Fwd Packet Length Mean",
      "Fwd Packet Length Std",
      "Bwd Packet Length Max",
      "Bwd Packet Length Min",
      "Bwd Packet Length Mean",
      "Bwd Packet Length Std",
      "Min Packet Length",
      "Max Packet Length",
      "Packet Length Mean",
      "Packet Length Std",
      "Packet Length Variance",
      "Average Packet Size",
      "Avg Fwd Segment Size",
      "Avg Bwd Segment Size",
      "Subflow Fwd Bytes",
      "Subflow Bwd Bytes"
    ],
    "packets": [
      "Total Fwd Packets",
      "Total Backward Packets",
      "Flow Packets/s",
      "Fwd Packets/s",
      "Bwd Packets/s",
      "Subflow Fwd Packets",
      "Subflow Bwd Packets"
    ],
    "duration": [
      "Flow Duration",
      "Active Mean",
      "Active Std",
      "Active Max",
      "Active Min",
      "Idle Mean",
      "Idle Std",
      "Idle Max",
      "Idle Min"
    ],
    "tcp_flags": [
      "Fwd PSH Flags",
      "Bwd PSH Flags",
      "Fwd URG Flags",
      "Bwd URG Flags",
      "FIN Flag Count",
      "SYN Flag Count",
      "RST Flag Count",
      "PSH Flag Count",
      "ACK Flag Count",
      "URG Flag Count",
      "CWE Flag Count",
      "ECE Flag Count"
    ],
    "iat": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "flow_direction_and_other": [
      "Destination Port",
      "Down/Up Ratio",
      "Fwd Header Length",
      "Bwd Header Length",
      "Init_Win_bytes_forward",
      "Init_Win_bytes_backward",
      "act_data_pkt_fwd",
      "min_seg_size_forward"
    ]
  },
  "packet": {
    "ttl": {
      "available": false,
      "columns": []
    },
    "ttl_variance": {
      "available": false,
      "columns": []
    },
    "tcp_window_size": {
      "available": false,
      "columns": []
    },
    "fragmentation": {
      "available": false,
      "columns": []
    },
    "payload_size_distribution": {
      "available": false,
      "columns": []
    },
    "retransmission_indicators": {
      "available": false,
      "columns": []
    },
    "packet_level_timing": {
      "available": false,
      "columns": []
    },
    "packet_level_scan_signatures": {
      "available": false,
      "columns": []
    }
  },
  "temporal": {
    "within_flow_iat_columns": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "causal_event_timestamp": false,
    "causal_temporal_features_available": false
  }
}
```

## Monday-WorkingHours.pcap_ISCX.csv

- Size: 176927918 bytes
- Rows: 529918 (529481 valid)
- Columns: 79
- Timestamp: unavailable
- Timestamp range: {'min': None, 'max': None}
- Labels: `{"BENIGN": 529918}`
- Missing values: {'total_cells': 0, 'by_column': {}}
- Malformed values: {'total_rows': 437, 'wrong_width_rows': 0, 'non_numeric_rows': 437, 'by_column': {'Flow Bytes/s': 437, 'Flow Packets/s': 437}}
- Duplicate rows: 26935
- Source/destination IPs: unavailable / unavailable
- Source/destination ports: unavailable / Destination Port available
- Protocol: unavailable

### Exact Columns

```text
Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

### Feature Availability

```json
{
  "flow": {
    "bytes": [
      "Total Length of Fwd Packets",
      "Total Length of Bwd Packets",
      "Flow Bytes/s",
      "Fwd Packet Length Max",
      "Fwd Packet Length Min",
      "Fwd Packet Length Mean",
      "Fwd Packet Length Std",
      "Bwd Packet Length Max",
      "Bwd Packet Length Min",
      "Bwd Packet Length Mean",
      "Bwd Packet Length Std",
      "Min Packet Length",
      "Max Packet Length",
      "Packet Length Mean",
      "Packet Length Std",
      "Packet Length Variance",
      "Average Packet Size",
      "Avg Fwd Segment Size",
      "Avg Bwd Segment Size",
      "Subflow Fwd Bytes",
      "Subflow Bwd Bytes"
    ],
    "packets": [
      "Total Fwd Packets",
      "Total Backward Packets",
      "Flow Packets/s",
      "Fwd Packets/s",
      "Bwd Packets/s",
      "Subflow Fwd Packets",
      "Subflow Bwd Packets"
    ],
    "duration": [
      "Flow Duration",
      "Active Mean",
      "Active Std",
      "Active Max",
      "Active Min",
      "Idle Mean",
      "Idle Std",
      "Idle Max",
      "Idle Min"
    ],
    "tcp_flags": [
      "Fwd PSH Flags",
      "Bwd PSH Flags",
      "Fwd URG Flags",
      "Bwd URG Flags",
      "FIN Flag Count",
      "SYN Flag Count",
      "RST Flag Count",
      "PSH Flag Count",
      "ACK Flag Count",
      "URG Flag Count",
      "CWE Flag Count",
      "ECE Flag Count"
    ],
    "iat": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "flow_direction_and_other": [
      "Destination Port",
      "Down/Up Ratio",
      "Fwd Header Length",
      "Bwd Header Length",
      "Init_Win_bytes_forward",
      "Init_Win_bytes_backward",
      "act_data_pkt_fwd",
      "min_seg_size_forward"
    ]
  },
  "packet": {
    "ttl": {
      "available": false,
      "columns": []
    },
    "ttl_variance": {
      "available": false,
      "columns": []
    },
    "tcp_window_size": {
      "available": false,
      "columns": []
    },
    "fragmentation": {
      "available": false,
      "columns": []
    },
    "payload_size_distribution": {
      "available": false,
      "columns": []
    },
    "retransmission_indicators": {
      "available": false,
      "columns": []
    },
    "packet_level_timing": {
      "available": false,
      "columns": []
    },
    "packet_level_scan_signatures": {
      "available": false,
      "columns": []
    }
  },
  "temporal": {
    "within_flow_iat_columns": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "causal_event_timestamp": false,
    "causal_temporal_features_available": false
  }
}
```

## Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv

- Size: 83102436 bytes
- Rows: 288602 (288395 valid)
- Columns: 79
- Timestamp: unavailable
- Timestamp range: {'min': None, 'max': None}
- Labels: `{"BENIGN": 288566, "INFILTRATION": 36}`
- Missing values: {'total_cells': 0, 'by_column': {}}
- Malformed values: {'total_rows': 207, 'wrong_width_rows': 0, 'non_numeric_rows': 207, 'by_column': {'Flow Bytes/s': 207, 'Flow Packets/s': 207}}
- Duplicate rows: 35630
- Source/destination IPs: unavailable / unavailable
- Source/destination ports: unavailable / Destination Port available
- Protocol: unavailable

### Exact Columns

```text
Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

### Feature Availability

```json
{
  "flow": {
    "bytes": [
      "Total Length of Fwd Packets",
      "Total Length of Bwd Packets",
      "Flow Bytes/s",
      "Fwd Packet Length Max",
      "Fwd Packet Length Min",
      "Fwd Packet Length Mean",
      "Fwd Packet Length Std",
      "Bwd Packet Length Max",
      "Bwd Packet Length Min",
      "Bwd Packet Length Mean",
      "Bwd Packet Length Std",
      "Min Packet Length",
      "Max Packet Length",
      "Packet Length Mean",
      "Packet Length Std",
      "Packet Length Variance",
      "Average Packet Size",
      "Avg Fwd Segment Size",
      "Avg Bwd Segment Size",
      "Subflow Fwd Bytes",
      "Subflow Bwd Bytes"
    ],
    "packets": [
      "Total Fwd Packets",
      "Total Backward Packets",
      "Flow Packets/s",
      "Fwd Packets/s",
      "Bwd Packets/s",
      "Subflow Fwd Packets",
      "Subflow Bwd Packets"
    ],
    "duration": [
      "Flow Duration",
      "Active Mean",
      "Active Std",
      "Active Max",
      "Active Min",
      "Idle Mean",
      "Idle Std",
      "Idle Max",
      "Idle Min"
    ],
    "tcp_flags": [
      "Fwd PSH Flags",
      "Bwd PSH Flags",
      "Fwd URG Flags",
      "Bwd URG Flags",
      "FIN Flag Count",
      "SYN Flag Count",
      "RST Flag Count",
      "PSH Flag Count",
      "ACK Flag Count",
      "URG Flag Count",
      "CWE Flag Count",
      "ECE Flag Count"
    ],
    "iat": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "flow_direction_and_other": [
      "Destination Port",
      "Down/Up Ratio",
      "Fwd Header Length",
      "Bwd Header Length",
      "Init_Win_bytes_forward",
      "Init_Win_bytes_backward",
      "act_data_pkt_fwd",
      "min_seg_size_forward"
    ]
  },
  "packet": {
    "ttl": {
      "available": false,
      "columns": []
    },
    "ttl_variance": {
      "available": false,
      "columns": []
    },
    "tcp_window_size": {
      "available": false,
      "columns": []
    },
    "fragmentation": {
      "available": false,
      "columns": []
    },
    "payload_size_distribution": {
      "available": false,
      "columns": []
    },
    "retransmission_indicators": {
      "available": false,
      "columns": []
    },
    "packet_level_timing": {
      "available": false,
      "columns": []
    },
    "packet_level_scan_signatures": {
      "available": false,
      "columns": []
    }
  },
  "temporal": {
    "within_flow_iat_columns": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "causal_event_timestamp": false,
    "causal_temporal_features_available": false
  }
}
```

## Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv

- Size: 52023263 bytes
- Rows: 170366 (170231 valid)
- Columns: 79
- Timestamp: unavailable
- Timestamp range: {'min': None, 'max': None}
- Labels: `{"BENIGN": 168186, "WEB ATTACK \ufffd BRUTE FORCE": 1507, "WEB ATTACK \ufffd XSS": 652, "WEB ATTACK \ufffd SQL INJECTION": 21}`
- Missing values: {'total_cells': 0, 'by_column': {}}
- Malformed values: {'total_rows': 135, 'wrong_width_rows': 0, 'non_numeric_rows': 135, 'by_column': {'Flow Bytes/s': 135, 'Flow Packets/s': 135}}
- Duplicate rows: 6066
- Source/destination IPs: unavailable / unavailable
- Source/destination ports: unavailable / Destination Port available
- Protocol: unavailable

### Exact Columns

```text
Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

### Feature Availability

```json
{
  "flow": {
    "bytes": [
      "Total Length of Fwd Packets",
      "Total Length of Bwd Packets",
      "Flow Bytes/s",
      "Fwd Packet Length Max",
      "Fwd Packet Length Min",
      "Fwd Packet Length Mean",
      "Fwd Packet Length Std",
      "Bwd Packet Length Max",
      "Bwd Packet Length Min",
      "Bwd Packet Length Mean",
      "Bwd Packet Length Std",
      "Min Packet Length",
      "Max Packet Length",
      "Packet Length Mean",
      "Packet Length Std",
      "Packet Length Variance",
      "Average Packet Size",
      "Avg Fwd Segment Size",
      "Avg Bwd Segment Size",
      "Subflow Fwd Bytes",
      "Subflow Bwd Bytes"
    ],
    "packets": [
      "Total Fwd Packets",
      "Total Backward Packets",
      "Flow Packets/s",
      "Fwd Packets/s",
      "Bwd Packets/s",
      "Subflow Fwd Packets",
      "Subflow Bwd Packets"
    ],
    "duration": [
      "Flow Duration",
      "Active Mean",
      "Active Std",
      "Active Max",
      "Active Min",
      "Idle Mean",
      "Idle Std",
      "Idle Max",
      "Idle Min"
    ],
    "tcp_flags": [
      "Fwd PSH Flags",
      "Bwd PSH Flags",
      "Fwd URG Flags",
      "Bwd URG Flags",
      "FIN Flag Count",
      "SYN Flag Count",
      "RST Flag Count",
      "PSH Flag Count",
      "ACK Flag Count",
      "URG Flag Count",
      "CWE Flag Count",
      "ECE Flag Count"
    ],
    "iat": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "flow_direction_and_other": [
      "Destination Port",
      "Down/Up Ratio",
      "Fwd Header Length",
      "Bwd Header Length",
      "Init_Win_bytes_forward",
      "Init_Win_bytes_backward",
      "act_data_pkt_fwd",
      "min_seg_size_forward"
    ]
  },
  "packet": {
    "ttl": {
      "available": false,
      "columns": []
    },
    "ttl_variance": {
      "available": false,
      "columns": []
    },
    "tcp_window_size": {
      "available": false,
      "columns": []
    },
    "fragmentation": {
      "available": false,
      "columns": []
    },
    "payload_size_distribution": {
      "available": false,
      "columns": []
    },
    "retransmission_indicators": {
      "available": false,
      "columns": []
    },
    "packet_level_timing": {
      "available": false,
      "columns": []
    },
    "packet_level_scan_signatures": {
      "available": false,
      "columns": []
    }
  },
  "temporal": {
    "within_flow_iat_columns": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "causal_event_timestamp": false,
    "causal_temporal_features_available": false
  }
}
```

## Tuesday-WorkingHours.pcap_ISCX.csv

- Size: 135078995 bytes
- Rows: 445909 (445645 valid)
- Columns: 79
- Timestamp: unavailable
- Timestamp range: {'min': None, 'max': None}
- Labels: `{"BENIGN": 432074, "FTP-PATATOR": 7938, "SSH-PATATOR": 5897}`
- Missing values: {'total_cells': 0, 'by_column': {}}
- Malformed values: {'total_rows': 264, 'wrong_width_rows': 0, 'non_numeric_rows': 264, 'by_column': {'Flow Bytes/s': 264, 'Flow Packets/s': 264}}
- Duplicate rows: 24065
- Source/destination IPs: unavailable / unavailable
- Source/destination ports: unavailable / Destination Port available
- Protocol: unavailable

### Exact Columns

```text
Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

### Feature Availability

```json
{
  "flow": {
    "bytes": [
      "Total Length of Fwd Packets",
      "Total Length of Bwd Packets",
      "Flow Bytes/s",
      "Fwd Packet Length Max",
      "Fwd Packet Length Min",
      "Fwd Packet Length Mean",
      "Fwd Packet Length Std",
      "Bwd Packet Length Max",
      "Bwd Packet Length Min",
      "Bwd Packet Length Mean",
      "Bwd Packet Length Std",
      "Min Packet Length",
      "Max Packet Length",
      "Packet Length Mean",
      "Packet Length Std",
      "Packet Length Variance",
      "Average Packet Size",
      "Avg Fwd Segment Size",
      "Avg Bwd Segment Size",
      "Subflow Fwd Bytes",
      "Subflow Bwd Bytes"
    ],
    "packets": [
      "Total Fwd Packets",
      "Total Backward Packets",
      "Flow Packets/s",
      "Fwd Packets/s",
      "Bwd Packets/s",
      "Subflow Fwd Packets",
      "Subflow Bwd Packets"
    ],
    "duration": [
      "Flow Duration",
      "Active Mean",
      "Active Std",
      "Active Max",
      "Active Min",
      "Idle Mean",
      "Idle Std",
      "Idle Max",
      "Idle Min"
    ],
    "tcp_flags": [
      "Fwd PSH Flags",
      "Bwd PSH Flags",
      "Fwd URG Flags",
      "Bwd URG Flags",
      "FIN Flag Count",
      "SYN Flag Count",
      "RST Flag Count",
      "PSH Flag Count",
      "ACK Flag Count",
      "URG Flag Count",
      "CWE Flag Count",
      "ECE Flag Count"
    ],
    "iat": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "flow_direction_and_other": [
      "Destination Port",
      "Down/Up Ratio",
      "Fwd Header Length",
      "Bwd Header Length",
      "Init_Win_bytes_forward",
      "Init_Win_bytes_backward",
      "act_data_pkt_fwd",
      "min_seg_size_forward"
    ]
  },
  "packet": {
    "ttl": {
      "available": false,
      "columns": []
    },
    "ttl_variance": {
      "available": false,
      "columns": []
    },
    "tcp_window_size": {
      "available": false,
      "columns": []
    },
    "fragmentation": {
      "available": false,
      "columns": []
    },
    "payload_size_distribution": {
      "available": false,
      "columns": []
    },
    "retransmission_indicators": {
      "available": false,
      "columns": []
    },
    "packet_level_timing": {
      "available": false,
      "columns": []
    },
    "packet_level_scan_signatures": {
      "available": false,
      "columns": []
    }
  },
  "temporal": {
    "within_flow_iat_columns": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "causal_event_timestamp": false,
    "causal_temporal_features_available": false
  }
}
```

## Wednesday-workingHours.pcap_ISCX.csv

- Size: 225166395 bytes
- Rows: 692703 (691406 valid)
- Columns: 79
- Timestamp: unavailable
- Timestamp range: {'min': None, 'max': None}
- Labels: `{"BENIGN": 440031, "DOS SLOWLORIS": 5796, "DOS SLOWHTTPTEST": 5499, "DOS HULK": 231073, "DOS GOLDENEYE": 10293, "HEARTBLEED": 11}`
- Missing values: {'total_cells': 0, 'by_column': {}}
- Malformed values: {'total_rows': 1297, 'wrong_width_rows': 0, 'non_numeric_rows': 1297, 'by_column': {'Flow Bytes/s': 1297, 'Flow Packets/s': 1297}}
- Duplicate rows: 81909
- Source/destination IPs: unavailable / unavailable
- Source/destination ports: unavailable / Destination Port available
- Protocol: unavailable

### Exact Columns

```text
Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std, Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length, Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate, Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes, Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward, Active Mean, Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min, Label
```

### Feature Availability

```json
{
  "flow": {
    "bytes": [
      "Total Length of Fwd Packets",
      "Total Length of Bwd Packets",
      "Flow Bytes/s",
      "Fwd Packet Length Max",
      "Fwd Packet Length Min",
      "Fwd Packet Length Mean",
      "Fwd Packet Length Std",
      "Bwd Packet Length Max",
      "Bwd Packet Length Min",
      "Bwd Packet Length Mean",
      "Bwd Packet Length Std",
      "Min Packet Length",
      "Max Packet Length",
      "Packet Length Mean",
      "Packet Length Std",
      "Packet Length Variance",
      "Average Packet Size",
      "Avg Fwd Segment Size",
      "Avg Bwd Segment Size",
      "Subflow Fwd Bytes",
      "Subflow Bwd Bytes"
    ],
    "packets": [
      "Total Fwd Packets",
      "Total Backward Packets",
      "Flow Packets/s",
      "Fwd Packets/s",
      "Bwd Packets/s",
      "Subflow Fwd Packets",
      "Subflow Bwd Packets"
    ],
    "duration": [
      "Flow Duration",
      "Active Mean",
      "Active Std",
      "Active Max",
      "Active Min",
      "Idle Mean",
      "Idle Std",
      "Idle Max",
      "Idle Min"
    ],
    "tcp_flags": [
      "Fwd PSH Flags",
      "Bwd PSH Flags",
      "Fwd URG Flags",
      "Bwd URG Flags",
      "FIN Flag Count",
      "SYN Flag Count",
      "RST Flag Count",
      "PSH Flag Count",
      "ACK Flag Count",
      "URG Flag Count",
      "CWE Flag Count",
      "ECE Flag Count"
    ],
    "iat": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "flow_direction_and_other": [
      "Destination Port",
      "Down/Up Ratio",
      "Fwd Header Length",
      "Bwd Header Length",
      "Init_Win_bytes_forward",
      "Init_Win_bytes_backward",
      "act_data_pkt_fwd",
      "min_seg_size_forward"
    ]
  },
  "packet": {
    "ttl": {
      "available": false,
      "columns": []
    },
    "ttl_variance": {
      "available": false,
      "columns": []
    },
    "tcp_window_size": {
      "available": false,
      "columns": []
    },
    "fragmentation": {
      "available": false,
      "columns": []
    },
    "payload_size_distribution": {
      "available": false,
      "columns": []
    },
    "retransmission_indicators": {
      "available": false,
      "columns": []
    },
    "packet_level_timing": {
      "available": false,
      "columns": []
    },
    "packet_level_scan_signatures": {
      "available": false,
      "columns": []
    }
  },
  "temporal": {
    "within_flow_iat_columns": [
      "Flow IAT Mean",
      "Flow IAT Std",
      "Flow IAT Max",
      "Flow IAT Min",
      "Fwd IAT Total",
      "Fwd IAT Mean",
      "Fwd IAT Std",
      "Fwd IAT Max",
      "Fwd IAT Min",
      "Bwd IAT Total",
      "Bwd IAT Mean",
      "Bwd IAT Std",
      "Bwd IAT Max",
      "Bwd IAT Min"
    ],
    "causal_event_timestamp": false,
    "causal_temporal_features_available": false
  }
}
```

## PortScan Assessment

- Records: 286467
- Attack labels: `{"BENIGN": 127537, "PORTSCAN": 158930}`
- Timestamp coverage: none
- Temporal ordering: unavailable; source order is not event chronology
- Meaningful PortScan temporal episode: no, not from this CSV alone because event timestamps and endpoint identity are absent.

## Final Answers

### A. Flow Features
Directly usable or aggregatable: Destination Port, Flow Duration, forward/backward packet counts, forward/backward byte totals, packet-length statistics, flow/forward/backward rates, within-flow IAT aggregates, TCP flag counters, header lengths, initial window-byte aggregates, active/idle statistics, subflow counts/bytes, and related numeric flow fields. The current model mappings are explicit in the JSON report; TTL, direction-specific TCP window means, RTT, source-port uniqueness, and protocol counts are unavailable rather than inferred.

### B. Packet Features
TTL and TTL variance, packet TCP window observations, fragmentation, per-packet payload-size distribution, retransmission indicators, packet-level timing, and packet-level scan signatures remain unavailable.

### C. PCAPs
Acquire the official original PCAP for Friday-WorkingHours-Afternoon-PortScan first, as previously identified in the research status, then the original scenario-matched captures for Friday morning, Friday afternoon DDoS, Monday, Tuesday, Wednesday, Thursday morning WebAttacks, and Thursday afternoon Infiltration. Exact archive filenames and checksums must be verified at acquisition; no PCAP is present locally. The CSVs do not contain the required packet evidence.

### D. World Model Schema
Do not modify the current schema or trained model. Keep packet fields explicitly unavailable and add flow ingestion only at this separate adapter boundary.

### E. Temporal Training
Not ready for timestamp-based temporal training. The CSVs are ready for deterministic flow-level static analysis and label-preserving ingestion, but chronological training requires verified event timestamps; SIH packet compliance additionally requires the original PCAPs.

## Recommendation
Acquire and audit the official scenario-matched PCAPs, beginning with Friday-WorkingHours-Afternoon-PortScan. Add verified packet observations through a separate PCAP adapter, validate event ordering and episode boundaries, and only then consider a controlled training experiment. Do not retrain the current World Model yet.

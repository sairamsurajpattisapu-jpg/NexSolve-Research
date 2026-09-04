# CIC-IDS2017 Forecastability

Run timestamp (UTC): `2026-09-03T10:49:46+00:00`

## Dataset

CIC-IDS2017

## Status

Temporal forecasting unsupported from the available extracted CSV schema.

## Timestamp Field

None

## Timestamp Status

Not available: the eight extracted CIC CSVs contain flow features and Label but no timestamp column.

## File Order Activity

```json
[
  {
    "file": "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "rows": 225745,
    "labels": {
      "BENIGN": 97718,
      "DDoS": 128027
    },
    "timestamp_columns": [],
    "first_timestamp": null,
    "last_timestamp": null
  },
  {
    "file": "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "rows": 286467,
    "labels": {
      "BENIGN": 127537,
      "PortScan": 158930
    },
    "timestamp_columns": [],
    "first_timestamp": null,
    "last_timestamp": null
  },
  {
    "file": "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "rows": 191033,
    "labels": {
      "BENIGN": 189067,
      "Bot": 1966
    },
    "timestamp_columns": [],
    "first_timestamp": null,
    "last_timestamp": null
  },
  {
    "file": "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Monday-WorkingHours.pcap_ISCX.csv",
    "rows": 529918,
    "labels": {
      "BENIGN": 529918
    },
    "timestamp_columns": [],
    "first_timestamp": null,
    "last_timestamp": null
  },
  {
    "file": "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "rows": 288602,
    "labels": {
      "BENIGN": 288566,
      "Infiltration": 36
    },
    "timestamp_columns": [],
    "first_timestamp": null,
    "last_timestamp": null
  },
  {
    "file": "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "rows": 170366,
    "labels": {
      "BENIGN": 168186,
      "Web Attack \ufffd Brute Force": 1507,
      "Web Attack \ufffd XSS": 652,
      "Web Attack \ufffd Sql Injection": 21
    },
    "timestamp_columns": [],
    "first_timestamp": null,
    "last_timestamp": null
  },
  {
    "file": "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Tuesday-WorkingHours.pcap_ISCX.csv",
    "rows": 445909,
    "labels": {
      "BENIGN": 432074,
      "FTP-Patator": 7938,
      "SSH-Patator": 5897
    },
    "timestamp_columns": [],
    "first_timestamp": null,
    "last_timestamp": null
  },
  {
    "file": "CIC-IDS2017\\MachineLearningCSV\\MachineLearningCVE\\Wednesday-workingHours.pcap_ISCX.csv",
    "rows": 692703,
    "labels": {
      "BENIGN": 440031,
      "DoS slowloris": 5796,
      "DoS Slowhttptest": 5499,
      "DoS Hulk": 231073,
      "DoS GoldenEye": 10293,
      "Heartbleed": 11
    },
    "timestamp_columns": [],
    "first_timestamp": null,
    "last_timestamp": null
  }
]
```

## Candidate Windows

```json
{
  "30": "Not computed \u2014 no timestamp field exists to assign records to time windows.",
  "60": "Not computed \u2014 no timestamp field exists to assign records to time windows.",
  "300": "Not computed \u2014 no timestamp field exists to assign records to time windows.",
  "600": "Not computed \u2014 no timestamp field exists to assign records to time windows."
}
```

## Episodes

Not computed — temporal episodes cannot be defined from row order or filename day labels without fabricating event times.

## Future Mixed State Episodes

0

## Usable Forecast Cases

0

## Baseline Evaluation

Not computed — no defensible chronological observation/future-window target can be constructed.

## Leakage Status

No forecast features or future labels were constructed.

## Decision

CIC does not currently support the NexSolve temporal forecasting claim from these files alone; use it for detection benchmarking only.

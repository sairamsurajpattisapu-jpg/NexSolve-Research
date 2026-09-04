# Timestamped Dataset Suitability

Run timestamp (UTC): `2026-09-03T10:49:46+00:00`

## Study

Batch timestamped dataset suitability audit

## Methodology

Literature and institutional metadata review only; no candidate dataset was downloaded or evaluated locally.

## Unsw Reference

```json
{
  "forecast_cases": 24,
  "eligible_mixed_state_episodes": 1,
  "baseline_result": "three trivial baselines tied",
  "evidence_level": "extremely limited"
}
```

## Scoring Scale

0-5 per criterion, maximum 50; UNKNOWN evidence receives no inferred bonus.

## Candidates

```json
{
  "CSE-CIC-IDS2018": {
    "authoritative_sources": [
      "https://www.unb.ca/cic/datasets/ids-2018.html",
      "https://registry.opendata.aws/cse-cic-ids2018/"
    ],
    "evidence": "Official CIC/UNB documentation describes seven attack scenarios, multi-day attack schedules, raw traffic/logs, and 80 traffic features. Exact local timestamp-bearing file schema was not verified.",
    "timestamp": {
      "finding": "Documented attack schedules and raw captures; exact generated-flow timestamp field UNKNOWN until downloaded and inspected.",
      "score": 3
    },
    "temporal_coverage": {
      "finding": "Attack schedules span multiple dates from February 14 through March 2, 2018 in the official table.",
      "score": 4
    },
    "temporal_variation": {
      "finding": "Multiple attack scenarios and benign background traffic are documented across days; exact flow-level transitions UNKNOWN.",
      "score": 4
    },
    "label_quality": {
      "finding": "Official scenario/IP/port/protocol labeling procedure is documented.",
      "score": 4
    },
    "forecast_case_volume": {
      "finding": "Multi-day traffic and 80 features imply substantial potential volume; exact records UNKNOWN.",
      "score": 4
    },
    "flow_features": {
      "finding": "Official source documents more than 80 CICFlowMeter features and flow identifiers in the generated output description.",
      "score": 5
    },
    "accessibility": {
      "finding": "AWS Open Data Registry documents no-account S3 access.",
      "score": 5
    },
    "computational_practicality": {
      "finding": "Likely large raw traffic/log distribution; exact size UNKNOWN, so full acquisition may exceed a student laptop budget.",
      "score": 3
    },
    "reproducibility": {
      "finding": "Institutional documentation, AWS registry, licensing, and citation are available.",
      "score": 5
    },
    "nexsolve_compatibility": {
      "finding": "Potentially strong, but timestamp schema and scenario-period leakage require direct verification.",
      "score": 3
    },
    "forecastability": "MEDIUM",
    "vs_unsw": "BETTER THAN UNSW in documented temporal coverage potential, but not yet locally verified.",
    "leakage_risks": [
      "fixed attack scenario periods",
      "source/destination and scenario identifiers may encode labels",
      "attack schedule metadata may leak the target"
    ],
    "access": "Public AWS Open Data Registry; no account required according to the registry.",
    "next_download": {
      "filename": "UNKNOWN: inspect official S3 listing before selecting a smallest file",
      "source": "s3://cse-cic-ids2018/",
      "approximate_size": "UNKNOWN",
      "purpose": "Verify exact timestamp-bearing generated-flow schema on one day/subset."
    },
    "scores": {
      "timestamp": 3,
      "temporal_coverage": 4,
      "temporal_variation": 4,
      "label_quality": 4,
      "forecast_case_volume": 4,
      "flow_features": 5,
      "accessibility": 5,
      "computational_practicality": 3,
      "reproducibility": 5,
      "nexsolve_compatibility": 3
    },
    "total_score": 40
  },
  "CIC-DDoS2019": {
    "authoritative_sources": [
      "https://www.unb.ca/cic/datasets/ddos-2019.html",
      "https://ieeexplore.ieee.org/abstract/document/8888419"
    ],
    "evidence": "Official UNB documentation explicitly states generated CSV flows are labeled based on timestamp, source/destination IPs, ports, protocols, and attack; it documents first-day and second-day attack schedules.",
    "timestamp": {
      "finding": "Timestamp is explicitly part of the official flow-labeling basis; exact field name/precision/timezone UNKNOWN until files are inspected.",
      "score": 5
    },
    "temporal_coverage": {
      "finding": "Two documented capture days with attack times from approximately 09:43 through 17:35 and 10:35 through 17:15.",
      "score": 4
    },
    "temporal_variation": {
      "finding": "Benign background plus many scheduled attacks on two days; repeated transitions are plausible, but exact flow-level transition counts UNKNOWN.",
      "score": 4
    },
    "label_quality": {
      "finding": "Official flow labels use timestamp and network tuple evidence; multiple DDoS families are documented.",
      "score": 5
    },
    "forecast_case_volume": {
      "finding": "Per-machine generated CSVs and raw PCAPs across two days indicate substantial potential volume; exact record count UNKNOWN.",
      "score": 4
    },
    "flow_features": {
      "finding": "Official source documents more than 80 CICFlowMeter features and tuple fields.",
      "score": 5
    },
    "accessibility": {
      "finding": "UNB provides an official download directory and permits redistribution with citation.",
      "score": 5
    },
    "computational_practicality": {
      "finding": "The official distribution includes PCAPs and per-machine CSVs; exact total size UNKNOWN and likely large.",
      "score": 3
    },
    "reproducibility": {
      "finding": "Official UNB page, paper, attack-time tables, download path, and license are documented.",
      "score": 5
    },
    "nexsolve_compatibility": {
      "finding": "Best documented candidate for chronological flow analysis, subject to verifying that timestamps survive in selected CSVs and auditing schedule/tuple leakage.",
      "score": 5
    },
    "forecastability": "HIGH",
    "vs_unsw": "BETTER THAN UNSW in documented timestamp provenance and potential episode volume; local validation is still required.",
    "leakage_risks": [
      "attack-time schedule may make targets trivially predictable",
      "source/destination tuple and protocol may identify attack scenarios",
      "training/test day role must not be confused with a natural deployment split"
    ],
    "access": "Official UNB/CIC download directory; license requires citation.",
    "next_download": {
      "filename": "UNKNOWN: official directory listing must be inspected before selecting a smallest generated CSV",
      "source": "http://cicresearch.ca//CICDataset/CICDDoS2019/",
      "approximate_size": "UNKNOWN",
      "purpose": "Inspect one official generated flow CSV header and timestamp coverage before full acquisition."
    },
    "scores": {
      "timestamp": 5,
      "temporal_coverage": 4,
      "temporal_variation": 4,
      "label_quality": 5,
      "forecast_case_volume": 4,
      "flow_features": 5,
      "accessibility": 5,
      "computational_practicality": 3,
      "reproducibility": 5,
      "nexsolve_compatibility": 5
    },
    "total_score": 45
  },
  "TON_IoT": {
    "authoritative_sources": [
      "https://research.unsw.edu.au/projects/toniot-datasets",
      "https://ieeexplore.ieee.org/document/9189760"
    ],
    "evidence": "UNSW\u2019s official page documents raw/processed/train-test/security-event folders and says SecurityEvents_GroundTruth datasets contain hacking events and timestamp ts; labels use IP addresses and timestamps.",
    "timestamp": {
      "finding": "Official source explicitly documents timestamp field ts in security-event ground truth; exact network CSV timestamp field and precision UNKNOWN.",
      "score": 5
    },
    "temporal_coverage": {
      "finding": "Heterogeneous IoT/IIoT, network, Linux, and Windows sources were collected in parallel across multiple events; exact duration UNKNOWN.",
      "score": 4
    },
    "temporal_variation": {
      "finding": "Official source documents several normal and cyber-attack events and timestamped ground truth.",
      "score": 5
    },
    "label_quality": {
      "finding": "Processed datasets have labels and separate security-event ground truth; linkage is timestamp/IP based and must be audited.",
      "score": 4
    },
    "forecast_case_volume": {
      "finding": "Raw and processed heterogeneous sources plus train/test samples imply useful volume; exact network record count UNKNOWN.",
      "score": 4
    },
    "flow_features": {
      "finding": "Network data includes PCAP, Zeek logs, and CSV; other telemetry sources broaden context but complicate a single flow contract.",
      "score": 4
    },
    "accessibility": {
      "finding": "UNSW provides a public academic-use download link and states free academic research use.",
      "score": 4
    },
    "computational_practicality": {
      "finding": "The official distribution is heterogeneous; selecting only network CSV plus ground truth is practical, full multimodal acquisition is not assumed.",
      "score": 3
    },
    "reproducibility": {
      "finding": "Institutional page, papers, folder organization, statistics, and usage terms are documented.",
      "score": 5
    },
    "nexsolve_compatibility": {
      "finding": "Strong temporal ground-truth potential, but heterogeneous sources and IP/timestamp labeling create join and leakage risks.",
      "score": 4
    },
    "forecastability": "HIGH",
    "vs_unsw": "BETTER THAN UNSW in documented ground-truth organization and event diversity potential; exact network subset remains to be verified.",
    "leakage_risks": [
      "IP-based labeling can expose attack identity",
      "security-event ground truth must be used only as future evaluation labels",
      "provided train/test samples may not represent chronological deployment splits"
    ],
    "access": "Public UNSW academic-use SharePoint distribution.",
    "next_download": {
      "filename": "Train_Test_Network.csv and the corresponding network security-event ground-truth file (exact ground-truth filename UNKNOWN until official folder listing)",
      "source": "UNSW official TON_IoT dataset link",
      "approximate_size": "UNKNOWN",
      "purpose": "Acquire the smallest network-only labeled subset plus its timestamped ground truth."
    },
    "scores": {
      "timestamp": 5,
      "temporal_coverage": 4,
      "temporal_variation": 5,
      "label_quality": 4,
      "forecast_case_volume": 4,
      "flow_features": 4,
      "accessibility": 4,
      "computational_practicality": 3,
      "reproducibility": 5,
      "nexsolve_compatibility": 4
    },
    "total_score": 42
  },
  "Edge-IIoTset": {
    "authoritative_sources": [
      "https://doi.org/10.1109/ACCESS.2022.3165809",
      "https://doi.org/10.36227/techrxiv.18857336"
    ],
    "evidence": "The IEEE Access paper metadata/abstract identifies a purpose-built seven-layer IoT/IIoT testbed, more than 10 device types, 14 attacks in five threat groups, and 61 selected features from 1176 candidates.",
    "timestamp": {
      "finding": "Timestamp-bearing network files are not established by the accessible authoritative abstract metadata.",
      "score": 2
    },
    "temporal_coverage": {
      "finding": "Purpose-built testbed and multiple applications are documented, but capture duration and chronological file organization are UNKNOWN.",
      "score": 3
    },
    "temporal_variation": {
      "finding": "Fourteen attacks across five threat groups suggest scenario diversity; repeated benign/attack transitions are UNKNOWN.",
      "score": 4
    },
    "label_quality": {
      "finding": "The paper documents attack categories and processed features, but exact label/event semantics require direct file inspection.",
      "score": 4
    },
    "forecast_case_volume": {
      "finding": "The paper establishes multi-source features but not exact record count or 60-second case volume in accessible metadata.",
      "score": 3
    },
    "flow_features": {
      "finding": "61 selected features from 1176 sources, including network traffic, alerts, system resources, and logs.",
      "score": 5
    },
    "accessibility": {
      "finding": "The paper metadata identifies public access through IEEE DataPort/associated open-access materials, but exact access workflow is UNKNOWN.",
      "score": 3
    },
    "computational_practicality": {
      "finding": "A processed feature set may be practical, but exact file sizes and multimodal scope are UNKNOWN.",
      "score": 3
    },
    "reproducibility": {
      "finding": "Peer-reviewed paper and DOI are stable; exact dataset packaging and acquisition details require verification.",
      "score": 4
    },
    "nexsolve_compatibility": {
      "finding": "Rich features and attack diversity are promising, but missing verified temporal semantics prevent a stronger score.",
      "score": 3
    },
    "forecastability": "UNKNOWN",
    "vs_unsw": "UNKNOWN until timestamp and chronology are verified from the actual files.",
    "leakage_risks": [
      "purpose-built scenario identifiers may encode labels",
      "feature selection may have used labels or full-dataset statistics",
      "multimodal alerts/logs may contain post-event information"
    ],
    "access": "IEEE/TechRxiv-associated public access; exact download workflow UNKNOWN.",
    "next_download": {
      "filename": "UNKNOWN: inspect the official IEEE DataPort package listing first",
      "source": "IEEE Access paper DOI",
      "approximate_size": "UNKNOWN",
      "purpose": "Verify timestamp-bearing processed network file and label semantics before acquisition."
    },
    "scores": {
      "timestamp": 2,
      "temporal_coverage": 3,
      "temporal_variation": 4,
      "label_quality": 4,
      "forecast_case_volume": 3,
      "flow_features": 5,
      "accessibility": 3,
      "computational_practicality": 3,
      "reproducibility": 4,
      "nexsolve_compatibility": 3
    },
    "total_score": 34
  }
}
```

## Winner

CIC-DDoS2019

## Backup

TON_IoT

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

## Backup Reason

TON_IoT has explicit timestamped security-event ground truth and event diversity, but its heterogeneous multimodal packaging and IP/timestamp joins create more linkage and leakage complexity.

## Selection Decision

CIC-DDoS2019 is the best candidate for temporal attack-forecasting follow-up, subject to direct timestamp/schema validation before any model work.

## Advanced Model

NOT JUSTIFIED YET

## Next Step

Inspect the official CIC-DDoS2019 directory and acquire one smallest generated flow CSV for timestamp/schema validation; do not download the full dataset.

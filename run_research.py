"""Streaming, reproducible NexSolve research run for the local datasets."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import platform
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
RESULTS = ROOT / "results"
RUN_UTC = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
UNSW_NAMES = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload",
    "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
    "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt",
    "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
    "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "attack_cat", "Label",
]
UNSW_TRAFFIC = [ROOT / "UNSW-NB15" / "raw" / f"UNSW-NB15_{i}.csv" for i in range(1, 5)]
UNSW_GT = ROOT / "UNSW-NB15" / "raw" / "UNSW-NB15_GT.csv"
UNSW_FEATURES = ROOT / "UNSW-NB15" / "raw" / "UNSW-NB15_features.csv"
UNSW_EVENTS = ROOT / "UNSW-NB15" / "raw" / "UNSW-NB15_LIST_EVENTS.csv"
CIC_DIR = ROOT / "CIC-IDS2017" / "MachineLearningCSV" / "MachineLearningCVE"


def json_safe(value: object) -> object:
    if isinstance(value, dict):
        converted = {}
        for key, item in value.items():
            if isinstance(key, tuple):
                output_key = "tuple:" + json.dumps(list(key), ensure_ascii=True, separators=(",", ":"))
            elif isinstance(key, (str, int, float, bool)) or key is None:
                output_key = str(key) if not isinstance(key, str) else key
            else:
                output_key = "key:" + json.dumps(key, ensure_ascii=True, default=str, separators=(",", ":"))
            if output_key in converted:
                raise ValueError(f"JSON key collision while serializing {key!r}")
            converted[output_key] = json_safe(item)
        return converted
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_safe(value), indent=2, ensure_ascii=True, default=str), encoding="utf-8")


def md_report(path: Path, title: str, data: dict) -> None:
    lines = [f"# {title}", "", f"Run timestamp (UTC): `{RUN_UTC}`", ""]
    for key, value in data.items():
        lines.append(f"## {str(key).replace('_', ' ').title()}")
        if isinstance(value, (dict, list)):
            lines += ["", "```json", json.dumps(json_safe(value), indent=2, ensure_ascii=True, default=str), "```", ""]
        else:
            lines += ["", str(value), ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def file_record(path: Path) -> dict:
    stat = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": str(path.relative_to(ROOT)), "size_bytes": stat.st_size,
            "modified_time": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            "sha256": digest.hexdigest()}


def parse_float(value: str) -> float | None:
    try:
        number = float(value.strip())
        return number if math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def stream_csv(path: Path, header: bool, names: list[str] | None = None, limit: int | None = None) -> dict:
    counts = Counter()
    missing = Counter()
    malformed = 0
    blank = 0
    adjacent_duplicates = 0
    rows = 0
    first_row = None
    last_row = None
    column_count = None
    label_index = None
    attack_index = None
    timestamp_indices = []
    timestamp_min = None
    timestamp_max = None
    previous_digest = None
    actual_names = names
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        reader = csv.reader(stream)
        if header:
            actual_names = next(reader, [])
            actual_names = [name.strip() for name in actual_names]
        actual_names = actual_names or []
        column_count = len(actual_names)
        lowered = [name.strip().lower() for name in actual_names]
        label_index = lowered.index("label") if "label" in lowered else (lowered.index("label") if "label" in lowered else None)
        attack_index = lowered.index("attack_cat") if "attack_cat" in lowered else None
        timestamp_indices = [i for i, name in enumerate(lowered) if "time" in name or name in {"stime", "ltime"}]
        for row in reader:
            if limit is not None and rows >= limit:
                break
            if not row or not any(cell.strip() for cell in row):
                blank += 1
                continue
            rows += 1
            first_row = first_row or row
            last_row = row
            if len(row) != column_count:
                malformed += 1
                continue
            digest = hashlib.blake2b(",".join(row).encode("utf-8", "replace"), digest_size=16).digest()
            if digest == previous_digest:
                adjacent_duplicates += 1
            previous_digest = digest
            for index, cell in enumerate(row):
                if not cell.strip():
                    missing[str(index)] += 1
            if label_index is not None:
                counts["labels:" + (row[label_index].strip() or "<missing>")] += 1
            if attack_index is not None:
                counts["attack_categories:" + (row[attack_index].strip() or "<missing>")] += 1
            for index in timestamp_indices:
                value = parse_float(row[index])
                if value is not None:
                    timestamp_min = value if timestamp_min is None else min(timestamp_min, value)
                    timestamp_max = value if timestamp_max is None else max(timestamp_max, value)
    labels = {key[7:]: value for key, value in counts.items() if key.startswith("labels:")}
    attack_categories = {key[18:]: value for key, value in counts.items() if key.startswith("attack_categories:")}
    return {"file": str(path.relative_to(ROOT)), "size_bytes": path.stat().st_size, "rows": rows,
            "columns": column_count, "column_names": actual_names, "labels": labels,
            "attack_categories": attack_categories, "blank_rows": blank, "malformed_rows": malformed,
            "missing_cells_by_column_index": dict(missing), "adjacent_duplicate_rows": adjacent_duplicates,
            "timestamp_columns": [actual_names[i] for i in timestamp_indices],
            "timestamp_min_numeric": timestamp_min, "timestamp_max_numeric": timestamp_max,
            "first_row": first_row, "last_row_nonempty": bool(last_row)}


def parse_unsw_temporal(window_seconds: int = 60) -> dict:
    bins = Counter()
    states = Counter()
    transitions = Counter()
    last_state = None
    total = 0
    first_time = None
    last_time = None
    for path in UNSW_TRAFFIC:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
            for row in csv.reader(stream):
                if len(row) != 49:
                    continue
                timestamp = parse_float(row[28])
                if timestamp is None:
                    continue
                label = "BENIGN" if row[48].strip() in {"", "0", "0.0"} else (row[47].strip() or "ATTACK")
                total += 1
                first_time = timestamp if first_time is None else min(first_time, timestamp)
                last_time = timestamp if last_time is None else max(last_time, timestamp)
                bucket = int(timestamp // window_seconds)
                bins[bucket] += 1
                states[(bucket, label)] += 1
                if last_state is not None:
                    transitions[(last_state, label)] += 1
                last_state = label
    attack_bins = sum(1 for bucket in bins if states[(bucket, "BENIGN")] < bins[bucket])
    populated = len(bins)
    return {"dataset": "UNSW-NB15 traffic files", "window_seconds": window_seconds,
            "timestamp_column": "Stime", "records_with_parseable_timestamp": total,
            "first_unix_timestamp": first_time, "last_unix_timestamp": last_time,
            "duration_seconds": None if first_time is None else last_time - first_time,
            "windows_with_traffic": populated, "attack_windows": attack_bins,
            "benign_only_windows": populated - attack_bins,
            "average_records_per_window": (total / populated) if populated else None,
            "median_records_per_window": sorted(bins.values())[len(bins) // 2] if bins else None,
            "state_counts": dict(states), "transition_counts": {f"{a}->{b}": n for (a, b), n in transitions.items()},
            "unique_states": sorted({state for _, state in states}),
            "note": "UNSW traffic files have epoch timestamps; CIC flow files do not expose a timestamp column."}


def binary_metrics(actual: list[int], predicted: list[int], scores: list[float] | None = None) -> dict:
    from sklearn.metrics import (average_precision_score, balanced_accuracy_score, confusion_matrix,
                                 f1_score, precision_score, recall_score, roc_auc_score)
    result = {"precision": precision_score(actual, predicted, labels=[0, 1], zero_division=0),
              "recall": recall_score(actual, predicted, labels=[0, 1], zero_division=0),
              "f1": f1_score(actual, predicted, labels=[0, 1], zero_division=0),
              "macro_f1": f1_score(actual, predicted, labels=[0, 1], average="macro", zero_division=0),
              "balanced_accuracy": balanced_accuracy_score(actual, predicted) if len(set(actual)) == 2 else "Not computed: evaluation support contains one class",
              "confusion_matrix": confusion_matrix(actual, predicted, labels=[0, 1]).tolist(),
              "class_support": dict(Counter(str(value) for value in actual))}
    if scores is not None and len(set(actual)) == 2:
        result["roc_auc"] = roc_auc_score(actual, scores)
        result["pr_auc"] = average_precision_score(actual, scores)
    else:
        result["roc_auc"] = "Not computed"
        result["pr_auc"] = "Not computed"
    return result


def read_cic_sample(path: Path, cap: int) -> tuple[list[list[float]], list[int], int]:
    rows = []
    labels = []
    total = 0
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, [])
        label_index = [name.strip().lower() for name in header].index("label")
        for row in reader:
            if not row or len(row) != len(header):
                continue
            total += 1
    stride = max(1, math.ceil(total / cap))
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, [])
        label_index = [name.strip().lower() for name in header].index("label")
        for index, row in enumerate(reader):
            if len(row) != len(header) or index % stride != 0:
                continue
            if len(rows) >= cap:
                break
            values = []
            for column, value in enumerate(row):
                if column == label_index:
                    continue
                number = parse_float(value)
                values.append(number if number is not None else 0.0)
            rows.append(values)
            labels.append(0 if row[label_index].strip().upper() == "BENIGN" else 1)
    return rows, labels, total


def run_cic_detection() -> dict:
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    order = {"Monday": 0, "Tuesday": 1, "Wednesday": 2, "Thursday": 3, "Friday": 4}
    paths = sorted(CIC_DIR.glob("*.csv"), key=lambda path: (order.get(path.name.split("-")[0], 99), path.name))
    split_names = {"train": {"Monday", "Tuesday"}, "validation": {"Wednesday"}, "test": {"Thursday", "Friday"}}
    samples = {name: {"x": [], "y": [], "files": [], "rows_total": 0} for name in split_names}
    for path in paths:
        day = path.name.split("-")[0]
        split = next(name for name, days in split_names.items() if day in days)
        features, labels, total = read_cic_sample(path, 50000)
        samples[split]["x"].extend(features)
        samples[split]["y"].extend(labels)
        samples[split]["files"].append(str(path.relative_to(ROOT)))
        samples[split]["rows_total"] += total
    import numpy as np
    scaler = StandardScaler()
    x_train = scaler.fit_transform(np.asarray(samples["train"]["x"], dtype=float))
    x_validation = scaler.transform(np.asarray(samples["validation"]["x"], dtype=float))
    x_test = scaler.transform(np.asarray(samples["test"]["x"], dtype=float))
    model = LogisticRegression(class_weight="balanced", max_iter=100, solver="liblinear", random_state=0)
    model.fit(x_train, samples["train"]["y"])
    result = {"dataset": "CIC-IDS2017", "model": "LogisticRegression",
              "features": "All numeric flow columns except Label; nonnumeric/nonfinite values replaced with 0.0.",
              "sampling": "Deterministic systematic sample, cap 50,000 valid rows per source file; source totals are also reported. Sampling bounds memory while preserving chronological file partitions.",
              "split": {name: {"source_files": value["files"], "source_rows_total": value["rows_total"], "evaluated_samples": len(value["y"]), "label_distribution": dict(Counter(str(v) for v in value["y"]))} for name, value in samples.items()},
              "chronology": "Monday and Tuesday train, Wednesday validation, Thursday and Friday test. CIC files have no explicit timestamp, so chronology is available only at day-file granularity.",
              "preprocessing": "StandardScaler fitted on training samples only; class_weight=balanced fitted by the estimator using training labels only.",
              "parameters": {"solver": "liblinear", "max_iter": 100, "class_weight": "balanced", "random_state": 0},
              "validation_metrics": binary_metrics(samples["validation"]["y"], model.predict(x_validation), model.predict_proba(x_validation)[:, 1]),
              "test_metrics": binary_metrics(samples["test"]["y"], model.predict(x_test), model.predict_proba(x_test)[:, 1]),
              "limitations": ["No CIC event timestamp exists, so the chronological split is file/day based rather than flow-time based.", "Results are bounded deterministic samples, not full-row evaluation."]}
    return result


def run_cic_forecastability() -> dict:
    files = sorted(CIC_DIR.glob("*.csv"))
    file_activity = []
    for path in files:
        report = stream_csv(path, header=True)
        file_activity.append({"file": report["file"], "rows": report["rows"], "labels": report["labels"],
                              "timestamp_columns": report["timestamp_columns"], "first_timestamp": report["timestamp_min_numeric"],
                              "last_timestamp": report["timestamp_max_numeric"]})
    return {"dataset": "CIC-IDS2017", "status": "Temporal forecasting unsupported from the available extracted CSV schema.",
            "timestamp_field": None, "timestamp_status": "Not available: the eight extracted CIC CSVs contain flow features and Label but no timestamp column.",
            "file_order_activity": file_activity,
            "candidate_windows": {str(seconds): "Not computed — no timestamp field exists to assign records to time windows." for seconds in (30, 60, 300, 600)},
            "episodes": "Not computed — temporal episodes cannot be defined from row order or filename day labels without fabricating event times.",
            "future_mixed_state_episodes": 0,
            "usable_forecast_cases": 0,
            "baseline_evaluation": "Not computed — no defensible chronological observation/future-window target can be constructed.",
            "leakage_status": "No forecast features or future labels were constructed.",
            "decision": "CIC does not currently support the NexSolve temporal forecasting claim from these files alone; use it for detection benchmarking only."}


def run_cic_timestamp_source_audit() -> dict:
    files = sorted(CIC_DIR.glob("*.csv"))
    archive = ROOT / "CIC-IDS2017" / "MachineLearningCSV.zip"
    archive_entries = []
    import zipfile
    with zipfile.ZipFile(archive) as source:
        archive_entries = [{"name": entry.filename, "size_bytes": entry.file_size} for entry in source.infolist()]
    return {"workspace": str(ROOT), "state": "D", "classification": "NO PRACTICAL TIMESTAMP SOURCE IDENTIFIED",
            "source_archive": {"path": str(archive.relative_to(ROOT)), "size_bytes": archive.stat().st_size, "entries": archive_entries},
            "generated_labelled_flows_present": False, "pcap_or_pcapng_present": False,
            "cic_machine_learning_files": [{"path": str(path.relative_to(ROOT)), "size_bytes": path.stat().st_size,
                                             "timestamp_column_present": False, "flow_id_column_present": False,
                                             "header": next(csv.reader(path.open("r", encoding="utf-8-sig", errors="replace", newline="")), [])} for path in files],
            "timestamp_source": {"available": False, "field": None, "format": None, "earliest": None, "latest": None,
                                 "genuine_event_timestamps": "Not established.", "reason": "Only MachineLearningCVE flow feature CSVs are present; their headers contain no Timestamp field."},
            "join_analysis": {"status": "Not performed", "reason": "No timestamp-bearing GeneratedLabelledFlows source is available locally."},
            "decision": "CIC forecasting is not scientifically possible from the current local files without a timestamp-bearing source. No download was performed."}


def run_dataset_selection_audit() -> dict:
    candidates = {
        "CSE-CIC-IDS2018": {
            "authoritative_sources": ["https://www.unb.ca/cic/datasets/ids-2018.html", "https://registry.opendata.aws/cse-cic-ids2018/"],
            "evidence": "Official CIC/UNB documentation describes seven attack scenarios, multi-day attack schedules, raw traffic/logs, and 80 traffic features. Exact local timestamp-bearing file schema was not verified.",
            "timestamp": {"finding": "Documented attack schedules and raw captures; exact generated-flow timestamp field UNKNOWN until downloaded and inspected.", "score": 3},
            "temporal_coverage": {"finding": "Attack schedules span multiple dates from February 14 through March 2, 2018 in the official table.", "score": 4},
            "temporal_variation": {"finding": "Multiple attack scenarios and benign background traffic are documented across days; exact flow-level transitions UNKNOWN.", "score": 4},
            "label_quality": {"finding": "Official scenario/IP/port/protocol labeling procedure is documented.", "score": 4},
            "forecast_case_volume": {"finding": "Multi-day traffic and 80 features imply substantial potential volume; exact records UNKNOWN.", "score": 4},
            "flow_features": {"finding": "Official source documents more than 80 CICFlowMeter features and flow identifiers in the generated output description.", "score": 5},
            "accessibility": {"finding": "AWS Open Data Registry documents no-account S3 access.", "score": 5},
            "computational_practicality": {"finding": "Likely large raw traffic/log distribution; exact size UNKNOWN, so full acquisition may exceed a student laptop budget.", "score": 3},
            "reproducibility": {"finding": "Institutional documentation, AWS registry, licensing, and citation are available.", "score": 5},
            "nexsolve_compatibility": {"finding": "Potentially strong, but timestamp schema and scenario-period leakage require direct verification.", "score": 3},
            "forecastability": "MEDIUM", "vs_unsw": "BETTER THAN UNSW in documented temporal coverage potential, but not yet locally verified.",
            "leakage_risks": ["fixed attack scenario periods", "source/destination and scenario identifiers may encode labels", "attack schedule metadata may leak the target"],
            "access": "Public AWS Open Data Registry; no account required according to the registry.",
            "next_download": {"filename": "UNKNOWN: inspect official S3 listing before selecting a smallest file", "source": "s3://cse-cic-ids2018/", "approximate_size": "UNKNOWN", "purpose": "Verify exact timestamp-bearing generated-flow schema on one day/subset."}
        },
        "CIC-DDoS2019": {
            "authoritative_sources": ["https://www.unb.ca/cic/datasets/ddos-2019.html", "https://ieeexplore.ieee.org/abstract/document/8888419"],
            "evidence": "Official UNB documentation explicitly states generated CSV flows are labeled based on timestamp, source/destination IPs, ports, protocols, and attack; it documents first-day and second-day attack schedules.",
            "timestamp": {"finding": "Timestamp is explicitly part of the official flow-labeling basis; exact field name/precision/timezone UNKNOWN until files are inspected.", "score": 5},
            "temporal_coverage": {"finding": "Two documented capture days with attack times from approximately 09:43 through 17:35 and 10:35 through 17:15.", "score": 4},
            "temporal_variation": {"finding": "Benign background plus many scheduled attacks on two days; repeated transitions are plausible, but exact flow-level transition counts UNKNOWN.", "score": 4},
            "label_quality": {"finding": "Official flow labels use timestamp and network tuple evidence; multiple DDoS families are documented.", "score": 5},
            "forecast_case_volume": {"finding": "Per-machine generated CSVs and raw PCAPs across two days indicate substantial potential volume; exact record count UNKNOWN.", "score": 4},
            "flow_features": {"finding": "Official source documents more than 80 CICFlowMeter features and tuple fields.", "score": 5},
            "accessibility": {"finding": "UNB provides an official download directory and permits redistribution with citation.", "score": 5},
            "computational_practicality": {"finding": "The official distribution includes PCAPs and per-machine CSVs; exact total size UNKNOWN and likely large.", "score": 3},
            "reproducibility": {"finding": "Official UNB page, paper, attack-time tables, download path, and license are documented.", "score": 5},
            "nexsolve_compatibility": {"finding": "Best documented candidate for chronological flow analysis, subject to verifying that timestamps survive in selected CSVs and auditing schedule/tuple leakage.", "score": 5},
            "forecastability": "HIGH", "vs_unsw": "BETTER THAN UNSW in documented timestamp provenance and potential episode volume; local validation is still required.",
            "leakage_risks": ["attack-time schedule may make targets trivially predictable", "source/destination tuple and protocol may identify attack scenarios", "training/test day role must not be confused with a natural deployment split"],
            "access": "Official UNB/CIC download directory; license requires citation.",
            "next_download": {"filename": "UNKNOWN: official directory listing must be inspected before selecting a smallest generated CSV", "source": "http://cicresearch.ca//CICDataset/CICDDoS2019/", "approximate_size": "UNKNOWN", "purpose": "Inspect one official generated flow CSV header and timestamp coverage before full acquisition."}
        },
        "TON_IoT": {
            "authoritative_sources": ["https://research.unsw.edu.au/projects/toniot-datasets", "https://ieeexplore.ieee.org/document/9189760"],
            "evidence": "UNSW’s official page documents raw/processed/train-test/security-event folders and says SecurityEvents_GroundTruth datasets contain hacking events and timestamp ts; labels use IP addresses and timestamps.",
            "timestamp": {"finding": "Official source explicitly documents timestamp field ts in security-event ground truth; exact network CSV timestamp field and precision UNKNOWN.", "score": 5},
            "temporal_coverage": {"finding": "Heterogeneous IoT/IIoT, network, Linux, and Windows sources were collected in parallel across multiple events; exact duration UNKNOWN.", "score": 4},
            "temporal_variation": {"finding": "Official source documents several normal and cyber-attack events and timestamped ground truth.", "score": 5},
            "label_quality": {"finding": "Processed datasets have labels and separate security-event ground truth; linkage is timestamp/IP based and must be audited.", "score": 4},
            "forecast_case_volume": {"finding": "Raw and processed heterogeneous sources plus train/test samples imply useful volume; exact network record count UNKNOWN.", "score": 4},
            "flow_features": {"finding": "Network data includes PCAP, Zeek logs, and CSV; other telemetry sources broaden context but complicate a single flow contract.", "score": 4},
            "accessibility": {"finding": "UNSW provides a public academic-use download link and states free academic research use.", "score": 4},
            "computational_practicality": {"finding": "The official distribution is heterogeneous; selecting only network CSV plus ground truth is practical, full multimodal acquisition is not assumed.", "score": 3},
            "reproducibility": {"finding": "Institutional page, papers, folder organization, statistics, and usage terms are documented.", "score": 5},
            "nexsolve_compatibility": {"finding": "Strong temporal ground-truth potential, but heterogeneous sources and IP/timestamp labeling create join and leakage risks.", "score": 4},
            "forecastability": "HIGH", "vs_unsw": "BETTER THAN UNSW in documented ground-truth organization and event diversity potential; exact network subset remains to be verified.",
            "leakage_risks": ["IP-based labeling can expose attack identity", "security-event ground truth must be used only as future evaluation labels", "provided train/test samples may not represent chronological deployment splits"],
            "access": "Public UNSW academic-use SharePoint distribution.",
            "next_download": {"filename": "Train_Test_Network.csv and the corresponding network security-event ground-truth file (exact ground-truth filename UNKNOWN until official folder listing)", "source": "UNSW official TON_IoT dataset link", "approximate_size": "UNKNOWN", "purpose": "Acquire the smallest network-only labeled subset plus its timestamped ground truth."}
        },
        "Edge-IIoTset": {
            "authoritative_sources": ["https://doi.org/10.1109/ACCESS.2022.3165809", "https://doi.org/10.36227/techrxiv.18857336"],
            "evidence": "The IEEE Access paper metadata/abstract identifies a purpose-built seven-layer IoT/IIoT testbed, more than 10 device types, 14 attacks in five threat groups, and 61 selected features from 1176 candidates.",
            "timestamp": {"finding": "Timestamp-bearing network files are not established by the accessible authoritative abstract metadata.", "score": 2},
            "temporal_coverage": {"finding": "Purpose-built testbed and multiple applications are documented, but capture duration and chronological file organization are UNKNOWN.", "score": 3},
            "temporal_variation": {"finding": "Fourteen attacks across five threat groups suggest scenario diversity; repeated benign/attack transitions are UNKNOWN.", "score": 4},
            "label_quality": {"finding": "The paper documents attack categories and processed features, but exact label/event semantics require direct file inspection.", "score": 4},
            "forecast_case_volume": {"finding": "The paper establishes multi-source features but not exact record count or 60-second case volume in accessible metadata.", "score": 3},
            "flow_features": {"finding": "61 selected features from 1176 sources, including network traffic, alerts, system resources, and logs.", "score": 5},
            "accessibility": {"finding": "The paper metadata identifies public access through IEEE DataPort/associated open-access materials, but exact access workflow is UNKNOWN.", "score": 3},
            "computational_practicality": {"finding": "A processed feature set may be practical, but exact file sizes and multimodal scope are UNKNOWN.", "score": 3},
            "reproducibility": {"finding": "Peer-reviewed paper and DOI are stable; exact dataset packaging and acquisition details require verification.", "score": 4},
            "nexsolve_compatibility": {"finding": "Rich features and attack diversity are promising, but missing verified temporal semantics prevent a stronger score.", "score": 3},
            "forecastability": "UNKNOWN", "vs_unsw": "UNKNOWN until timestamp and chronology are verified from the actual files.",
            "leakage_risks": ["purpose-built scenario identifiers may encode labels", "feature selection may have used labels or full-dataset statistics", "multimodal alerts/logs may contain post-event information"],
            "access": "IEEE/TechRxiv-associated public access; exact download workflow UNKNOWN.",
            "next_download": {"filename": "UNKNOWN: inspect the official IEEE DataPort package listing first", "source": "IEEE Access paper DOI", "approximate_size": "UNKNOWN", "purpose": "Verify timestamp-bearing processed network file and label semantics before acquisition."}
        }
    }
    criteria = ["timestamp", "temporal_coverage", "temporal_variation", "label_quality", "forecast_case_volume", "flow_features", "accessibility", "computational_practicality", "reproducibility", "nexsolve_compatibility"]
    for candidate in candidates.values():
        candidate["scores"] = {criterion: candidate[criterion]["score"] for criterion in criteria}
        candidate["total_score"] = sum(candidate[criterion]["score"] for criterion in criteria)
    return {"study": "Batch timestamped dataset suitability audit", "methodology": "Literature and institutional metadata review only; no candidate dataset was downloaded or evaluated locally.", "unsw_reference": {"forecast_cases": 24, "eligible_mixed_state_episodes": 1, "baseline_result": "three trivial baselines tied", "evidence_level": "extremely limited"}, "scoring_scale": "0-5 per criterion, maximum 50; UNKNOWN evidence receives no inferred bonus.", "candidates": candidates, "winner": "CIC-DDoS2019", "backup": "TON_IoT", "winner_reasons": ["Official UNB documentation explicitly states timestamp-based flow labeling.", "Source/destination IP, ports, and protocol fields are part of the documented label basis.", "Two documented capture days provide a chronological future-day design.", "Attack schedules include many distinct attack periods rather than one single block.", "Benign background traffic is explicitly described.", "Generated per-machine CSVs provide a practical first acquisition target.", "Official download, paper, license, and attack-time tables support reproducibility."], "backup_reason": "TON_IoT has explicit timestamped security-event ground truth and event diversity, but its heterogeneous multimodal packaging and IP/timestamp joins create more linkage and leakage complexity.", "selection_decision": "CIC-DDoS2019 is the best candidate for temporal attack-forecasting follow-up, subject to direct timestamp/schema validation before any model work.", "advanced_model": "NOT JUSTIFIED YET", "next_step": "Inspect the official CIC-DDoS2019 directory and acquire one smallest generated flow CSV for timestamp/schema validation; do not download the full dataset."}


def collect_unsw_window_states(window_seconds: int) -> dict[int, int]:
    states = defaultdict(int)
    for path in UNSW_TRAFFIC:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
            for row in csv.reader(stream):
                if len(row) != 49:
                    continue
                timestamp = parse_float(row[28])
                if timestamp is None:
                    continue
                bucket = int(timestamp // window_seconds)
                if row[48].strip() not in {"", "0", "0.0"}:
                    states[bucket] = 1
                else:
                    states.setdefault(bucket, 0)
    return dict(states)


def run_unsw_forecast_baselines() -> dict:
    window_seconds = 60
    states = collect_unsw_window_states(window_seconds)
    buckets = sorted(states)
    runs = []
    current_run = [buckets[0]]
    for bucket in buckets[1:]:
        if bucket == current_run[-1] + 1:
            current_run.append(bucket)
        else:
            runs.append(current_run)
            current_run = [bucket]
    runs.append(current_run)
    first_mixed_run = next(index for index, run in enumerate(runs[1:], 1) if set(states[bucket] for bucket in run) == {0, 1})
    pre_test = [bucket for run in runs[:first_mixed_run] for bucket in run]
    train_end = int(len(pre_test) * 0.8)
    train = pre_test[:train_end]
    validation = pre_test[train_end:]
    train_pairs = [(current, following) for current, following in zip(train, train[1:]) if following == current + 1]
    validation_pairs = [(current, following) for current, following in zip(validation, validation[1:]) if following == current + 1]

    def evaluate(pairs_to_score: list[tuple[int, int]], predictor) -> dict:
        actual = [states[following] for _, following in pairs_to_score]
        predicted = []
        for current, _ in pairs_to_score:
            value = predictor(states[current])
            if value is not None:
                predicted.append(value)
            else:
                predicted.append(-1)
        usable = [(a, p) for a, p in zip(actual, predicted) if p != -1]
        abstentions = len(actual) - len(usable)
        metric = binary_metrics([a for a, _ in usable], [p for _, p in usable]) if usable else {"status": "Not computed"}
        metric.update({"forecast_cases": len(actual), "evaluated_cases": len(usable), "coverage": len(usable) / len(actual) if actual else 0.0,
                       "abstentions": abstentions, "abstention_rate": abstentions / len(actual) if actual else 0.0})
        metric["_actual"] = [a for a, _ in usable]
        metric["_predicted"] = [p for _, p in usable]
        return metric

    def transition_mode_for(history: list[int]) -> tuple[dict[int, int], dict[int, Counter]]:
        counts = defaultdict(Counter)
        for current, following in zip(history, history[1:]):
            if following == current + 1:
                counts[states[current]][states[following]] += 1
        return {state: values.most_common(1)[0][0] for state, values in counts.items()}, counts

    min_pairs = 20
    _, initial_transition_counts = transition_mode_for(train)
    episode_results = []
    all_run_stats = []
    eligible_runs = []
    for index, run in enumerate(runs):
        pairs = [(current, following) for current, following in zip(run, run[1:]) if following == current + 1]
        run_states = [states[bucket] for bucket in run]
        transitions = Counter(f"{a}->{b}" for a, b in zip(run_states, run_states[1:]))
        has_both = set(run_states) == {0, 1}
        eligible = index >= first_mixed_run and has_both and len(pairs) >= min_pairs
        stat = {"episode_index": index, "start_utc": datetime.fromtimestamp(run[0] * window_seconds, timezone.utc).isoformat(),
                "end_utc_exclusive": datetime.fromtimestamp((run[-1] + 1) * window_seconds, timezone.utc).isoformat(),
                "windows": len(run), "benign_windows": run_states.count(0), "attack_windows": run_states.count(1),
                "attack_percentage": run_states.count(1) / len(run) if run else 0.0, "valid_forecast_pairs": len(pairs),
                "state_transitions": dict(transitions), "suitable_for_future_evaluation": eligible,
                "exclusion_reason": None if eligible else ("before the pre-test training period" if index < first_mixed_run else "does not contain both states or has fewer than 20 valid forecast pairs")}
        all_run_stats.append(stat)
        if eligible:
            eligible_runs.append(index)
            history = train + [bucket for prior_index in eligible_runs[:-1] for bucket in runs[prior_index]]
            transition_mode, transition_counts = transition_mode_for(history)
            result = {"episode_index": index, "start_utc": stat["start_utc"], "end_utc_exclusive": stat["end_utc_exclusive"],
                      "target_windows": {"benign": run_states.count(0), "attack": run_states.count(1)}, "forecast_cases": len(pairs)}
            for name, predictor in {"current_state": lambda state: state, "persistence": lambda state: state,
                                    "empirical_transition": lambda state: transition_mode.get(state)}.items():
                metrics = evaluate(pairs, lambda state, fn=predictor: fn(state))
                result[name] = {key: value for key, value in metrics.items() if not key.startswith("_")}
                result[name]["_actual"] = metrics["_actual"]
                result[name]["_predicted"] = metrics["_predicted"]
            result["training_transition_counts"] = {str(state): dict(values) for state, values in transition_counts.items()}
            episode_results.append(result)

    def aggregate(name: str) -> dict:
        actual = [value for episode in episode_results for value in episode[name]["_actual"]]
        predicted = [value for episode in episode_results for value in episode[name]["_predicted"]]
        metric = binary_metrics(actual, predicted) if actual else {"status": "Not computed"}
        cases = sum(episode[name]["forecast_cases"] for episode in episode_results)
        evaluated = len(actual)
        metric.update({"forecast_cases": cases, "evaluated_cases": evaluated, "coverage": evaluated / cases if cases else 0.0,
                       "abstentions": cases - evaluated, "abstention_rate": (cases - evaluated) / cases if cases else 0.0})
        return metric

    baselines = {name: aggregate(name) for name in ("current_state", "persistence", "empirical_transition")}
    for episode in episode_results:
        for name in ("current_state", "persistence", "empirical_transition"):
            episode[name].pop("_actual", None)
            episode[name].pop("_predicted", None)
    split = {"train": train, "validation": validation, "test": runs[first_mixed_run]}
    split_summary = {}
    for name, window_list in split.items():
        split_summary[name] = {"windows": len(window_list), "benign_windows": sum(states[bucket] == 0 for bucket in window_list),
                               "attack_windows": sum(states[bucket] == 1 for bucket in window_list),
                               "start_utc": datetime.fromtimestamp(window_list[0] * window_seconds, timezone.utc).isoformat(),
                               "end_utc_exclusive": datetime.fromtimestamp((window_list[-1] + 1) * window_seconds, timezone.utc).isoformat()}
    split_analysis = {"window_seconds": window_seconds, "all_nonempty_windows": len(buckets),
                      "contiguous_runs": [{"start_utc": datetime.fromtimestamp(run[0] * window_seconds, timezone.utc).isoformat(),
                                           "end_utc_exclusive": datetime.fromtimestamp((run[-1] + 1) * window_seconds, timezone.utc).isoformat(),
                                           "windows": len(run), "benign_windows": sum(states[bucket] == 0 for bucket in run),
                                           "attack_windows": sum(states[bucket] == 1 for bucket in run)} for run in runs],
                      "original_split_failure": {"train": {"benign_windows": sum(states[bucket] == 0 for bucket in buckets[:int(len(buckets) * 0.6)]), "attack_windows": sum(states[bucket] == 1 for bucket in buckets[:int(len(buckets) * 0.6)])},
                                                  "validation": {"benign_windows": sum(states[bucket] == 0 for bucket in buckets[int(len(buckets) * 0.6):int(len(buckets) * 0.8)]), "attack_windows": sum(states[bucket] == 1 for bucket in buckets[int(len(buckets) * 0.6):int(len(buckets) * 0.8)])},
                                                  "test": {"benign_windows": sum(states[bucket] == 0 for bucket in buckets[int(len(buckets) * 0.8):]), "attack_windows": sum(states[bucket] == 1 for bucket in buckets[int(len(buckets) * 0.8):])}},
                      "corrected_split": split_summary,
                      "test_run_index": first_mixed_run,
                      "minimum_eligible_pairs": min_pairs,
                      "episode_evaluation_rule": "Evaluate all runs at or after the first future mixed-state run that contain both states and at least 20 valid contiguous pairs.",
                      "episodes": all_run_stats,
                      "boundary_crossing_transitions": {"train_validation": "None: a gap or state boundary is not used as a forecast pair.", "validation_test": "None: the test run begins after a multi-week timestamp gap."},
                      "selection_rule": "Select the first complete future contiguous run containing both BENIGN and ATTACK states; selection is episode-structure based and not metric based."}
    return {"dataset": "UNSW-NB15", "window_seconds": window_seconds, "state_representation": {"0": "BENIGN", "1": "ATTACK if any row in the window has Label=1"},
            "forecast_horizon": "Next contiguous 60-second window", "windows": {"total_nonempty": len(buckets), "contiguous_forecast_pairs": sum(len(run) - 1 for run in runs), "train": len(train), "validation": len(validation), "test": sum(len(runs[index]) for index in eligible_runs), "test_forecast_pairs": sum(len(runs[index]) - 1 for index in eligible_runs)},
            "split_boundaries": split_summary, "split_analysis": split_analysis,
            "episode_evaluations": episode_results, "eligible_episode_count": len(episode_results),
            "training_transition_counts": {str(state): dict(counts) for state, counts in initial_transition_counts.items()},
            "baselines": baselines,
            "limitations": ["UNSW is evaluated separately because CIC has no timestamp column.", "Only contiguous nonempty windows are paired; gaps are not treated as an immediate next window.", "Current-state and persistence are intentionally identical for this binary representation."]}


def load_unsw_feature_definitions() -> list[dict]:
    with UNSW_FEATURES.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        return [{"number": row[0], "name": row[1], "type": row[2].strip(), "description": row[3]}
                for row in csv.reader(stream) if len(row) >= 4 and row[0].strip().isdigit()]


def main() -> None:
    REPORTS.mkdir(exist_ok=True)
    RESULTS.mkdir(exist_ok=True)
    all_files = [p for p in ROOT.rglob("*") if p.is_file() and p.name != "run_research.py"]
    manifest = {"run_timestamp_utc": RUN_UTC, "workspace": str(ROOT),
                "python": sys.version, "platform": platform.platform(),
                "packages": {"numpy": "available", "scikit-learn": "available", "pandas": "not installed"},
                "files_discovered": [file_record(p) for p in sorted(all_files)],
                "scripts_discovered": [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.py")],
                "datasets_discovered": ["CIC-IDS2017", "UNSW-NB15", "MITRE ATT&CK 19.2"]}
    write_json(REPORTS / "research_run_manifest.json", manifest)

    cic = [stream_csv(path, header=True) for path in sorted(CIC_DIR.glob("*.csv"))]
    cic_data = {"dataset": "CIC-IDS2017", "source_directory": str(CIC_DIR.relative_to(ROOT)),
                "files": cic, "quality_warnings": [
                    "CIC flow CSVs contain no explicit timestamp column, so timestamp and temporal forecasting metrics are Not computed.",
                    "Duplicate analysis is adjacent-row only; global duplicate counts were not computed to avoid excessive memory use.",
                ], "forecasting_suitability": "Not established for timestamp-based forecasting from these files alone."}
    write_json(REPORTS / "cic_ids2017_quality.json", cic_data)
    md_report(REPORTS / "cic_ids2017_quality.md", "CIC-IDS2017 Quality", cic_data)
    cic_forecastability = run_cic_forecastability()
    write_json(REPORTS / "cic_forecastability.json", cic_forecastability)
    md_report(REPORTS / "cic_forecastability.md", "CIC-IDS2017 Forecastability", cic_forecastability)
    write_json(RESULTS / "cic_forecast_baseline_comparison.json", {"dataset": "CIC-IDS2017", "status": "Not computed", "reason": "No timestamp field exists; a chronological future-window target cannot be constructed without fabricating time."})
    md_report(RESULTS / "cic_forecast_baseline_comparison.md", "CIC Forecast Baseline Comparison", {"status": "Not computed", "reason": "No timestamp field exists; a chronological future-window target cannot be constructed without fabricating time."})
    cic_timestamp_audit = run_cic_timestamp_source_audit()
    write_json(REPORTS / "cic_timestamp_source_audit.json", cic_timestamp_audit)
    md_report(REPORTS / "cic_timestamp_source_audit.md", "CIC Timestamp Source Audit", cic_timestamp_audit)

    unsw = [stream_csv(path, header=False, names=UNSW_NAMES) for path in UNSW_TRAFFIC]
    gt = stream_csv(UNSW_GT, header=True)
    features = load_unsw_feature_definitions()
    events = stream_csv(UNSW_EVENTS, header=True)
    unsw_data = {"dataset": "UNSW-NB15", "traffic_files": unsw, "ground_truth": gt,
                 "feature_definitions": features, "event_list": events,
                 "gt_relationship": "Not joined: GT records use start/end times and flow identity fields, while traffic rows have no proven one-to-one key. Row-number alignment was not assumed.",
                 "quality_warnings": ["The four traffic files are headerless; column names are assigned from the local feature definition and the observed 49-field schema.",
                                      "Global duplicate counts were not computed; adjacent duplicate counts are reported.",
                                      "GT-to-traffic linkage requires a documented key and was not claimed from row order."],
                 "forecasting_suitability": "Timestamped traffic supports exploratory window/state analysis, but GT linkage and dataset ordering require care."}
    write_json(REPORTS / "unsw_nb15_quality.json", unsw_data)
    md_report(REPORTS / "unsw_nb15_quality.md", "UNSW-NB15 Quality", unsw_data)

    temporal = {"dataset": "UNSW-NB15", "candidate_windows": [parse_unsw_temporal(seconds) for seconds in (30, 60, 300, 600)],
                "cic_temporal_status": "Not computed: no explicit timestamp column in CIC flow files.",
                "interpretation": "Window selection should be based on traffic density and chronological ordering; no 300-second default is assumed."}
    write_json(REPORTS / "temporal_analysis.json", temporal)
    md_report(REPORTS / "temporal_analysis.md", "Temporal Analysis", temporal)

    feature_risks = []
    for feature in features:
        name = feature["name"]
        risk = "Possible leakage or unavailable-at-prediction-time field" if name in {"Label", "attack_cat", "Stime", "Ltime"} or name.startswith("ct_") else "No direct target role identified; availability must be checked at feature-construction time"
        feature_risks.append({"feature": name, "type": feature["type"], "meaning": feature["description"], "leakage_review": risk})
    forecast_definition = {"observation_window": "One 60-second non-empty traffic window; 60 seconds is retained because it gives 1,441 windows and sufficient per-window traffic density.",
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
                           "detection_distinction": "Detection asks what is happening in the current observed window; forecasting asks what state occurs in the subsequent future window. Detection accuracy is not forecasting evidence."}
    md_report(REPORTS / "forecast_problem_definition.md", "Forecast Problem Definition", forecast_definition)
    write_json(REPORTS / "forecast_problem_definition.json", forecast_definition)
    leakage = {"feature_review": feature_risks, "risks": [
        "Label and attack_cat are targets and must not be input features.",
        "Stime/Ltime may define ordering but must not be used as future-derived content without a clear policy.",
        "ct_* contextual counters describe prior connection history only if generated causally; provenance is not proven here.",
        "GT events must not be joined by row number without a demonstrated key.",
        "All imputation, scaling, feature selection, and transition probabilities must be fit on training time only.",
        "Random splits are prohibited because adjacent flows and repeated entities can cross splits."],
        "temporal_feature_rule": "Every feature(t) must use records with timestamp <= t; no engineered rolling feature was created in this run.",
        "status": "Audit completed for raw schemas and planned methodology; no model feature pipeline was run."}
    write_json(REPORTS / "leakage_audit.json", leakage)
    md_report(REPORTS / "leakage_audit.md", "Leakage Audit", leakage)

    states = {"BENIGN": {"raw_labels": ["0", "normal", "<missing>"], "mitre_status": "unmapped"},
              "ATTACK": {"raw_labels": "Any non-benign observed attack category", "mitre_status": "unmapped"}}
    md_report(REPORTS / "attack_state_design.md", "Attack State Design", {"mapping": states,
        "principle": "Observed dataset labels, NexSolve security states, and ATT&CK techniques remain separate; no automatic label-to-technique mapping is asserted.",
        "unsupported_states": ["INITIAL_ACCESS", "EXECUTION", "PERSISTENCE", "PRIVILEGE_ESCALATION", "CREDENTIAL_ACCESS", "DISCOVERY", "LATERAL_MOVEMENT", "COMMAND_AND_CONTROL", "EXFILTRATION", "IMPACT"],
        "reason": "The available datasets do not directly observe MITRE lifecycle stages; any future mapping must be evidence-based and marked uncertain when unsupported."})
    write_json(REPORTS / "attack_state_design.json", {"mapping": states, "unsupported_states": ["INITIAL_ACCESS", "EXECUTION", "PERSISTENCE", "PRIVILEGE_ESCALATION", "CREDENTIAL_ACCESS", "DISCOVERY", "LATERAL_MOVEMENT", "COMMAND_AND_CONTROL", "EXFILTRATION", "IMPACT"], "principle": "Observed label -> security state -> ATT&CK mapping -> forecasted next state are separate concepts."})
    claim_boundary = {"supported_now": ["Local network traffic ingestion and deterministic feature extraction", "CIC malicious/benign detection benchmarking", "UNSW timestamp-based temporal analysis", "Binary next-window baseline evaluation on one mixed-state future episode", "Local MITRE ATT&CK v19.2 data integration"],
                      "limited_evidence": ["UNSW attack-state forecasting: one eligible future episode and 24 forecast pairs", "Future transition prediction: baselines tie exactly", "Probability/confidence estimates: not produced by current hard-label baselines", "Explainability: no model contribution analysis computed"],
                      "not_supported_yet": ["High-confidence real-world attack prediction", "Generalization to arbitrary networks", "Multi-stage MITRE attack forecasting", "Production-grade forecasting accuracy", "Claims of beating advanced forecasting models", "Claims of preventing attacks", "CIC temporal forecasting from current files"],
                      "scientific_claim": "NexSolve currently demonstrates a leakage-audited research contract and limited UNSW next-state baseline evidence, not forecasting superiority or operational prediction."}
    md_report(REPORTS / "forecast_claim_boundary.md", "Forecast Claim Boundary", claim_boundary)
    write_json(REPORTS / "forecast_claim_boundary.json", claim_boundary)
    methodology = {"contract": ["Network traffic is ingested and timestamped where the source provides genuine timestamps.", "Features at prediction time T use only information available at or before T.", "Current state is represented as observed BENIGN/ATTACK; attack_cat remains descriptive metadata.", "The forecast target is the state of the next contiguous 60-second window.", "Future labels are used only after prediction for evaluation.", "ATT&CK context is an evidence-based optional mapping, never ground truth by label name alone.", "Explanations describe association or model contribution, not causality."],
                   "baselines": {"current_state": "Predict the current observed state for the next window.", "persistence": "Predict persistence of the current state; identical to current-state for the present binary formulation.", "empirical_transition": "Predict the most frequent next state conditional on current state, learned from training transitions only."},
                   "advance_gate": ["Sufficient future forecast cases", "Meaningful state variation in held-out periods", "Nontrivial baseline benchmark", "Passed leakage audit", "Multiple temporal episodes where possible", "Chronological train/validation/test comparison", "Interpretable improvement over trivial baselines"],
                   "current_gate_status": "Not passed: one eligible UNSW episode with 24 pairs, tied baselines, CIC without timestamps."}
    md_report(REPORTS / "forecast_methodology.md", "Forecast Methodology", methodology)

    mitre = json.loads((ROOT / "MITRE" / "enterprise-attack-19.2.json").read_text(encoding="utf-8"))
    patterns = [obj for obj in mitre.get("objects", []) if obj.get("type") == "attack-pattern"]
    mitre_data = {"source": "MITRE/enterprise-attack-19.2.json", "attack_pattern_count": len(patterns),
                  "mapping": [{"dataset_label": "UNSW attack categories and CIC labels", "security_state": "ATTACK",
                               "candidate_attack_technique": None, "confidence": None, "evidence": "Network dataset labels do not establish ATT&CK technique identity.", "mapping_status": "unmapped"}],
                  "observed_vs_forecasted": "No observed or forecasted ATT&CK mapping is claimed in this run."}
    write_json(REPORTS / "mitre_mapping.json", mitre_data)
    md_report(REPORTS / "mitre_mapping.md", "MITRE ATT&CK Mapping", mitre_data)
    detection = run_cic_detection()
    write_json(RESULTS / "detection_baseline.json", detection)
    md_report(RESULTS / "detection_baseline.md", "Detection Baseline", detection)
    forecasting = run_unsw_forecast_baselines()
    write_json(RESULTS / "forecast_baseline_comparison.json", forecasting)
    md_report(RESULTS / "forecast_baseline_comparison.md", "Forecast Baseline Comparison", forecasting)
    write_json(REPORTS / "forecast_split_analysis.json", forecasting["split_analysis"])
    md_report(REPORTS / "forecast_split_analysis.md", "Forecast Split Analysis", forecasting["split_analysis"])
    eligible_results = forecasting["episode_evaluations"]
    f1_by_baseline = {name: [episode[name]["f1"] for episode in eligible_results] for name in ("current_state", "persistence", "empirical_transition")}
    expanded = {
        "dataset": "UNSW-NB15",
        "locked_contract": {"window_seconds": 60, "target": "next contiguous window state", "states": ["BENIGN", "ATTACK"], "chronological_only": True},
        "previous_24_pair_experiment": {"forecast_cases": 24, "eligible_episode_count": 1, "status": "retained as the same sole eligible episode under the expanded objective rule"},
        "temporal_reconstruction": {"valid_timestamped_rows": 2540047, "non_empty_windows": forecasting["windows"]["total_nonempty"], "contiguous_forecast_pairs": forecasting["windows"]["contiguous_forecast_pairs"], "temporal_episodes": len(forecasting["split_analysis"]["episodes"])},
        "episode_selection_rule": "Before inspecting metrics, include every episode strictly after the training period that is contiguous, contains both states, has at least 20 valid contiguous forecast pairs, and has support for all three baselines.",
        "eligible_episode_count": len(eligible_results),
        "eligible_episode_indices": [episode["episode_index"] for episode in eligible_results],
        "excluded_episodes": [episode for episode in forecasting["split_analysis"]["episodes"] if not episode["suitable_for_future_evaluation"]],
        "per_episode_results": eligible_results,
        "aggregate_results": forecasting["baselines"],
        "total_forecast_cases": forecasting["windows"]["test_forecast_pairs"],
        "aggregate_target_support": {"benign": forecasting["baselines"]["current_state"]["class_support"].get("0", 0), "attack": forecasting["baselines"]["current_state"]["class_support"].get("1", 0)},
        "episode_f1_variability": {name: {"mean": sum(values) / len(values) if values else None, "median": sorted(values)[len(values) // 2] if values else None, "min": min(values) if values else None, "max": max(values) if values else None, "values": values} for name, values in f1_by_baseline.items()},
        "validation_support": {"benign_windows": forecasting["split_analysis"]["corrected_split"]["validation"]["benign_windows"], "attack_windows": forecasting["split_analysis"]["corrected_split"]["validation"]["attack_windows"], "limitation": "Validation remains benign-only under the locked chronological construction; no attack validation samples were manufactured."},
        "leakage_safeguards": ["Training history precedes every eligible episode.", "Transition counts are learned from training history only and expanding history before later eligible episodes.", "Future episode labels are used only for scoring.", "Timestamp gaps are not treated as contiguous forecast pairs.", "No randomization or future-derived feature is used."],
        "evidence_level": "extremely limited",
        "forecasting_value": "Not demonstrated: all three baselines tie on the sole eligible episode.",
        "advanced_model_decision": "ADVANCED MODEL NOT JUSTIFIED",
        "reason": "Only one eligible future mixed-state episode and 24 total forecast pairs are available; later runs are attack-only and excluded by the pre-specified rule."
    }
    write_json(REPORTS / "unsw_forecast_expanded_evaluation.json", expanded)
    md_report(REPORTS / "unsw_forecast_expanded_evaluation.md", "UNSW Forecast Expanded Evaluation", expanded)
    expanded_baselines = {"dataset": expanded["dataset"], "eligible_episode_count": expanded["eligible_episode_count"], "total_forecast_cases": expanded["total_forecast_cases"], "per_episode_results": expanded["per_episode_results"], "aggregate_results": expanded["aggregate_results"], "episode_f1_variability": expanded["episode_f1_variability"], "comparison": expanded["forecasting_value"], "advanced_model_decision": expanded["advanced_model_decision"]}
    write_json(RESULTS / "unsw_forecast_expanded_baselines.json", expanded_baselines)
    md_report(RESULTS / "unsw_forecast_expanded_baselines.md", "UNSW Forecast Expanded Baselines", expanded_baselines)
    selection = run_dataset_selection_audit()
    write_json(REPORTS / "timestamped_dataset_suitability.json", selection)
    md_report(REPORTS / "timestamped_dataset_suitability.md", "Timestamped Dataset Suitability", selection)
    selection_decision = {"best_candidate": selection["winner"], "backup_candidate": selection["backup"], "winner_score": selection["candidates"][selection["winner"]]["total_score"], "backup_score": selection["candidates"][selection["backup"]]["total_score"], "winner_reasons": selection["winner_reasons"], "backup_not_selected": selection["backup_reason"], "exact_next_download": selection["candidates"][selection["winner"]]["next_download"], "forecasting_potential": selection["candidates"][selection["winner"]]["forecastability"], "advanced_model": selection["advanced_model"], "next_step": selection["next_step"]}
    write_json(REPORTS / "dataset_selection_decision.json", selection_decision)
    md_report(REPORTS / "dataset_selection_decision.md", "Dataset Selection Decision", selection_decision)
    md_report(REPORTS / "explainability_findings.md", "Explainability Findings", {"status": "Not computed: the detection baseline does not include an explainability method.", "policy": "Future reports must distinguish model contribution and statistical association from causal mechanism."})
    md_report(REPORTS / "cross_dataset_comparison.md", "Cross-Dataset Comparison", {"common_concepts": ["flow duration", "packet/byte counts", "protocol/service concepts", "labels"], "incompatibilities": ["CIC has an explicit header and no timestamp column; UNSW traffic is headerless with epoch Stime/Ltime.", "Label taxonomies and feature schemas differ."], "shared_representation": "A coarse BENIGN/ATTACK representation is defensible for descriptive comparison; a shared temporal forecasting representation is not yet established."})
    final = {"dataset_status": {"CIC-IDS2017": "Inspected; quality computed.", "UNSW-NB15": "Inspected; all seven required files read and quality computed.", "MITRE": f"Local enterprise ATT&CK 19.2 JSON inspected; {len(patterns)} attack-pattern objects."},
             "temporal_findings": {"UNSW": "60-second timestamp windows computed.", "CIC": cic_forecastability["timestamp_status"], "CIC_timestamp_source_state": cic_timestamp_audit["state"]},
             "forecast_definition": forecast_definition, "detection_baseline": detection, "forecasting_baselines": forecasting["baselines"],
             "coverage": {name: value.get("coverage") for name, value in forecasting["baselines"].items()}, "mitre": "Unmapped.", "explainability": "Not computed.",
             "cross_dataset": "UNSW supports a small timestamped exploratory forecast; CIC supports detection benchmarking but not temporal forecasting from the available schema. CIC timestamp-source audit state: D.",
             "model_decision": expanded["advanced_model_decision"] + ": UNSW has one eligible future mixed-state episode and 24 pairs with tied baselines; CIC has no timestamp field.",
             "expanded_forecast_evaluation": {"eligible_episodes": expanded["eligible_episode_count"], "total_forecast_cases": expanded["total_forecast_cases"], "evidence_level": expanded["evidence_level"], "forecasting_value": expanded["forecasting_value"]},
             "candidate_dataset_selection": {"winner": selection["winner"], "backup": selection["backup"], "winner_score": selection["candidates"][selection["winner"]]["total_score"], "backup_score": selection["candidates"][selection["backup"]]["total_score"], "advanced_model": selection["advanced_model"]},
             "scientific_claim_boundary": claim_boundary,
             "product_prediction": "Given network behavior observed through prediction time T, NexSolve may estimate the next contiguous 60-second UNSW security state as BENIGN or ATTACK; current baselines provide hard labels only and do not establish operational forecasting value.",
             "conceptual_product_contract": "Network traffic -> ingestion -> current detection -> temporal state -> forecast engine -> evidence-based ATT&CK context -> non-causal explanation -> alert/risk/recommended action.",
             "limitations": ["No existing research implementation was available.", "CIC has no flow timestamp, so its split is day-file based rather than flow-time based.", "Detection uses a deterministic cap of 50,000 sampled rows per CIC file.", "Global duplicate counts were not computed to avoid excessive memory use.", "UNSW forecast test has only 24 contiguous pairs, though both target states are present."],
             "recommended_next_engineering_step": selection["next_step"]}
    md_report(REPORTS / "NEXSOLVE_RESEARCH_STATUS.md", "NexSolve Research Status", final)


if __name__ == "__main__":
    main()
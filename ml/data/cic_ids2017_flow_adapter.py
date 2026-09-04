"""Deterministic adapter and audit for CIC-IDS2017 ISCX flow CSV files."""
from __future__ import annotations

import csv
import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[2]
CIC_DIR = ROOT / "CIC-IDS2017" / "MachineLearningCSV" / "MachineLearningCVE"
REPORT_JSON = ROOT / "reports" / "cic_ids2017_flow_audit.json"
REPORT_MD = ROOT / "reports" / "cic_ids2017_flow_audit.md"

FLOW_GROUPS = {
    "bytes": ["Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std", "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Subflow Fwd Bytes", "Subflow Bwd Bytes"],
    "packets": ["Total Fwd Packets", "Total Backward Packets", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s", "Subflow Fwd Packets", "Subflow Bwd Packets"],
    "duration": ["Flow Duration", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"],
    "tcp_flags": ["Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count"],
    "iat": ["Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min"],
    "flow_direction_and_other": ["Destination Port", "Down/Up Ratio", "Fwd Header Length", "Bwd Header Length", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward"],
}
PACKET_FEATURES = ["ttl", "ttl_variance", "tcp_window_size", "fragmentation", "payload_size_distribution", "retransmission_indicators", "packet_level_timing", "packet_level_scan_signatures"]


def normalize_column_names(names: list[str]) -> list[str]:
    seen: Counter[str] = Counter()
    result = []
    for name in names:
        normalized = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
        seen[normalized] += 1
        result.append(normalized if seen[normalized] == 1 else f"{normalized}_{seen[normalized]}")
    return result


def normalize_label(value: str) -> str | None:
    label = re.sub(r"\s+", " ", value.strip()).upper()
    return label or None


def parse_number(value: str) -> float | None:
    try:
        parsed = float(value.strip())
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def digest(row: list[str]) -> str:
    return hashlib.sha256("\x1f".join(row).encode("utf-8", "replace")).hexdigest()


def audit_file(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        reader = csv.reader(stream)
        names = [name.strip() for name in next(reader, [])]
        normalized = normalize_column_names(names)
        label_index = names.index("Label") if "Label" in names else None
        timestamp_columns = [name for name in names if "time" in name.lower() or "timestamp" in name.lower()]
        rows = valid_rows = wrong_width = invalid_rows = duplicate_rows = 0
        missing: Counter[str] = Counter()
        malformed: Counter[str] = Counter()
        labels: Counter[str] = Counter()
        seen: set[str] = set()
        timestamps: list[float] = []
        order_violations = 0
        previous_timestamp = None
        for row in reader:
            if not row or not any(cell.strip() for cell in row):
                continue
            rows += 1
            row_digest = digest(row)
            duplicate_rows += row_digest in seen
            seen.add(row_digest)
            if len(row) != len(names):
                wrong_width += 1
                continue
            invalid = False
            for index, value in enumerate(row):
                if not value.strip():
                    missing[names[index]] += 1
                elif index != label_index and parse_number(value) is None:
                    malformed[names[index]] += 1
                    invalid = True
            if label_index is not None:
                label = normalize_label(row[label_index])
                if label is None:
                    missing[names[label_index]] += 1
                else:
                    labels[label] += 1
            if invalid:
                invalid_rows += 1
                continue
            valid_rows += 1
            for column in timestamp_columns:
                timestamp = parse_number(row[names.index(column)])
                if timestamp is not None:
                    timestamps.append(timestamp)
                    if previous_timestamp is not None and timestamp < previous_timestamp:
                        order_violations += 1
                    previous_timestamp = timestamp
        available = {group: [column for column in columns if column in names] for group, columns in FLOW_GROUPS.items()}
        return {
            "file": str(path.relative_to(ROOT)).replace("\\", "/"), "file_size_bytes": path.stat().st_size,
            "row_count": rows, "valid_row_count": valid_rows, "column_count": len(names),
            "column_names_exact": names, "normalized_column_names": normalized,
            "timestamp": {"available": bool(timestamp_columns), "columns": timestamp_columns,
                           "range": {"min": min(timestamps) if timestamps else None, "max": max(timestamps) if timestamps else None},
                           "order_violations": order_violations},
            "label_distribution": dict(labels),
            "missing_values": {"total_cells": sum(missing.values()), "by_column": dict(missing)},
            "malformed_values": {"total_rows": wrong_width + invalid_rows, "wrong_width_rows": wrong_width,
                                  "non_numeric_rows": invalid_rows, "by_column": dict(malformed)},
            "duplicate_rows": int(duplicate_rows),
            "source_destination_ips": {"source": False, "destination": False},
            "source_destination_ports": {"source": False, "destination": "Destination Port" in names},
            "protocol": {"available": False, "columns": []},
            "available_flow_features": available,
            "packet_features": {name: {"available": False, "columns": []} for name in PACKET_FEATURES},
            "temporal_features": {"within_flow_iat_columns": available["iat"], "causal_event_timestamp": False,
                                   "causal_temporal_features_available": False},
        }


def iter_adapted_records(path: Path) -> Iterator[dict]:
    """Yield valid records in source-file and source-row order."""
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        reader = csv.reader(stream)
        names = [name.strip() for name in next(reader, [])]
        normalized = normalize_column_names(names)
        label_index = names.index("Label") if "Label" in names else None
        for source_row, row in enumerate(reader, start=2):
            if not row or len(row) != len(names) or not any(cell.strip() for cell in row):
                continue
            features = {}
            invalid = False
            for index, value in enumerate(row):
                if index == label_index:
                    features[normalized[index]] = normalize_label(value)
                elif not value.strip():
                    features[normalized[index]] = None
                else:
                    parsed = parse_number(value)
                    if parsed is None:
                        invalid = True
                        break
                    features[normalized[index]] = parsed
            label = features.get(normalized[label_index]) if label_index is not None else None
            if invalid or label is None:
                continue
            yield {"timestamp": None, "source_file": path.name, "source_row": source_row, "label": label, "features": features}


def build_report() -> dict:
    audits = [audit_file(path) for path in sorted(CIC_DIR.glob("*.csv"), key=lambda item: item.name)]
    schemas = {tuple(item["column_names_exact"]) for item in audits}
    portscan = next((item for item in audits if "PortScan" in item["file"]), None)
    return {
        "title": "CIC-IDS2017 ISCX flow CSV audit", "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source_directory": str(CIC_DIR.relative_to(ROOT)).replace("\\", "/"), "files_audited": len(audits), "schema_consistent": len(schemas) == 1,
        "chronological_combination": {"possible": False, "reason": "No exact timestamp field exists; preserve source file and row order, without shuffling."},
        "world_model_mapping": {
            "flow_level_features": "Verified aggregate columns listed per file.",
            "current_schema": {"available_direct_or_aggregate": {"flow_count": "row count", "total_src_bytes": "Total Length of Fwd Packets", "total_dst_bytes": "Total Length of Bwd Packets", "total_packets": "Total Fwd Packets + Total Backward Packets", "mean_duration": "Flow Duration", "mean_flow_bytes": "forward plus backward byte totals divided by flow count", "mean_flow_packets": "forward plus backward packet totals divided by flow count", "mean_iat": "Flow IAT Mean", "unique_dst_ports": "Destination Port distinct-count aggregation"}, "unavailable": ["mean_sttl", "mean_dttl", "mean_swin", "mean_dwin", "mean_tcp_rtt", "unique_src_ports", "proto_tcp_count", "proto_udp_count", "proto_other_count"]},
            "packet_level_features": "Unavailable; flow aggregates are not packet observations.",
            "causal_temporal_features": "Unavailable without event timestamps; IAT fields are within-flow aggregates.",
        },
        "adapter_transformations": ["UTF-8 CSV with BOM tolerance.", "Trim exact headers and normalize to lowercase snake_case; duplicate normalized names get deterministic suffixes.", "Normalize labels by trimming, collapsing whitespace, and uppercasing.", "Reject wrong-width, non-numeric, non-finite, or missing-label records.", "Preserve alphabetical source-file order and source-row order; timestamp remains null.", "Never synthesize packet or causal temporal features."],
        "files": audits, "quality_report": {"total_rows": sum(item["row_count"] for item in audits), "total_valid_rows": sum(item["valid_row_count"] for item in audits), "total_duplicate_rows": sum(item["duplicate_rows"] for item in audits), "total_malformed_rows": sum(item["malformed_values"]["total_rows"] for item in audits)},
        "portscan_assessment": portscan,
        "pcap_requirement": ["TTL", "TTL variance", "TCP window size", "fragmentation", "payload-size distribution", "retransmission indicators", "packet-level timing", "packet-level scan signatures"],
    }


def write_reports() -> dict:
    report = build_report()
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    lines = ["# CIC-IDS2017 Flow Audit", "", "This audit covers only the eight ISCX flow CSVs. They are not packet captures.", "", "## Executive Findings", "", "- No file contains an exact timestamp, source/destination IP, source port, or protocol field.", "- Flow aggregates are usable; packet-level and causal event-time features remain unavailable.", "- The files cannot be combined chronologically without an external timestamp source.", "- The adapter preserves source order and rejects malformed records; it does not retrain or modify the World Model.", ""]
    for audit in report["files"]:
        lines += [f"## {Path(audit['file']).name}", "", f"- Size: {audit['file_size_bytes']} bytes", f"- Rows: {audit['row_count']} ({audit['valid_row_count']} valid)", f"- Columns: {audit['column_count']}", f"- Timestamp: {'available' if audit['timestamp']['available'] else 'unavailable'}", f"- Timestamp range: {audit['timestamp']['range']}", f"- Labels: `{json.dumps(audit['label_distribution'], ensure_ascii=True)}`", f"- Missing values: {audit['missing_values']}", f"- Malformed values: {audit['malformed_values']}", f"- Duplicate rows: {audit['duplicate_rows']}", "- Source/destination IPs: unavailable / unavailable", "- Source/destination ports: unavailable / Destination Port available", "- Protocol: unavailable", "", "### Exact Columns", "", "```text", ", ".join(audit["column_names_exact"]), "```", "", "### Feature Availability", "", "```json", json.dumps({"flow": audit["available_flow_features"], "packet": audit["packet_features"], "temporal": audit["temporal_features"]}, indent=2, ensure_ascii=True), "```", ""]
    portscan = report["portscan_assessment"]
    lines += ["## PortScan Assessment", "", f"- Records: {portscan['row_count']}", f"- Attack labels: `{json.dumps(portscan['label_distribution'], ensure_ascii=True)}`", "- Timestamp coverage: none", "- Temporal ordering: unavailable; source order is not event chronology", "- Meaningful PortScan temporal episode: no, not from this CSV alone because event timestamps and endpoint identity are absent.", "", "## Final Answers", "", "### A. Flow Features", "Directly usable or aggregatable: Destination Port, Flow Duration, forward/backward packet counts, forward/backward byte totals, packet-length statistics, flow/forward/backward rates, within-flow IAT aggregates, TCP flag counters, header lengths, initial window-byte aggregates, active/idle statistics, subflow counts/bytes, and related numeric flow fields. The current model mappings are explicit in the JSON report; TTL, direction-specific TCP window means, RTT, source-port uniqueness, and protocol counts are unavailable rather than inferred.", "", "### B. Packet Features", "TTL and TTL variance, packet TCP window observations, fragmentation, per-packet payload-size distribution, retransmission indicators, packet-level timing, and packet-level scan signatures remain unavailable.", "", "### C. PCAPs", "Acquire the official original PCAP for Friday-WorkingHours-Afternoon-PortScan first, as previously identified in the research status, then the original scenario-matched captures for Friday morning, Friday afternoon DDoS, Monday, Tuesday, Wednesday, Thursday morning WebAttacks, and Thursday afternoon Infiltration. Exact archive filenames and checksums must be verified at acquisition; no PCAP is present locally. The CSVs do not contain the required packet evidence.", "", "### D. World Model Schema", "Do not modify the current schema or trained model. Keep packet fields explicitly unavailable and add flow ingestion only at this separate adapter boundary.", "", "### E. Temporal Training", "Not ready for timestamp-based temporal training. The CSVs are ready for deterministic flow-level static analysis and label-preserving ingestion, but chronological training requires verified event timestamps; SIH packet compliance additionally requires the original PCAPs.", "", "## Recommendation", "Acquire and audit the official scenario-matched PCAPs, beginning with Friday-WorkingHours-Afternoon-PortScan. Add verified packet observations through a separate PCAP adapter, validate event ordering and episode boundaries, and only then consider a controlled training experiment. Do not retrain the current World Model yet.", ""]
    REPORT_MD.write_text("\n".join(lines), encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(write_reports()["quality_report"], indent=2))
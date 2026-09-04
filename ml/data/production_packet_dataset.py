"""Read-only access and validation for the completed packet-window dataset."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_DATASET = ROOT / "data" / "processed" / "cic_ids2017_packet_windows.parquet"

REQUIRED_COLUMNS = (
    "window_start", "window_end", "packet_count", "ttl_mean", "ttl_variance", "ttl_min", "ttl_max",
    "tcp_window_mean", "tcp_window_variance", "tcp_window_min", "tcp_window_max", "packet_size_mean",
    "packet_size_variance", "packet_size_min", "packet_size_max", "payload_mean", "payload_variance",
    "payload_min", "payload_max", "iat_mean", "iat_variance", "iat_min", "iat_max", "packet_size_median",
    "packet_size_p95", "payload_median", "payload_p95", "iat_median", "iat_p95", "payload_zero_ratio",
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count", "urg_count", "fragment_count",
    "fragment_ratio", "tcp_count", "udp_count", "icmp_count", "unique_src_ips", "unique_dst_ips",
    "unique_dst_ports", "tcp_retransmission_count", "tcp_retransmission_rate", "port_scan_score",
    "protocol_counts",
)


def _table(path: str | Path = PRODUCTION_DATASET):
    import pyarrow.parquet as parquet

    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise FileNotFoundError("production packet dataset is unavailable")
    return parquet.read_table(dataset_path)


def load_packet_windows(path: str | Path = PRODUCTION_DATASET) -> list[dict[str, Any]]:
    """Load aggregated windows without reading or rewriting the source file."""
    return _table(path).to_pylist()


def validate_packet_dataset(path: str | Path = PRODUCTION_DATASET) -> dict[str, Any]:
    table = _table(path)
    columns = table.column_names
    missing_columns = [name for name in REQUIRED_COLUMNS if name not in columns]
    null_counts = {name: int(table[name].null_count) for name in columns}
    null_ratios = {name: count / table.num_rows if table.num_rows else 0.0 for name, count in null_counts.items()}
    constant_columns: list[str] = []
    numeric_ranges: dict[str, dict[str, float]] = {}
    for field in table.schema:
        if not str(field.type).startswith(("int", "uint", "float", "double")):
            continue
        values = table[field.name].to_pylist()
        finite = [float(value) for value in values if value is not None and math.isfinite(float(value))]
        if len(set(finite)) <= 1:
            constant_columns.append(field.name)
        if finite:
            numeric_ranges[field.name] = {"min": min(finite), "max": max(finite)}

    rows = table.to_pylist()
    protocols: dict[str, int] = {}
    for row in rows:
        for name, count in (row.get("protocol_counts") or {}).items():
            protocols[str(name)] = protocols.get(str(name), 0) + int(count or 0)
    starts = [int(row["window_start"]) for row in rows]
    ends = [int(row["window_end"]) for row in rows]
    return {
        "status": "VALID" if not missing_columns and table.num_rows else "INVALID",
        "rows": table.num_rows,
        "columns": columns,
        "dtypes": {field.name: str(field.type) for field in table.schema},
        "missing_columns": missing_columns,
        "null_counts": null_counts,
        "null_ratios": null_ratios,
        "constant_columns": sorted(constant_columns),
        "numeric_ranges": numeric_ranges,
        "protocol_counts": dict(sorted(protocols.items())),
        "window": {
            "unit": "UTC epoch seconds",
            "seconds": int(ends[0] - starts[0]) if starts and ends else None,
            "start_min": min(starts) if starts else None,
            "start_max": max(starts) if starts else None,
            "ordered": starts == sorted(starts),
        },
        "model_compatibility": {
            "flow_features_available": False,
            "packet_features_available": True,
            "labels_available": False,
            "forecast_model_ready": False,
            "reason": "The production artifact contains packet aggregates, not the world model's flow and temporal state contract.",
        },
    }
"""NFStream Integration Adapter & Canonical Schema Transformation Matrix.

Maps NFStream bidirectional statistical flow features to the NexSolve 45-feature
canonical world model contract.

Zero Hard Dependency: Runs either via installed 'nfstream' or via pre-exported
NFStream dictionaries/DataFrames/CSV data.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

try:
    import nfstream  # type: ignore
    NFSTREAM_AVAILABLE = True
except ImportError:
    NFSTREAM_AVAILABLE = False

from nexsolve_core.schemas import FlowRecord


# Explicit mathematical mapping between NFStream attributes and NexSolve 45-Feature Contract
NFSTREAM_TO_NEXSOLVE_MAP = {
    "src2dst_bytes": "total_src_bytes",
    "dst2src_bytes": "total_dst_bytes",
    "bidirectional_bytes": "total_bytes",
    "src2dst_packets": "total_src_packets",
    "dst2src_packets": "total_dst_packets",
    "bidirectional_packets": "total_packets",
    "bidirectional_syn_packets": "tcp_syn_count",
    "bidirectional_fin_packets": "tcp_fin_count",
    "bidirectional_rst_packets": "tcp_rst_count",
    "bidirectional_psh_packets": "tcp_psh_count",
    "bidirectional_ack_packets": "tcp_ack_count",
    "bidirectional_duration_ms": "duration (converted ms -> s)",
    "bidirectional_mean_ps": "mean_packet_len",
    "bidirectional_stddev_ps": "std_packet_len",
    "bidirectional_min_ps": "min_packet_len",
    "bidirectional_max_ps": "max_packet_len",
    "bidirectional_mean_piat_ms": "mean_iat (converted ms -> s)",
    "bidirectional_stddev_piat_ms": "std_iat (converted ms -> s)",
    "bidirectional_min_piat_ms": "min_iat (converted ms -> s)",
    "bidirectional_max_piat_ms": "max_iat (converted ms -> s)",
    "src2dst_tcp_initial_window_size": "mean_swin",
    "dst2src_tcp_initial_window_size": "mean_dwin",
}


class NFStreamAdapter:
    """Production adapter for NFStream bidirectional flow mapping."""

    def __init__(self) -> None:
        self.available = NFSTREAM_AVAILABLE

    @property
    def mapping_matrix(self) -> dict[str, str]:
        """Return the documented mapping between NFStream and NexSolve features."""
        return dict(NFSTREAM_TO_NEXSOLVE_MAP)

    def convert_flow(self, nflow: Mapping[str, Any], flow_index: int = 0) -> FlowRecord:
        """Convert a single NFStream flow dictionary or Series into a NexSolve FlowRecord."""
        flow_id = str(nflow.get("id") or f"nf-flow-{flow_index}")
        src_ip = str(nflow.get("src_ip", "0.0.0.0"))
        dst_ip = str(nflow.get("dst_ip", "0.0.0.0"))
        src_port = int(nflow.get("src_port", 0))
        dst_port = int(nflow.get("dst_port", 0))
        proto_num = int(nflow.get("protocol", 6))
        protocol = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else ("ICMP" if proto_num == 1 else "OTHER"))

        # Timestamps (ms -> s)
        first_seen_ms = float(nflow.get("bidirectional_first_seen_ms", 0.0))
        last_seen_ms = float(nflow.get("bidirectional_last_seen_ms", first_seen_ms))
        start_ts = first_seen_ms / 1000.0 if first_seen_ms > 1e6 else first_seen_ms
        end_ts = last_seen_ms / 1000.0 if last_seen_ms > 1e6 else last_seen_ms
        duration_s = float(nflow.get("bidirectional_duration_ms", 0.0)) / 1000.0

        # Packets and bytes
        total_pkts = int(nflow.get("bidirectional_packets", 0))
        src_pkts = int(nflow.get("src2dst_packets", total_pkts))
        dst_pkts = int(nflow.get("dst2src_packets", 0))
        total_bytes = int(nflow.get("bidirectional_bytes", 0))
        src_bytes = int(nflow.get("src2dst_bytes", total_bytes))
        dst_bytes = int(nflow.get("dst2src_bytes", 0))

        # TCP flags
        syn_count = int(nflow.get("bidirectional_syn_packets", 0))
        fin_count = int(nflow.get("bidirectional_fin_packets", 0))
        rst_count = int(nflow.get("bidirectional_rst_packets", 0))
        psh_count = int(nflow.get("bidirectional_psh_packets", 0))
        ack_count = int(nflow.get("bidirectional_ack_packets", 0))

        # Packet length moments
        mean_len = float(nflow.get("bidirectional_mean_ps", 0.0))
        std_len = float(nflow.get("bidirectional_stddev_ps", 0.0))
        min_len = int(nflow.get("bidirectional_min_ps", 0))
        max_len = int(nflow.get("bidirectional_max_ps", 0))

        # IAT moments (ms -> s)
        mean_iat = float(nflow.get("bidirectional_mean_piat_ms", 0.0)) / 1000.0
        std_iat = float(nflow.get("bidirectional_stddev_piat_ms", 0.0)) / 1000.0
        min_iat = float(nflow.get("bidirectional_min_piat_ms", 0.0)) / 1000.0
        max_iat = float(nflow.get("bidirectional_max_piat_ms", 0.0)) / 1000.0

        # Window sizes
        src_win = int(nflow.get("src2dst_tcp_initial_window_size", 0))
        dst_win = int(nflow.get("dst2src_tcp_initial_window_size", 0))

        from nexsolve_core.schemas import Provenance

        return FlowRecord(
            flow_id=flow_id,
            start_timestamp=start_ts,
            end_timestamp=end_ts,
            duration_seconds=duration_s,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            forward_packet_count=src_pkts,
            reverse_packet_count=dst_pkts,
            total_packet_count=total_pkts,
            forward_bytes=src_bytes,
            reverse_bytes=dst_bytes,
            total_bytes=total_bytes,
            packet_rate=total_pkts / duration_s if duration_s > 0 else 0.0,
            byte_rate=total_bytes / duration_s if duration_s > 0 else 0.0,
            syn_count=syn_count,
            ack_count=ack_count,
            fin_count=fin_count,
            rst_count=rst_count,
            retransmission_count=0,
            completeness="ESTABLISHED" if syn_count and ack_count else "UNKNOWN",
            provenance=Provenance(capture_id=flow_id, flow_ids=(flow_id,), transformation_stage="nfstream_conversion"),
        )

    def convert_flow_batch(self, nflows: Sequence[Mapping[str, Any]]) -> list[FlowRecord]:
        """Convert a batch of NFStream flow records into NexSolve FlowRecords."""
        return [self.convert_flow(nf, i) for i, nf in enumerate(nflows)]


def convert_flow(nflow: Any, flow_index: int = 0) -> FlowRecord:
    """Convenience function to convert a single NFStream flow into FlowRecord."""
    if not isinstance(nflow, Mapping) and hasattr(nflow, "__dict__"):
        nflow = {k: getattr(nflow, k) for k in dir(nflow) if not k.startswith("_")}
    elif not isinstance(nflow, Mapping):
        nflow = dict(nflow)
    return NFStreamAdapter().convert_flow(nflow, flow_index)


def convert_flow_batch(nflows: Sequence[Any]) -> list[FlowRecord]:
    """Convenience function to convert a batch of NFStream flows into FlowRecords."""
    return [convert_flow(nf, i) for i, nf in enumerate(nflows)]

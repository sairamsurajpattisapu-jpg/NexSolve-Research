"""Cryptographic capture fingerprinting, capability probing, and feature provenance tracking."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


@dataclass(slots=True, frozen=True)
class CaptureFingerprint:
    """Cryptographic and architectural fingerprint of an ingested capture."""

    sha256: str
    file_size_bytes: int
    format: str
    magic: str
    link_type: str
    packet_count: int
    duration_seconds: float
    capabilities: dict[str, Any] = field(default_factory=dict)
    provenance_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_pcap(
        cls,
        file_path: Path | str,
        packet_count: int = 0,
        duration_seconds: float = 0.0,
        capabilities: dict[str, Any] | None = None,
        provenance_metadata: dict[str, Any] | None = None,
    ) -> CaptureFingerprint:
        path = Path(file_path)
        sha256 = compute_pcap_sha256(path)
        file_size = path.stat().st_size if path.exists() else 0
        magic_hex = "unknown"
        fmt = path.suffix.lstrip(".").lower() or "pcap"
        link_type = "Ethernet"

        if path.exists() and file_size >= 4:
            with open(path, "rb") as f:
                header = f.read(32)
            magic_bytes = header[:4]
            magic_hex = f"0x{magic_bytes.hex()}"
            if magic_bytes in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                fmt = "pcap"
                if len(header) >= 24:
                    import struct
                    order = "<" if magic_bytes in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
                    linktype_id = struct.unpack(f"{order}I", header[20:24])[0]
                    link_map = {0: "NULL", 1: "Ethernet", 9: "PPP", 12: "RAW_IP", 101: "RAW_IP", 105: "IEEE802_11", 113: "LINUX_SLL"}
                    link_type = link_map.get(linktype_id, f"LINKTYPE_{linktype_id}")
            elif magic_bytes == b"\x0a\x0d\x0d\x0a":
                fmt = "pcapng"
                link_type = "PCAPNG_INTERFACE"

        if capabilities and capabilities.get("link_type") and capabilities["link_type"] != "UNKNOWN":
            link_type = str(capabilities["link_type"])

        return cls(
            sha256=sha256,
            file_size_bytes=file_size,
            format=fmt,
            magic=magic_hex,
            link_type=link_type,
            packet_count=packet_count,
            duration_seconds=duration_seconds,
            capabilities=dict(capabilities or {}),
            provenance_metadata=dict(provenance_metadata or {}),
        )


def compute_pcap_sha256(file_path: Path | str, chunk_size: int = 65536) -> str:
    """Streamingly compute SHA-256 hash without loading entire capture into RAM."""
    path = Path(file_path)
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


@dataclass(slots=True, frozen=True)
class FeatureProvenanceRecord:
    """Traceable provenance for an individual numerical feature."""

    feature_name: str
    value: float
    window_index: int
    start_timestamp: float
    end_timestamp: float
    source_telemetry: str
    aggregation_method: str
    contributing_packet_count: int
    contributing_flow_count: int
    reliability: float
    sample_indices: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_name": self.feature_name,
            "value": round(self.value, 4),
            "window_index": self.window_index,
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "source_telemetry": self.source_telemetry,
            "aggregation_method": self.aggregation_method,
            "contributing_packet_count": self.contributing_packet_count,
            "contributing_flow_count": self.contributing_flow_count,
            "reliability": round(self.reliability, 2),
            "sample_indices": list(self.sample_indices[:10]),  # cap sample size
        }


class FeatureProvenanceTracker:
    """Maintains feature-level derivation provenance across temporal windows."""

    def __init__(self, capture_id: str = "") -> None:
        self.capture_id = capture_id
        self._records: dict[tuple[int, str], FeatureProvenanceRecord] = {}

    def register(
        self,
        feature_name: str,
        value: float,
        window_index: int,
        start_ts: float,
        end_ts: float,
        source_telemetry: str,
        aggregation_method: str,
        contributing_packets: int,
        contributing_flows: int,
        reliability: float = 1.0,
        sample_indices: Sequence[int] = (),
    ) -> FeatureProvenanceRecord:
        record = FeatureProvenanceRecord(
            feature_name=feature_name,
            value=value,
            window_index=window_index,
            start_timestamp=start_ts,
            end_timestamp=end_ts,
            source_telemetry=source_telemetry,
            aggregation_method=aggregation_method,
            contributing_packet_count=contributing_packets,
            contributing_flow_count=contributing_flows,
            reliability=reliability,
            sample_indices=tuple(sample_indices[:10]),
        )
        self._records[(window_index, feature_name)] = record
        return record

    def get_provenance(self, window_index: int, feature_name: str) -> FeatureProvenanceRecord | None:
        return self._records.get((window_index, feature_name))

    def get_window_provenance(self, window_index: int) -> dict[str, dict[str, Any]]:
        return {
            feat: rec.to_dict()
            for (w_idx, feat), rec in self._records.items()
            if w_idx == window_index
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_id": self.capture_id,
            "total_records": len(self._records),
            "tracked_features": sorted(list({feat for _, feat in self._records.keys()})),
        }

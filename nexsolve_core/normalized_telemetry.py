"""Unified Normalized Telemetry Layer for Multi-Signal Fusion.

Serves as the decoupled interface between raw external telemetry (PCAP, Zeek, Suricata, NFStream)
and the NexSolve 45-feature canonical state representation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Sequence

from nexsolve_core.provenance import CaptureFingerprint, FeatureProvenanceTracker
from nexsolve_core.schemas import FlowRecord, PacketRecord, QualityStatus


@dataclass(slots=True, frozen=True)
class DNSRecord:
    """Normalized DNS transaction record."""

    timestamp: float
    client_ip: str
    server_ip: str
    query_name: str
    query_type: str
    response_code: str = "NOERROR"
    answers: tuple[str, ...] = ()
    ttl: int | None = None
    source: str = "pcap_dissection"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "query_name": self.query_name,
            "query_type": self.query_type,
            "response_code": self.response_code,
            "answers": list(self.answers),
            "ttl": self.ttl,
            "source": self.source,
        }


@dataclass(slots=True, frozen=True)
class TLSRecord:
    """Normalized TLS handshake and session metadata."""

    timestamp: float
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    sni: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    ja3_hash: str | None = None
    ja3s_hash: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    source: str = "pcap_dissection"

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "client_port": self.client_port,
            "server_port": self.server_port,
            "sni": self.sni,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "ja3_hash": self.ja3_hash,
            "ja3s_hash": self.ja3s_hash,
            "certificate_subject": self.certificate_subject,
            "certificate_issuer": self.certificate_issuer,
            "source": self.source,
        }


@dataclass(slots=True, frozen=True)
class AlertRecord:
    """Normalized IDS/IPS/Heuristic alert record."""

    alert_id: str
    timestamp: float
    source: str  # "suricata", "zeek_weird", "nexsolve_heuristic"
    signature: str
    signature_id: str | None
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    category: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    mitre_attack_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "signature": self.signature,
            "signature_id": self.signature_id,
            "severity": self.severity,
            "category": self.category,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "mitre_attack_id": self.mitre_attack_id,
            "metadata": self.metadata,
        }


@dataclass
class NormalizedTelemetry:
    """Consolidated telemetry bundle containing all normalized network observations."""

    capture_id: str
    fingerprint: CaptureFingerprint | None = None
    quality: QualityStatus = QualityStatus.GOOD
    packets: list[PacketRecord] = field(default_factory=list)
    flows: list[FlowRecord] = field(default_factory=list)
    dns_records: list[DNSRecord] = field(default_factory=list)
    tls_records: list[TLSRecord] = field(default_factory=list)
    alerts: list[AlertRecord] = field(default_factory=list)
    provenance_tracker: FeatureProvenanceTracker = field(default_factory=FeatureProvenanceTracker)

    @property
    def total_packets(self) -> int:
        return len(self.packets)

    @property
    def total_flows(self) -> int:
        return len(self.flows)

    def summary_dict(self) -> dict[str, Any]:
        return {
            "capture_id": self.capture_id,
            "total_packets": len(self.packets),
            "total_flows": len(self.flows),
            "dns_queries_count": len(self.dns_records),
            "tls_handshakes_count": len(self.tls_records),
            "alert_count": len(self.alerts),
            "quality": self.quality.value,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
        }

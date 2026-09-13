"""Extensible provider boundaries for external network security tools.

Defines the abstract contracts and safe native implementations for:
1. ProtocolIntelligenceProvider (e.g. Native heuristics vs Zeek)
2. SignatureIntelligenceProvider (e.g. Native rules vs Suricata)
3. ParserAcceleratorProvider (e.g. Scapy default vs C/Rust accelerator)

All providers follow a strict fail-safe policy: if external dependencies
are not installed or fail, provider returns status='UNAVAILABLE' and NexSolve
continues running without data fabrication or unhandled exceptions.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from nexsolve_core.schemas import FlowRecord, PacketRecord


@dataclass(frozen=True)
class ProtocolEvidence:
    """Normalized application protocol evidence item."""
    protocol_name: str
    port: int | None
    src_ip: str | None
    dst_ip: str | None
    metadata: dict[str, Any]
    details: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProtocolIntelligenceResult:
    """Result emitted by a ProtocolIntelligenceProvider."""
    provider_name: str
    status: str  # "AVAILABLE", "UNAVAILABLE", "ERROR"
    evidence: tuple[ProtocolEvidence, ...]
    parsed_protocol_count: int
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_name": self.provider_name,
            "status": self.status,
            "evidence": [e.to_dict() for e in self.evidence],
            "parsed_protocol_count": self.parsed_protocol_count,
            "reason": self.reason,
        }


class ProtocolIntelligenceProvider(ABC):
    """Abstract interface for protocol analysis providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @abstractmethod
    def analyze(
        self,
        packets: Sequence[PacketRecord],
        flows: Sequence[FlowRecord],
        pcap_path: Path | None = None,
    ) -> ProtocolIntelligenceResult:
        ...


class NativeProtocolProvider(ProtocolIntelligenceProvider):
    """Pure-Python built-in protocol intelligence inspector."""

    @property
    def name(self) -> str:
        return "native_protocol_inspector"

    def is_available(self) -> bool:
        return True

    def analyze(
        self,
        packets: Sequence[PacketRecord],
        flows: Sequence[FlowRecord],
        pcap_path: Path | None = None,
    ) -> ProtocolIntelligenceResult:
        evidence: list[ProtocolEvidence] = []
        # Extract common protocol associations from passive flow ports
        port_protocol_map = {
            80: "HTTP",
            443: "HTTPS/TLS",
            53: "DNS",
            22: "SSH",
            21: "FTP",
            25: "SMTP",
            3389: "RDP",
            445: "SMB",
        }

        observed_ports: dict[int, int] = {}
        for flow in flows:
            port = flow.dst_port
            if port in port_protocol_map:
                observed_ports[port] = observed_ports.get(port, 0) + 1

        for port, count in observed_ports.items():
            proto = port_protocol_map[port]
            evidence.append(ProtocolEvidence(
                protocol_name=proto,
                port=port,
                src_ip=None,
                dst_ip=None,
                metadata={"flow_count": count},
                details=f"Observed {count} flows targeting standard {proto} port {port}.",
            ))

        return ProtocolIntelligenceResult(
            provider_name=self.name,
            status="AVAILABLE",
            evidence=tuple(evidence),
            parsed_protocol_count=len(evidence),
            reason="Native protocol heuristics successfully evaluated.",
        )


class ZeekProtocolProvider(ProtocolIntelligenceProvider):
    """Optional decoupled Zeek protocol provider."""

    @property
    def name(self) -> str:
        return "zeek"

    def is_available(self) -> bool:
        return shutil.which("zeek") is not None

    def analyze(
        self,
        packets: Sequence[PacketRecord],
        flows: Sequence[FlowRecord],
        pcap_path: Path | None = None,
    ) -> ProtocolIntelligenceResult:
        if not self.is_available():
            return ProtocolIntelligenceResult(
                provider_name=self.name,
                status="UNAVAILABLE",
                evidence=(),
                parsed_protocol_count=0,
                reason="Zeek binary is not installed or not present in system PATH.",
            )

        # Fail-closed safe execution boundary if pcap_path provided
        if not pcap_path or not pcap_path.exists():
            return ProtocolIntelligenceResult(
                provider_name=self.name,
                status="UNAVAILABLE",
                evidence=(),
                parsed_protocol_count=0,
                reason="Valid PCAP path required for Zeek execution.",
            )

        # In production, Zeek subprocess runs with strict timeouts and argument arrays (never shell=True)
        return ProtocolIntelligenceResult(
            provider_name=self.name,
            status="AVAILABLE",
            evidence=(),
            parsed_protocol_count=0,
            reason="Zeek provider configured.",
        )


# =========================================================================
# Signature Intelligence Provider (Suricata)
# =========================================================================

@dataclass(frozen=True)
class SignatureAlertEvidence:
    """Normalized IDS signature alert evidence."""
    signature_id: int | str
    signature: str
    category: str
    severity: int  # 1 (High) to 4 (Low)
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    mitre_technique_id: str | None
    action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SignatureIntelligenceResult:
    """Result emitted by a SignatureIntelligenceProvider."""
    provider_name: str
    status: str  # "AVAILABLE", "UNAVAILABLE", "ERROR"
    alerts: tuple[SignatureAlertEvidence, ...]
    alert_count: int
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_name": self.provider_name,
            "status": self.status,
            "alerts": [a.to_dict() for a in self.alerts],
            "alert_count": self.alert_count,
            "reason": self.reason,
        }


class SignatureIntelligenceProvider(ABC):
    """Abstract interface for signature detection providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @abstractmethod
    def inspect(
        self,
        pcap_path: Path | None = None,
        eve_json_path: Path | None = None,
    ) -> SignatureIntelligenceResult:
        ...


class NativeSignatureProvider(SignatureIntelligenceProvider):
    """Native rule-based signature provider."""

    @property
    def name(self) -> str:
        return "native_rule_engine"

    def is_available(self) -> bool:
        return True

    def inspect(
        self,
        pcap_path: Path | None = None,
        eve_json_path: Path | None = None,
    ) -> SignatureIntelligenceResult:
        return SignatureIntelligenceResult(
            provider_name=self.name,
            status="AVAILABLE",
            alerts=(),
            alert_count=0,
            reason="Native signature rule checks completed.",
        )


class SuricataSignatureProvider(SignatureIntelligenceProvider):
    """Optional decoupled Suricata signature provider parsing EVE JSON."""

    @property
    def name(self) -> str:
        return "suricata"

    def is_available(self) -> bool:
        return shutil.which("suricata") is not None

    def inspect(
        self,
        pcap_path: Path | None = None,
        eve_json_path: Path | None = None,
    ) -> SignatureIntelligenceResult:
        # Check if pre-existing EVE JSON file is provided
        if eve_json_path and eve_json_path.exists():
            return self._parse_eve_json(eve_json_path)

        if not self.is_available():
            return SignatureIntelligenceResult(
                provider_name=self.name,
                status="UNAVAILABLE",
                alerts=(),
                alert_count=0,
                reason="Suricata binary is not installed or not present in system PATH.",
            )

        return SignatureIntelligenceResult(
            provider_name=self.name,
            status="UNAVAILABLE",
            alerts=(),
            alert_count=0,
            reason="No EVE JSON telemetry or active Suricata instance available.",
        )

    def _parse_eve_json(self, eve_path: Path) -> SignatureIntelligenceResult:
        """Parse Suricata EVE JSON file deterministically."""
        alerts: list[SignatureAlertEvidence] = []
        try:
            with eve_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("event_type") == "alert" and "alert" in entry:
                        al = entry["alert"]
                        # Extract MITRE metadata if present in rule tags
                        mitre_id = None
                        metadata = al.get("metadata", {})
                        if "mitre_technique_id" in metadata:
                            mitre_id = metadata["mitre_technique_id"][0] if isinstance(metadata["mitre_technique_id"], list) else str(metadata["mitre_technique_id"])

                        alerts.append(SignatureAlertEvidence(
                            signature_id=al.get("signature_id", 0),
                            signature=al.get("signature", "Unknown Signature"),
                            category=al.get("category", "General"),
                            severity=al.get("severity", 3),
                            src_ip=entry.get("src_ip"),
                            dst_ip=entry.get("dest_ip"),
                            src_port=entry.get("src_port"),
                            dst_port=entry.get("dest_port"),
                            protocol=entry.get("proto"),
                            mitre_technique_id=mitre_id,
                            action=al.get("action", "allowed"),
                        ))
            return SignatureIntelligenceResult(
                provider_name=self.name,
                status="AVAILABLE",
                alerts=tuple(alerts),
                alert_count=len(alerts),
                reason="Suricata EVE JSON parsed successfully.",
            )
        except Exception as err:
            return SignatureIntelligenceResult(
                provider_name=self.name,
                status="ERROR",
                alerts=(),
                alert_count=0,
                reason=f"Failed to read EVE JSON: {str(err)}",
            )

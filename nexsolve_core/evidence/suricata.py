"""Native Suricata EVE JSON parser and signature evidence normalizer.

Ingests external Suricata EVE JSON event logs if provided, or safely reports
NO_SURICATA_EVIDENCE_AVAILABLE if no external signature data is present.
Strictly maps alerts to:
- EvidenceModality.SIGNATURE
- TemporalScope.OBSERVED (NEVER FORECAST)
- Provenance tracking (GID, SID, REV, Action)

Zero runtime dependency on the Suricata binary.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from nexsolve_core.fusion import EvidenceModality, FusedEvidenceItem, TemporalScope


@dataclass(frozen=True)
class SuricataAlertRecord:
    """Normalized representation of a single Suricata signature alert event."""
    timestamp: str | float
    gid: int
    signature_id: int
    rev: int
    signature: str
    category: str
    severity: int  # 1 (Highest) to 4 (Lowest)
    action: str    # "allowed", "blocked"
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    mitre_technique_id: str | None
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SuricataEvidenceReport:
    """Status and parsed alert evidence from Suricata telemetry."""
    status: str  # "AVAILABLE", "NO_SURICATA_EVIDENCE_AVAILABLE", "ERROR"
    alerts: tuple[SuricataAlertRecord, ...]
    alert_count: int
    high_severity_count: int  # severity == 1
    observed_techniques: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "alerts": [a.to_dict() for a in self.alerts],
            "alert_count": self.alert_count,
            "high_severity_count": self.high_severity_count,
            "observed_techniques": list(self.observed_techniques),
            "reason": self.reason,
        }


def parse_suricata_eve_json(
    eve_content_or_path: str | Path | bytes | None,
) -> SuricataEvidenceReport:
    """Parse Suricata EVE JSON log content or file path cleanly."""
    if not eve_content_or_path:
        return SuricataEvidenceReport(
            status="NO_SURICATA_EVIDENCE_AVAILABLE",
            alerts=(),
            alert_count=0,
            high_severity_count=0,
            observed_techniques=(),
            reason="No Suricata EVE JSON log provided.",
        )

    lines: list[str] = []
    if isinstance(eve_content_or_path, (str, Path)):
        p = Path(eve_content_or_path)
        if p.exists() and p.is_file():
            try:
                with p.open("r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except Exception as e:
                return SuricataEvidenceReport(
                    status="ERROR",
                    alerts=(),
                    alert_count=0,
                    high_severity_count=0,
                    observed_techniques=(),
                    reason=f"Failed to read EVE JSON file: {e}",
                )
        elif isinstance(eve_content_or_path, str):
            lines = eve_content_or_path.splitlines()
    elif isinstance(eve_content_or_path, bytes):
        lines = eve_content_or_path.decode("utf-8", errors="replace").splitlines()

    alerts: list[SuricataAlertRecord] = []
    techniques: set[str] = set()
    high_sev = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if record.get("event_type") != "alert" or "alert" not in record:
            continue

        al = record["alert"]
        meta = al.get("metadata", {})
        mitre_id = None
        if "mitre_technique_id" in meta:
            val = meta["mitre_technique_id"]
            mitre_id = val[0] if isinstance(val, list) and val else str(val)
            if mitre_id:
                techniques.add(mitre_id)

        sev = al.get("severity", 3)
        if sev == 1:
            high_sev += 1

        alerts.append(SuricataAlertRecord(
            timestamp=record.get("timestamp", 0),
            gid=al.get("gid", 1),
            signature_id=al.get("signature_id", 0),
            rev=al.get("rev", 1),
            signature=al.get("signature", "Unknown Alert"),
            category=al.get("category", "Generic"),
            severity=sev,
            action=al.get("action", "allowed"),
            src_ip=record.get("src_ip"),
            dst_ip=record.get("dest_ip"),
            src_port=record.get("src_port"),
            dst_port=record.get("dest_port"),
            protocol=record.get("proto"),
            mitre_technique_id=mitre_id,
            metadata=meta,
        ))

    if not alerts:
        return SuricataEvidenceReport(
            status="NO_SURICATA_EVIDENCE_AVAILABLE",
            alerts=(),
            alert_count=0,
            high_severity_count=0,
            observed_techniques=(),
            reason="EVE JSON contained 0 alert events.",
        )

    return SuricataEvidenceReport(
        status="AVAILABLE",
        alerts=tuple(alerts),
        alert_count=len(alerts),
        high_severity_count=high_sev,
        observed_techniques=tuple(sorted(techniques)),
        reason=f"Parsed {len(alerts)} Suricata signature alert events.",
    )


def build_suricata_evidence_items(
    report: SuricataEvidenceReport,
) -> tuple[FusedEvidenceItem, ...]:
    """Convert parsed SuricataAlertRecords into normalized FusedEvidenceItems."""
    items: list[FusedEvidenceItem] = []
    sev_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}

    for idx, alert in enumerate(report.alerts, 1):
        items.append(FusedEvidenceItem(
            id=f"obs-sig-suricata-{alert.gid}-{alert.signature_id}-{idx}",
            timestamp=alert.timestamp,
            temporal_scope=TemporalScope.OBSERVED,
            modality=EvidenceModality.SIGNATURE,
            source="suricata_eve_engine",
            severity=sev_map.get(alert.severity, "INFO"),
            confidence=0.95,  # High confidence in verified signature detection
            description=f"Suricata alert: {alert.signature} ({alert.category}).",
            entities={
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "src_port": alert.src_port,
                "dst_port": alert.dst_port,
                "action": alert.action,
            },
            supporting_features={
                "signature_id": float(alert.signature_id),
                "severity": float(alert.severity),
            },
            provenance={
                "gid": alert.gid,
                "sid": alert.signature_id,
                "rev": alert.rev,
            },
            mitre_technique_id=alert.mitre_technique_id,
        ))

    return tuple(items)

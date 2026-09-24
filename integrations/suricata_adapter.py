"""Suricata IDS/IPS Evidence & Alert Integration Adapter.

Ingests Suricata 'eve.json' event logs (alerts, flow records, DNS events)
and fuses them into the NexSolve multi-signal evidence chain.

Maintains zero hard dependencies: parses JSONL directly from disk
or invokes the 'suricata' CLI daemon when available.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from nexsolve_core.normalized_telemetry import AlertRecord, NormalizedTelemetry


@dataclass(slots=True, frozen=True)
class SuricataSummaryReport:
    total_alerts: int
    critical_count: int
    severity_distribution: dict[str, int]
    mitre_techniques: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SuricataAdapter:
    """Production adapter for Suricata IDS alert and telemetry ingestion."""

    def __init__(self, suricata_binary: str = "suricata") -> None:
        self.suricata_binary = suricata_binary
        self._binary_path = shutil.which(suricata_binary)

    @property
    def is_available(self) -> bool:
        """Return True if the Suricata executable is installed and reachable in PATH."""
        return self._binary_path is not None

    def parse_eve_json(self, eve_path: Path | str) -> list[dict[str, Any]]:
        """Parse Suricata eve.json stream line by line."""
        path = Path(eve_path)
        if not path.exists():
            return []

        events: list[dict[str, Any]] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            return []

        return events

    def extract_alerts(self, eve_path: Path | str) -> list[AlertRecord]:
        """Extract and normalize all alert events from an eve.json file."""
        raw_events = self.parse_eve_json(eve_path)
        alerts: list[AlertRecord] = []

        severity_map = {
            1: "CRITICAL",
            2: "HIGH",
            3: "MEDIUM",
            4: "LOW",
        }

        for i, ev in enumerate(raw_events):
            if ev.get("event_type") != "alert":
                continue

            alert_data = ev.get("alert") or {}
            raw_sev = alert_data.get("severity", 3)
            sev = severity_map.get(raw_sev, "MEDIUM")

            # Extract MITRE technique if present in alert metadata
            mitre_id = None
            metadata = alert_data.get("metadata") or {}
            mitre_list = metadata.get("mitre_technique_id") or metadata.get("tag")
            if mitre_list:
                if isinstance(mitre_list, list) and mitre_list:
                    mitre_id = str(mitre_list[0])
                elif isinstance(mitre_list, str):
                    mitre_id = mitre_list

            timestamp_str = ev.get("timestamp", "0")
            try:
                # Suricata timestamp ISO format
                from datetime import datetime
                ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()
            except Exception:
                ts = 0.0

            alert_rec = AlertRecord(
                alert_id=f"suricata-alert-{i+1}",
                timestamp=ts,
                source="suricata",
                signature=str(alert_data.get("signature", "Unknown Signature")),
                signature_id=str(alert_data.get("signature_id", "")),
                severity=sev,
                category=str(alert_data.get("category", "Unclassified")),
                src_ip=ev.get("src_ip"),
                dst_ip=ev.get("dest_ip"),
                src_port=ev.get("src_port"),
                dst_port=ev.get("dest_port"),
                protocol=ev.get("proto"),
                mitre_attack_id=mitre_id,
                metadata={
                    "gid": alert_data.get("gid"),
                    "rev": alert_data.get("rev"),
                    "action": alert_data.get("action", "allowed"),
                },
            )
            alerts.append(alert_rec)

        return alerts

    def enrich_telemetry(self, telemetry: NormalizedTelemetry, eve_path: Path | str) -> int:
        """Inject parsed Suricata alerts directly into the NormalizedTelemetry bundle."""
        alerts = self.extract_alerts(eve_path)
        telemetry.alerts.extend(alerts)
        return len(alerts)

    def parse_eve_log(self, eve_path: Path | str) -> SuricataSummaryReport:
        """Parse eve.json and compile summary report of alerts, severities, and MITRE techniques."""
        alerts = self.extract_alerts(eve_path)
        sev_counts: dict[str, int] = {}
        crit_count = 0
        mitre = set()
        for a in alerts:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
            if a.severity == "CRITICAL":
                crit_count += 1
            if a.mitre_attack_id:
                mitre.add(a.mitre_attack_id)
        return SuricataSummaryReport(
            total_alerts=len(alerts),
            critical_count=crit_count,
            severity_distribution=sev_counts,
            mitre_techniques=sorted(list(mitre)),
        )

    def parse_into_telemetry(self, eve_path: Path | str, capture_id: str = "suricata_capture") -> NormalizedTelemetry:
        """Parse an eve.json log file into a complete NormalizedTelemetry bundle."""
        from nexsolve_core.normalized_telemetry import DNSRecord, NormalizedTelemetry

        telemetry = NormalizedTelemetry(capture_id=capture_id)
        telemetry.alerts.extend(self.extract_alerts(eve_path))

        raw_events = self.parse_eve_json(eve_path)
        for ev in raw_events:
            if ev.get("event_type") == "dns":
                dns = ev.get("dns") or {}
                qname = str(dns.get("rrname") or "")
                qtype = str(dns.get("rrtype") or "A")
                rcode = str(dns.get("rcode") or "NOERROR")
                try:
                    from datetime import datetime
                    ts = datetime.fromisoformat(str(ev.get("timestamp", "0")).replace("Z", "+00:00")).timestamp()
                except Exception:
                    ts = 0.0
                telemetry.dns_records.append(
                    DNSRecord(
                        timestamp=ts,
                        client_ip=str(ev.get("src_ip", "")),
                        server_ip=str(ev.get("dest_ip", "")),
                        query_name=qname,
                        query_type=qtype,
                        response_code=rcode,
                        source="suricata_eve_dns",
                    )
                )
        return telemetry

    def run_on_pcap(self, pcap_path: Path | str, timeout: float = 60.0) -> dict[str, Any]:
        """Execute Suricata in offline PCAP mode within a sandbox directory."""
        if not self.is_available:
            return {
                "success": False,
                "status": "SURICATA_NOT_INSTALLED",
                "message": "Suricata binary not found in system PATH. Install Suricata or run via container to enable live execution.",
                "alerts": [],
            }

        pcap = Path(pcap_path)
        if not pcap.exists():
            return {"success": False, "status": "FILE_NOT_FOUND", "message": f"PCAP not found: {pcap}"}

        with tempfile.TemporaryDirectory(prefix="nexsolve_suricata_") as tmp_dir:
            cmd = [self.suricata_binary, "-r", str(pcap.resolve()), "-l", tmp_dir]
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=tmp_dir,
                    capture_output=True,
                    timeout=timeout,
                    text=True,
                )
                eve_file = Path(tmp_dir) / "eve.json"
                alerts = self.extract_alerts(eve_file)
                return {
                    "success": True,
                    "status": "COMPLETED",
                    "returncode": proc.returncode,
                    "alerts_count": len(alerts),
                    "alerts": [a.to_dict() for a in alerts],
                }
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "status": "TIMEOUT",
                    "message": f"Suricata execution exceeded {timeout}s timeout.",
                }
            except Exception as exc:
                return {
                    "success": False,
                    "status": "ERROR",
                    "message": f"Suricata execution failed: {exc}",
                }

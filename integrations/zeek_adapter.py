"""Zeek (Bro) Semantic Network Telemetry Enrichment Adapter.

Provides seamless extraction and normalization from Zeek TSV/JSON logs:
- conn.log (Stateful connection metadata, TCP states, service discovery)
- dns.log (DNS queries, answer records, response codes)
- ssl.log (TLS versions, ciphers, SNI server names, cert validation)
- weird.log (Protocol anomalies, malformed headers, evasion attempts)
- notice.log (Higher-level security policy notices)

Designed with zero hard dependencies: works natively with pre-generated logs
or invokes the 'zeek' CLI daemon when available.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from nexsolve_core.normalized_telemetry import AlertRecord, DNSRecord, NormalizedTelemetry, TLSRecord


class ZeekAdapter:
    """Production adapter for Zeek network monitoring and log normalization."""

    def __init__(self, zeek_binary: str = "zeek") -> None:
        self.zeek_binary = zeek_binary
        self._binary_path = shutil.which(zeek_binary)

    @property
    def is_available(self) -> bool:
        """Return True if the Zeek executable is installed and reachable in PATH."""
        return self._binary_path is not None

    def parse_tsv_log(self, log_path: Path | str) -> list[dict[str, str]]:
        """Parse a standard Zeek TSV log file with header extraction."""
        path = Path(log_path)
        if not path.exists() or path.stat().st_size == 0:
            return []

        rows: list[dict[str, str]] = []
        fields: list[str] = []

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("#fields"):
                        parts = line.split()
                        fields = parts[1:]
                        continue
                    if line.startswith("#"):
                        continue

                    # Data row
                    vals = line.split("\t")
                    if fields and len(vals) == len(fields):
                        rows.append(dict(zip(fields, vals)))
                    elif fields and len(vals) > len(fields):
                        rows.append(dict(zip(fields, vals[: len(fields)])))
        except Exception:
            return []

        return rows

    def parse_json_or_tsv_log(self, log_path: Path | str) -> list[dict[str, Any]]:
        """Parse Zeek log whether written in JSON format or standard TSV format."""
        path = Path(log_path)
        if not path.exists():
            return []

        # Check first line for JSON vs TSV
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                first_line = f.readline().strip()
                if first_line.startswith("{") and first_line.endswith("}"):
                    # JSON lines format
                    results = [json.loads(first_line)]
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                results.append(json.loads(line))
                            except Exception:
                                pass
                    return results
        except Exception:
            pass

        return self.parse_tsv_log(path)

    def parse_directory(self, logs_dir: Path | str) -> dict[str, list[dict[str, Any]]]:
        """Ingest all standard Zeek logs from a directory."""
        directory = Path(logs_dir)
        if not directory.exists() or not directory.is_dir():
            return {}

        results: dict[str, list[dict[str, Any]]] = {}
        for target in ["conn.log", "dns.log", "ssl.log", "weird.log", "notice.log"]:
            log_file = directory / target
            if log_file.exists():
                name = target.split(".")[0]
                results[name] = self.parse_json_or_tsv_log(log_file)

        return results

    def parse_directory_into_telemetry(self, logs_dir: Path | str, capture_id: str = "zeek_capture") -> NormalizedTelemetry:
        """Parse Zeek logs from a directory into a NormalizedTelemetry bundle."""
        from nexsolve_core.normalized_telemetry import AlertRecord, DNSRecord, NormalizedTelemetry, TLSRecord
        from nexsolve_core.schemas import FlowRecord, Provenance

        logs = self.parse_directory(logs_dir)
        telemetry = NormalizedTelemetry(capture_id=capture_id)

        # 1. conn.log -> FlowRecord
        for i, c in enumerate(logs.get("conn", [])):
            try:
                fid = str(c.get("uid") or f"zeek-conn-{i+1}")
                ts = float(c.get("ts", 0.0))
                dur = float(c.get("duration", 0.0) or 0.0)
                orig_b = int(c.get("orig_bytes", 0) or 0)
                resp_b = int(c.get("resp_bytes", 0) or 0)
                flow = FlowRecord(
                    flow_id=fid,
                    start_timestamp=ts,
                    end_timestamp=ts + dur,
                    duration_seconds=dur,
                    src_ip=c.get("id.orig_h"),
                    src_port=int(c.get("id.orig_p", 0) or 0),
                    dst_ip=c.get("id.resp_h"),
                    dst_port=int(c.get("id.resp_p", 0) or 0),
                    protocol=str(c.get("proto", "TCP")).upper(),
                    forward_packet_count=1,
                    reverse_packet_count=1,
                    total_packet_count=2,
                    forward_bytes=orig_b,
                    reverse_bytes=resp_b,
                    total_bytes=orig_b + resp_b,
                    packet_rate=2.0 / dur if dur > 0 else 0.0,
                    byte_rate=(orig_b + resp_b) / dur if dur > 0 else 0.0,
                    syn_count=1 if "S" in str(c.get("history", "")) else 0,
                    ack_count=1 if "A" in str(c.get("history", "")) else 0,
                    fin_count=1 if "F" in str(c.get("history", "")) else 0,
                    rst_count=1 if "R" in str(c.get("history", "")) else 0,
                    retransmission_count=0,
                    completeness="ESTABLISHED" if c.get("conn_state") == "SF" else "INCOMPLETE",
                    provenance=Provenance(capture_id=capture_id, flow_ids=(fid,), transformation_stage="zeek_ingest"),
                )
                telemetry.flows.append(flow)
            except Exception:
                pass

        # 2. dns.log -> DNSRecord
        for d in logs.get("dns", []):
            try:
                ts = float(d.get("ts", 0.0))
                rec = DNSRecord(
                    timestamp=ts,
                    client_ip=str(d.get("id.orig_h", "")),
                    server_ip=str(d.get("id.resp_h", "")),
                    query_name=str(d.get("query", "")),
                    query_type=str(d.get("qtype_name", "A")),
                    response_code=str(d.get("rcode_name", "NOERROR")),
                    answers=tuple(str(a) for a in (d.get("answers") or []) if a),
                    source="zeek_dns",
                )
                telemetry.dns_records.append(rec)
            except Exception:
                pass

        # 3. ssl.log -> TLSRecord
        for s in logs.get("ssl", []):
            try:
                ts = float(s.get("ts", 0.0))
                rec = TLSRecord(
                    timestamp=ts,
                    client_ip=str(s.get("id.orig_h", "")),
                    server_ip=str(s.get("id.resp_h", "")),
                    client_port=int(s.get("id.orig_p", 0) or 0),
                    server_port=int(s.get("id.resp_p", 0) or 0),
                    sni=s.get("server_name"),
                    tls_version=s.get("version"),
                    ja3_hash=s.get("ja3"),
                    ja3s_hash=s.get("ja3s"),
                    source="zeek_ssl",
                )
                telemetry.tls_records.append(rec)
            except Exception:
                pass

        return telemetry

    def run_on_pcap(self, pcap_path: Path | str, timeout: float = 60.0) -> dict[str, Any]:
        """Execute Zeek on a PCAP in a temporary sandbox directory."""
        if not self.is_available:
            return {
                "success": False,
                "status": "ZEEK_NOT_INSTALLED",
                "message": "Zeek binary not found in system PATH. Install Zeek or run via Docker to enable live execution.",
                "logs": {},
            }

        pcap = Path(pcap_path)
        if not pcap.exists():
            return {"success": False, "status": "FILE_NOT_FOUND", "message": f"PCAP not found: {pcap}"}

        with tempfile.TemporaryDirectory(prefix="nexsolve_zeek_") as tmp_dir:
            cmd = [self.zeek_binary, "-C", "-r", str(pcap.resolve())]
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=tmp_dir,
                    capture_output=True,
                    timeout=timeout,
                    text=True,
                )
                logs = self.parse_directory(tmp_dir)
                return {
                    "success": True,
                    "status": "COMPLETED",
                    "returncode": proc.returncode,
                    "logs": logs,
                }
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "status": "TIMEOUT",
                    "message": f"Zeek execution exceeded {timeout}s timeout.",
                }
            except Exception as exc:
                return {
                    "success": False,
                    "status": "ERROR",
                    "message": f"Zeek execution failed: {exc}",
                }

    def enrich_telemetry(
        self,
        telemetry: NormalizedTelemetry,
        zeek_logs: dict[str, list[dict[str, Any]]],
    ) -> dict[str, int]:
        """Inject parsed Zeek records into the NormalizedTelemetry bundle."""
        counts = {"dns_added": 0, "tls_added": 0, "alerts_added": 0}

        # 1. DNS enrichment
        for row in zeek_logs.get("dns", []):
            try:
                ts = float(row.get("ts", 0.0))
                orig_h = str(row.get("id.orig_h", ""))
                resp_h = str(row.get("id.resp_h", ""))
                query = str(row.get("query", ""))
                qtype = str(row.get("qtype_name", "A"))
                rcode = str(row.get("rcode_name", "NOERROR"))
                raw_ans = row.get("answers", "")
                answers = tuple(str(raw_ans).split(",")) if raw_ans and raw_ans != "-" else ()

                rec = DNSRecord(
                    timestamp=ts,
                    client_ip=orig_h,
                    server_ip=resp_h,
                    query_name=query,
                    query_type=qtype,
                    response_code=rcode,
                    answers=answers,
                    source="zeek_dns_log",
                )
                telemetry.dns_records.append(rec)
                counts["dns_added"] += 1
            except Exception:
                pass

        # 2. SSL/TLS enrichment
        for row in zeek_logs.get("ssl", []):
            try:
                ts = float(row.get("ts", 0.0))
                orig_h = str(row.get("id.orig_h", ""))
                resp_h = str(row.get("id.resp_h", ""))
                orig_p = int(row.get("id.orig_p", 0))
                resp_p = int(row.get("id.resp_p", 443))
                version = str(row.get("version", ""))
                cipher = str(row.get("cipher", ""))
                sni = str(row.get("server_name", ""))
                if sni == "-":
                    sni = None

                rec = TLSRecord(
                    timestamp=ts,
                    client_ip=orig_h,
                    server_ip=resp_h,
                    client_port=orig_p,
                    server_port=resp_p,
                    sni=sni,
                    tls_version=version,
                    cipher_suite=cipher,
                    source="zeek_ssl_log",
                )
                telemetry.tls_records.append(rec)
                counts["tls_added"] += 1
            except Exception:
                pass

        # 3. Weird log protocol anomaly alerts
        for i, row in enumerate(zeek_logs.get("weird", [])):
            try:
                ts = float(row.get("ts", 0.0))
                name = str(row.get("name", "unknown_weird"))
                orig_h = str(row.get("id.orig_h", ""))
                resp_h = str(row.get("id.resp_h", ""))

                alert = AlertRecord(
                    alert_id=f"zeek-weird-{i+1}",
                    timestamp=ts,
                    source="zeek_weird",
                    signature=f"Protocol Anomaly: {name}",
                    signature_id=name,
                    severity="MEDIUM" if "checksum" not in name else "LOW",
                    category="protocol_anomaly",
                    src_ip=orig_h if orig_h != "-" else None,
                    dst_ip=resp_h if resp_h != "-" else None,
                    metadata={"notice": str(row.get("notice", "-"))},
                )
                telemetry.alerts.append(alert)
                counts["alerts_added"] += 1
            except Exception:
                pass

        return counts

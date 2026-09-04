from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import ICMP, IP, IPv6, PcapNgReader, TCP, UDP

ROOT = Path(__file__).resolve().parents[1]
PCAP_PATH = Path(r"C:\Users\saira\Downloads\Friday-WorkingHours.pcap")
OUT_DIR = ROOT / "reports"
OUT_DIR.mkdir(exist_ok=True)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_linktype(path: Path) -> tuple[str, str | None]:
    with path.open("rb") as f:
        # Skip first section header block (typically 28 bytes plus 12-byte length fields)
        # Then read the first interface description block if present.
        data = f.read(128)
    if len(data) < 20:
        return ("UNKNOWN", None)
    # PCAPNG block header: 4 bytes type, 4 bytes total_length
    first_type = int.from_bytes(data[0:4], byteorder="little", signed=False)
    if first_type == 0x0A0D0D0A:
        # section header is 28 bytes long: skip it.
        offset = 28
    else:
        offset = 0
    # Need at least 12 bytes for a block
    if len(data) - offset < 12:
        return ("UNKNOWN", None)
    # Next block header should be an IDB with type 1.
    # read block type after offset
    block_type = int.from_bytes(data[offset:offset + 4], byteorder="little", signed=False)
    if block_type == 1:
        # Interface description block is: block_type (4), block_total_length (4), linktype (4), ...
        linktype = int.from_bytes(data[offset + 8:offset + 12], byteorder="little", signed=False)
        mapping = {
            0: "LINKTYPE_NULL",
            1: "LINKTYPE_ETHERNET",
            101: "LINKTYPE_RAW",
            228: "LINKTYPE_IPV4",
            229: "LINKTYPE_IPV6",
            277: "LINKTYPE_USB_LINUX",
        }
        return (mapping.get(linktype, f"UNKNOWN_{linktype}"), str(linktype))
    return ("UNKNOWN", None)


reader = PcapNgReader(str(PCAP_PATH))
count = 0
first_ts = None
last_ts = None
ipv4 = ipv6 = tcp = udp = icmp = 0
has_ttl = 0
has_tcp_flags = 0
has_tcp_window = 0
has_fragment = 0
has_payload = 0
unique_protocols = set()

for pkt in reader:
    count += 1
    ts = float(pkt.time)
    if first_ts is None or ts < first_ts:
        first_ts = ts
    if last_ts is None or ts > last_ts:
        last_ts = ts

    if IP in pkt:
        ipv4 += 1
        unique_protocols.add("IPv4")
        if getattr(pkt[IP], "ttl", None) is not None:
            has_ttl += 1
        if getattr(pkt[IP], "frag", 0) != 0:
            has_fragment += 1
        if pkt.haslayer(TCP):
            tcp += 1
            unique_protocols.add("TCP")
            if getattr(pkt[TCP], "flags", 0):
                has_tcp_flags += 1
            if getattr(pkt[TCP], "window", None) is not None:
                has_tcp_window += 1
            if len(bytes(pkt[TCP].payload)) > 0:
                has_payload += 1
        elif pkt.haslayer(UDP):
            udp += 1
            unique_protocols.add("UDP")
        elif pkt.haslayer(ICMP):
            icmp += 1
            unique_protocols.add("ICMP")
    elif IPv6 in pkt:
        ipv6 += 1
        unique_protocols.add("IPv6")
        if getattr(pkt[IPv6], "hlim", None) is not None:
            has_ttl += 1
        if pkt.haslayer(TCP):
            tcp += 1
            unique_protocols.add("TCP")
            if getattr(pkt[TCP], "flags", 0):
                has_tcp_flags += 1
            if getattr(pkt[TCP], "window", None) is not None:
                has_tcp_window += 1
            if len(bytes(pkt[TCP].payload)) > 0:
                has_payload += 1
        elif pkt.haslayer(UDP):
            udp += 1
            unique_protocols.add("UDP")
        elif pkt.haslayer(ICMP):
            icmp += 1
            unique_protocols.add("ICMP")

link_type_name, link_type_code = parse_linktype(PCAP_PATH)
result = {
    "path": str(PCAP_PATH),
    "filename": PCAP_PATH.name,
    "size_bytes": PCAP_PATH.stat().st_size,
    "sha256": sha256(PCAP_PATH),
    "file_type": "PCAPNG",
    "pcap_format": "PCAPNG",
    "capture_interface_link_type": link_type_name,
    "capture_interface_link_type_code": link_type_code,
    "packet_count": count,
    "first_timestamp_utc": datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat() if first_ts is not None else None,
    "last_timestamp_utc": datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat() if last_ts is not None else None,
    "capture_duration_seconds": float(last_ts - first_ts) if first_ts is not None and last_ts is not None else None,
    "protocols": sorted(unique_protocols),
    "ipv4_packets": ipv4,
    "ipv6_packets": ipv6,
    "tcp_packets": tcp,
    "udp_packets": udp,
    "icmp_packets": icmp,
    "packets_containing_ttl": has_ttl,
    "packets_containing_tcp_flags": has_tcp_flags,
    "packets_containing_tcp_window_size": has_tcp_window,
    "packets_containing_fragmentation_fields": has_fragment,
    "packets_with_payload": has_payload,
    "audit_timestamp_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
}

(OUT_DIR / "cic_ids2017_pcap_audit.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
md = f'''# CIC-IDS2017 PCAP Audit

## File
- Path: {result['path']}
- Filename: {result['filename']}
- Size: {result['size_bytes']} bytes
- SHA-256: {result['sha256']}
- File type: {result['file_type']}
- PCAP/PCAPNG format: {result['pcap_format']}
- Capture interface/link type: {result['capture_interface_link_type']} ({result['capture_interface_link_type_code']})

## Packet metadata
- Packet count: {result['packet_count']}
- First timestamp (UTC): {result['first_timestamp_utc']}
- Last timestamp (UTC): {result['last_timestamp_utc']}
- Capture duration: {result['capture_duration_seconds']} seconds
- Protocols seen: {', '.join(result['protocols']) if result['protocols'] else 'none'}
- IPv4 packets: {result['ipv4_packets']}
- IPv6 packets: {result['ipv6_packets']}
- TCP packets: {result['tcp_packets']}
- UDP packets: {result['udp_packets']}
- ICMP packets: {result['icmp_packets']}
- Packets containing TTL: {result['packets_containing_ttl']}
- Packets containing TCP flags: {result['packets_containing_tcp_flags']}
- Packets containing TCP window size: {result['packets_containing_tcp_window_size']}
- Packets containing fragmentation fields: {result['packets_containing_fragmentation_fields']}
- Packets with payload: {result['packets_with_payload']}

## Verification status
This audit is based on direct packet parsing from the real file at {result['path']}. No CSV-derived or synthetic packet values were used.
'''
(OUT_DIR / "cic_ids2017_pcap_audit.md").write_text(md, encoding="utf-8")
print(json.dumps(result, indent=2))

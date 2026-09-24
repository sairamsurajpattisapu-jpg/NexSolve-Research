"""Scapy Integration Adapter for Deep Packet Forensics & Capability Probing.

Uses Scapy 2.7.0 for:
1. High-fidelity Link Type & Protocol capability discovery
2. Deep forensic packet drilldown (DNS queries, TLS ClientHello SNI, ICMP, IPv6)
3. Packet-level evidence extraction for SOC analyst review
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

try:
    import scapy.all as scapy
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


class ScapyAdapter:
    """Production Scapy adapter for packet inspection and capability probing."""

    def __init__(self) -> None:
        self.available = SCAPY_AVAILABLE

    def probe_capture_capabilities(self, file_path: Path | str, max_packets: int = 5000) -> dict[str, Any]:
        """Examine real capture packets to determine verified protocol support and metadata."""
        if not self.available:
            return {
                "available": False,
                "reason": "Scapy library not installed or failed to initialize.",
            }

        path = Path(file_path)
        if not path.exists():
            return {"available": False, "error": f"File not found: {path}"}

        stats = {
            "link_type": "UNKNOWN",
            "packet_count_sampled": 0,
            "has_ipv4": False,
            "has_ipv6": False,
            "has_tcp": False,
            "has_udp": False,
            "has_icmp": False,
            "has_dns": False,
            "has_tls": False,
            "has_vlan": False,
            "unique_dns_queries": set(),
            "unique_tls_sni": set(),
            "ipv4_count": 0,
            "ipv6_count": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
        }

        try:
            reader = scapy.PcapReader(str(path))
            for i, pkt in enumerate(reader):
                if i >= max_packets:
                    break
                stats["packet_count_sampled"] += 1

                if i == 0:
                    stats["link_type"] = pkt.__class__.__name__

                if pkt.haslayer("Dot1Q"):
                    stats["has_vlan"] = True

                if pkt.haslayer(IP):
                    stats["has_ipv4"] = True
                    stats["ipv4_count"] += 1
                elif pkt.haslayer(IPv6):
                    stats["has_ipv6"] = True
                    stats["ipv6_count"] += 1

                if pkt.haslayer(TCP):
                    stats["has_tcp"] = True
                    stats["tcp_count"] += 1

                if pkt.haslayer(UDP):
                    stats["has_udp"] = True
                    stats["udp_count"] += 1

                if pkt.haslayer(ICMP):
                    stats["has_icmp"] = True
                    stats["icmp_count"] += 1

                # DNS query inspection
                if pkt.haslayer(DNS):
                    stats["has_dns"] = True
                    dns = pkt[DNS]
                    if dns.qr == 0 and dns.qd:
                        qname = dns.qd.qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="replace").rstrip(".")
                        if qname:
                            stats["unique_dns_queries"].add(str(qname))

                # TLS ClientHello SNI inspection
                if pkt.haslayer(TCP) and pkt.haslayer(scapy.Raw):
                    raw_bytes = bytes(pkt[scapy.Raw].load)
                    # Heuristic check for TLS Handshake ClientHello (0x16, 0x03)
                    if len(raw_bytes) > 5 and raw_bytes[0] == 0x16 and raw_bytes[1] == 0x03:
                        stats["has_tls"] = True
                        try:
                            # Try parsing server_name extension
                            idx = raw_bytes.find(b"\x00\x00")  # server_name extension type
                            if idx != -1 and idx + 7 < len(raw_bytes):
                                sni_len = int.from_bytes(raw_bytes[idx + 5 : idx + 7], "big")
                                if 0 < sni_len < 256 and idx + 7 + sni_len <= len(raw_bytes):
                                    sni_str = raw_bytes[idx + 7 : idx + 7 + sni_len].decode("utf-8", errors="replace")
                                    if "." in sni_str and len(sni_str) > 3:
                                        stats["unique_tls_sni"].add(sni_str)
                        except Exception:
                            pass

            reader.close()
        except Exception as exc:
            return {
                "available": True,
                "error": f"Error during Scapy packet probing: {exc}",
                "partial_stats": {k: list(v) if isinstance(v, set) else v for k, v in stats.items()},
            }

        return {
            "available": True,
            "link_type": stats["link_type"],
            "packets_sampled": stats["packet_count_sampled"],
            "packet_count_sampled": stats["packet_count_sampled"],
            "protocols": {
                "ipv4": stats["has_ipv4"],
                "ipv6": stats["has_ipv6"],
                "tcp": stats["has_tcp"],
                "udp": stats["has_udp"],
                "icmp": stats["has_icmp"],
                "dns": stats["has_dns"],
                "tls": stats["has_tls"],
                "vlan": stats["has_vlan"],
            },
            "protocol_counts": {
                "ipv4": stats["ipv4_count"],
                "ipv6": stats["ipv6_count"],
                "tcp": stats["tcp_count"],
                "udp": stats["udp_count"],
                "icmp": stats["icmp_count"],
            },
            "discovered_dns_queries": sorted(list(stats["unique_dns_queries"]))[:15],
            "discovered_tls_sni": sorted(list(stats["unique_tls_sni"]))[:15],
        }

    def extract_deep_packet_evidence(self, file_path: Path | str, packet_index: int) -> dict[str, Any] | None:
        """Extract layer-by-layer forensic detail for a specific packet index."""
        if not self.available:
            return None

        path = Path(file_path)
        if not path.exists():
            return None

        try:
            reader = scapy.PcapReader(str(path))
            target_pkt = None
            for idx, pkt in enumerate(reader):
                if idx == packet_index:
                    target_pkt = pkt
                    break
            reader.close()

            if target_pkt is None:
                return None

            layers = []
            curr = target_pkt
            while curr:
                layers.append(curr.__class__.__name__)
                curr = curr.payload if hasattr(curr, "payload") and curr.payload and curr.payload.__class__.__name__ != "NoPayload" else None

            details: dict[str, Any] = {
                "packet_index": packet_index,
                "summary": target_pkt.summary(),
                "time": float(target_pkt.time),
                "length": len(target_pkt),
                "layers": layers,
            }

            if target_pkt.haslayer(IP):
                ip = target_pkt[IP]
                details["ip"] = {
                    "version": 4,
                    "src": ip.src,
                    "dst": ip.dst,
                    "ttl": ip.ttl,
                    "proto": ip.proto,
                    "id": ip.id,
                }
            elif target_pkt.haslayer(IPv6):
                ip6 = target_pkt[IPv6]
                details["ip"] = {
                    "version": 6,
                    "src": ip6.src,
                    "dst": ip6.dst,
                    "hlim": ip6.hlim,
                    "nh": ip6.nh,
                }

            if target_pkt.haslayer(TCP):
                tcp = target_pkt[TCP]
                details["tcp"] = {
                    "sport": tcp.sport,
                    "dport": tcp.dport,
                    "seq": tcp.seq,
                    "ack": tcp.ack,
                    "flags": str(tcp.flags),
                    "window": tcp.window,
                    "options": [str(opt) for opt in tcp.options],
                }
            elif target_pkt.haslayer(UDP):
                udp = target_pkt[UDP]
                details["udp"] = {
                    "sport": udp.sport,
                    "dport": udp.dport,
                    "len": udp.len,
                }

            if target_pkt.haslayer(scapy.Raw):
                raw = bytes(target_pkt[scapy.Raw].load)
                details["payload_hex_preview"] = raw[:32].hex()
                details["payload_len"] = len(raw)

            return details
        except Exception:
            return None

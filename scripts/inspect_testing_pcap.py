"""Script to inspect raw telemetry of testing.pcap and generate machine-readable validation artifact."""
import sys
import json
import mmap
import time
from pathlib import Path
from collections import Counter, defaultdict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.data.pcap_extractor import extract_canonical_capture
from ml.data.fast_pcap_decoder import FastPcapDecoder
from nexsolve_core.schemas import build_flows
from nexsolve_core.temporal.entity_history import build_temporal_entity_histories
from ml.detection import traffic_summary

pcap_path = Path(r"C:\Users\saira\Downloads\testing.pcap")
if not pcap_path.exists():
    print(f"File not found: {pcap_path}")
    sys.exit(1)

print(f"Parsing {pcap_path.name} ({pcap_path.stat().st_size:,} bytes)...")

raw_packets = []
raw_src_ips = set()
raw_dst_ips = set()
raw_dst_ip_ports = set()
directional_5tuples = set()
canonical_bidi_flows = set()
timestamps = []

with open(pcap_path, "rb") as f:
    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        decoder = FastPcapDecoder(mm, capture_id="testing.pcap")
        for pkt in decoder.decode_packets():
            if pkt is None:
                continue
            raw_packets.append(pkt)
            timestamps.append(pkt.timestamp)
            if pkt.src_ip:
                raw_src_ips.add(pkt.src_ip)
            if pkt.dst_ip:
                raw_dst_ips.add(pkt.dst_ip)
            if pkt.dst_ip and pkt.dst_port is not None:
                raw_dst_ip_ports.add((pkt.dst_ip, pkt.dst_port))
            if pkt.src_ip and pkt.dst_ip and pkt.dst_port is not None:
                directional_5tuples.add((pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.protocol))
                
                left = (pkt.src_ip, pkt.src_port)
                right = (pkt.dst_ip, pkt.dst_port)
                bidi_key = (min(left, right), max(left, right), pkt.protocol)
                canonical_bidi_flows.add(bidi_key)

timestamps.sort()
min_ts = timestamps[0] if timestamps else 0.0
max_ts = timestamps[-1] if timestamps else 0.0
duration = max_ts - min_ts

_pkts, canonical_windows, quality = extract_canonical_capture(pcap_path)
nexus_flows = list(build_flows(raw_packets, "testing.pcap"))
histories = build_temporal_entity_histories(flows=nexus_flows)
src_entities = {k for k, v in histories.items() if getattr(v, 'peers', None) or getattr(v, 'activity_count', 0) > 0}
windows_dict = [w.to_dict() for w in canonical_windows]
traffic = traffic_summary(windows_dict)

common_ips = raw_src_ips.intersection(raw_dst_ips)
src_only = raw_src_ips - raw_dst_ips
dst_only = raw_dst_ips - raw_src_ips
all_unique_ips = raw_src_ips.union(raw_dst_ips)

validation_payload = {
    "capture_name": "testing.pcap",
    "file_size_bytes": pcap_path.stat().st_size,
    "validation_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "telemetry_reconciliation": {
        "raw_packet_count": len(raw_packets),
        "quality_parsed_packets": quality['parsed_packets'],
        "first_timestamp_sec": min_ts,
        "last_timestamp_sec": max_ts,
        "duration_seconds": round(duration, 2),
        "duration_minutes": round(duration / 60.0, 2),
        "temporal_windows_60s": len(canonical_windows),
        "raw_unique_source_ips": len(raw_src_ips),
        "raw_unique_destination_ips": len(raw_dst_ips),
        "ips_in_both_src_and_dst": len(common_ips),
        "ips_only_src": len(src_only),
        "ips_only_dst": len(dst_only),
        "total_combined_unique_ips": len(all_unique_ips),
        "raw_unique_dst_ip_port_pairs": len(raw_dst_ip_ports),
        "directional_5tuples": len(directional_5tuples),
        "canonical_bidirectional_flows": len(canonical_bidi_flows),
        "nexsolve_reconstructed_flows": len(nexus_flows),
        "flow_reconstruction_semantics": "NexSolve canonical 5-tuple timeout-bounded flow reconstruction",
        "temporal_entity_histories_count": len(histories),
        "active_entity_count": len(src_entities)
    },
    "traffic_summary_output": traffic,
    "forecast_validation": {
        "validation_status": "NOT VALIDATED — no future ground-truth segment available",
        "reason": "Single standalone capture without future ground-truth label continuation",
        "signal_strength_labeling": "Uncalibrated Signal Strength Score (0-100)",
        "signal_monotonicity_enforced": True,
        "step_score_range": [0.0, 1.0],
        "cumulative_risk_range": [0.0, 1.0]
    }
}

val_dir = ROOT / "artifacts" / "validation"
val_dir.mkdir(parents=True, exist_ok=True)
val_path = val_dir / "testing_pcap_validation.json"
val_path.write_text(json.dumps(validation_payload, indent=2), encoding="utf-8")

print(f"Successfully generated validation artifact at: {val_path}")

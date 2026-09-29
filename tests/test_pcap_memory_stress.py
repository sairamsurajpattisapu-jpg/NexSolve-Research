"""Deterministic memory stress and bounded ingestion tests for PCAP/PCAPNG processing."""
from __future__ import annotations

import gc
import tempfile
import time
import tracemalloc
from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, UDP, wrpcap

from ml.data.fast_pcap_decoder import FastPcapDecoder
from ml.data.pcap_extractor import PacketSequence, extract_canonical_capture
from model_service.jobs import JOB_MANAGER
from nexsolve_core.state import MODEL_SCHEMA_45, build_network_state_candidates


def _build_synthetic_multistep_pcap(path: Path, num_windows: int = 10, pkts_per_window: int = 2000) -> int:
    """Generate a synthetic PCAP with num_windows * pkts_per_window packets."""
    base_ts = 1700000040.0  # Aligned to 60s epoch boundary
    packets = []
    total_packets = 0
    for w in range(num_windows):
        win_start = base_ts + w * 60.0
        for p in range(pkts_per_window):
            pkt_ts = win_start + (p / float(pkts_per_window)) * 59.0
            if p % 5 == 0:
                pkt = Ether() / IP(src=f"10.0.1.{(p % 250) + 1}", dst="192.168.1.100") / UDP(sport=1024 + (p % 1000), dport=53) / (b"X" * 32)
            else:
                flags = "S" if (p % 20 == 0) else "PA" if (p % 4 == 0) else "A"
                pkt = Ether() / IP(src=f"10.0.1.{(p % 250) + 1}", dst="192.168.1.100") / TCP(sport=1024 + (p % 1000), dport=80, flags=flags) / (b"DATA" * 16)
            pkt.time = pkt_ts
            packets.append(pkt)
            total_packets += 1

    wrpcap(str(path), packets)
    return total_packets


def test_synthetic_20k_packets_memory_bounded():
    """Verify that 20,000 packets across 10 windows are parsed with bounded memory."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_pcap = Path(tf.name)

    try:
        total = _build_synthetic_multistep_pcap(temp_pcap, num_windows=10, pkts_per_window=2000)
        assert total == 20000

        gc.collect()
        tracemalloc.start()
        snap1 = tracemalloc.take_snapshot()

        pkts, windows, quality = extract_canonical_capture(temp_pcap, window_seconds=60, include_raw_packets=False)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Invariants
        assert isinstance(pkts, PacketSequence)
        assert len(pkts) == 20000
        assert len(windows) == 10
        assert quality["parsed_packets"] == 20000
        assert quality["status"].lower() in ("good", "degraded")

        # Crucial memory check: raw packet records are NOT retained in windows when include_raw_packets=False
        for w in windows:
            assert w.packets == ()
            assert "mean_duration" in w.aggregate_features
            assert "packet_count" in w.aggregate_features

        # Candidates build cleanly from precomputed flow features without needing packet objects
        candidates = build_network_state_candidates(windows, MODEL_SCHEMA_45)
        assert len(candidates) == 10
        assert candidates[0].flow_features["flow_count"] > 0
        assert candidates[0].packet_features["packet_count"] > 0

        # Memory overhead of extraction alone must remain strictly under 40 MB
        peak_mb = peak / (1024 * 1024)
        assert peak_mb < 40.0, f"Extraction peak memory exceeded threshold: {peak_mb:.2f} MB"
    finally:
        temp_pcap.unlink(missing_ok=True)


def test_linux_sll_cooked_capture_native_fast_pcap_decoder():
    """Verify that Linux Cooked captures (link type 113) decode natively without Scapy fallback."""
    fixture_path = Path("research/open_source/nfstream/nfstream-master/tests/pcaps/reasm_crash_anon.pcapng")
    if not fixture_path.exists():
        pytest.skip("reasm_crash_anon.pcapng fixture not found")

    import mmap

    with open(fixture_path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            decoder = FastPcapDecoder(mm, capture_id="reasm_crash_anon.pcapng")
            assert decoder.valid is True
            assert decoder.fallback_needed is False
            packets = list(decoder.decode_packets())
            assert len(packets) == 209
            assert all(p.parsing_status == "parsed" for p in packets)


def test_job_manager_real_slice_end_to_end_bounded():
    """Verify full asynchronous JOB_MANAGER execution on real Friday 10-window slice."""
    pcap_path = Path("data/test_slices/friday_10windows_slice.pcap")
    if not pcap_path.exists():
        pytest.skip("friday_10windows_slice.pcap fixture not found")

    content = pcap_path.read_bytes()
    job = JOB_MANAGER.create_job(pcap_path.name, content)

    for _ in range(120):
        rec = JOB_MANAGER.get_job(job.job_id)
        if rec and rec.status in ("COMPLETED", "FAILED", "RESOURCE_LIMIT_EXCEEDED"):
            break
        time.sleep(0.2)

    rec = JOB_MANAGER.get_job(job.job_id)
    assert rec is not None
    assert rec.status == "COMPLETED", f"Job failed with error: {rec.error}"
    assert rec.processing_statistics["packets_processed"] == 2277
    assert rec.processing_statistics["windows_processed"] == 10

    res = rec.result
    assert res["model_compatibility"]["model_ready"] is True
    assert res["model_compatibility"]["active_schema"] == "MODEL_SCHEMA_45"
    assert len(res["forecasts"]) == 5
    for pt in res["forecasts"]:
        assert pt["attackProbability"] is not None
        assert 0.0 <= pt["attackProbability"] <= 1.0

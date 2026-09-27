"""NexSolve End-to-End Real PCAP Model Validation & Benchmarking Script.

Profiles all stages:
1. PCAP ingestion & packet parsing
2. Flow reconstruction & candidate generation
3. Temporal history & compatibility gating
4. Conversion to canonical 45-feature NetworkStates
5. Normalization, Candidate V2 LSTM inference, & multi-horizon rollout
Across multiple captures and multiple runs for repeatability, latency, and memory profiling.
"""
from __future__ import annotations

import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.data.pcap_extractor import extract_canonical_capture
from nexsolve_core.state import (
    MODEL_SCHEMA_45,
    build_network_state_candidates,
    build_state_history,
    candidates_to_network_states,
    evaluate_model_compatibility,
)
from ml.forecasting.production_inference import (
    AbstentionReason,
    ForecastAvailabilityStatus,
    ProductionInferenceEngine,
    predict_pcap_forecast,
)


def profile_capture(pcap_path: Path, engine: ProductionInferenceEngine, runs_count: int = 5) -> dict[str, Any]:
    print(f"\n=======================================================")
    print(f"Profiling Capture: {pcap_path.name} ({pcap_path.stat().st_size} bytes)")
    print(f"=======================================================")

    run_records = []
    first_res = None

    for run_idx in range(runs_count):
        tracemalloc.start()
        t_start = time.perf_counter()

        # Stage 1: PCAP Ingestion & Packet Parsing
        t0 = time.perf_counter()
        pkts, windows, quality = extract_canonical_capture(pcap_path, window_seconds=60)
        t_ingest = time.perf_counter() - t0

        q_status = quality.get("status") if isinstance(quality, dict) else getattr(quality, "status", None)
        if hasattr(q_status, "value"):
            q_status = q_status.value

        # Stage 2: Flow Reconstruction & Candidates
        t0 = time.perf_counter()
        candidates = build_network_state_candidates(windows)
        t_candidates = time.perf_counter() - t0

        # Stage 3: Temporal History & Model Compatibility Gate
        t0 = time.perf_counter()
        history = build_state_history(candidates, lookback=engine.spec.lookback)
        compat = evaluate_model_compatibility(candidates, MODEL_SCHEMA_45, history.status)
        t_history = time.perf_counter() - t0

        # Stage 4: Conversion to 45-Feature NetworkStates
        t0 = time.perf_counter()
        states = ()
        if compat.model_ready:
            states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history.status)
        t_convert = time.perf_counter() - t0

        # Stage 5: Inference Pipeline (Validation, Normalization, LSTM Rollout)
        t0 = time.perf_counter()
        res = engine.predict_pcap(pcap_path, window_seconds=60)
        t_infer = time.perf_counter() - t0

        total_time = time.perf_counter() - t_start
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        if first_res is None:
            first_res = res

        prob_list = [res.horizons[f"T+{h}"].attack_probability for h in range(1, 6)] if not res.abstained else []
        pred_list = [res.horizons[f"T+{h}"].binary_prediction for h in range(1, 6)] if not res.abstained else []

        run_records.append({
            "run": run_idx + 1,
            "packets": len(pkts),
            "windows": len(windows),
            "quality": q_status,
            "history_status": history.status,
            "model_ready": compat.model_ready,
            "abstained": res.abstained,
            "reason": res.abstention_reason,
            "t_ingest_ms": round(t_ingest * 1000, 2),
            "t_candidates_ms": round(t_candidates * 1000, 2),
            "t_history_ms": round(t_history * 1000, 2),
            "t_convert_ms": round(t_convert * 1000, 2),
            "t_infer_ms": round(t_infer * 1000, 2),
            "total_ms": round(total_time * 1000, 2),
            "peak_mem_mb": round(peak_mem / (1024 * 1024), 2),
            "probs": prob_list,
            "preds": pred_list,
        })

    # Summary
    avg_total = sum(r["total_ms"] for r in run_records) / runs_count
    avg_ingest = sum(r["t_ingest_ms"] for r in run_records) / runs_count
    avg_infer = sum(r["t_infer_ms"] for r in run_records) / runs_count
    avg_mem = sum(r["peak_mem_mb"] for r in run_records) / runs_count

    print(f"Packets: {run_records[0]['packets']}, Windows: {run_records[0]['windows']}, Quality: {run_records[0]['quality']}")
    print(f"History Status: {run_records[0]['history_status']}, Model Ready: {run_records[0]['model_ready']}")
    print(f"Outcome: {'ABSTAINED (' + str(run_records[0]['reason']) + ')' if run_records[0]['abstained'] else 'AVAILABLE (5 Horizons)'}")
    if not run_records[0]["abstained"]:
        print(f"Probabilities (T+1..T+5): {[round(p, 4) for p in run_records[0]['probs']]}")
        print(f"Predictions (T+1..T+5):   {run_records[0]['preds']}")
    print(f"Latency: Total={avg_total:.2f}ms (Ingest={avg_ingest:.2f}ms, Infer={avg_infer:.2f}ms)")
    print(f"Peak Memory: {avg_mem:.2f} MB")

    # Repeatability verification
    if not run_records[0]["abstained"]:
        for r in run_records[1:]:
            assert r["probs"] == run_records[0]["probs"], "Non-deterministic probability variation detected!"
            assert r["preds"] == run_records[0]["preds"], "Non-deterministic binary prediction detected!"
        print("Repeatability: 100% BITWISE DETERMINISTIC across all runs.")
    else:
        for r in run_records[1:]:
            assert r["abstained"] == run_records[0]["abstained"], "Inconsistent abstention decision across runs!"
            assert r["reason"] == run_records[0]["reason"], "Inconsistent abstention reason across runs!"
        print("Repeatability: 100% CONSISTENT ABSTENTION across all runs.")

    return {
        "path": str(pcap_path),
        "name": pcap_path.name,
        "size_bytes": pcap_path.stat().st_size,
        "packets": run_records[0]["packets"],
        "windows": run_records[0]["windows"],
        "quality": run_records[0]["quality"],
        "history_status": run_records[0]["history_status"],
        "model_ready": run_records[0]["model_ready"],
        "abstained": run_records[0]["abstained"],
        "reason": run_records[0]["reason"],
        "avg_total_ms": round(avg_total, 2),
        "avg_ingest_ms": round(avg_ingest, 2),
        "avg_infer_ms": round(avg_infer, 2),
        "avg_peak_mem_mb": round(avg_mem, 2),
        "probs": run_records[0]["probs"],
        "preds": run_records[0]["preds"],
        "runs": run_records,
    }


def main():
    engine = ProductionInferenceEngine(model_id="candidate_v2")

    test_targets = [
        # Condition 1: Multi-window real capture (10 windows, reconnaissance / port scan activity)
        ROOT / "data" / "test_slices" / "friday_10windows_slice.pcap",
        # Condition 2: Attack traffic with short history (SYN scan attack, 1 window)
        ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "synscan.pcap",
        # Condition 3: Web attack with insufficient history (SQL injection, 2 windows)
        ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "WebattackSQLinj.pcap",
        # Condition 4: SSH traffic with insufficient history (4 windows)
        ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "ssh.pcap",
        # Condition 5: Normal/benign tunnel traffic (WireGuard UDP, 8 windows, missing TCP window semantics)
        ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "wireguard.pcap",
        # Condition 6: Micro-capture (1 packet, insufficient quality)
        ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "raw.pcap",
    ]

    all_results = []
    for path in test_targets:
        if path.exists():
            res = profile_capture(path, engine, runs_count=5)
            all_results.append(res)
        else:
            print(f"Skipping non-existent path: {path}")

    # Write results summary to json
    out_json = ROOT / "experiments" / "candidate_v2" / "pcap_validation_metrics.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    import json
    out_json.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    print(f"\nAll profiling metrics saved to {out_json}")


if __name__ == "__main__":
    main()

"""Run the deterministic, real-data UNSW research demonstration."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from world_model import build_network_states
from research_intelligence.engine import run_model_intelligence

ROOT = Path(__file__).resolve().parents[1]


def run() -> dict:
    started = time.perf_counter()
    states, _ = build_network_states()
    if len(states) < 8:
        raise RuntimeError("insufficient timestamped states for the demo")
    result = run_model_intelligence(states[:8])
    output = {"status": "completed", "input": {"dataset": "UNSW-NB15", "states": 8, "window_seconds": 60, "episode_selection": "first eight states of the protected local research input"}, "model": {"architecture": "NumPy LSTM", "feature_count": 46, "lookback": 8, "horizon": 5, "packet_features_available": False}, "forecast": result["forecast"], "current_state": result["current_state"], "defender_guidance": result["defender_guidance"], "evidence": result["evidence"], "limitations": result["limitations"], "runtime_seconds": time.perf_counter() - started}
    (ROOT / "reports" / "demo_execution.json").write_text(json.dumps(output, indent=2, ensure_ascii=True), encoding="utf-8")
    (ROOT / "reports" / "demo_execution.md").write_text("# Demo Execution\n\nReal local UNSW-NB15 input, protected NumPy LSTM, deterministic 60-second states, and recursive T+1 through T+5 output.\n\n```json\n" + json.dumps(output, indent=2, ensure_ascii=True) + "\n```\n\nNo packet data or fabricated values are used. This remains a research demonstration with limited evaluation evidence and uncalibrated probabilities.\n", encoding="utf-8")
    return output


if __name__ == "__main__":
    print(json.dumps({"status": run()["status"]}, indent=2))
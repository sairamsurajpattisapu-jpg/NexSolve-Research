import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.data.pcap_extractor import extract_canonical_capture
from ml.final_production_inference import FinalProductionInferenceEngine
from nexsolve_core.state import (
    MODEL_SCHEMA_45,
    build_network_state_candidates,
    build_state_history,
    candidates_to_network_states,
)

ROOT = Path(".")
pcaps = [
    ("friday_10windows_slice.pcap", ROOT / "data/test_slices/friday_10windows_slice.pcap"),
    ("synscan.pcap", ROOT / "research/open_source/nfstream/nfstream-master/tests/results/synscan.pcap"),
    ("WebattackSQLinj.pcap", ROOT / "research/open_source/nfstream/nfstream-master/tests/results/WebattackSQLinj.pcap"),
    ("ssh.pcap", ROOT / "research/open_source/zeek/zeek-master/testing/btest/Traces/ssh/ssh.pcap"),
    ("wireguard.pcap", ROOT / "research/open_source/nfstream/nfstream-master/tests/results/wireguard.pcap"),
    ("raw.pcap", ROOT / "research/open_source/nfstream/nfstream-master/tests/results/raw.pcap"),
]

engine = FinalProductionInferenceEngine()

print("=== REAL PCAP INFERENCE AUDIT ===")
for name, pcap_path in pcaps:
    if not pcap_path.exists():
        print(f"{name}: FILE NOT FOUND at {pcap_path}")
        continue
    t0 = time.time()
    try:
        res1 = engine.predict_pcap(pcap_path)
        dt = (time.time() - t0) * 1000

        # Determinism check
        res2 = engine.predict_pcap(pcap_path)
        det = (res1.get("status") == res2.get("status") and
               res1.get("operational_tier") == res2.get("operational_tier") and
               res1.get("abstention_reason") == res2.get("abstention_reason"))

        dq = res1.get("data_quality", {})
        print(f"{name}:")
        print(f"  Status:             {res1.get('status')}")
        print(f"  Operational Tier:   {res1.get('operational_tier')}")
        print(f"  Window Count:       {dq.get('window_count', 'N/A')}")
        print(f"  Forecast Available: {not res1.get('is_abstained')}")
        print(f"  Abstention Reason:  {res1.get('abstention_reason')}")
        print(f"  Latency:            {dt:.2f} ms")
        print(f"  Deterministic:      {det}")
    except Exception as e:
        print(f"{name}: ERROR -> {e}")

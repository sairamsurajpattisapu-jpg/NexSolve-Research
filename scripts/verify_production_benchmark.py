"""Script to verify that ProductionInferenceEngine produces identical metrics to metrics.json."""
import json
import sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.forecasting.production_inference import ProductionInferenceEngine
from ml.train_candidate_v2 import load_dataset_v2, compute_classification_metrics
from world_model import LOOKBACK

def main():
    states, splits = load_dataset_v2()
    val_states = splits["validation"]
    test_states = splits["test"]

    engine = ProductionInferenceEngine(model_id="candidate_v2")

    # Load authoritative metrics.json
    with open("models/candidate_v2/metrics.json", encoding="utf-8") as f:
        meta_metrics = json.load(f)

    # 1. Validation T+1 & T+2
    print("--- Verifying Validation Set (Episode 2) ---")
    for h in (1, 2):
        actuals = []
        preds = []
        probs = []
        for t in range(LOOKBACK, len(val_states) - h + 1):
            hist = val_states[t - LOOKBACK : t]
            target = val_states[t + h - 1]
            res = engine.predict_states(hist, horizons=(h,))
            assert not res.abstained, f"Abstained at step {t}: {res.abstention_reason}"
            out = res.horizons[f"T+{h}"]
            probs.append(out.attack_probability)
            preds.append(out.binary_prediction)
            actuals.append(int(target.attack_state))

        m = compute_classification_metrics(actuals, preds, probs)
        expected = meta_metrics["validation_benchmark"]["Candidate_V2_Calibrated"][f"T+{h}"]

        print(f"Val T+{h}: precision={m['precision']}, recall={m['recall']}, f1={m['f1']}")
        assert m["precision"] == expected["precision"], f"Precision mismatch at T+{h}: {m['precision']} vs {expected['precision']}"
        assert m["recall"] == expected["recall"], f"Recall mismatch at T+{h}: {m['recall']} vs {expected['recall']}"
        assert m["f1"] == expected["f1"], f"F1 mismatch at T+{h}: {m['f1']} vs {expected['f1']}"
        assert m["confusion_matrix"] == expected["confusion_matrix"], f"Confusion matrix mismatch at T+{h}"

    print("Validation T+1 and T+2 exactly match metrics.json!\n")

    # 2. Test Set (Episode 3) T+1 & T+2
    print("--- Verifying Test Set (Episode 3) ---")
    for h in (1, 2):
        actuals = []
        preds = []
        probs = []
        for t in range(LOOKBACK, len(test_states) - h + 1):
            hist = test_states[t - LOOKBACK : t]
            target = test_states[t + h - 1]
            res = engine.predict_states(hist, horizons=(h,))
            assert not res.abstained, f"Abstained at test step {t}: {res.abstention_reason}"
            out = res.horizons[f"T+{h}"]
            probs.append(out.attack_probability)
            preds.append(out.binary_prediction)
            actuals.append(int(target.attack_state))

        m = compute_classification_metrics(actuals, preds, probs)
        expected = meta_metrics["test_benchmark"]["Candidate_V2_Calibrated"][f"T+{h}"]

        print(f"Test T+{h}: precision={m['precision']}, recall={m['recall']}, f1={m['f1']}, sample_count={m['sample_count']}")
        assert m["recall"] == expected["recall"], f"Test recall mismatch at T+{h}: {m['recall']} vs {expected['recall']}"
        assert m["f1"] == expected["f1"], f"Test F1 mismatch at T+{h}: {m['f1']} vs {expected['f1']}"
        assert m["confusion_matrix"] == expected["confusion_matrix"], f"Test CM mismatch at T+{h}"

    print("Test T+1 and T+2 exactly match metrics.json!")
    print("\n>>> ZERO METRIC DEGRADATION CONFIRMED ON BOTH VALIDATION AND TEST SETS! <<<")

if __name__ == "__main__":
    main()

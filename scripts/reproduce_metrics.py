import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
from ml.models.final_world_model import FinalNetworkWorldModel
from ml.train_final_world_model import load_dataset, evaluate_binary_predictions
from ml.forecasting.temporal_split import make_episode_sequences
from world_model import FEATURE_NAMES_45, LOOKBACK
from sklearn.metrics import mean_squared_error, mean_absolute_error

model = FinalNetworkWorldModel.load(Path("models/final_world_model"))
states, splits = load_dataset()
val_x, val_targets, labels_val = make_episode_sequences(splits["val_episodes"], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45)
test_x, test_targets, labels_test = make_episode_sequences(splits["test_episodes"], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45)

x_val = (val_x - model.scaler_mean) / model.scaler_scale
targets_val = (val_targets - model.scaler_mean) / model.scaler_scale
x_test = (test_x - model.scaler_mean) / model.scaler_scale
targets_test = (test_targets - model.scaler_mean) / model.scaler_scale

saved_metrics = json.load(open("models/final_world_model/metrics.json"))

print("=================================================================")
print("INDEPENDENT RECOMPUTATION OF FINAL WORLD MODEL METRICS")
print("=================================================================")

for split_name, x_data, targets_data, labels_data, key in [
    ("Validation", x_val, targets_val, labels_val, "validation_horizons"),
    ("Test", x_test, targets_test, labels_test, "test_horizons"),
]:
    n_seq = len(x_data)
    for h in range(1, 6):
        actual_labels = [int(labels_data[i + h - 1]) for i in range(n_seq - h + 1)]
        predicted_probs = []
        state_mses = []
        for i in range(n_seq - h + 1):
            seq = x_data[i]
            views_seq = [model.extract_views_from_canonical_45(step_vec) for step_vec in seq]
            _, _, step_outputs = model.predict_k_steps(views_seq, k=h)
            target_out = step_outputs[h - 1]
            predicted_probs.append(target_out.attack_probability)
            actual_state = targets_data[i + h - 1]
            state_mses.append(float(mean_squared_error(actual_state, target_out.predicted_state_vector)))

        bm = evaluate_binary_predictions(actual_labels, predicted_probs, threshold=0.05)
        bm["state_mse"] = float(np.mean(state_mses))
        saved = saved_metrics[key][f"T+{h}"]

        f1_diff = abs(bm["f1"] - saved["f1"])
        mse_diff = abs(bm["state_mse"] - saved["state_mse"])
        rec_diff = abs(bm["recall"] - saved["recall"])
        prec_diff = abs(bm["precision"] - saved["precision"])
        brier_diff = abs(bm["brier_score"] - saved["brier_score"])
        ece_diff = abs(bm["expected_calibration_error"] - saved["expected_calibration_error"])

        status = "EXACT MATCH" if (f1_diff < 1e-5 and mse_diff < 1e-4) else "MISMATCH"
        print(f"[{split_name}] T+{h}: {status}")
        print(f"   F1:        recomputed={bm['f1']:.6f} | saved={saved['f1']:.6f} | diff={f1_diff:.2e}")
        print(f"   Precision: recomputed={bm['precision']:.6f} | saved={saved['precision']:.6f} | diff={prec_diff:.2e}")
        print(f"   Recall:    recomputed={bm['recall']:.6f} | saved={saved['recall']:.6f} | diff={rec_diff:.2e}")
        print(f"   State MSE: recomputed={bm['state_mse']:.6f} | saved={saved['state_mse']:.6f} | diff={mse_diff:.2e}")
        print(f"   Brier:     recomputed={bm['brier_score']:.6f} | saved={saved['brier_score']:.6f} | diff={brier_diff:.2e}")
        print(f"   ECE:       recomputed={bm['expected_calibration_error']:.6f} | saved={saved['expected_calibration_error']:.6f} | diff={ece_diff:.2e}")
        print(f"   PR-AUC:    recomputed={bm['pr_auc']} | saved={saved['pr_auc']}")
        print(f"   ROC-AUC:   recomputed={bm['roc_auc']} | saved={saved['roc_auc']}")

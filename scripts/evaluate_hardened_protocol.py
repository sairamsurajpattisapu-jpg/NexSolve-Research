import json
import sys
import numpy as np
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.models.final_world_model import FinalNetworkWorldModel
from ml.train_final_world_model import load_dataset, evaluate_binary_predictions
from ml.forecasting.temporal_split import make_episode_sequences
from world_model import FEATURE_NAMES_45, LOOKBACK
from sklearn.metrics import mean_squared_error, mean_absolute_error, precision_score, recall_score, f1_score

model = FinalNetworkWorldModel.load(ROOT / "models" / "final_world_model")
states, splits = load_dataset()

# All 5 episodes from dataset
episodes = splits.get("all_episodes", None)
if episodes is None:
    from ml.forecasting.temporal_split import extract_contiguous_episodes
    episodes = extract_contiguous_episodes(states, window_seconds=60)

print(f"Loaded {len(episodes)} episodes.")

# 1. Validation Onset (Episode 2: 10 Benign, 15 Attack)
val_x, val_targets, labels_val = make_episode_sequences([episodes[2]], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45)
x_val = (val_x - model.scaler_mean) / model.scaler_scale
targets_val = (val_targets - model.scaler_mean) / model.scaler_scale

print("\n--- PARTITION 2: VALIDATION ONSET EVALUATION (EPISODE 2) ---")
val_probs = []
val_mses = []
for i in range(len(x_val)):
    seq = x_val[i]
    views_seq = [model.extract_views_from_canonical_45(step_vec) for step_vec in seq]
    _, _, step_outputs = model.predict_k_steps(views_seq, k=1)
    val_probs.append(step_outputs[0].attack_probability)
    val_mses.append(mean_squared_error(targets_val[i], step_outputs[0].predicted_state_vector))

val_eval = evaluate_binary_predictions(labels_val, val_probs, threshold=0.05)
print(f"Validation T+1: F1={val_eval['f1']:.4f}, Prec={val_eval['precision']:.4f}, Rec={val_eval['recall']:.4f}, PR-AUC={val_eval['pr_auc']:.4f}, ROC-AUC={val_eval['roc_auc']:.4f}, MSE={np.mean(val_mses):.4f}")
print(f"Confusion Matrix: {val_eval['confusion_matrix']}")

# 2. Holdout Benign Partition (Episode 1: 291 Benign Windows, 0 Attack)
benign_x, benign_targets, labels_benign = make_episode_sequences([episodes[1]], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45)
x_benign = (benign_x - model.scaler_mean) / model.scaler_scale

print("\n--- PARTITION 3: HOLDOUT BENIGN EVALUATION (EPISODE 1: 283 SEQUENCES) ---")
benign_probs = []
for i in range(len(x_benign)):
    seq = x_benign[i]
    views_seq = [model.extract_views_from_canonical_45(step_vec) for step_vec in seq]
    _, _, step_outputs = model.predict_k_steps(views_seq, k=1)
    benign_probs.append(step_outputs[0].attack_probability)

# Compute False Positive Rate across different thresholds
for tau in [0.05, 0.15, 0.30, 0.50]:
    fps = sum(1 for p in benign_probs if p >= tau)
    tns = len(benign_probs) - fps
    fpr = fps / len(benign_probs)
    spec = tns / len(benign_probs)
    print(f"Threshold tau={tau:.2f}: Total={len(benign_probs)}, TN={tns}, FP={fps}, False Positive Rate={fpr:.4f}, Specificity={spec:.4f}")

# 3. Abrupt Benign Burst Analysis in Episode 1
# Find windows in Episode 1 where packet_count or flow_count is in top 10% of benign traffic
benign_packet_counts = [seq[-1, 17] for seq in benign_x]
burst_threshold = float(np.percentile(benign_packet_counts, 90))
burst_indices = [idx for idx, cnt in enumerate(benign_packet_counts) if cnt >= burst_threshold]
burst_probs = [benign_probs[idx] for idx in burst_indices]

print(f"\n--- ABRUPT BENIGN BURST SUBSET ({len(burst_indices)} burst windows) ---")
for tau in [0.05, 0.15, 0.30, 0.50]:
    burst_fps = sum(1 for p in burst_probs if p >= tau)
    burst_fpr = burst_fps / len(burst_probs)
    print(f"Threshold tau={tau:.2f}: Bursts={len(burst_probs)}, False Alarms={burst_fps}, Burst FPR={burst_fpr:.4f}")

# 4. Holdout Campaign Test Partition (Episode 3: 562 Attack Windows)
test_x, test_targets, labels_test = make_episode_sequences([episodes[3]], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45)
x_test = (test_x - model.scaler_mean) / model.scaler_scale
targets_test = (test_targets - model.scaler_mean) / model.scaler_scale

print("\n--- PARTITION 4: HOLDOUT CAMPAIGN TEST EVALUATION (EPISODE 3: 554 SEQUENCES) ---")
for h in range(1, 6):
    probs_h = []
    mses_h = []
    n_seq = len(x_test) - h + 1
    for i in range(n_seq):
        seq = x_test[i]
        views_seq = [model.extract_views_from_canonical_45(step_vec) for step_vec in seq]
        _, _, step_outputs = model.predict_k_steps(views_seq, k=h)
        probs_h.append(step_outputs[h - 1].attack_probability)
        mses_h.append(mean_squared_error(targets_test[i + h - 1], step_outputs[h - 1].predicted_state_vector))

    rec = sum(1 for p in probs_h if p >= 0.05) / len(probs_h)
    rec_nom = sum(1 for p in probs_h if p >= 0.30) / len(probs_h)
    print(f"T+{h}: State MSE={np.mean(mses_h):.4f}, State MAE={np.mean([np.sqrt(m) for m in mses_h]):.4f}, Recall(tau=0.05)={rec:.4f}, Recall(tau=0.30)={rec_nom:.4f}")

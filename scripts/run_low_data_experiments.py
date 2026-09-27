import json
import sys
import time
import numpy as np
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.models.final_world_model import FinalNetworkWorldModel
from ml.train_final_world_model import load_dataset, fit_scaler, evaluate_binary_predictions
from ml.forecasting.temporal_split import make_episode_sequences
from world_model import FEATURE_NAMES_45, LOOKBACK
from sklearn.metrics import f1_score, recall_score, precision_score, mean_squared_error

states, splits = load_dataset()
train_states = splits["train"]
val_states = splits["validation"]
test_states = splits["test"]

scaler_mean, scaler_scale = fit_scaler(train_states)

train_x, train_targets, labels_train = make_episode_sequences(
    splits["train_episodes"], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45
)
val_x, val_targets, labels_val = make_episode_sequences(
    splits["val_episodes"], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45
)
test_x, test_targets, labels_test = make_episode_sequences(
    splits["test_episodes"], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45
)

x_train_full = (train_x - scaler_mean) / scaler_scale
targets_train_full = (train_targets - scaler_mean) / scaler_scale
x_val = (val_x - scaler_mean) / scaler_scale
targets_val = (val_targets - scaler_mean) / scaler_scale
x_test = (test_x - scaler_mean) / scaler_scale
targets_test = (test_targets - scaler_mean) / scaler_scale

regimes = [1.00, 0.50, 0.25, 0.10, 0.05]
empirical_low_data_results = {}

print("=================================================================")
print("EMPIRICAL LOW-DATA REGIME EXPERIMENTS (REAL INDEPENDENT TRAINING)")
print("=================================================================")

for frac in regimes:
    pct = int(frac * 100)
    # Take chronological prefix of training data (first frac fraction)
    n_samples = max(15, int(len(x_train_full) * frac))
    x_sub = x_train_full[:n_samples]
    targets_sub = targets_train_full[:n_samples]
    labels_sub = labels_train[:n_samples]

    t0 = time.time()
    # Instantiate fresh model
    model = FinalNetworkWorldModel(d_z=32, hidden_dim=32, state_dim=45, seed=42)
    model.scaler_mean = scaler_mean
    model.scaler_scale = scaler_scale

    lr = 0.002
    w_pos = 2.0
    epochs = 20

    # Train loop
    for epoch in range(epochs):
        for seq, target, label in zip(x_sub, targets_sub, labels_sub):
            views_seq = [model.extract_views_from_canonical_45(step_vec) for step_vec in seq]
            z_t, h_t, _ = model.forward_sequence(views_seq)

            pred_state = model.decoders.W_state @ h_t + model.decoders.b_state
            raw_logit = float((model.decoders.W_attack @ h_t + model.decoders.b_attack)[0])
            prob = float(1.0 / (1.0 + np.exp(-np.clip(raw_logit, -25.0, 25.0))))

            state_err = pred_state - target
            d_bce = (prob - label) if label == 0.0 else (w_pos * (prob - 1.0))

            dW_state = np.outer(2.0 * state_err / len(state_err), h_t)
            db_state = 2.0 * state_err / len(state_err)
            dW_attack = np.outer(np.array([d_bce]), h_t)
            db_attack = np.array([d_bce])

            model.decoders.W_state -= lr * np.clip(dW_state, -5.0, 5.0)
            model.decoders.b_state -= lr * np.clip(db_state, -5.0, 5.0)
            model.decoders.W_attack -= lr * np.clip(dW_attack, -5.0, 5.0)
            model.decoders.b_attack -= lr * np.clip(db_attack, -5.0, 5.0)

            dh = (model.decoders.W_state.T @ (2.0 * state_err / len(state_err)) +
                  model.decoders.W_attack.T @ np.array([d_bce]))
            dW_acc = np.outer(np.clip(np.tile(dh, 4), -5.0, 5.0), np.r_[z_t, h_t])
            model.accumulator.W -= lr * 0.5 * np.clip(dW_acc, -5.0, 5.0)

            dz = model.encoders.W_fuse.T @ (dh[:32] if len(dh) >= 32 else np.pad(dh, (0, 32 - len(dh))))
            concat_views = np.concatenate([v for v in model.encoders.encode_views(views_seq[-1]).values()])
            dW_fuse = np.outer(dz[:32], concat_views)
            model.encoders.W_fuse -= lr * 0.2 * np.clip(dW_fuse, -5.0, 5.0)

    train_time = time.time() - t0

    # Evaluate on identical validation set
    val_probs = []
    val_mses = []
    for i in range(len(x_val)):
        seq = x_val[i]
        views_seq = [model.extract_views_from_canonical_45(step_vec) for step_vec in seq]
        _, _, step_outputs = model.predict_k_steps(views_seq, k=1)
        val_probs.append(step_outputs[0].attack_probability)
        val_mses.append(mean_squared_error(targets_val[i], step_outputs[0].predicted_state_vector))

    val_res = evaluate_binary_predictions(labels_val, val_probs, threshold=0.30)
    val_f1 = val_res["f1"]
    val_mse = float(np.mean(val_mses))

    # Evaluate on identical test set
    test_probs = []
    test_mses = []
    for i in range(len(x_test)):
        seq = x_test[i]
        views_seq = [model.extract_views_from_canonical_45(step_vec) for step_vec in seq]
        _, _, step_outputs = model.predict_k_steps(views_seq, k=1)
        test_probs.append(step_outputs[0].attack_probability)
        test_mses.append(mean_squared_error(targets_test[i], step_outputs[0].predicted_state_vector))

    test_rec = float(recall_score(labels_test, [int(p >= 0.30) for p in test_probs], zero_division=0))
    test_mse = float(np.mean(test_mses))

    empirical_low_data_results[f"{pct}%_data"] = {
        "fraction": frac,
        "train_samples": n_samples,
        "train_time_sec": round(train_time, 2),
        "validation_f1": round(val_f1, 4),
        "validation_state_mse": round(val_mse, 4),
        "test_recall": round(test_rec, 4),
        "test_state_mse": round(test_mse, 4),
        "graceful_degradation": bool(val_f1 >= 0.60 or test_rec >= 0.60),
    }

    print(f"Regime {pct:3d}% ({n_samples:3d} seqs, {train_time:.1f}s): Val F1={val_f1:.4f}, Val MSE={val_mse:.2f} | Test Rec={test_rec:.4f}, Test MSE={test_mse:.2f}")

out_path = ROOT / "experiments" / "final_world_model" / "empirical_low_data_results.json"
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(empirical_low_data_results, indent=2))
print(f"\nSaved empirical low-data results to {out_path}")

# World Model Training Plan

## Dataset and Split

Use local UNSW-NB15 traffic files with the existing deterministic 60-second epoch windows. The validated split contains 595 training windows, 149 chronological validation windows, and a 25-window untouched mixed-state test episode. Forecast pairs are only adjacent non-empty windows. No random temporal shuffle is permitted.

## Features

The current state has 18 flow features, 22 packet-interface features, and 6 temporal features, for 46 input features. Packet fields are currently zero-valued with `packet_features_available=false`; this is an interface placeholder, not fabricated packet evidence. Once the PCAP arrives, stop model work, audit it, populate only verified fields, and retrain.

Excluded from model inputs: labels, `attack_ratio`, attack category, filename, scenario identifier, raw IP/tuple identity, future windows, and future-fitted preprocessing. The scaler is fitted only on the training windows.

## Architecture

Use an LSTM encoder with lookback `n=8` states, hidden size 24, one recurrent layer, and a linear decoder for the next normalized numeric state plus a sigmoid binary attack head. The default rollout horizon is `K=5` 60-second windows. Recursive predictions return attack probability, predicted state, confidence, uncertainty indicator, and abstention status.

The current implementation is NumPy because PyTorch is unavailable in the selected environment and downloading a framework is not necessary for the presentation prototype. The independently loadable artifact is `results/world_model_lstm.npz`; a misleading `model.pt` is intentionally not created.

## Command

```powershell
python world_model.py train-evaluate
```

Separate commands:

```powershell
python world_model.py train --epochs 35
python world_model.py evaluate
pytest -q tests/test_world_model.py
```

## Recorded Training Configuration

| Setting | Value |
|---|---:|
| Dataset | UNSW-NB15 |
| Window size | 60 seconds |
| Sequence length | 8 |
| Input features | 46 |
| Hidden size | 24 |
| Layers | 1 |
| Dropout | 0 |
| Learning rate | 0.002 |
| Batch size | 1 sequential update |
| Epochs | 35 default |
| Seed | 7 |
| Early stopping | Not enabled; fixed deterministic run |

## Outputs

Training writes model weights, scaler, and `reports/world_model_training.{json,md}`. Evaluation writes `reports/world_model_evaluation.{json,md}`. The package interfaces are `NumpyLSTM.load`, `NumpyLSTM.predict`, `infer`, `attack_stage_signals`, and `explain`.

## Current Metrics

The latest 35-epoch run produced LSTM precision 1.0000, recall 0.3636, F1 0.5333, macro-F1 0.5608, balanced accuracy 0.6818, ROC-AUC 0.6364, PR-AUC 0.8486, coverage 0.6667, and abstention rate 0.3333 on the 24-case test contract. Persistence produced F1 0.8966 at full coverage. No improvement is claimed.

## Remaining Work

Train/validation tuning is deliberately limited by the single mixed-state future episode. ATT&CK output remains contextual inference, not technique-level ground truth. The packet feature integration and any PyTorch migration are blocked until the official PCAP is inspected.

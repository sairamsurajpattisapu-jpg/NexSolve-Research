# Model Selection

## Selected Components

### External pretrained detection model

**None selected.** Kitsune/KitNET is the only credible official detection reference found with a clear MIT license, but its repository provides source code and local online training, not a compatible pretrained checkpoint. Its output is reconstruction RMSE, not future attack probability.

### External pretrained representation model

**None selected.** No official candidate was found with verified network-traffic packet/flow input, public compatible weights, clear licensing, and a demonstrated transferable representation for CIC-IDS2017, UNSW-NB15, or TON-IoT.

## Selected NexSolve Model

The local NumPy LSTM is selected because it is runnable in the current environment, consumes the validated 60-second NetworkState contract, predicts continuous next-state features and attack probability, supports recursive `K=5` rollout, serializes independently, and has no external checkpoint or cloud dependency.

It is not a claim of production readiness. Packet features are currently an explicit unavailable interface pending the Friday CIC PCAP audit.

## Existing Baselines

Keep the existing CIC Logistic Regression detector unchanged. Use the existing UNSW persistence and empirical-transition baselines for temporal comparison. The CIC detector is not directly comparable to UNSW next-window forecasting.

## Acquisition Recommendation

Do not download any external model tonight. The exact next acquisition is the already pending official Friday CIC PCAP. After its packet audit, integrate only verified packet fields and retrain the local world model.

# Pretrained Model Candidates

Run date (UTC): `2026-09-03`

## Decision

No external pretrained weights are selected or downloaded. No reviewed candidate is an A-level directly reusable temporal world model.

| Candidate | Official page / download | Class | License | Size | Input/output | Relevance and risks |
|---|---|---|---|---|---|---|
| Kitsune-py / KitNET-py | [Kitsune](https://github.com/ymirsky/Kitsune-py), [KitNET](https://github.com/ymirsky/KitNET-py); clone URL `https://github.com/ymirsky/Kitsune-py.git` | B | MIT, verified in repository | No pretrained weight file or published checkpoint size; source only | PCAP/TSV packet stream to online reconstruction RMSE anomaly score | Useful detection/packet feature reference. It is an online autoencoder detector, not future-state forecasting. Requires local training and Scapy or tshark; Mirai demo data is not NexSolve data. |
| CICFlowMeter | [Official repository](https://github.com/ahlashkari/CICFlowMeter); clone URL `https://github.com/ahlashkari/CICFlowMeter.git` | B | Repository license exists; exact license text should be reviewed before redistribution | No pretrained weights; Java flow extractor | PCAP to bidirectional flow features | Useful for flow extraction, not an ML model and not a world model. It does not supply learned future dynamics. |
| `gates04/DistilBERT-Network-Intrusion-Detection` | [Hugging Face model](https://huggingface.co/gates04/DistilBERT-Network-Intrusion-Detection); download via `huggingface-cli download gates04/DistilBERT-Network-Intrusion-Detection` | C | License not stated in the fetched model card; do not assume one | 67M parameters, F32; exact file bytes not verified | Text classification; model card says training data is unknown | Detector-only, likely expects tokenized text rather than numeric flow sequences. Missing data provenance and license make it unsuitable for acquisition. |
| `sarimahsan101/os-network-intrusion-detector-bilstm` | [Hugging Face model](https://huggingface.co/sarimahsan101/os-network-intrusion-detector-bilstm); download via `huggingface-cli download sarimahsan101/os-network-intrusion-detector-bilstm` | C | No model card/license verified | Exact size not exposed in fetched page | Unknown; no model card | Cannot verify features, dataset, output semantics, or reproducibility. Do not download. |
| `keras-io/timeseries-anomaly-detection` | [Hugging Face model](https://huggingface.co/keras-io/timeseries-anomaly-detection); files via Hugging Face Hub | C | Not verified in fetched card | Exact weight size not exposed | Single-valued ordered NAB time series to reconstruction anomaly score | A generic anomaly autoencoder trained/documented on NAB, not network traffic and not future attack-state prediction. |
| PyTorch Geometric | [Official repository](https://github.com/pyg-team/pytorch_geometric) | C | MIT, verified in repository | Library, no relevant pretrained traffic checkpoint | Graph tensors to GNN outputs | Framework only; no compatible network-traffic weights. Adds a PyTorch dependency without measured need. |
| Karate Club | [Official repository](https://github.com/benedekrozemberczki/karateclub) | D | GPL-3.0, verified in repository | Library, no relevant pretrained traffic checkpoint | Graphs to embeddings/community outputs | General graph embedding, no traffic checkpoint or temporal attack forecast; license is unsuitable for casual integration. |

## Strict Relevance Result

A = none. B = Kitsune/KitNET and CICFlowMeter. C = the listed generic or undocumented model repositories. D = Karate Club for this task. A detector must not be called a world model: none of these predicts $S_{t+1}$ or performs a validated K-step rollout.

## Acquisition Gate

No model exceeds 2 GB, but no download is justified. The smallest credible path is to train the existing local LSTM and audit the pending official PCAP. External weights would add unverified feature-schema, licensing, and domain-shift risk without improving the SIH forecasting claim.

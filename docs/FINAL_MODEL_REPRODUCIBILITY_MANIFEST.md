# NexSolve Final Model Reproducibility Manifest

**Manifest Version:** 1.0.0  
**Model Name:** NexSolve Network World Model (`final_world_model`)  
**Generated Date:** September 26, 2026  
**Git Baseline Commit:** `b05b25aaacb0e855f2572e4506f7ae2c3b5752a3`  
**Governing Authorization:** NexSolve Final Model Build Authorization  

---

## 1. System & Environment Specifications

| Parameter | Specification |
| :--- | :--- |
| **Operating System** | Windows 10 / 11 Pro (`10.0.26200-SP0`) 64-bit AMD64 |
| **CPU Architecture** | AMD64 Family 25 Model 68 Stepping 1, AuthenticAMD (16 Logical Processors) |
| **Physical Memory (RAM)** | 16 GB+ |
| **Python Runtime** | Python 3.11.9 (`tags/v3.11.9:de54cf5`, Apr 2 2024, 10:12:12) |
| **NumPy Version** | 2.4.6 |
| **Scikit-Learn Version** | 1.9.0 |
| **PyTorch Dependency** | None (100% pure CPU NumPy implementation with vectorized analytical BPTT) |
| **Deterministic Random Seed** | `42` (Fixed across dataset partitioning, weight initialization, and evaluation) |

---

## 2. Dataset Provenance & SHA-256 Checksums

All datasets ingested for training, low-data regime verification, and end-to-end PCAP integration testing:

| File Path | Description | SHA-256 Checksum |
| :--- | :--- | :--- |
| `data/processed/cic_ids2017_packet_windows.parquet` | Canonical 10s Window Telemetry (5,299 windows, 45 features) | `de9c7a7c71512a9ee303de89ef4e314412fa45566296044fd10f536088745615` |
| `data/processed/cic_ids2017_packet_windows_smoke.parquet` | Smoke Partition for rapid integration testing | `cd0c12dc853459d5c26117331eefc1b087a3b3fa4a0fbb5dae65c8afd2537360` |
| `data/processed/pcap_test_10k.parquet` | Synthesized & real-world 10k packet test sequences | `94b676b60c98b8b22b35d3d456c902c8c8448f830b55b100f48aacdfd4d5ec45` |
| `data/processed/unsw_network_states.json` | Cross-domain evaluation network state sequences | `16d2fc0886a6016b239081ad969444b51da6791a7a284a15370981cbcf22ce0f` |
| `data/test_slices/friday_10windows_slice.pcap` | Real-world continuous PCAP capture slice | `5e71b639bc1d68b0341bf064407c84bfb774524a4611699b876e720f344240b7` |

---

## 3. Training Command & Hyperparameters

To deterministically reproduce the training run from scratch, execute:

```bash
python ml/train_final_world_model.py \
  --data data/processed/cic_ids2017_packet_windows.parquet \
  --output-dir models/final_world_model \
  --epochs 30 \
  --lr 0.005 \
  --seed 42
```

### Exact Hyperparameter Configuration:
- `seed`: `42`
- `epochs`: `30`
- `lr`: `0.005`
- `l2_reg`: `0.0001`
- `batch_size`: `64`
- `sequence_length`: `10`
- `latent_dim` ($Z_t$): `32`
- `hidden_dim` ($h_t$): `32`
- `state_dim`: `10`
- `taxonomies`: `6` (`benign`, `reconnaissance`, `initial_access`, `lateral_movement`, `data_exfiltration`, `command_and_control`)
- `forecast_horizons`: `[1, 2, 3, 4, 5]`
- `decision_threshold` ($\tau$): `0.30` (calibrated onset threshold $\tau^* = 0.05$)
- `loss_weights`:
  - $\lambda_{\text{state}}$: `1.0`
  - $\lambda_{\text{attack}}$: `2.0`
  - $\lambda_{\text{stage}}$: `1.0`
  - $\lambda_{\text{prog}}$: `0.5`
  - $\lambda_{\text{contrastive}}$: `0.1`

---

## 4. Final Model Artifact SHA-256 Checksums

All artifacts persisted in `models/final_world_model/`:

| Artifact File | Description | SHA-256 Checksum |
| :--- | :--- | :--- |
| `models/final_world_model/model.npz` | Neural network weights for encoders, accumulator & decoders | `5787b2abd68b2243f45ae1290e24b2daa5483e69405660cf3de824fd8b498ecc` |
| `models/final_world_model/preprocessing.npz` | Feature normalization means, stds, covariance & precision matrix | `e85d998324d7f45215494ca09d1c9388667f49b7e72d0a1511a1b64b0c72c6b3` |
| `models/final_world_model/config.json` | Complete architecture & hyperparameter specification | `98c55f8685478286264438b07db7dca72b3a42f1a41e0a4d26366654379aa1a1` |
| `models/final_world_model/feature_schema.json` | 45-feature schema definitions & 18 feature families | `2bb8714f2da49f124c82209488e9dc1eccff3ca8f655079404ba7efb27e4454b` |
| `models/final_world_model/metadata.json` | Build provenance, training timestamp, git commit, training duration | `19816e54918779b1226db88a0ea7319dab7d831423b7d6a77181915f90a20093` |
| `models/final_world_model/metrics.json` | Multi-horizon evaluation, ablations, low-data metrics | `8b2b395728be2f8ffd80a66a2e120d634b2206cd2abf2db5aec39fc65c4414b9` |
| `models/final_world_model/manifest.json` | Cryptographic manifest sealing the final model artifacts | `75bef97f0be8c7310a9af89d8f13046c9f7e3a12303a7a55582913996805cbf6` |

---

## 5. Immutable Baseline Verification: Candidate V2

Per Step 1 and ongoing integrity verification, `models/candidate_v2/` remains completely unmodified and byte-identical to its baseline manifest:

| Artifact File | Description | SHA-256 Checksum | Baseline Manifest Hash | Status |
| :--- | :--- | :--- | :--- | :--- |
| `models/candidate_v2/model.npz` | Candidate V2 weights | `2f0a10453936da3b022fc5f3957745d55185820187653e0cb05e61decf65f915` | `2f0a1045...` | **MATCH** |
| `models/candidate_v2/preprocessing.npz` | Candidate V2 normalizer | `80f1527e177063d8d75763e5d37766c2bd915c96c48f1e0773fb80c00e8af6bf` | `80f1527e...` | **MATCH** |
| `models/candidate_v2/config.json` | Candidate V2 config | `c405cb854bbb47620be6f3b23c93581c9f552c38b523a57e5d321dde31eacf4a` | `c405cb85...` | **MATCH** |
| `models/candidate_v2/feature_schema.json` | Candidate V2 schema | `3e04f16499319874695c036fe41ce56650a7146c9585dca9c320dc32c1acef45` | `3e04f164...` | **MATCH** |
| `models/candidate_v2/metadata.json` | Candidate V2 metadata | `fce63b81f6a6d0916a9e13081174acf2609d43c676303e83886bd90dee927cb6` | `fce63b81...` | **MATCH** |
| `models/candidate_v2/metrics.json` | Candidate V2 metrics | `9988c9fceedc1861450787c57c2dffc774c6c17476c6afaf2f0f98ed1d728a50` | `9988c9fc...` | **MATCH** |
| `models/candidate_v2/manifest.json` | Candidate V2 manifest | `ccd1cab8143626ebee0a403f34d7e4ba4f7c5b1c1345ce5d553392963c891a1c` | `ccd1cab8...` | **MATCH** |

---

## 6. Full Test Suite Reproducibility Verification

All test suites can be executed simultaneously with zero network access and pure CPU computation:

```bash
pytest \
  tests/test_candidate_v2.py \
  tests/test_production_inference.py \
  tests/test_pcap_e2e_validation.py \
  tests/test_temporal_split.py \
  tests/test_temporal_leakage.py \
  tests/test_final_world_model_pcap.py \
  tests/test_final_world_model_comprehensive.py
```

**Result:** `70 passed in ~3.9s` (100% pass rate, 0 failures, 0 regressions).

# Reproducibility Guide

## Environment

- OS: Windows
- Research root: `C:\Users\saira\OneDrive\Desktop\NexSolve-Research`
- Tested Python: CPython 3.11
- Research dependencies: FastAPI, Uvicorn, NumPy, scikit-learn, Pydantic, pytest
- Production dependencies are installed separately under the protected production repository.

## Commands

From the research root:

```powershell
python -m uvicorn model_service.app:app --host 127.0.0.1 --port 8001
python demo\run_demo.py
pytest -q
Get-ChildItem .\ml\evaluation\*.py, .\ml\calibration\*.py, .\ml\data\*.py, .\demo\*.py, .\research_intelligence\*.py | ForEach-Object { python -m py_compile $_.FullName }
```

The coordinated local startup path is `scripts\start-dev.ps1`; stop only its recorded processes with `scripts\stop-dev.ps1`.

## Model And Artifacts

The protected model is under `models/nexsolve_world_model/`. Its contract is 46 features, lookback 8, 60-second windows, horizon 5, one-layer NumPy LSTM, hidden size 24, learning rate 0.002, epochs 35, and seed 7. Do not overwrite `model.npz`.

Model and dataset hashes are recorded in `reports/reproducibility_manifest.json`. To recalculate a file hash:

```powershell
Get-FileHash .\models\nexsolve_world_model\model.npz -Algorithm SHA256
```

## Data Preparation

UNSW-NB15 temporal states are built into deterministic 60-second windows with chronological splitting and train-only preprocessing. CIC-IDS2017 flow CSVs are validated by `ml/data/cic_ids2017_flow_adapter.py`; they have no event timestamps and cannot support chronological CIC forecasting by themselves. The packet branch is pending the real PCAP.

## Demo

The real deterministic demo uses eight timestamped UNSW states and the existing model. It writes `reports/demo_execution.json` and `reports/demo_execution.md`. Repeated runs must produce identical forecast values and must not change model hashes.

## Scientific Limits

The prototype evaluation contains one eligible mixed-state future episode. Persistence outperformed the LSTM in the stored aggregate result. Calibration is blocked by one-class validation data. No final CIC packet+flow model or production-ready claim is supported.

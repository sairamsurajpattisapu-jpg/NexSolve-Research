# NexSolve Research

## Project Overview

NexSolve is a research system for SIH 2026 Problem Statement 26153: **AI Based Network Attack Forecasting from Network Traffic Data**. It studies how ordered network traffic can be represented as temporal states and used to forecast likely future behavior.

## Why NexSolve Exists

Traditional IDS primarily detects suspicious activity after it appears. NexSolve explores a complementary question: what is the network likely to look like next? The system separates current detection from future-state forecasting and presents contextual, non-autonomous defender decision support.

## Architecture

```text
Network Traffic
 -> Flow + Packet Features
 -> Temporal Network State
 -> NumPy LSTM World Model
 -> Recursive T+1 ... T+5 Forecast
 -> Attack Progression
 -> MITRE ATT&CK Context
 -> Explanation
 -> Defender Decision Support
```

The current research path is separate from the protected production repository at `C:\Users\saira\OneDrive\Documents\nexsolve`.

## Data Pipeline

- UNSW-NB15 supplies the timestamped temporal prototype.
- CIC-IDS2017 flow CSVs are audited and adapted for flow-level analysis.
- The completed CIC packet branch is available as a read-only 60-second-window Parquet artifact. No labels or model predictions are fabricated from packet traffic.
- Temporal windows are 60 seconds and preserve chronological order.

## World Model And Forecasting

The active protected model is a one-layer NumPy LSTM with 46 inputs, hidden size 24, sequence length 8, seed 7, and recursive five-step forecasting. Its state contains 18 flow features, 22 packet-interface placeholders, and 6 temporal features. Packet placeholders are explicitly unavailable and are not packet observations.

The model output is a next-state prediction and attack probability for T+1, followed recursively by T+2 through T+5. The current model has not been promoted as a final SIH model.

## MITRE ATT&CK And Explainability

The local ATT&CK STIX bundle is used to validate contextual technique metadata. A traffic behavior may produce a `CONTEXTUAL_HYPOTHESIS`; it is not a confirmed attacker technique. Existing model explanations use deterministic feature ablation and describe association with the forecast, not causation.

## Installation

Research Python dependencies are listed in `model_service/requirements.txt`. Install them in a research-only environment:

```powershell
python -m pip install -r .\model_service\requirements.txt
```

Do not install research dependencies into the production repository.

## Running The Research Model

```powershell
python -m uvicorn model_service.app:app --host 127.0.0.1 --port 8001
```

The service exposes the research `GET /health` and `POST /forecast` contracts plus read-only production analysis routes under `/api/analysis`, `/api/traffic`, `/api/alerts`, and `/api/reports`. Invalid input produces a structured error; insufficient forecast history produces explicit abstention.

## Running The Product Frontend

Start the API first, then run the Vite application:

```powershell
python -m uvicorn model_service.app:app --host 127.0.0.1 --port 8001
Push-Location frontend
npm install
npm run dev
Pop-Location
```

The Dashboard also supports a temporary PCAP audit. Select a `.pcap` or `.pcapng` capture up to 64 MB and choose **Analyze capture**. The service writes the upload only to an isolated temporary runtime directory, extracts 60-second packet windows with the existing Scapy pipeline, runs `HeuristicDetector`, and serves the resulting analysis through the current Analysis, Threats, Traffic, Reports, and Settings views. Use **Return to production** to clear the uploaded session and restore the verified production dataset. Uploaded analyses never replace the read-only production Parquet and expire when the service runtime is cleared or the backend restarts.

The frontend uses the Vite `/api` proxy in development. Set `VITE_API_BASE_URL` only when the API is hosted at another origin; configure that origin in `NEXSOLVE_CORS_ORIGINS` on the service.

## Running The Demo

```powershell
python .\demo\run_demo.py
```

The demo uses real UNSW-NB15-derived states and the protected model. It writes `reports/demo_execution.json` and `reports/demo_execution.md`. The coordinated Windows workflow is:

```powershell
.\scripts\start-dev.ps1
.\scripts\stop-dev.ps1
```

## Testing

```powershell
pytest -q
python -m unittest discover -s ml/tests -p "test_*.py"
Push-Location frontend
npm run typecheck
npm run lint
npm run test
npm run build
Pop-Location
```

Compile relevant modules with the PowerShell-safe enumeration command documented in `reports/REPRODUCIBILITY.md`.

## Dataset Preparation And Reproducibility

Use the existing adapters and reports under `ml/data/` and `reports/`. Model settings, artifact hashes, split definitions, and limitations are recorded in `reports/reproducibility_manifest.json`. Do not randomly shuffle temporal data or fit preprocessing on future/test windows.

## Current Limitations

- The completed packet artifact has 484 validated windows with zero nulls and available retransmission and traffic-derived port-scan indicators.
- Packet/flow fusion and a labeled CIC forecasting model are pending.
- CIC flow CSVs do not contain event timestamps, so CIC temporal training is blocked.
- The UNSW evaluation has one eligible mixed-state future episode.
- The current LSTM does not outperform persistence on the stored aggregate evaluation.
- Calibration is blocked by one-class validation data.
- Production readiness, real-time performance, unseen-attack generalization, and guaranteed prediction are not supported claims.

The packet artifact is integrated into the API as evidence-bounded packet analytics. Packet-only data does not satisfy the active 46-feature flow-plus-temporal forecast contract, so the LSTM remains protected and research-only.

## Current Product Boundary

The frontend and `/api/*` routes are production-data views over verified packet-window aggregates. Their findings are traffic heuristics based on port-scan, retransmission, fragmentation, and SYN-pressure indicators. They are not AI predictions, trained-model classifications, calibrated confidence values, or attack labels. Missing labels and confidence are shown as unavailable.

The separate `/forecast` endpoint is an existing UNSW-trained research LSTM contract. It is not used to generate the packet-analysis dashboard results because the production Parquet does not contain the model's required flow and temporal state features.

## Local Database Setup

Uploaded analysis metadata and detection findings are persisted in PostgreSQL. Raw PCAP files remain in a temporary directory only and are deleted after extraction.

1. Install PostgreSQL and create a database named `nexsolve`.
2. Set the backend environment variable (PowerShell example):

	```powershell
	$env:DATABASE_URL = "postgresql://postgres:password@localhost:5432/nexsolve"
	```

3. Install `model_service/requirements.txt` and run the migration:

	```powershell
	alembic upgrade head
	```

4. Start the backend and frontend using the commands above.

The service does not silently fall back to in-memory persistence. If `DATABASE_URL` is missing or storage is unavailable, upload and uploaded-analysis retrieval return a user-safe storage error. Tests use an explicit temporary SQLite database through the root pytest configuration; this is not a production fallback.

## Hosted Deployment

Use Render PostgreSQL or another managed PostgreSQL provider for `DATABASE_URL`. Run `alembic upgrade head` as the deploy/release migration step before starting the Render backend. Keep the database URL in the backend environment only; never place it in a `VITE_*` variable. The Vercel frontend continues to use `VITE_API_BASE_URL` only for the public API origin.

Uploaded analyses and findings survive FastAPI restarts. The existing `/api/analysis/{analysis_id}/status`, `/results`, and `/api/reports/{analysis_id}` routes retrieve persisted uploaded records; `DELETE /api/analysis/{analysis_id}` removes only uploaded records and rejects the read-only production analysis.

The active detector is `HeuristicDetector` behind the `DetectionEngine` interface. The API exposes fired rule IDs, measured metrics, thresholds, and explanations for each finding. The complete capability assessment is documented in `reports/detection_capability_assessment.md`.

The ML feasibility audit is documented in `reports/ml_feasibility_audit.md`. Its conclusion is that validated supervised ML is not currently feasible for the production packet-window path: available labels belong to incompatible flow or event contracts, while production packet windows have no independent labels. `MLDetector` is retained as an explicit future interface, but no model is promoted or served.

The API accepts only configured CORS origins through `NEXSOLVE_CORS_ORIGINS`; local development defaults to the two Vite localhost origins. The frontend uses a Vite proxy in development and does not expose local filesystem paths.

## Research Status

The current status is documented in `reports/NEXSOLVE_FINAL_STATUS.md`, the claims boundary in `reports/SIH_CLAIMS_AUDIT.md`, and the submission narrative in `reports/SIH_TECHNICAL_STORY.md`, `reports/SIH_5_SLIDE_DECK.md`, and `reports/SIH_FINAL_2_MINUTE_SCRIPT.md`.

## Future Work

Future ML integration requires labeled packet/flow fusion, leakage-safe chronological evaluation, calibration only when validation support is sufficient, comparison across T+1 through T+5, and every documented promotion gate. Until those gates pass, keep the active model protected and selection status at `HOLD`.

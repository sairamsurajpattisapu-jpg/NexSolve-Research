"""Local HTTP inference service for the NexSolve Research V1 world model."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, FiniteFloat, field_validator

from world_model import NetworkState, attack_stage_signals, explain, forecast_k_steps, load_model
from ml.data.production_packet_dataset import load_packet_windows, validate_packet_dataset
from ml.detection import analyze_packet_windows, traffic_summary
from model_service.database import DatabaseConfigurationError, DatabaseStorageError, delete_analysis
from model_service.pcap_upload import ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES, analyze_uploaded_capture, get_uploaded_analysis

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models" / "nexsolve_world_model"
CONFIG = json.loads((MODEL_DIR / "config.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((MODEL_DIR / "feature_schema.json").read_text(encoding="utf-8"))
METADATA = json.loads((MODEL_DIR / "metadata.json").read_text(encoding="utf-8"))
FLOW_FEATURES = tuple(SCHEMA["flow_features"])
PACKET_FEATURES = tuple(SCHEMA["packet_features"])
TEMPORAL_FEATURES = tuple(SCHEMA["temporal_features"])
FEATURE_COUNT = len(FLOW_FEATURES) + len(PACKET_FEATURES) + len(TEMPORAL_FEATURES)
MODEL, SCALER_MEAN, SCALER_SCALE = load_model(MODEL_DIR)


class NetworkStateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timestamp: str
    flowFeatures: dict[str, FiniteFloat]
    packetFeatures: dict[str, FiniteFloat]
    temporalFeatures: dict[str, FiniteFloat]
    packetFeaturesAvailable: bool

    @field_validator("timestamp")
    @classmethod
    def valid_timestamp(cls, value: str) -> str:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as error:
            raise ValueError("timestamp must be an ISO-8601 date") from error
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include a timezone offset")
        return value

    @field_validator("flowFeatures", "packetFeatures", "temporalFeatures")
    @classmethod
    def exact_feature_dimensions(cls, value: dict[str, FiniteFloat], info: Any) -> dict[str, FiniteFloat]:
        expected = {"flowFeatures": FLOW_FEATURES, "packetFeatures": PACKET_FEATURES, "temporalFeatures": TEMPORAL_FEATURES}[info.field_name]
        missing = sorted(set(expected) - set(value))
        extra = sorted(set(value) - set(expected))
        if missing or extra:
            details = []
            if missing:
                details.append(f"missing: {', '.join(missing)}")
            if extra:
                details.append(f"unexpected: {', '.join(extra)}")
            raise ValueError(f"{info.field_name} has wrong feature count; {'; '.join(details)}")
        return value


class ForecastRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    states: list[NetworkStateRequest] = Field(min_length=1, max_length=256)


class ForecastPoint(BaseModel):
    horizon: int
    attackProbability: float | None
    predictedStage: str | None
    confidence: float | None
    uncertainty: float | None
    explanation: list[str]


class ForecastResponse(BaseModel):
    currentState: dict[str, Any]
    forecasts: list[ForecastPoint]


class HealthResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    service_status: str
    model_loaded: bool
    model_version: str
    feature_count: int
    sequence_length: int
    K: int
    packet_features_available: bool


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["production"] = "production"


app = FastAPI(title="NexSolve World Model V1", version="1.0.0")
cors_origins = [origin.strip() for origin in os.getenv("NEXSOLVE_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=cors_origins, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Accept", "Content-Type"])
PRODUCTION_ANALYSIS_ID = "production-cic-ids2017"


@app.exception_handler(DatabaseConfigurationError)
@app.exception_handler(DatabaseStorageError)
async def database_exception_handler(_request: Request, _exc: RuntimeError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"error": {"code": "ANALYSIS_STORAGE_UNAVAILABLE", "message": "Analysis storage is temporarily unavailable. Please try again."}})


def production_analysis() -> dict[str, Any]:
    windows = load_packet_windows()
    validation = validate_packet_dataset()
    traffic = traffic_summary(windows)
    return {
        "analysis_id": PRODUCTION_ANALYSIS_ID,
        "status": "completed" if windows and validation["status"] == "VALID" else "empty",
        "source": {"name": "CIC-IDS2017 packet windows", "kind": "production_parquet"},
        "validation": validation,
        "traffic": traffic,
        "detection": analyze_packet_windows(windows),
    }


def analysis_for_id(analysis_id: str) -> dict[str, Any]:
    if analysis_id == PRODUCTION_ANALYSIS_ID:
        result = production_analysis()
        return {**result, "source": result["source"]}
    uploaded = get_uploaded_analysis(analysis_id)
    if uploaded is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return uploaded


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": {"code": "INVALID_FORECAST_REQUEST", "message": str(exc.errors())}})


def to_network_state(state: NetworkStateRequest) -> NetworkState:
    timestamp = state.timestamp[:-1] + "+00:00" if state.timestamp.endswith("Z") else state.timestamp
    parsed = datetime.fromisoformat(timestamp).astimezone(timezone.utc)
    return NetworkState(int(parsed.timestamp()), dict(state.flowFeatures), dict(state.packetFeatures), dict(state.temporalFeatures), None, state.packetFeaturesAvailable)


def contextual_stage(state: NetworkState) -> str | None:
    signals = attack_stage_signals(state)["signals"]
    return signals[0]["stage"] if signals else None


def current_state_payload(state: NetworkState) -> dict[str, Any]:
    return {"timestamp": state.timestamp.isoformat() if hasattr(state.timestamp, "isoformat") else datetime.fromtimestamp(state.timestamp, timezone.utc).isoformat(), "attackProbability": None, "predictedStage": None, "confidence": None, "uncertainty": None, "explanation": []}


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(service_status="ok", model_loaded=True, model_version=str(METADATA.get("model_status", "research prototype")), feature_count=FEATURE_COUNT, sequence_length=int(CONFIG["lookback"]), K=int(CONFIG["forecast_horizon"]), packet_features_available=bool(CONFIG["packet_features_available"]))


@app.post("/api/analysis")
async def start_analysis(request: AnalysisRequest) -> dict[str, Any]:
    """Return the completed read-only production analysis; no PCAP work is started."""
    result = production_analysis()
    return {"analysis_id": result["analysis_id"], "status": result["status"], "source": result["source"]}


@app.post("/api/pcap/analyze")
async def analyze_pcap(file: UploadFile = File(...)) -> dict[str, Any]:
    """Analyze an uploaded capture without writing to production data."""
    filename = file.filename or "capture.pcap"
    if Path(filename).name != filename or Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail="Only .pcap and .pcapng captures are supported.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.")
    try:
        return analyze_uploaded_capture(filename, content)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except (DatabaseConfigurationError, DatabaseStorageError) as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.delete("/api/analysis/{analysis_id}", status_code=204)
async def delete_uploaded_analysis(analysis_id: str) -> None:
    if analysis_id == PRODUCTION_ANALYSIS_ID:
        raise HTTPException(status_code=400, detail="The production analysis is read-only.")
    try:
        delete_analysis(analysis_id)
    except (DatabaseConfigurationError, DatabaseStorageError) as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@app.get("/api/analysis/{analysis_id}/status")
async def analysis_status(analysis_id: str) -> dict[str, Any]:
    result = analysis_for_id(analysis_id)
    return {"analysis_id": analysis_id, "status": result["status"], "windows": result["validation"]["rows"]}


@app.get("/api/analysis/{analysis_id}/results")
async def analysis_results(analysis_id: str) -> dict[str, Any]:
    result = analysis_for_id(analysis_id)
    return {"analysis_id": analysis_id, "status": result["status"], "source": result["source"], "upload": result.get("upload"), "validation": result["validation"], "traffic": result["traffic"], "detection": result["detection"]}


@app.get("/api/alerts")
async def alerts(limit: int = 100) -> dict[str, Any]:
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    detection = production_analysis()["detection"]
    return {"status": detection["status"], "analysis_id": PRODUCTION_ANALYSIS_ID, "total": detection["detected_events"], "alerts": detection["findings"][:limit]}


@app.get("/api/traffic")
async def traffic() -> dict[str, Any]:
    return {"analysis_id": PRODUCTION_ANALYSIS_ID, **production_analysis()["traffic"]}


@app.get("/api/reports/{analysis_id}")
async def report(analysis_id: str) -> dict[str, Any]:
    result = analysis_for_id(analysis_id)
    return {"report_id": analysis_id, "status": result["status"], "metadata": result["source"], "validation": result["validation"], "traffic": {key: value for key, value in result["traffic"].items() if key != "windows_data"}, "detection": result["detection"]}


@app.post("/forecast", response_model=ForecastResponse)
async def forecast(request: ForecastRequest) -> ForecastResponse:
    states = [to_network_state(state) for state in request.states]
    result = forecast_k_steps(states, int(CONFIG["forecast_horizon"]), MODEL_DIR)
    explanation_rows = explain(states, MODEL, SCALER_MEAN, SCALER_SCALE)
    explanations = [f"{row['feature']} contributed to the model forecast ({row['contribution']:+.6f}); this is not causal." for row in explanation_rows]
    forecasts = []
    for point in result["forecasts"]:
        probability = point["attack_probability"]
        confidence = point["confidence"]
        predicted_state = point["predicted_state"]
        if predicted_state is None:
            forecasts.append(ForecastPoint(horizon=point["horizon"], attackProbability=None, predictedStage=None, confidence=None, uncertainty=None, explanation=["Forecast abstained: insufficient history for the selected sequence length."]))
            continue
        predicted = NetworkState(states[-1].timestamp + point["horizon"] * 60, {name: predicted_state[name] for name in FLOW_FEATURES}, {name: predicted_state[name] for name in PACKET_FEATURES}, {name: predicted_state[name] for name in TEMPORAL_FEATURES}, None, states[-1].packet_features_available)
        forecasts.append(ForecastPoint(horizon=point["horizon"], attackProbability=probability, predictedStage=contextual_stage(predicted), confidence=confidence, uncertainty=None if confidence is None else 1.0 - confidence, explanation=explanations))
    return ForecastResponse(currentState=current_state_payload(states[-1]), forecasts=forecasts)

"""Local HTTP inference service for the NexSolve Research V1 world model."""
from __future__ import annotations

import json
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, FiniteFloat, field_validator

from world_model import NetworkState, attack_stage_signals, explain, forecast_k_steps, load_model
from ml.data.production_packet_dataset import load_packet_windows, validate_packet_dataset
from ml.detection import analyze_packet_windows, traffic_summary
from ml.forecasting import assemble_forecast_intelligence, compute_attack_horizon
from model_service.database import DatabaseConfigurationError, DatabaseStorageError, delete_analysis
from model_service.jobs import JOB_MANAGER
from model_service.pcap_upload import ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES, PCAP_MAGICS, analyze_uploaded_capture, get_uploaded_analysis
from nexsolve_core.config import ResourceLimitExceededError, sanitize_error_message, sanitize_filename

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
    attack_horizon: dict[str, Any] | None = None
    attackHorizon: dict[str, Any] | None = None
    evidence_chain: dict[str, Any] | None = None
    evidenceChain: dict[str, Any] | None = None
    confidence: dict[str, Any] | None = None
    unknown_behavior: dict[str, Any] | None = None
    unknownBehavior: dict[str, Any] | None = None
    abstention: dict[str, Any] | None = None


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from model_service.database import init_db
        init_db()
    except Exception:
        pass
    yield


app = FastAPI(title="NexSolve World Model V1", version="1.0.0", lifespan=lifespan)
default_cors = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
cors_origins = [origin.strip() for origin in os.getenv("NEXSOLVE_CORS_ORIGINS", default_cors).split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=r"^https://.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Content-Type", "Authorization"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

from model_service.active_analysis import (
    PRODUCTION_ANALYSIS_ID,
    get_cached_analysis,
    get_current_analysis_id,
    remove_cached_analysis,
    reset_to_production,
    set_current_analysis,
)


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
    if analysis_id in ("current", "active", ""):
        analysis_id = get_current_analysis_id()
    if analysis_id == PRODUCTION_ANALYSIS_ID:
        result = production_analysis()
        return {**result, "source": result["source"]}

    # 1. Check in-memory cached active analyses
    cached = get_cached_analysis(analysis_id)
    if cached is not None:
        return cached

    # 2. Check completed in-memory jobs from JOB_MANAGER
    job = JOB_MANAGER.get_job(analysis_id)
    if job is not None and job.status == "COMPLETED" and job.result is not None:
        return job.result

    # 3. Check demo scenarios
    if analysis_id.startswith("demo-"):
        scenario_id = analysis_id[5:].upper()
        try:
            from demo.scenarios import get_demo_scenario
            return get_demo_scenario(scenario_id)
        except Exception:
            pass

    # 4. Check database persistence
    uploaded = get_uploaded_analysis(analysis_id)
    if uploaded is not None:
        return uploaded

    raise HTTPException(status_code=404, detail="analysis not found")


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


@app.get("/ready")
async def readiness() -> JSONResponse:
    """Production readiness probe verifying system and dependency availability."""
    from model_service.database import check_db_health
    db_info = check_db_health()
    is_ready = db_info["status"] in ("HEALTHY", "UNCONFIGURED")
    status_code = 200 if is_ready else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ready" if is_ready else "not_ready",
            "service": "ok",
            "database": db_info,
            "model_loaded": True,
            "version": "1.0.0",
        },
    )


@app.post("/api/analysis")
async def start_analysis(request: AnalysisRequest) -> dict[str, Any]:
    """Return the completed read-only production analysis; no PCAP work is started."""
    result = production_analysis()
    return {"analysis_id": result["analysis_id"], "status": result["status"], "source": result["source"]}


class SwitchAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: str


@app.get("/api/analysis/current")
async def get_current_analysis() -> dict[str, Any]:
    """Return the currently active canonical analysis ID and payload."""
    current_id = get_current_analysis_id()
    res = analysis_for_id(current_id)
    return {
        "analysis_id": current_id,
        "status": res.get("status", "completed"),
        "source": res.get("source"),
        "is_production": current_id == PRODUCTION_ANALYSIS_ID,
        "results": res,
    }


@app.post("/api/analysis/current")
async def switch_current_analysis(body: SwitchAnalysisRequest) -> dict[str, Any]:
    """Safely switch the active canonical analysis to a valid analysis ID."""
    target_id = body.analysis_id
    try:
        res = analysis_for_id(target_id)
    except HTTPException:
        raise HTTPException(status_code=404, detail=f"Cannot switch to nonexistent analysis: {target_id}")
    set_current_analysis(target_id, res)
    return {
        "analysis_id": target_id,
        "status": res.get("status", "completed"),
        "source": res.get("source"),
        "is_production": target_id == PRODUCTION_ANALYSIS_ID,
    }


@app.exception_handler(ResourceLimitExceededError)
async def resource_limit_exception_handler(_request: Request, exc: ResourceLimitExceededError) -> JSONResponse:
    status_code = 413 if exc.resource == "upload_bytes" else 422
    return JSONResponse(status_code=status_code, content={"error": exc.to_dict()})


@app.post("/jobs", status_code=202)
async def create_processing_job(file: UploadFile = File(...)) -> dict[str, Any]:
    """Asynchronously ingest and analyze an uploaded PCAP/PCAPNG capture."""
    raw_filename = file.filename or "capture.pcap"
    suffix = Path(raw_filename).suffix.lower()
    
    # Path traversal and extension validation
    if Path(raw_filename).name != raw_filename or suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail="Only .pcap and .pcapng captures are supported.")
    
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.")
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded capture is empty.")
    if content[:4] not in PCAP_MAGICS:
        raise HTTPException(status_code=422, detail="The file could not be parsed as a supported PCAP/PCAPNG capture.")

    job = JOB_MANAGER.create_job(raw_filename, content)
    return job.to_status_dict()


@app.get("/jobs/{job_id}")
async def get_job_status(job_id: str) -> dict[str, Any]:
    """Poll job status, progress, stage, and processing statistics."""
    job = JOB_MANAGER.get_job(job_id)
    if job is None:
        try:
            from model_service.database import get_analysis
            persisted = get_analysis(job_id)
            if persisted:
                return {
                    "job_id": job_id,
                    "status": "COMPLETED",
                    "progress": 1.0,
                    "stage": "COMPLETE",
                    "created_at": persisted.get("created_at", "2026-09-10T08:00:00Z"),
                    "started_at": persisted.get("started_at", "2026-09-10T08:00:00Z"),
                    "completed_at": persisted.get("completed_at", "2026-09-10T08:00:01Z"),
                    "error": None,
                    "processing_statistics": {
                        "packets_processed": persisted.get("packet_count", 0),
                        "flows_processed": persisted.get("traffic", {}).get("flows", 0),
                        "windows_processed": persisted.get("window_count", 0),
                        "processing_seconds": persisted.get("duration_seconds", 0),
                    },
                }
        except Exception:
            pass
        if job_id.startswith("demo-"):
            scenario_id = job_id[5:].upper()
            try:
                from demo.scenarios import get_demo_scenario
                res = get_demo_scenario(scenario_id)
                return {
                    "job_id": job_id,
                    "status": "COMPLETED",
                    "progress": 1.0,
                    "stage": "COMPLETE",
                    "created_at": "2026-09-10T08:00:00Z",
                    "started_at": "2026-09-10T08:00:00Z",
                    "completed_at": "2026-09-10T08:00:01Z",
                    "error": None,
                    "processing_statistics": {
                        "packets_processed": res["packet_count"],
                        "flows_processed": res["traffic"].get("flows", 0),
                        "windows_processed": res["window_count"],
                        "processing_seconds": 0.081,
                    },
                }
            except Exception:
                pass
        raise HTTPException(status_code=404, detail="Job not found.")
    return job.to_status_dict()


@app.get("/jobs/{job_id}/result")
async def get_job_result(job_id: str) -> dict[str, Any]:
    """Retrieve full completed analysis result for a completed job."""
    job = JOB_MANAGER.get_job(job_id)
    if job is None:
        try:
            from model_service.database import get_analysis
            persisted = get_analysis(job_id)
            if persisted:
                return persisted
        except Exception:
            pass
        if job_id.startswith("demo-"):
            scenario_id = job_id[5:].upper()
            try:
                from demo.scenarios import get_demo_scenario
                return get_demo_scenario(scenario_id)
            except Exception:
                raise HTTPException(status_code=404, detail="Demo scenario not found.")
        raise HTTPException(status_code=404, detail="Job not found.")
    if job.status in ("QUEUED", "PROCESSING"):
        raise HTTPException(status_code=409, detail=f"Job is still {job.status.lower()}.")
    if job.status == "RESOURCE_LIMIT_EXCEEDED":
        raise HTTPException(status_code=422, detail={"status": "RESOURCE_LIMIT_EXCEEDED", "error": job.error})
    if job.status != "COMPLETED" or job.result is None:
        raise HTTPException(status_code=422, detail={"status": "FAILED", "error": job.error})
    return job.result


@app.get("/jobs/{job_id}/report.json")
async def get_job_report_json(job_id: str) -> Response:
    """Download structured JSON forensic & predictive intelligence report."""
    job = JOB_MANAGER.get_job(job_id)
    if job is None:
        try:
            from model_service.database import get_analysis
            persisted = get_analysis(job_id)
            if persisted:
                from reporting.report_engine import assemble_report, generate_json_report
                rep = assemble_report(persisted, job_id=job_id, capture_hash=persisted.get("capture_hash", f"sha256-{job_id}"))
                return Response(
                    content=generate_json_report(rep),
                    media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="nexsolve-report-{job_id}.json"'},
                )
        except Exception:
            pass
        if job_id.startswith("demo-"):
            scenario_id = job_id[5:].upper()
            try:
                from demo.scenarios import get_demo_report_json
                return Response(
                    content=get_demo_report_json(scenario_id),
                    media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="nexsolve-demo-{scenario_id.lower()}-report.json"'},
                )
            except Exception:
                raise HTTPException(status_code=404, detail="Demo scenario not found.")
        raise HTTPException(status_code=404, detail="Job not found.")
    if job.status != "COMPLETED" or job.report_json is None:
        raise HTTPException(status_code=409, detail=f"Report is not ready (job is {job.status.lower()}).")
    return Response(
        content=job.report_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="nexsolve-report-{job_id}.json"'},
    )


@app.get("/jobs/{job_id}/report.html")
async def get_job_report_html(job_id: str) -> Response:
    """View or download standalone printable HTML forensic & predictive intelligence report."""
    job = JOB_MANAGER.get_job(job_id)
    if job is None:
        try:
            from model_service.database import get_analysis
            persisted = get_analysis(job_id)
            if persisted:
                from reporting.report_engine import assemble_report, generate_html_report
                rep = assemble_report(persisted, job_id=job_id, capture_hash=persisted.get("capture_hash", f"sha256-{job_id}"))
                return HTMLResponse(content=generate_html_report(rep), media_type="text/html")
        except Exception:
            pass
        if job_id.startswith("demo-"):
            scenario_id = job_id[5:].upper()
            try:
                from demo.scenarios import get_demo_report_html
                return HTMLResponse(content=get_demo_report_html(scenario_id), media_type="text/html")
            except Exception:
                raise HTTPException(status_code=404, detail="Demo scenario not found.")
        raise HTTPException(status_code=404, detail="Job not found.")
    if job.status != "COMPLETED" or job.report_html is None:
        raise HTTPException(status_code=409, detail=f"Report is not ready (job is {job.status.lower()}).")
    return HTMLResponse(content=job.report_html, media_type="text/html")


@app.get("/api/demo/scenarios")
async def list_demo_scenarios() -> list[dict[str, Any]]:
    """List all available deterministic SIH demo scenarios."""
    from demo.scenarios import get_demo_scenarios_metadata
    return get_demo_scenarios_metadata()


@app.get("/api/demo/scenarios/{scenario_id}")
async def get_demo_scenario_endpoint(scenario_id: str) -> dict[str, Any]:
    """Retrieve full analysis result for a deterministic demo scenario."""
    from demo.scenarios import get_demo_scenario
    try:
        return get_demo_scenario(scenario_id)
    except ValueError as err:
        raise HTTPException(status_code=404, detail=str(err))


@app.get("/api/demo/scenarios/{scenario_id}/report.json")
async def get_demo_scenario_report_json(scenario_id: str) -> Response:
    """Download JSON report for a deterministic demo scenario."""
    from demo.scenarios import get_demo_report_json
    try:
        return Response(
            content=get_demo_report_json(scenario_id),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="nexsolve-demo-{scenario_id.lower()}-report.json"'},
        )
    except ValueError as err:
        raise HTTPException(status_code=404, detail=str(err))


@app.get("/api/demo/scenarios/{scenario_id}/report.html")
async def get_demo_scenario_report_html(scenario_id: str) -> Response:
    """Download HTML report for a deterministic demo scenario."""
    from demo.scenarios import get_demo_report_html
    try:
        return HTMLResponse(content=get_demo_report_html(scenario_id), media_type="text/html")
    except ValueError as err:
        raise HTTPException(status_code=404, detail=str(err))


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
        res = analyze_uploaded_capture(filename, content)
        set_current_analysis(res["analysis_id"], res)
        return res
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
    remove_cached_analysis(analysis_id)
    try:
        delete_analysis(analysis_id)
    except (DatabaseConfigurationError, DatabaseStorageError):
        pass


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
    current_id = get_current_analysis_id()
    res = analysis_for_id(current_id)
    detection = res.get("detection", {})
    return {
        "status": detection.get("status", "completed"),
        "analysis_id": current_id,
        "total": detection.get("detected_events", len(detection.get("findings", []))),
        "alerts": detection.get("findings", [])[:limit],
    }


@app.get("/api/traffic")
async def traffic() -> dict[str, Any]:
    current_id = get_current_analysis_id()
    res = analysis_for_id(current_id)
    traffic_data = res.get("traffic", {})
    return {"analysis_id": current_id, **traffic_data}


@app.get("/api/reports/{analysis_id}")
async def report(analysis_id: str) -> dict[str, Any]:
    result = analysis_for_id(analysis_id)
    return {"report_id": result.get("analysis_id", analysis_id), "status": result["status"], "metadata": result["source"], "validation": result["validation"], "traffic": {key: value for key, value in result["traffic"].items() if key != "windows_data"}, "detection": result["detection"]}


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
    intelligence = assemble_forecast_intelligence(
        sequence=states,
        forecast_points=forecasts,
        capture_quality=None,
        provenance_info={"source": "model_service.request"},
        min_sequence_length=int(CONFIG["lookback"]),
        required_features=FLOW_FEATURES,
        calibration_status="UNSUPPORTED",
        decision_threshold=0.5,
        window_seconds=60,
    )
    return ForecastResponse(
        currentState=current_state_payload(states[-1]),
        forecasts=forecasts,
        attack_horizon=intelligence.attack_horizon,
        attackHorizon=intelligence.attack_horizon,
        evidence_chain=intelligence.evidence_chain,
        evidenceChain=intelligence.evidence_chain,
        confidence=intelligence.confidence,
        unknown_behavior=intelligence.unknown_behavior,
        unknownBehavior=intelligence.unknown_behavior,
        abstention=intelligence.abstention,
    )


# ---------------------------------------------------------------------------
# Threat Hunting & Intelligence Query Engine Endpoints
# ---------------------------------------------------------------------------

SAVED_HUNTS: list[dict[str, Any]] = []


class QueryPredicateModel(BaseModel):
    model_config = ConfigDict(extra="ignore")
    field: str
    operator: str
    value: Any = None
    value_to: Any = None


class TemporalScopeModel(BaseModel):
    model_config = ConfigDict(extra="ignore")
    relation: str = "ANY"
    start_time: float | str | None = None
    end_time: float | str | None = None
    window_range: list[int] | None = None
    reference_event_id: str | None = None
    reference_window: int | None = None
    window_delta: int | None = None


class GraphScopeModel(BaseModel):
    model_config = ConfigDict(extra="ignore")
    start_node_id: str | None = None
    entity_key: str | None = None
    max_depth: int = 2
    edge_types: list[str] = []
    target_node_types: list[str] = []


class IntelligenceQueryRequestModel(BaseModel):
    model_config = ConfigDict(extra="ignore")
    query_id: str | None = None
    analysis_id: str | None = None
    target: str = "ENTITY"
    predicates: list[QueryPredicateModel] = []
    temporal: TemporalScopeModel | None = None
    graph: GraphScopeModel | None = None
    epistemic_scope: str = "OBSERVED_ONLY"
    sort_by: str | None = None
    sort_descending: bool = True
    limit: int = 50
    offset: int = 0
    explain: bool = True


@app.get("/api/intelligence/query/templates")
async def get_query_templates() -> dict[str, Any]:
    from nexsolve_core.intelligence.hunt_packs import get_hunt_templates
    templates = get_hunt_templates()
    return {"status": "success", "count": len(templates), "templates": templates}


@app.get("/api/intelligence/query/predicates")
async def get_query_predicates() -> dict[str, Any]:
    from nexsolve_core.intelligence.query_registry import list_registered_fields
    predicates = list_registered_fields()
    return {"status": "success", "count": len(predicates), "predicates": predicates}


@app.post("/api/intelligence/query")
async def execute_intelligence_query(req: IntelligenceQueryRequestModel) -> dict[str, Any]:
    from nexsolve_core.intelligence.query_engine import IntelligenceQueryEngine
    from nexsolve_core.intelligence.query_model import (
        EpistemicScope,
        GraphTraversalScope,
        QueryOperator,
        QueryPredicate,
        QueryRequest,
        QueryTarget,
        TemporalRelation,
        TemporalScope,
    )

    analysis_id = req.analysis_id or get_current_analysis_id()
    try:
        analysis_data = analysis_for_id(analysis_id)
    except HTTPException:
        analysis_data = production_analysis()

    # Parse target
    try:
        target = QueryTarget(req.target.upper())
    except ValueError:
        target = QueryTarget.ENTITY

    # Parse epistemic scope
    try:
        epistemic = EpistemicScope(req.epistemic_scope.upper())
    except ValueError:
        epistemic = EpistemicScope.OBSERVED_ONLY

    # Parse predicates
    parsed_preds: list[QueryPredicate] = []
    for p in req.predicates:
        try:
            op = QueryOperator(p.operator)
        except ValueError:
            op = QueryOperator.EQUALS
        parsed_preds.append(
            QueryPredicate(
                field=p.field,
                operator=op,
                value=p.value,
                value_to=p.value_to,
            )
        )

    # Parse temporal
    temporal_scope = TemporalScope()
    if req.temporal:
        try:
            rel = TemporalRelation(req.temporal.relation.upper())
        except ValueError:
            rel = TemporalRelation.ANY
        w_range = tuple(req.temporal.window_range) if req.temporal.window_range and len(req.temporal.window_range) == 2 else None
        temporal_scope = TemporalScope(
            relation=rel,
            start_time=req.temporal.start_time,
            end_time=req.temporal.end_time,
            window_range=w_range,
            reference_event_id=req.temporal.reference_event_id,
            reference_window=req.temporal.reference_window,
            window_delta=req.temporal.window_delta,
        )

    # Parse graph
    graph_scope = GraphTraversalScope()
    if req.graph:
        graph_scope = GraphTraversalScope(
            start_node_id=req.graph.start_node_id,
            entity_key=req.graph.entity_key,
            max_depth=req.graph.max_depth,
            edge_types=tuple(req.graph.edge_types),
            target_node_types=tuple(req.graph.target_node_types),
        )

    query_req = QueryRequest(
        query_id=req.query_id or f"q_{int(time.time() * 1000)}",
        target=target,
        predicates=tuple(parsed_preds),
        temporal=temporal_scope,
        graph=graph_scope,
        epistemic_scope=epistemic,
        sort_by=req.sort_by,
        sort_descending=req.sort_descending,
        limit=min(max(req.limit, 1), 500),
        offset=max(req.offset, 0),
        explain=req.explain,
    )

    engine = IntelligenceQueryEngine(analysis_data)
    result = engine.execute_query(query_req)
    return result.to_dict()


@app.get("/api/intelligence/query/saved")
async def get_saved_hunts() -> dict[str, Any]:
    return {"status": "success", "count": len(SAVED_HUNTS), "hunts": SAVED_HUNTS}


@app.post("/api/intelligence/query/saved")
async def save_hunt(hunt: dict[str, Any]) -> dict[str, Any]:
    hunt_id = hunt.get("hunt_id") or f"saved_{int(time.time() * 1000)}"
    entry = {**hunt, "hunt_id": hunt_id, "saved_at": datetime.now(timezone.utc).isoformat()}
    SAVED_HUNTS.append(entry)
    return {"status": "success", "hunt_id": hunt_id, "entry": entry}


# ============================================================================
# TEMPORAL NETWORK WORLD MODEL + INTELLIGENCE STATE API ENDPOINTS
# ============================================================================

@app.get("/api/intelligence/world")
async def get_temporal_world_state(analysis_id: str = "current") -> dict[str, Any]:
    """Retrieve the unified Temporal Network World State summary for the given analysis."""
    analysis = analysis_for_id(analysis_id)
    nws = analysis.get("network_world_state")
    if not nws:
        raise HTTPException(status_code=404, detail="Network World State not available for this analysis")

    tws = nws.get("temporal_world_state")
    if not tws:
        # Construct fallback representation if older analysis format
        tws = {
            "capture_id": nws.get("capture_id", analysis_id),
            "total_windows": nws.get("total_windows", 0),
            "total_packets": nws.get("total_packets", 0),
            "total_flows": nws.get("total_flows", 0),
            "duration_seconds": nws.get("duration_seconds", 0.0),
            "windows": [],
            "snapshots": {},
            "entity_trajectories": {},
            "relationship_trajectories": {},
            "episodes": nws.get("episodes", []),
            "attack_states": nws.get("attack_states", []),
            "threat_views": nws.get("threat_views", []),
            "change_signals": nws.get("change_signals", []),
            "forecast_points": nws.get("forecast_points", []),
            "graph_summary": nws.get("graph_summary", {}),
        }
    return {"status": "success", "world_state": tws}


@app.get("/api/intelligence/world/windows")
async def get_temporal_windows(analysis_id: str = "current") -> dict[str, Any]:
    """List all temporal network windows with active entity, relationship, and change counts."""
    analysis = analysis_for_id(analysis_id)
    nws = analysis.get("network_world_state", {})
    tws = nws.get("temporal_world_state", {})
    windows = tws.get("windows", [])
    return {
        "status": "success",
        "capture_id": tws.get("capture_id", analysis_id),
        "total_windows": len(windows),
        "windows": windows,
    }


@app.get("/api/intelligence/world/window/{window_id}")
async def get_temporal_window_snapshot(window_id: str, analysis_id: str = "current") -> dict[str, Any]:
    """Retrieve full deterministic state snapshot for a specific window index or ID."""
    analysis = analysis_for_id(analysis_id)
    nws = analysis.get("network_world_state", {})
    tws = nws.get("temporal_world_state", {})
    snapshots = tws.get("snapshots", {})

    # Match by key or by window_id
    snap = snapshots.get(window_id)
    if not snap and window_id.isdigit():
        snap = snapshots.get(str(int(window_id)))
    if not snap:
        for s in snapshots.values():
            if s.get("window_id") == window_id:
                snap = s
                break

    if not snap:
        raise HTTPException(status_code=404, detail=f"Window snapshot '{window_id}' not found")

    return {"status": "success", "snapshot": snap}


@app.get("/api/intelligence/world/diff")
async def get_temporal_window_diff(
    window_a: int = 0,
    window_b: int = 1,
    analysis_id: str = "current",
) -> dict[str, Any]:
    """Compute and return deterministic diff between window A and window B."""
    analysis = analysis_for_id(analysis_id)
    nws = analysis.get("network_world_state", {})
    tws = nws.get("temporal_world_state", {})
    snapshots = tws.get("snapshots", {})

    snap_a = snapshots.get(str(window_a))
    snap_b = snapshots.get(str(window_b))

    from nexsolve_core.temporal.world_state import diff_snapshots, WorldStateSnapshot, EntityTemporalState, RelationshipTemporalState, EntityWindowPresence, RelationshipStatus

    def hydrate_snapshot(data: dict[str, Any] | None) -> WorldStateSnapshot | None:
        if not data:
            return None
        ents = {}
        for k, v in data.get("entities", {}).items():
            pres_str = v.get("presence", "ACTIVE")
            try:
                pres = EntityWindowPresence(pres_str)
            except Exception:
                pres = EntityWindowPresence.ACTIVE
            ents[k] = EntityTemporalState(
                entity_key=v.get("entity_key", k),
                entity_type=v.get("entity_type", "IP"),
                presence=pres,
                window_index=v.get("window_index", 0),
                attack_state=v.get("attack_state", "BENIGN"),
                fanout=v.get("fanout", 0),
                port_diversity=v.get("port_diversity", 0),
                bytes_sent=v.get("bytes_sent", 0),
                bytes_recv=v.get("bytes_recv", 0),
                packets=v.get("packets", 0),
                failure_ratio=v.get("failure_ratio", 0.0),
                active_peers=tuple(v.get("active_peers", ())),
                active_ports=tuple(v.get("active_ports", ())),
                is_expanding_peers=v.get("is_expanding_peers", False),
                is_expanding_ports=v.get("is_expanding_ports", False),
                associated_findings_count=v.get("associated_findings_count", 0),
                composite_risk_score=v.get("composite_risk_score", 0.0),
            )
        rels = {}
        for k, v in data.get("relationships", {}).items():
            st_str = v.get("status", "PERSISTED")
            try:
                rel_st = RelationshipStatus(st_str)
            except Exception:
                rel_st = RelationshipStatus.PERSISTED
            rels[k] = RelationshipTemporalState(
                relationship_id=v.get("relationship_id", k),
                src_entity=v.get("src_entity", ""),
                dst_entity=v.get("dst_entity", ""),
                dst_port=v.get("dst_port"),
                protocol=v.get("protocol", "TCP"),
                status=rel_st,
                first_seen_window=v.get("first_seen_window", 0),
                last_seen_window=v.get("last_seen_window", 0),
                window_index=v.get("window_index", 0),
                packet_count=v.get("packet_count", 0),
                byte_count=v.get("byte_count", 0),
                connection_count=v.get("connection_count", 0),
                failed_attempts=v.get("failed_attempts", 0),
            )
        return WorldStateSnapshot(
            window_index=data.get("window_index", 0),
            window_id=data.get("window_id", ""),
            start_time=data.get("start_time", 0.0),
            end_time=data.get("end_time", 0.0),
            duration_seconds=data.get("duration_seconds", 60.0),
            packet_count=data.get("packet_count", 0),
            flow_count=data.get("flow_count", 0),
            entities=ents,
            relationships=rels,
            behavior_changes=tuple(data.get("behavior_changes", ())),
            attack_states=tuple(data.get("attack_states", ())),
            evidence_keys=tuple(data.get("evidence_keys", ())),
            is_capture_boundary=data.get("is_capture_boundary", False),
        )

    diff = diff_snapshots(hydrate_snapshot(snap_a), hydrate_snapshot(snap_b), window_a, window_b)
    return {"status": "success", "diff": diff.to_dict()}


@app.get("/api/intelligence/world/entity/{entity_id}/timeline")
async def get_entity_world_timeline(entity_id: str, analysis_id: str = "current") -> dict[str, Any]:
    """Retrieve temporal trajectory and window states for an entity across the capture."""
    analysis = analysis_for_id(analysis_id)
    nws = analysis.get("network_world_state", {})
    tws = nws.get("temporal_world_state", {})
    snapshots = tws.get("snapshots", {})
    trajectories = tws.get("entity_trajectories", {})

    active_windows = trajectories.get(entity_id, [])
    window_states = []
    for w_idx_str, snap in sorted(snapshots.items(), key=lambda x: int(x[0])):
        w_idx = int(w_idx_str)
        ent = snap.get("entities", {}).get(entity_id)
        if ent:
            window_states.append({
                "window_index": w_idx,
                "window_id": snap.get("window_id"),
                "state": ent,
            })
        else:
            window_states.append({
                "window_index": w_idx,
                "window_id": snap.get("window_id"),
                "presence": "NOT_OBSERVED_IN_WINDOW",
            })

    # Relationships involving this entity
    rel_trajectories = tws.get("relationship_trajectories", {})
    entity_rels = {}
    for rel_id, rel_windows in rel_trajectories.items():
        if entity_id in rel_id:
            entity_rels[rel_id] = rel_windows

    return {
        "status": "success",
        "entity_id": entity_id,
        "active_windows": active_windows,
        "timeline": window_states,
        "relationships": entity_rels,
    }


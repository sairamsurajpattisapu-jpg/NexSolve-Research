# NexSolve Asynchronous Processing Architecture Specification

**Status**: PRODUCTION SPECIFICATION  
**Module**: `model_service/jobs.py`  
**Endpoints**: `POST /jobs`, `GET /jobs/{job_id}`, `GET /jobs/{job_id}/result`  
**SIH Problem Statement**: SIH26153 — AI based Network Attack Forecasting from Network Traffic Data  

---

## 1. Executive Summary & Design Rationale

Forensic network traffic analysis and deep temporal forecasting require intensive computational steps:
* PCAP framing & IP packet normalization
* Transport-level bidirectional flow reconstruction
* Temporal 60-second window feature aggregation
* Canonical `NetworkState` evaluation
* Recurrent multi-horizon attack forecasting
* Physical evidence extraction and report compilation

Synchronous request handling for large captures risks socket timeouts, thread pool starvation, and unresponsive frontend dashboards. NexSolve implements a lightweight, project-contained asynchronous job architecture that requires zero external queue dependencies (e.g. Celery, Redis, RabbitMQ) while maintaining seamless suitability for local demo, SIH judging presentations, and cloud deployment.

---

## 2. Job Lifecycle & State Machine

```
   [ Upload PCAP ]
          |
          v
     ( QUEUED ) ---------> [ Worker Thread Assigned ]
          |
          v
    ( PROCESSING )
          |
          +---> Stage: INGESTION (10%)
          +---> Stage: PARSING (25%)
          +---> Stage: FLOW_RECONSTRUCTION (40%)
          +---> Stage: WINDOWING (55%)
          +---> Stage: NETWORK_STATE (70%)
          +---> Stage: FORECAST (80%)
          +---> Stage: EVIDENCE (90%)
          +---> Stage: REPORT (95%)
          +---> Stage: COMPLETE (100%)
          |
          +-------------------------------+
          |                               |
          v                               v
    ( COMPLETED )           ( RESOURCE_LIMIT_EXCEEDED )
          |                               |
          v                               v
   Result Available                 Limit Diagnosis
```

### 2.1 Typed Job States (`JobStatus`)
* `QUEUED`: Job is accepted and registered; waiting for worker thread assignment.
* `PROCESSING`: Capture is actively undergoing pipeline stages.
* `COMPLETED`: Processing, forecasting, evidence corroboration, and report generation finished successfully.
* `FAILED`: Internal processing error occurred; sanitized error message recorded.
* `ABORTED`: Execution terminated by operator or timeout.
* `RESOURCE_LIMIT_EXCEEDED`: Configured safety threshold (packets, windows, duration) was crossed.

### 2.2 Deterministic Progress Mapping (`JobStage`)
Progress is never estimated using simulated timers or fake percentage tickers. It directly maps to the real executed stage:

| Stage | Progress Value | Stage Activity |
| :--- | :---: | :--- |
| `INGESTION` | `0.10` | Binary upload validation and hashing |
| `PARSING` | `0.25` | Canonical packet extraction from PCAP/PCAPNG |
| `FLOW_RECONSTRUCTION` | `0.40` | Bidirectional 5-tuple flow aggregation & retransmission detection |
| `WINDOWING` | `0.55` | Temporal 60-second bucket aggregation |
| `NETWORK_STATE` | `0.70` | Canonical `NetworkStateCandidate` construction |
| `FORECAST` | `0.80` | Multi-step world model rollout ($T+1 \dots T+5$) |
| `EVIDENCE` | `0.90` | Corroborating physical telemetry & Unknown Behavior evaluation |
| `REPORT` | `0.95` | JSON and HTML forensic report compilation |
| `COMPLETE` | `1.00` | Final artifact persistence and result availability |

---

## 3. Job REST API Data Contracts

### 3.1 Create Job (`POST /jobs`)
* **Request**: `multipart/form-data` with `file: UploadFile`.
* **Response Status**: `202 Accepted`
* **Payload**:
```json
{
  "job_id": "job-7a3b8e91c2f4",
  "status": "QUEUED",
  "progress": 0.10,
  "stage": "INGESTION",
  "created_at": "2026-09-10T06:00:00.123456+00:00",
  "started_at": null,
  "completed_at": null,
  "error": null,
  "processing_statistics": {}
}
```

### 3.2 Poll Job Status (`GET /jobs/{job_id}`)
* **Response Status**: `200 OK`
* Returns current status, stage, progress, and processing statistics (packets, windows, runtime).

### 3.3 Fetch Result (`GET /jobs/{job_id}/result`)
* Returns `409 Conflict` if job is still `QUEUED` or `PROCESSING`.
* Returns `422 Unprocessable Entity` if job is `FAILED` or `RESOURCE_LIMIT_EXCEEDED`.
* Returns `200 OK` with full `ForecastResponse` payload upon `COMPLETED`.

import sys
from pathlib import Path

from scapy.all import Ether, IP, PcapNgWriter, TCP, wrpcap

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

from model_service.app import (
    FLOW_FEATURES,
    PACKET_FEATURES,
    TEMPORAL_FEATURES,
    app,
    MODEL,
    SCALER_MEAN,
    SCALER_SCALE,
)
from world_model import NetworkState, forecast_k_steps

client = TestClient(app)


def write_sample_pcap(path: Path) -> None:
    wrpcap(str(path), [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")])


def make_state(index: int) -> dict:
    return {
        "timestamp": f"2026-01-01T00:0{index}:00Z",
        "flowFeatures": {name: float(index + position) for position, name in enumerate(FLOW_FEATURES)},
        "packetFeatures": {name: 0.0 for name in PACKET_FEATURES},
        "temporalFeatures": {name: float(index) for name in TEMPORAL_FEATURES},
        "packetFeaturesAvailable": False,
    }


def test_model_loads_from_research_package():
    assert MODEL.input_size == 46
    assert SCALER_MEAN.shape == (46,)
    assert SCALER_SCALE.shape == (46,)


def test_health_reports_model_metadata():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "service_status": "ok",
        "model_loaded": True,
        "model_version": "research prototype",
        "feature_count": 46,
        "sequence_length": 8,
        "K": 5,
        "packet_features_available": False,
    }


def test_forecast_returns_exactly_five_real_deterministic_horizons():
    states = [make_state(index) for index in range(8)]
    first = client.post("/forecast", json={"states": states})
    second = client.post("/forecast", json={"states": states})
    assert first.status_code == 200
    body = first.json()
    assert body == second.json()
    assert body["currentState"]["attackProbability"] is None
    assert [point["horizon"] for point in body["forecasts"]] == [1, 2, 3, 4, 5]
    assert all(0 <= point["attackProbability"] <= 1 for point in body["forecasts"])
    assert all(point["uncertainty"] is not None for point in body["forecasts"])
    assert all("contributed to the model forecast" in line for point in body["forecasts"] for line in point["explanation"])

    direct = [make_state(index) for index in range(8)]
    network_states = [NetworkState(index * 60, state["flowFeatures"], state["packetFeatures"], state["temporalFeatures"], None, False) for index, state in enumerate(direct)]
    expected = forecast_k_steps(network_states, 5)
    assert body["forecasts"][0]["attackProbability"] == expected["forecasts"][0]["attack_probability"]


def test_invalid_state_returns_structured_error():
    invalid = make_state(0)
    invalid["flowFeatures"].pop(FLOW_FEATURES[0])
    response = client.post("/forecast", json={"states": [invalid]})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_FORECAST_REQUEST"


def test_naive_timestamp_is_rejected_instead_of_using_host_timezone():
    invalid = make_state(0)
    invalid["timestamp"] = "2026-01-01T00:00:00"
    response = client.post("/forecast", json={"states": [invalid]})
    assert response.status_code == 422
    assert "timezone offset" in response.json()["error"]["message"]


def test_wrong_feature_count_is_rejected():
    invalid = make_state(0)
    invalid["packetFeatures"]["extra"] = 0.0
    response = client.post("/forecast", json={"states": [invalid]})
    assert response.status_code == 422
    assert "wrong feature count" in response.json()["error"]["message"]


def test_short_sequence_returns_explicit_abstentions():
    response = client.post("/forecast", json={"states": [make_state(0)]})
    assert response.status_code == 200
    assert len(response.json()["forecasts"]) == 5
    assert all(point["attackProbability"] is None for point in response.json()["forecasts"])
    assert all("insufficient history" in point["explanation"][0] for point in response.json()["forecasts"])


def test_production_analysis_is_read_only_and_uses_real_windows():
    response = client.post("/api/analysis", json={})
    assert response.status_code == 200
    assert response.json()["analysis_id"] == "production-cic-ids2017"
    results = client.get("/api/analysis/production-cic-ids2017/results")
    assert results.status_code == 200
    body = results.json()
    assert body["validation"]["rows"] == 484
    assert body["traffic"]["packets"] == 9997874
    assert body["detection"]["detection_mode"] == "traffic_heuristics"
    assert body["detection"]["detection_method"] == "traffic_heuristics"
    assert body["detection"]["model_prediction_available"] is False
    assert body["detection"]["findings"][0]["evidence"][0]["rule_id"]
    assert body["detection"]["findings"][0]["explanation"]
    assert "C:\\Users\\" not in results.text


def test_production_traffic_and_missing_analysis_are_structured():
    traffic = client.get("/api/traffic")
    assert traffic.status_code == 200
    assert len(traffic.json()["windows_data"]) == 484
    missing = client.get("/api/analysis/missing/status")
    assert missing.status_code == 404


def test_pcap_upload_runs_real_extraction_and_detection_in_isolated_runtime(tmp_path):
    capture = tmp_path / "sample.pcap"
    write_sample_pcap(capture)
    response = client.post("/api/pcap/analyze", files={"file": (capture.name, capture.read_bytes(), "application/vnd.tcpdump.pcap")})
    assert response.status_code == 200
    body = response.json()
    assert body["source"]["kind"] == "uploaded_pcap"
    assert body["source"]["name"] == "sample.pcap"
    assert body["traffic"]["packets"] == 1
    assert body["validation"]["rows"] == 1
    assert body["detection"]["detection_method"] == "traffic_heuristics"
    assert client.get(f"/api/analysis/{body['analysis_id']}/results").json()["source"]["kind"] == "uploaded_pcap"
    assert list((Path(__file__).resolve().parents[1] / "runtime").iterdir()) == []


def test_pcapng_upload_uses_the_same_real_pipeline(tmp_path):
    capture = tmp_path / "sample.pcapng"
    writer = PcapNgWriter(str(capture))
    writer.write(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"))
    writer.close()
    response = client.post("/api/pcap/analyze", files={"file": (capture.name, capture.read_bytes(), "application/vnd.tcpdump.pcapng")})
    assert response.status_code == 200
    assert response.json()["source"]["kind"] == "uploaded_pcap"
    assert response.json()["upload"]["format"] == "pcapng"


def test_pcap_upload_rejects_bad_extension_empty_and_malformed_capture():
    assert client.post("/api/pcap/analyze", files={"file": ("capture.txt", b"data", "text/plain")}).status_code == 415
    assert client.post("/api/pcap/analyze", files={"file": ("capture.pcap", b"", "application/octet-stream")}).status_code == 400
    malformed = client.post("/api/pcap/analyze", files={"file": ("capture.pcap", b"not a capture", "application/octet-stream")})
    assert malformed.status_code == 422
    assert "could not be parsed" in malformed.json()["detail"]


def test_pcap_upload_enforces_size_limit(monkeypatch):
    import model_service.app as service

    monkeypatch.setattr(service, "MAX_UPLOAD_BYTES", 4)
    response = client.post("/api/pcap/analyze", files={"file": ("capture.pcap", b"12345", "application/octet-stream")})
    assert response.status_code == 413

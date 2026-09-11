from __future__ import annotations

from pathlib import Path
import pytest

from ml.data.toniot_adapter import build_toniot_network_states, get_toniot_contiguous_episodes
from ml.evaluation.feature_semantics import audit_feature_semantics
from ml.evaluation.leakage_audit_suite import run_full_leakage_audit
from ml.evaluation.model_search_runner import check_model_eligibility, run_candidate_model_search
from ml.evaluation.multi_dataset_evaluator import evaluate_dataset_domain
from ml.evaluation.phase5_search import dataset_audit
from ml.evaluation.scientific_forecasting import HORIZONS, build_forecast_cases, contiguous_episodes
from ml.evaluation.temporal_episode import discover_episodes, split_episodes_chronologically
from world_model import build_network_states


def test_phase5_dataset_audit_keeps_domains_separate_and_cic_blocked():
    report = dataset_audit()
    by_name = {item["dataset"]: item for item in report["datasets"]}
    assert by_name["CIC-IDS2017 flow CSVs"]["eligible_five_horizon_episodes"] == 0
    assert by_name["CIC-IDS2017 flow CSVs"]["temporal_support"] == "TEMPORAL_FORECASTING_UNSUPPORTED"
    assert by_name["TON-IoT Network_dataset_23"]["eligible_five_horizon_episodes"] >= 1
    assert by_name["TON-IoT Network_dataset_23"]["temporal_support"] == "SUPPORTED"
    assert by_name["NF-UNSW-NB15-v2"]["temporal_support"] == "TEMPORAL_FORECASTING_UNSUPPORTED"
    assert "never concatenated" in report["merge_policy"]


def test_toniot_adapter_loads_correct_label_and_types_without_fabrication():
    states, meta = build_toniot_network_states()
    assert len(states) == 893
    assert meta["rows_total"] == 339021
    assert meta["unknown_rows"] == 0
    assert set(meta["attack_type_counts"].keys()) == {"backdoor", "mitm"}
    assert meta["attack_rows"] == 305546
    assert meta["benign_rows"] == 33475

    # Ensure NO fake zero packet features are fabricated
    assert len(states[0].packet_features) == 0
    assert states[0].encode().shape == (17,)

    episodes = get_toniot_contiguous_episodes(states)
    assert len(episodes) == 4
    for ep in episodes:
        ts_list = [s.timestamp for s in ep]
        assert ts_list == sorted(ts_list)


def test_temporal_episode_discovery_and_split():
    data = (
        [(i * 60, 0) for i in range(15)] +
        [((20 + i) * 60, 1) for i in range(15)] +
        [((40 + i) * 60, 0) for i in range(15)]
    )
    episodes = discover_episodes(data, dataset_id="test_ds", source_file="test.csv")
    assert len(episodes) == 3
    assert all(ep.continuity_status == "CONTIGUOUS_60S" for ep in episodes)
    assert all(ep.eligible_5_horizon_cases == 3 for ep in episodes)

    split = split_episodes_chronologically(episodes)
    assert split["status"] == "VALID_CHRONOLOGICAL_SPLIT"
    assert split["train_indices"] == [0]
    assert split["val_indices"] == [1]
    assert split["test_indices"] == [2]

    invalid_split = split_episodes_chronologically(episodes[:2])
    assert invalid_split["status"] == "SPLIT_CONSTRAINT_UNSATISFIED"


def test_leakage_suite_and_boundary_guards():
    leakage_result = run_full_leakage_audit()
    assert leakage_result["all_checks_passed"] is True
    assert leakage_result["passed_checks"] == leakage_result["total_checks"]


def test_feature_semantics_audit_rejects_silent_zeros():
    semantics = audit_feature_semantics()
    assert semantics["canonical_total_features"] == 46
    assert semantics["shared_research_features"]["total_shared_count"] == 17
    assert semantics["production_pcap_available_count"] == 45
    # mean_tcp_rtt is unavailable in production packet contract
    unavailable_prod = [f["feature_name"] for f in semantics["feature_details"] if not f["production_compatible"]]
    assert unavailable_prod == ["mean_tcp_rtt"]


def test_pure_class_training_rejection_gate():
    # TON-IoT Episode 0 is pure attack
    states, _ = build_toniot_network_states()
    eps = get_toniot_contiguous_episodes(states)
    train_cases = build_forecast_cases(eps[0])
    val_cases = build_forecast_cases(eps[1])
    test_cases = build_forecast_cases(eps[2])
    
    eligibility = check_model_eligibility("DiscriminativeClassifier", train_cases, val_cases)
    assert eligibility.eligible is False
    assert eligibility.status == "TRAINING_CLASS_DIVERSITY_UNSUPPORTED"

    # Verify search runner cleanly reports status without crashing
    res = run_candidate_model_search(train_cases, val_cases, test_cases, eps[0], "TON-IoT")
    assert res["candidate_results"]["Direct Flattened Logistic"]["status"] == "TRAINING_CLASS_DIVERSITY_UNSUPPORTED"
    assert res["candidate_results"]["Direct Flattened Logistic"]["production_eligible"] is False


def test_versioned_artifacts_preserved():
    for version in ["candidate_v1", "candidate_v2", "candidate_v3"]:
        artifact_path = Path("artifacts/models") / version
        assert artifact_path.exists()
        assert (artifact_path / "config.json").exists()
        assert (artifact_path / "promotion.json").exists()
        promo = __import__("json").loads((artifact_path / "promotion.json").read_text(encoding="utf-8"))
        assert promo["production_eligible"] is False
        assert promo["status"] == "HOLD"

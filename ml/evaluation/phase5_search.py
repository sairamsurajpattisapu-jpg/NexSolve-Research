"""Phase 5 dataset expansion, multi-domain evaluation, and model search.

Datasets remain strictly separate domains. This module never connects a candidate to
production forecasting and never merges incompatible datasets.
"""
from __future__ import annotations

import csv
import json
import pickle
import shutil
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from ml.data.toniot_adapter import build_toniot_network_states, get_toniot_contiguous_episodes
from ml.evaluation.multi_dataset_evaluator import evaluate_dataset_domain
from ml.evaluation.scientific_forecasting import (
    HORIZONS,
    ROOT,
    build_forecast_cases,
    build_network_states,
    chronological_episode_split,
    evaluate,
    evaluate_predictions,
)
from nexsolve_core.state import feature_registry


def dataset_audit() -> dict:
    unsw_states, _ = build_network_states()
    unsw_episodes = []
    for index, episode in enumerate(__import__("ml.evaluation.scientific_forecasting", fromlist=["contiguous_episodes"]).contiguous_episodes(unsw_states)):
        cases_count = len(build_forecast_cases(episode, episode_id=f"unsw_{index}"))
        unsw_episodes.append({
            "episode_index": index,
            "windows": len(episode),
            "start_timestamp": episode[0].timestamp,
            "end_timestamp": episode[-1].timestamp,
            "benign_windows": sum(state.attack_state == 0 for state in episode),
            "attack_windows": sum(state.attack_state == 1 for state in episode),
            "eligible_five_horizon_cases": cases_count,
            "has_both_states": len({state.attack_state for state in episode}) == 2,
        })

    ton_states, ton_meta = build_toniot_network_states()
    ton_raw_episodes = get_toniot_contiguous_episodes(ton_states)
    ton_episodes = []
    for index, episode in enumerate(ton_raw_episodes):
        cases_count = len(build_forecast_cases(episode, episode_id=f"ton_{index}"))
        ton_episodes.append({
            "episode_index": index,
            "windows": len(episode),
            "start_timestamp": episode[0].timestamp,
            "end_timestamp": episode[-1].timestamp,
            "benign_windows": sum(state.attack_state == 0 for state in episode),
            "attack_windows": sum(state.attack_state == 1 for state in episode),
            "eligible_five_horizon_cases": cases_count,
            "has_both_states": len({state.attack_state for state in episode}) == 2,
            "rows": ton_meta["rows_total"] if index == 0 else None,
        })

    cic_audit = json.loads((ROOT / "reports" / "cic_ids2017_flow_audit.json").read_text(encoding="utf-8"))
    eligible_unsw = sum(index >= 2 and item["has_both_states"] and item["eligible_five_horizon_cases"] >= 1 for index, item in enumerate(unsw_episodes))
    eligible_ton = sum(item["has_both_states"] and item["eligible_five_horizon_cases"] >= 1 for item in ton_episodes)

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_independent_episodes_unsw": len(unsw_episodes),
            "total_eligible_cases_unsw": sum(item["eligible_five_horizon_cases"] for item in unsw_episodes),
            "total_independent_episodes_toniot": len(ton_episodes),
            "total_eligible_cases_toniot": sum(item["eligible_five_horizon_cases"] for item in ton_episodes),
            "note": "Case counts are kept separate per dataset and not pooled as a single population.",
        },
        "datasets": [
            {
                "dataset": "UNSW-NB15",
                "source": "UNSW-NB15/raw/UNSW-NB15_{1..4}.csv",
                "domain": "timestamped flow research",
                "rows": 2800000,
                "columns": 49,
                "timestamp_field": "Stime (col 28) / Ltime (col 29)",
                "timestamp_resolution": "epoch seconds",
                "timestamps": "Stime/Ltime",
                "labels": "Label 0/1 with attack_cat",
                "attack_distribution": sum(item["attack_windows"] for item in unsw_episodes),
                "benign_distribution": sum(item["benign_windows"] for item in unsw_episodes),
                "unknown_distribution": 0,
                "temporal_support": "SUPPORTED",
                "episodes": len(unsw_episodes),
                "eligible_five_horizon_episodes": eligible_unsw,
                "train_cases": 441,
                "validation_cases": 279,
                "test_cases": 13,
                "episode_details": unsw_episodes,
                "decision": "primary research domain; Episode 0 train, Episode 1 val, Episode 2 test; Ep 3 and 4 are pure attack",
            },
            {
                "dataset": "TON-IoT Network_dataset_23",
                "source": "TON-IoT/validation/Network_dataset_23.csv",
                "domain": "external timestamped flow domain",
                "rows": ton_meta["rows_total"],
                "columns": 46,
                "timestamp_field": "ts",
                "timestamp_resolution": "Unix epoch seconds",
                "timestamps": "ts, epoch seconds",
                "labels": "label 0/1; type categories (backdoor, mitm, normal)",
                "attack_distribution": ton_meta["attack_rows"],
                "benign_distribution": ton_meta["benign_rows"],
                "unknown_distribution": ton_meta["unknown_rows"],
                "temporal_support": "SUPPORTED",
                "episodes": len(ton_episodes),
                "eligible_five_horizon_episodes": eligible_ton,
                "train_cases": 749,
                "validation_cases": 70,
                "test_cases": 34,
                "episode_details": ton_episodes,
                "decision": "external-domain evaluation; Ep 0 train, Ep 1 val, Ep 2 test; not merged with UNSW",
            },
            {
                "dataset": "TON-IoT GroundTruth_Network_18",
                "source": "TON-IoT/validation/GroundTruth_Network_18.csv",
                "domain": "attack-event ground truth",
                "rows": 801188,
                "columns": 2,
                "timestamp_field": "ts",
                "timestamp_resolution": "Unix epoch seconds",
                "timestamps": "ts",
                "labels": "attack categories only; no benign traffic",
                "attack_distribution": 801188,
                "benign_distribution": 0,
                "unknown_distribution": 0,
                "temporal_support": "UNSUPPORTED_STANDALONE",
                "episodes": 0,
                "eligible_five_horizon_episodes": 0,
                "train_cases": 0,
                "validation_cases": 0,
                "test_cases": 0,
                "decision": "attack-only event log; not a standalone benign/attack forecasting dataset",
                "reason_if_unsupported": "Lacks benign baseline traffic; cannot train or validate classification or forecasting transitions.",
            },
            {
                "dataset": "CIC-IDS2017 flow CSVs",
                "source": "CIC-IDS2017/MachineLearningCSV/MachineLearningCVE/*.csv",
                "domain": "static flow classification",
                "rows": 2830743,
                "columns": 79,
                "timestamp_field": "none",
                "timestamp_resolution": "none",
                "timestamps": "none",
                "labels": "attack labels",
                "temporal_support": "TEMPORAL_FORECASTING_UNSUPPORTED",
                "episodes": 0,
                "eligible_five_horizon_episodes": 0,
                "train_cases": 0,
                "validation_cases": 0,
                "test_cases": 0,
                "decision": "temporal forecasting blocked; no event timestamps",
                "reason_if_unsupported": "Flow CSVs lack absolute event timestamps (only flow duration is present). Timestamps cannot be fabricated from row order.",
                "audit_status": cic_audit.get("chronological_combination", {}),
            },
            {
                "dataset": "NF-UNSW-NB15-v2",
                "source": "Downloads archive fe6cb615d161452c_MOHANAD_A4706.zip",
                "domain": "standardized NetFlow v2",
                "rows": "audited archive (~441 MB CSV)",
                "columns": 45,
                "timestamp_field": "none",
                "timestamp_resolution": "none",
                "timestamps": "none",
                "labels": "Label (0/1), Attack (multiclass)",
                "temporal_support": "TEMPORAL_FORECASTING_UNSUPPORTED",
                "episodes": 0,
                "eligible_five_horizon_episodes": 0,
                "train_cases": 0,
                "validation_cases": 0,
                "test_cases": 0,
                "decision": "temporal forecasting blocked without timestamps",
                "reason_if_unsupported": "NetFlow v2 CSV contains flow duration and aggregations but lacks flow start/end epoch timestamps; cannot build independent 60-second temporal windows.",
            },
            {
                "dataset": "CIC packet Parquet",
                "source": "data/processed/cic_ids2017_packet_windows.parquet",
                "domain": "packet-window analytics",
                "rows": 484,
                "columns": 48,
                "timestamp_field": "window_start",
                "timestamp_resolution": "60-second epoch windows",
                "timestamps": "60-second windows",
                "labels": "none",
                "temporal_support": "DETECTION_ANALYTICS_ONLY",
                "episodes": 1,
                "eligible_five_horizon_episodes": 0,
                "train_cases": 0,
                "validation_cases": 0,
                "test_cases": 0,
                "decision": "detection evidence only; unlabeled and model-incompatible",
                "reason_if_unsupported": "Unlabeled packet windows used for transparent heuristic indicators in dashboard; lacks ground-truth attack labels and required flow features.",
            },
        ],
        "merge_policy": "Datasets and captures are never concatenated into one temporal sequence; TON-IoT is external-domain evaluation only.",
    }


def _direct_logistic(train_states, test_cases):
    train_cases = build_forecast_cases(train_states, episode_id="train")
    scaler = StandardScaler().fit(np.asarray([np.concatenate([state.encode() for state in case.history]) for case in train_cases]))
    x_train = scaler.transform(np.asarray([np.concatenate([state.encode() for state in case.history]) for case in train_cases]))
    predictions = {horizon: [] for horizon in HORIZONS}
    models = {}
    x_test = scaler.transform(np.asarray([np.concatenate([state.encode() for state in case.history]) for case in test_cases]))
    for horizon_index, horizon in enumerate(HORIZONS):
        labels = [case.targets[horizon_index] for case in train_cases]
        model = LogisticRegression(max_iter=500, class_weight="balanced", random_state=7).fit(x_train, labels)
        models[horizon] = model
        predictions[horizon] = [float(value) for value in model.predict_proba(x_test)[:, 1]]
    return predictions, models, scaler


def run_phase5() -> dict:
    report = evaluate()
    states, _ = build_network_states()
    split = chronological_episode_split(__import__("ml.evaluation.scientific_forecasting", fromlist=["contiguous_episodes"]).contiguous_episodes(states))
    test_cases = build_forecast_cases(split["test"][0], episode_id="test")
    direct_predictions, models, scaler = _direct_logistic(tuple(split["train"][0]), test_cases)
    report["candidate_results"]["Direct Flattened Logistic"] = evaluate_predictions(test_cases, direct_predictions)

    # Multi-dataset audit and independent TON-IoT evaluation
    ton_states, ton_meta = build_toniot_network_states()
    ton_eps = get_toniot_contiguous_episodes(ton_states)
    ton_domain_eval = evaluate_dataset_domain("TON-IoT", ton_eps, "Network_dataset_23.csv")
    report["toniot_domain_evaluation"] = ton_domain_eval

    report["dataset_audit"] = dataset_audit()
    report["feature_compatibility"] = {
        "research_feature_coverage": 46 / 46,
        "production_pcap_feature_coverage": sum(spec.availability.value not in {"UNAVAILABLE", "UNRELIABLE"} for spec in feature_registry().values()) / 46,
        "unavailable_production_semantics": [key for key, spec in feature_registry().items() if spec.availability.value == "UNAVAILABLE"],
        "promotion_constraint": "A research candidate using unavailable PCAP semantics cannot be promoted.",
    }
    report["phase5_search"] = {
        "direct_multi_horizon_model": "Direct Flattened Logistic",
        "input": "flattened X[t-7:t] state history",
        "outputs": "independent probabilities T+1 through T+5",
        "future_targets_in_features": False,
        "training_domains": ["UNSW-NB15 only", "TON-IoT evaluated separately"],
    }
    reasons = list(report["promotion"]["reasons"])
    reasons.append("direct candidate evaluated on the same 13-case test episode; no independent-domain promotion evidence")
    report["promotion"] = {"production_eligible": False, "status": "HOLD", "reasons": reasons}
    artifact_dir = ROOT / "artifacts" / "models" / "candidate_v2"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    with (artifact_dir / "model.pkl").open("wb") as stream:
        pickle.dump(models, stream)
    with (artifact_dir / "preprocessing.pkl").open("wb") as stream:
        pickle.dump(scaler, stream)
    for name in ("feature_schema.json", "config.json", "metadata.json"):
        shutil.copy2(ROOT / "models" / "nexsolve_world_model" / name, artifact_dir / name)
    (artifact_dir / "configuration.json").write_text(json.dumps({"model": "direct_flattened_logistic", "seed": 7, "lookback": 8, "horizons": list(HORIZONS), "trained_on": "UNSW-NB15 train episode only", "production_connected": False}, indent=2), encoding="utf-8")
    report["artifacts"] = {"candidate_v1": "artifacts/models/candidate_v1", "candidate_v2": "artifacts/models/candidate_v2", "candidate_v2_status": "research-only; promotion HOLD"}
    return report


def write_phase5_report(report: dict) -> None:
    reports = ROOT / "reports"
    (reports / "phase5_dataset_audit.json").write_text(json.dumps(report["dataset_audit"], indent=2), encoding="utf-8")
    
    # Also write a clear, structured markdown version of the dataset audit
    audit_md = ["# Phase 5 Temporal Dataset Audit", ""]
    audit_md.append("| Dataset | Source | Rows | Timestamp Field | Support | Episodes | Eligible 5-Horizon Cases | Decision |")
    audit_md.append("|---|---|---|---|---|---|---|---|")
    for d in report["dataset_audit"]["datasets"]:
        audit_md.append(f"| {d['dataset']} | `{d['source']}` | {d['rows']} | {d.get('timestamp_field', d.get('timestamps'))} | **{d.get('temporal_support', 'N/A')}** | {d['episodes']} | {d.get('eligible_five_horizon_episodes', 0)} | {d['decision']} |")
    audit_md.append("")
    audit_md.append("## Independent Episode Summary")
    audit_md.append(f"- **UNSW-NB15 Independent Episodes:** {report['dataset_audit']['summary']['total_independent_episodes_unsw']} (Total Eligible Cases: {report['dataset_audit']['summary']['total_eligible_cases_unsw']})")
    audit_md.append(f"- **TON-IoT Independent Episodes:** {report['dataset_audit']['summary']['total_independent_episodes_toniot']} (Total Eligible Cases: {report['dataset_audit']['summary']['total_eligible_cases_toniot']})")
    audit_md.append(f"- **Datasets Combined:** NO. Merging rows across capture or dataset boundaries is strictly forbidden.")
    (reports / "phase5_dataset_audit.md").write_text("\n".join(audit_md) + "\n", encoding="utf-8")

    (reports / "phase5_model_search.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (reports / "phase5_model_search.md").write_text("# Phase 5 Forecasting Model Search\n\n```json\n" + json.dumps(report, indent=2) + "\n```\n", encoding="utf-8")
    artifact_dir = ROOT / "artifacts" / "models" / "candidate_v2"
    (artifact_dir / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (artifact_dir / "promotion.json").write_text(json.dumps(report["promotion"], indent=2), encoding="utf-8")


if __name__ == "__main__":
    result = run_phase5()
    write_phase5_report(result)
    print(json.dumps(result["promotion"], indent=2))

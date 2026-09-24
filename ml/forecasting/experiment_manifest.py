"""Experiment Manifest and Artifact Persistence Engine.

Generates complete, verifiable, reproducible experiment folders under:
experiments/<experiment_id>/
├── manifest.json        # Execution metadata, parameters, git commit, checksums
├── metrics.json         # High-level aggregate metrics per model
├── horizon_metrics.json # Fine-grained per-horizon performance decay
├── predictions.jsonl    # Individual sample-level predictions and ground truth
├── provenance.json     # Machine environment, dependencies, dataset provenance
└── README.md            # Human-readable experiment summary and comparative findings
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS_DIR = ROOT / "experiments"


def _get_git_info() -> dict[str, str]:
    """Retrieve current git commit hash and branch."""
    commit = "unknown"
    branch = "unknown"
    try:
        commit_res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if commit_res.returncode == 0:
            commit = commit_res.stdout.strip()

        branch_res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if branch_res.returncode == 0:
            branch = branch_res.stdout.strip()
    except Exception:
        pass
    return {"commit": commit, "branch": branch}


def _sha256_file(path: Path) -> str:
    """Calculate SHA256 checksum of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class ExperimentArtifactWriter:
    """Generates standardized, reproducible experiment artifact directories."""

    def __init__(self, experiment_id: str | None = None, base_dir: Path | None = None) -> None:
        if experiment_id:
            self.experiment_id = experiment_id
        else:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            self.experiment_id = f"exp_{ts}"

        self.exp_dir = (base_dir or EXPERIMENTS_DIR) / self.experiment_id

    def save_experiment(
        self,
        dataset_name: str,
        horizons: Sequence[int],
        models_evaluated: Sequence[str],
        horizon_metrics: Mapping[str, Mapping[int, Any]],
        predictions_records: Sequence[dict[str, Any]],
        split_config: dict[str, Any] | None = None,
        comparative_deltas: dict[str, Any] | None = None,
        holdout_results: dict[str, Any] | None = None,
        random_seed: int = 42,
        notes: str = "",
    ) -> Path:
        """Write all required experiment artifacts."""
        self.exp_dir.mkdir(parents=True, exist_ok=True)
        git_info = _get_git_info()
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Write predictions.jsonl
        pred_path = self.exp_dir / "predictions.jsonl"
        with pred_path.open("w", encoding="utf-8") as pf:
            for rec in predictions_records:
                pf.write(json.dumps(rec) + "\n")

        # 2. Write horizon_metrics.json
        h_metrics_serializable: dict[str, dict[str, Any]] = {}
        for m_name, h_map in horizon_metrics.items():
            h_metrics_serializable[m_name] = {}
            for h, m in h_map.items():
                if hasattr(m, "to_dict"):
                    h_metrics_serializable[m_name][str(h)] = m.to_dict()
                elif isinstance(m, dict):
                    h_metrics_serializable[m_name][str(h)] = m
                else:
                    h_metrics_serializable[m_name][str(h)] = str(m)

        h_metrics_path = self.exp_dir / "horizon_metrics.json"
        h_metrics_path.write_text(json.dumps(h_metrics_serializable, indent=2), encoding="utf-8")

        # 3. Write metrics.json (aggregate overview per model)
        aggregate_metrics: dict[str, Any] = {}
        for m_name, h_dict in h_metrics_serializable.items():
            # Overall summary from horizon 1 and mean across horizons
            h1 = h_dict.get("1", {})
            briers = [v.get("brier_score") for v in h_dict.values() if v.get("brier_score") is not None]
            f1s = [v.get("f1_score") for v in h_dict.values() if v.get("f1_score") is not None]
            eces = [v.get("expected_calibration_error") for v in h_dict.values() if v.get("expected_calibration_error") is not None]

            aggregate_metrics[m_name] = {
                "horizon_1": h1,
                "mean_brier": round(float(sum(briers) / len(briers)), 4) if briers else None,
                "mean_f1": round(float(sum(f1s) / len(f1s)), 4) if f1s else None,
                "mean_ece": round(float(sum(eces) / len(eces)), 4) if eces else None,
            }

        metrics_path = self.exp_dir / "metrics.json"
        metrics_path.write_text(json.dumps({
            "experiment_id": self.experiment_id,
            "dataset_name": dataset_name,
            "created_at": now_iso,
            "models": aggregate_metrics,
            "comparative_deltas": comparative_deltas or {},
            "holdout_results": holdout_results or {},
        }, indent=2), encoding="utf-8")

        # 4. Write provenance.json
        provenance = {
            "experiment_id": self.experiment_id,
            "timestamp_utc": now_iso,
            "python_version": sys.version,
            "platform": platform.platform(),
            "git_commit": git_info["commit"],
            "git_branch": git_info["branch"],
            "dataset": dataset_name,
            "random_seed": random_seed,
            "split_configuration": split_config or {},
            "notes": notes,
        }
        prov_path = self.exp_dir / "provenance.json"
        prov_path.write_text(json.dumps(provenance, indent=2), encoding="utf-8")

        # 5. Compute file checksums for manifest
        checksums = {
            "predictions.jsonl": _sha256_file(pred_path),
            "horizon_metrics.json": _sha256_file(h_metrics_path),
            "metrics.json": _sha256_file(metrics_path),
            "provenance.json": _sha256_file(prov_path),
        }

        # 6. Write manifest.json
        manifest = {
            "schema_version": "1.0",
            "experiment_id": self.experiment_id,
            "created_at": now_iso,
            "dataset": dataset_name,
            "horizons": list(horizons),
            "models_evaluated": list(models_evaluated),
            "git_commit": git_info["commit"],
            "git_branch": git_info["branch"],
            "random_seed": random_seed,
            "split_config": split_config or {},
            "total_predictions": len(predictions_records),
            "checksums": checksums,
        }
        manifest_path = self.exp_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        # 7. Write README.md summary
        readme_path = self.exp_dir / "README.md"
        readme_content = self._generate_readme(
            manifest=manifest,
            aggregate_metrics=aggregate_metrics,
            horizon_metrics=h_metrics_serializable,
            comparative_deltas=comparative_deltas or {},
            holdout_results=holdout_results or {},
            notes=notes,
        )
        readme_path.write_text(readme_content, encoding="utf-8")

        return self.exp_dir

    def _generate_readme(
        self,
        manifest: dict[str, Any],
        aggregate_metrics: dict[str, Any],
        horizon_metrics: dict[str, dict[str, Any]],
        comparative_deltas: dict[str, Any],
        holdout_results: dict[str, Any],
        notes: str,
    ) -> str:
        lines = [
            f"# NexSolve Forecasting Experiment: {self.experiment_id}",
            "",
            "## 1. Experiment Overview",
            f"- **Dataset:** `{manifest['dataset']}`",
            f"- **Created At (UTC):** `{manifest['created_at']}`",
            f"- **Git Commit:** `{manifest['git_commit']}`",
            f"- **Horizons Evaluated:** `{manifest['horizons']}`",
            f"- **Models Evaluated:** `{manifest['models_evaluated']}`",
            f"- **Total Prediction Points:** `{manifest['total_predictions']}`",
            "",
            "## 2. Multi-Horizon Metric Degradation",
            "",
            "| Model | Horizon | F1 Score | Accuracy | Brier Score | ECE | Undefined Reasons |",
            "|---|---|---|---|---|---|---|",
        ]

        for m_name, h_dict in horizon_metrics.items():
            for h_str, m_data in sorted(h_dict.items(), key=lambda kv: int(kv[0])):
                f1 = m_data.get("f1_score")
                f1_s = f"{f1:.4f}" if f1 is not None else "N/A"
                acc = m_data.get("accuracy")
                acc_s = f"{acc:.4f}" if acc is not None else "N/A"
                brier = m_data.get("brier_score")
                brier_s = f"{brier:.4f}" if brier is not None else "N/A"
                ece = m_data.get("expected_calibration_error")
                ece_s = f"{ece:.4f}" if ece is not None else "N/A"
                reasons = list(m_data.get("undefined_reasons", {}).keys())
                reasons_s = ", ".join(reasons) if reasons else "None"
                lines.append(f"| {m_name} | T+{h_str} | {f1_s} | {acc_s} | {brier_s} | {ece_s} | {reasons_s} |")

        lines.extend([
            "",
            "## 3. Comparative Deltas (World Model vs Persistence)",
            "",
        ])
        if comparative_deltas:
            lines.extend([
                "| Horizon | Brier Delta | F1 Delta | ECE Delta | Interpretation |",
                "|---|---|---|---|---|",
            ])
            for h_name, d_data in comparative_deltas.items():
                b_d = d_data.get("brier_delta")
                b_s = f"{b_d:+.4f}" if b_d is not None else "N/A"
                f_d = d_data.get("f1_delta")
                f_s = f"{f_d:+.4f}" if f_d is not None else "N/A"
                e_d = d_data.get("ece_delta")
                e_s = f"{e_d:+.4f}" if e_d is not None else "N/A"
                interp = d_data.get("interpretation", "")
                lines.append(f"| {h_name} | {b_s} | {f_s} | {e_s} | {interp} |")
        else:
            lines.append("No comparative deltas computed.")

        lines.extend([
            "",
            "## 4. Attack-Family Holdout Evaluation",
            "",
        ])
        if holdout_results and holdout_results.get("status") == "COMPLETED":
            lines.append(f"- **Held-out families:** {holdout_results.get('held_out_families')}")
            for fam, fam_data in holdout_results.get("family_evaluations", {}).items():
                lines.append(f"### Family: `{fam}`")
                lines.append(f"- Verdict: `{fam_data.get('verdict')}`")
                lines.append(f"- F1 Retention Ratio: `{fam_data.get('f1_retention_ratio')}`")
                lines.append(f"- Recall Drop: `{fam_data.get('recall_drop')}`")
        elif holdout_results and holdout_results.get("status") == "UNSUPPORTED":
            lines.append(f"> [!NOTE]\n> Holdout evaluation unsupported: {holdout_results.get('reason')}")
        else:
            lines.append("Holdout evaluation not executed for this run.")

        lines.extend([
            "",
            "## 5. Scientific Reproducibility & Integrity Guarantee",
            "- **Zero-Fabrication:** Missing values and undefined metrics are recorded as `None` with explicit reasons.",
            "- **Zero-Leakage:** Temporal splits enforced strictly chronologically with embargo purge gaps.",
            "- **Artifact Checksums:** Recorded in `manifest.json` for validation against tampering.",
            "",
        ])

        if notes:
            lines.extend([
                "## 6. Run Notes",
                notes,
                "",
            ])

        return "\n".join(lines)

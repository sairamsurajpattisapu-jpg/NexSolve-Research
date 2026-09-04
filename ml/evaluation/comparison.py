"""Machine-readable model comparison table construction."""
from __future__ import annotations


def comparison_table(model_results: dict[str, dict]) -> list[dict]:
    rows = []
    for model, result in sorted(model_results.items()):
        row = {"model": model}
        for horizon in range(1, 6):
            metric = result.get(f"T+{horizon}", {})
            row[f"T+{horizon}_f1"] = metric.get("f1", "N/A") if metric.get("status") == "computed" else "N/A"
        row["coverage"] = result.get("coverage", "N/A")
        row["calibration"] = result.get("calibration", "N/A")
        rows.append(row)
    return rows
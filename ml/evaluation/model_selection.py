"""Transparent, deterministic selection policy; missing evidence never wins."""
from __future__ import annotations


def _score(result: dict) -> tuple:
    horizons = [result.get(f"T+{horizon}", {}).get("macro_f1") for horizon in range(1, 6)]
    valid = [float(value) for value in horizons if isinstance(value, (int, float))]
    coverage = result.get("coverage", 0.0)
    calibration = result.get("calibration_score", 0.0)
    if len(valid) != 5:
        return (-1.0, -1.0, -1.0, -1.0)
    return (sum(valid) / len(valid), min(valid), float(coverage), -float(calibration) if calibration else 0.0)


def select_model(results: dict[str, dict]) -> dict:
    if not results:
        return {"status": "HOLD", "reason": "no candidate results"}
    ranked = sorted(((model, _score(result)) for model, result in results.items()), key=lambda item: (item[1], item[0]), reverse=True)
    best_model, best_score = ranked[0]
    if best_score[0] < 0:
        return {"status": "HOLD", "reason": "no candidate has complete T+1 through T+5 metrics", "ranking": [{"model": model, "score": score} for model, score in ranked]}
    return {"status": "HOLD", "model": best_model, "score": best_score, "ranking": [{"model": model, "score": score} for model, score in ranked], "policy": "maximize mean horizon macro-F1, then worst-horizon macro-F1, coverage, and deterministic tie-break; promotion requires independent validation"}
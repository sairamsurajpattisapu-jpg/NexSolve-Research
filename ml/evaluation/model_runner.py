"""Architecture-neutral model plugin contract for future candidates."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence


class TemporalModelPlugin(Protocol):
    name: str

    def fit(self, train_states: Sequence[Any], validation_states: Sequence[Any]) -> None: ...
    def predict_horizon(self, history: Sequence[Any], horizon: int) -> float | None: ...


@dataclass
class ModelRun:
    model_name: str
    model_version: str
    seed: int
    configuration: dict[str, Any] = field(default_factory=dict)
    predictions: dict[int, list[float | None]] = field(default_factory=dict)


def run_plugin(plugin: TemporalModelPlugin, histories: Sequence[Sequence[Any]], seed: int, model_version: str = "unversioned") -> ModelRun:
    """Run a plugin in fixed horizon order; plugin owns model-specific logic."""
    predictions = {horizon: [plugin.predict_horizon(history, horizon) for history in histories] for horizon in range(1, 6)}
    return ModelRun(plugin.name, model_version, seed, predictions=predictions)
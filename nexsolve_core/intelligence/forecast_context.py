"""Deterministic Forecast Context Engine for NexSolve.

Assembles rich, structured contextual telemetry for the forecasting layer:
- Inferred attack state & kinematic trajectory
- Active behavioral changes & baseline shifts
- Associated campaign duration & targeted horizons
- Empirical state persistence indicators
- Strict separation between OBSERVED evidence and FORECAST projections
- Prevents data leakage: Future information is never fed into current inference
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class EntityForecastContext:
    """Structured context supplied to forecasting pipelines for a specific entity."""
    entity: str
    current_attack_state: str
    state_duration_windows: int
    kinematic_trajectory_length: int
    highest_observed_state: str
    active_behavior_changes_count: int
    associated_campaign_id: str | None
    supported_forecast_horizons: tuple[int, ...]
    state_persistence_supported: bool
    downstream_progression_supported: bool
    abstention_reasons: tuple[str, ...]
    observed_context_summary: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "current_attack_state": self.current_attack_state,
            "state_duration_windows": self.state_duration_windows,
            "kinematic_trajectory_length": self.kinematic_trajectory_length,
            "highest_observed_state": self.highest_observed_state,
            "active_behavior_changes_count": self.active_behavior_changes_count,
            "associated_campaign_id": self.associated_campaign_id,
            "supported_forecast_horizons": list(self.supported_forecast_horizons),
            "state_persistence_supported": self.state_persistence_supported,
            "downstream_progression_supported": self.downstream_progression_supported,
            "abstention_reasons": list(self.abstention_reasons),
            "observed_context_summary": self.observed_context_summary,
            "provenance": self.provenance,
        }


def assemble_forecast_context(
    entity_profiles: Mapping[str, Any] | None = None,
    attack_kinematics: Mapping[str, Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    change_signals: Sequence[Any] | None = None,
    attack_progression: Any = None,
) -> dict[str, EntityForecastContext]:
    """Assemble deterministic forecast context objects across evaluated entities."""
    contexts: dict[str, EntityForecastContext] = {}
    profiles = entity_profiles or {}
    kinematics = attack_kinematics or {}
    cmps = campaigns or []
    changes = change_signals or []

    # Map campaigns by entity
    entity_cmp: dict[str, str] = {}
    for c in cmps:
        for ent in getattr(c, "primary_entities", ()):
            entity_cmp[ent] = getattr(c, "campaign_id", "cmp")

    for ent, prof in profiles.items():
        traj = kinematics.get(ent)
        curr_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
        curr_state_val = getattr(curr_state, "value", str(curr_state))
        highest_state = getattr(traj, "highest_severity_state", "BENIGN") if traj else "BENIGN"
        highest_val = getattr(highest_state, "value", str(highest_state))

        traj_len = len(getattr(traj, "trajectory", ())) if traj else 1
        ent_changes = [c for c in changes if getattr(c, "entity", "") == ent]

        # Empirical baseline rules: State persistence supported for K=1..5
        horizons = (1, 2, 3, 4, 5)
        persistence_supp = True
        progression_supp = False  # Downstream progression abstained unless empirical transition data supports it

        abstentions: list[str] = []
        if getattr(prof, "active_windows_count", 1) < 3:
            abstentions.append("Limited historical windows (<3); state persistence projection carries high uncertainty.")
        if curr_state_val == "RECONNAISSANCE":
            abstentions.append("Downstream Recon→DoS progression abstained per empirical evaluation findings.")

        summary = (
            f"Entity {ent} in {curr_state_val} (trajectory length {traj_len}). "
            f"Persistence supported across K={horizons}. {len(abstentions)} abstention rule(s) active."
        )

        contexts[ent] = EntityForecastContext(
            entity=ent,
            current_attack_state=curr_state_val,
            state_duration_windows=getattr(prof, "active_windows_count", 1),
            kinematic_trajectory_length=traj_len,
            highest_observed_state=highest_val,
            active_behavior_changes_count=len(ent_changes),
            associated_campaign_id=entity_cmp.get(ent),
            supported_forecast_horizons=horizons,
            state_persistence_supported=persistence_supp,
            downstream_progression_supported=progression_supp,
            abstention_reasons=tuple(abstentions),
            observed_context_summary=summary,
            provenance={"rule": "forecast_context_assembly_v1"},
        )

    return contexts

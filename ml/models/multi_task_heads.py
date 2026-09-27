"""Multi-Task Prediction Heads for NexSolve World Model.

Implements modular decoders operating on the unified Network World State Z_t
and recurrent temporal world context h_t:
A. Future Network-State Forecasting (T+1 .. T+K extensible decoder, D=45)
B. Forward Attack Probability Head (calibrated sigmoid logit)
C. Attack Stage Estimation Head (Softmax over MITRE stage taxonomy)
D. Attack Progression Trajectory Head (progression index and velocity)
E. Anomaly Detection Head (reconstruction residual and energy score)
F. Out-of-Distribution (OOD) Novelty Head (latent divergence metric)
G. Uncertainty & Observability Head (aleatoric, epistemic, sufficiency)
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

import numpy as np


class AttackStageName(str, Enum):
    BENIGN = "BENIGN"
    RECONNAISSANCE = "RECONNAISSANCE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    IMPACT_EXFILTRATION = "IMPACT_EXFILTRATION"


@dataclass(frozen=True)
class MultiTaskPredictionOutput:
    """Consolidated outputs from all multi-task prediction heads at timestamp t."""
    horizon_step: int
    attack_probability: float
    raw_probability: float
    predicted_state_vector: np.ndarray
    predicted_stage: AttackStageName
    stage_probabilities: dict[str, float]
    progression_index: float
    progression_trend: str
    anomaly_score: float
    is_anomaly: bool
    ood_score: float
    is_ood: bool
    epistemic_uncertainty: float
    aleatoric_uncertainty: float
    observability_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "horizon_step": self.horizon_step,
            "attack_probability": round(self.attack_probability, 4),
            "raw_probability": round(self.raw_probability, 4),
            "predicted_stage": self.predicted_stage.value,
            "stage_probabilities": {k: round(v, 4) for k, v in self.stage_probabilities.items()},
            "progression_index": round(self.progression_index, 4),
            "progression_trend": self.progression_trend,
            "anomaly_score": round(self.anomaly_score, 4),
            "is_anomaly": self.is_anomaly,
            "ood_score": round(self.ood_score, 4),
            "is_ood": self.is_ood,
            "epistemic_uncertainty": round(self.epistemic_uncertainty, 4),
            "aleatoric_uncertainty": round(self.aleatoric_uncertainty, 4),
            "observability_score": round(self.observability_score, 4),
        }


def _softmax(logits: np.ndarray) -> np.ndarray:
    e_x = np.exp(logits - np.max(logits))
    return e_x / np.sum(e_x)


class MultiTaskDecoders:
    """Decoders mapping recurrent world state context h_t to multi-task outputs."""

    def __init__(
        self,
        hidden_dim: int = 32,
        state_dim: int = 45,
        seed: int = 42,
    ) -> None:
        self.hidden_dim = hidden_dim
        self.state_dim = state_dim
        rng = np.random.default_rng(seed)
        scale = 1.0 / np.sqrt(hidden_dim)

        # 1. Continuous State Forecaster (h_t -> 45 future continuous features)
        self.W_state = rng.normal(0.0, scale, (state_dim, hidden_dim))
        self.b_state = np.zeros(state_dim, dtype=np.float64)

        # 2. Attack Probability Head (h_t -> scalar logit)
        self.W_attack = rng.normal(0.0, scale, (1, hidden_dim))
        self.b_attack = np.zeros(1, dtype=np.float64)

        # 3. Attack Stage Head (h_t -> 6 MITRE stage logits)
        self.stages = [
            AttackStageName.BENIGN,
            AttackStageName.RECONNAISSANCE,
            AttackStageName.INITIAL_ACCESS,
            AttackStageName.LATERAL_MOVEMENT,
            AttackStageName.COMMAND_AND_CONTROL,
            AttackStageName.IMPACT_EXFILTRATION,
        ]
        self.W_stage = rng.normal(0.0, scale, (len(self.stages), hidden_dim))
        self.b_stage = np.zeros(len(self.stages), dtype=np.float64)

        # 4. Attack Progression Head (h_t -> progression scalar logit)
        self.W_prog = rng.normal(0.0, scale, (1, hidden_dim))
        self.b_prog = np.zeros(1, dtype=np.float64)

        # 5. Latent Reconstruction Anomaly Head (h_t -> reconstructed h_t residual)
        self.W_recon = rng.normal(0.0, scale, (hidden_dim, hidden_dim))
        self.b_recon = np.zeros(hidden_dim, dtype=np.float64)

        # 6. Uncertainty Head (h_t -> log variance logit)
        self.W_unc = rng.normal(0.0, scale, (2, hidden_dim))
        self.b_unc = np.zeros(2, dtype=np.float64)

        # Calibration parameters
        self.temperature = 1.0
        self.threshold = 0.30

    def predict_single_step(
        self,
        h: np.ndarray,
        horizon_step: int = 1,
        observability_score: float = 1.0,
    ) -> MultiTaskPredictionOutput:
        """Executes all decoders for a single forward horizon step."""
        # 1. Future state forecast
        pred_state = self.W_state @ h + self.b_state

        # 2. Attack probability
        raw_logit = float((self.W_attack @ h + self.b_attack)[0])
        calibrated_logit = raw_logit / max(1e-3, self.temperature)
        raw_prob = float(1.0 / (1.0 + np.exp(-np.clip(raw_logit, -25.0, 25.0))))
        calibrated_prob = float(1.0 / (1.0 + np.exp(-np.clip(calibrated_logit, -25.0, 25.0))))

        # 3. Attack stage
        stage_logits = self.W_stage @ h + self.b_stage
        stage_probs = _softmax(stage_logits)
        stage_dict = {stage.value: float(p) for stage, p in zip(self.stages, stage_probs)}
        best_stage_idx = int(np.argmax(stage_probs))
        predicted_stage = self.stages[best_stage_idx]
        # If attack probability is below threshold, ensure Benign has dominant weight
        if calibrated_prob < self.threshold:
            predicted_stage = AttackStageName.BENIGN

        # 4. Attack progression
        prog_logit = float((self.W_prog @ h + self.b_prog)[0])
        prog_index = float(1.0 / (1.0 + np.exp(-np.clip(prog_logit, -25.0, 25.0))))
        prog_trend = "ACCELERATING" if prog_index > 0.65 else "STEADY" if prog_index > 0.35 else "LATENT"

        # 5. Anomaly detection via latent auto-encoding residual
        recon_h = np.tanh(self.W_recon @ h + self.b_recon)
        recon_error = float(np.mean((h - recon_h) ** 2))
        anomaly_score = float(min(1.0, recon_error * 5.0))
        is_anomaly = bool(anomaly_score > 0.50)

        # 6. OOD Novelty score (norm of hidden activation outside typical sphere)
        h_norm = float(np.linalg.norm(h))
        ood_score = float(max(0.0, min(1.0, (h_norm - 2.5) / 3.0)))
        is_ood = bool(ood_score > 0.60)

        # 7. Uncertainty estimation
        unc_logits = self.W_unc @ h + self.b_unc
        # Epistemic: derived from OOD score and lookahead decay
        epistemic = float(min(1.0, ood_score * 0.7 + (horizon_step - 1) * 0.08))
        # Aleatoric: derived from log-variance head and distance to decision boundary
        dist_to_boundary = abs(calibrated_prob - self.threshold)
        aleatoric = float(min(1.0, (1.0 - 2.0 * dist_to_boundary) * 0.5 + 1.0 / (1.0 + np.exp(-unc_logits[0])) * 0.5))

        return MultiTaskPredictionOutput(
            horizon_step=horizon_step,
            attack_probability=calibrated_prob,
            raw_probability=raw_prob,
            predicted_state_vector=pred_state,
            predicted_stage=predicted_stage,
            stage_probabilities=stage_dict,
            progression_index=prog_index,
            progression_trend=prog_trend,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            ood_score=ood_score,
            is_ood=is_ood,
            epistemic_uncertainty=epistemic,
            aleatoric_uncertainty=aleatoric,
            observability_score=observability_score,
        )

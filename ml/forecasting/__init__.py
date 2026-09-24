"""NexSolve Forecasting Package.

Contains temporal attack horizon calculation, multi-step rollout evaluators,
evidence chaining, unknown behavior detection, forecast confidence,
and explicit abstention for predictive network security.
"""
from ml.forecasting.attack_horizon import (
    AttackHorizonResult,
    AttackHorizonState,
    ConfidenceSummary,
    HorizonEvidence,
    compute_attack_horizon,
    epoch_to_iso,
    parse_timestamp,
)
from ml.forecasting.evidence_intelligence import (
    HIGH_CHANGE,
    LOW_CHANGE,
    MEDIUM_CHANGE,
    EvidenceChain,
    EvidenceDirection,
    EvidenceItem,
    EvidenceQuality,
    EvidenceSeverity,
    EvidenceType,
    build_evidence_chain,
)
from ml.forecasting.forecast_abstention import (
    AbstentionSeverity,
    ForecastAbstentionResult,
    ForecastAvailabilityStatus,
    evaluate_forecast_abstention,
)
from ml.forecasting.forecast_confidence import (
    CalibrationStatus,
    ConfidenceState,
    ForecastConfidenceResult,
    UncertaintyLevel,
    evaluate_forecast_confidence,
)
from ml.forecasting.forecast_intelligence import (
    ForecastIntelligenceResult,
    assemble_forecast_intelligence,
)
from ml.forecasting.unknown_behavior import (
    BehaviorClassification,
    UnknownBehaviorResult,
    classify_unknown_behavior,
)
from ml.forecasting.forecasting_engine import (
    EarlyWarningAssessment,
    EarlyWarningLevel,
    ForecastTrajectoryResult,
    ForecastingPipeline,
    HorizonForecastPoint,
    RiskLevel,
)

from ml.forecasting.baselines import (
    BaselineHorizonPoint,
    LogisticRegressionBaseline,
    PersistenceBaseline,
)
from ml.forecasting.evaluation import (
    MetricResult,
    MultiHorizonEvaluator,
    calculate_classification_metrics,
    calculate_expected_calibration_error,
    evaluate_attack_family_holdout,
    evaluate_unseen_attack_generalization,
)
from ml.forecasting.temporal_split import (
    SplitMetadata,
    TemporalLeakageError,
    TemporalSplitResult,
    TemporalSplitter,
    validate_temporal_windows,
)
from ml.forecasting.benchmark import (
    BenchmarkRunResult,
    ModelHorizonPerformance,
    StandardizedBenchmarkHarness,
)
from ml.forecasting.experiment_manifest import (
    ExperimentArtifactWriter,
)
from ml.forecasting.attack_stages import (
    AttackStage,
    StageCategory,
    StageClassification,
    VERIFIED_MITRE_TECHNIQUES,
    to_canonical_stage,
    to_legacy_stage_name,
    validate_mitre_technique_id,
)
from ml.forecasting.stage_evidence import (
    EvidencePolarity,
    EvidenceSource,
    SensorAgreement,
    StageEvidence,
    evaluate_sensor_agreement,
)
from ml.forecasting.stage_transitions import (
    AttackTransition,
    STAGE_TRANSITION_MATRIX,
    TransitionRule,
    TransitionSemantics,
    TransitionType,
    TransitionValidationStatus,
    validate_transition,
)
from ml.forecasting.attack_progression_engine import (
    ProgressionValidationResult,
    TimelineEvent,
    infer_current_attack_stage,
    validate_progression_timeline,
)
from ml.forecasting.attack_progression import (
    AttackProgressionForecast,
    AttackProgressionState,
    PredictionType,
    StageForecastPoint,
    build_continuous_progression_timeline,
    determine_observed_state,
    forecast_attack_progression,
)

__all__ = [
    "AttackHorizonResult",
    "AttackHorizonState",
    "ConfidenceSummary",
    "HorizonEvidence",
    "compute_attack_horizon",
    "epoch_to_iso",
    "parse_timestamp",
    "HIGH_CHANGE",
    "LOW_CHANGE",
    "MEDIUM_CHANGE",
    "EvidenceChain",
    "EvidenceDirection",
    "EvidenceItem",
    "EvidenceQuality",
    "EvidenceSeverity",
    "EvidenceType",
    "build_evidence_chain",
    "AbstentionSeverity",
    "ForecastAbstentionResult",
    "ForecastAvailabilityStatus",
    "evaluate_forecast_abstention",
    "CalibrationStatus",
    "ConfidenceState",
    "ForecastConfidenceResult",
    "UncertaintyLevel",
    "evaluate_forecast_confidence",
    "ForecastIntelligenceResult",
    "assemble_forecast_intelligence",
    "BehaviorClassification",
    "UnknownBehaviorResult",
    "classify_unknown_behavior",
    "ForecastingPipeline",
    "HorizonForecastPoint",
    "EarlyWarningAssessment",
    "ForecastTrajectoryResult",
    "RiskLevel",
    "EarlyWarningLevel",
    "PersistenceBaseline",
    "LogisticRegressionBaseline",
    "BaselineHorizonPoint",
    "calculate_classification_metrics",
    "calculate_expected_calibration_error",
    "MultiHorizonEvaluator",
    "evaluate_unseen_attack_generalization",
    "evaluate_attack_family_holdout",
    "MetricResult",
    "TemporalLeakageError",
    "TemporalSplitResult",
    "TemporalSplitter",
    "SplitMetadata",
    "validate_temporal_windows",
    "BenchmarkRunResult",
    "ModelHorizonPerformance",
    "StandardizedBenchmarkHarness",
    "ExperimentArtifactWriter",
    "AttackStage",
    "StageCategory",
    "StageClassification",
    "VERIFIED_MITRE_TECHNIQUES",
    "to_canonical_stage",
    "to_legacy_stage_name",
    "validate_mitre_technique_id",
    "StageEvidence",
    "EvidenceSource",
    "EvidencePolarity",
    "SensorAgreement",
    "evaluate_sensor_agreement",
    "AttackTransition",
    "STAGE_TRANSITION_MATRIX",
    "TransitionRule",
    "TransitionSemantics",
    "TransitionType",
    "TransitionValidationStatus",
    "validate_transition",
    "TimelineEvent",
    "ProgressionValidationResult",
    "validate_progression_timeline",
    "infer_current_attack_stage",
    "AttackProgressionForecast",
    "AttackProgressionState",
    "PredictionType",
    "StageForecastPoint",
    "build_continuous_progression_timeline",
    "determine_observed_state",
    "forecast_attack_progression",
]
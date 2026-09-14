from __future__ import annotations

from nexsolve_core.intelligence.attack_state import (
    AttackStateEnum,
    InferredAttackState,
    infer_attack_states,
)
from nexsolve_core.intelligence.threat_view import (
    ThreatCentricView,
    build_threat_centric_views,
)
from nexsolve_core.intelligence.network_world import (
    NetworkWorldState,
    build_network_world_state,
    EntityTemporalState,
    EntityWindowPresence,
    RelationshipStatus,
    RelationshipTemporalState,
    TemporalNetworkWindow,
    TemporalNetworkWorldState,
    WorldStateDiff,
    WorldStateSnapshot,
    build_temporal_network_world_state,
    diff_snapshots,
)
from nexsolve_core.intelligence.attack_kinematics import (
    KinematicState,
    TransitionType,
    AttackKinematicTransition,
    EntityKinematicTrajectory,
    analyze_attack_kinematics,
)
from nexsolve_core.intelligence.campaigns import (
    CampaignCorrelationReason,
    AttackCampaign,
    CampaignInvestigation,
    correlate_attack_campaigns,
    investigate_campaign,
)
from nexsolve_core.intelligence.entity_profile import (
    EntityBehavioralRole,
    EntityBehaviorProfile,
    build_entity_behavior_profiles,
)
from nexsolve_core.intelligence.patterns import (
    AttackPatternType,
    AttackPattern,
    detect_attack_patterns,
)
from nexsolve_core.intelligence.threat_story import (
    NarrativeStage,
    ThreatStory,
    generate_threat_stories,
)
from nexsolve_core.intelligence.prioritization import (
    ThreatPriorityLevel,
    PrioritizedThreat,
    ThreatRiskBreakdown,
    prioritize_threats,
    decompose_threat_risk,
)
from nexsolve_core.intelligence.forecast_context import (
    EntityForecastContext,
    assemble_forecast_context,
)
from nexsolve_core.intelligence.timeline import build_entity_timeline
from nexsolve_core.intelligence.entity_relationships import discover_entity_relationships
from nexsolve_core.intelligence.contradictions import ContradictionItem, detect_contradictions
from nexsolve_core.intelligence.entity_investigation import investigate_entity
from nexsolve_core.intelligence.mitigation import (
    MitigationActionType,
    MitigationRecommendation,
    generate_mitigation_recommendations,
)
from nexsolve_core.intelligence.incident import (
    IncidentInvestigation,
    build_incident_investigation,
)
from nexsolve_core.intelligence.threat_differentiation import (
    EvidenceGroundingState,
    ThreatSemanticTier,
    ThreatDifferentiationResult,
    differentiate_threat,
)
from nexsolve_core.intelligence.what_changed import (
    WhatChangedItem,
    build_what_changed,
)
from nexsolve_core.intelligence.false_positive import (
    BenignResolutionState,
    BenignHypothesis,
    evaluate_benign_hypotheses,
)
from nexsolve_core.intelligence.questions import (
    InvestigationQuestion,
    generate_analyst_questions,
)
from nexsolve_core.intelligence.investigation_value import (
    InvestigationValueReport,
    compute_investigation_value,
)
from nexsolve_core.intelligence.analyst_decision import (
    DecisionPriority,
    AnalystDecisionType,
    DecisionChainItem,
    AnalystDecision,
    build_analyst_decisions,
)
from nexsolve_core.intelligence.incident_reconstruction import (
    IncidentEventEpistemicStatus,
    IncidentPhaseType,
    IncidentEventType,
    IncidentUncertaintyLevel,
    IncidentActor,
    IncidentTarget,
    IncidentTransition,
    IncidentEvent,
    IncidentPhase,
    IncidentUncertainty,
    EvidenceChainLink,
    IncidentAssessment,
    IncidentStory,
    build_incident_story,
)
from nexsolve_core.intelligence.incident_fingerprint import (
    IncidentFingerprint,
    extract_incident_fingerprint,
)
from nexsolve_core.intelligence.campaign_correlation import (
    CorrelationRelationship,
    CampaignEvolutionState,
    IncidentCorrelation,
    CampaignClusterTimelineEvent,
    CampaignCluster,
    correlate_incidents,
    correlate_incident_set,
    build_campaign_clusters,
)
from nexsolve_core.intelligence.query_model import (
    QueryTarget,
    QueryOperator,
    TemporalRelation,
    EpistemicScope,
    QueryPredicate,
    TemporalScope,
    GraphTraversalScope,
    QueryRequest,
    QueryMatch,
    QueryResult,
)
from nexsolve_core.intelligence.query_registry import (
    FieldDescriptor,
    PREDICATE_REGISTRY,
    get_field_descriptor,
    list_registered_fields,
)
from nexsolve_core.intelligence.hunt_packs import (
    HuntTemplate,
    HUNT_TEMPLATES,
    get_hunt_templates,
    get_template_by_id,
)
from nexsolve_core.intelligence.query_engine import IntelligenceQueryEngine

__all__ = [
    "AttackStateEnum",
    "InferredAttackState",
    "infer_attack_states",
    "ThreatCentricView",
    "build_threat_centric_views",
    "NetworkWorldState",
    "build_network_world_state",
    "EntityTemporalState",
    "EntityWindowPresence",
    "RelationshipStatus",
    "RelationshipTemporalState",
    "TemporalNetworkWindow",
    "TemporalNetworkWorldState",
    "WorldStateDiff",
    "WorldStateSnapshot",
    "build_temporal_network_world_state",
    "diff_snapshots",
    "KinematicState",
    "TransitionType",
    "AttackKinematicTransition",
    "EntityKinematicTrajectory",
    "analyze_attack_kinematics",
    "CampaignCorrelationReason",
    "AttackCampaign",
    "CampaignInvestigation",
    "correlate_attack_campaigns",
    "investigate_campaign",
    "EntityBehavioralRole",
    "EntityBehaviorProfile",
    "build_entity_behavior_profiles",
    "AttackPatternType",
    "AttackPattern",
    "detect_attack_patterns",
    "NarrativeStage",
    "ThreatStory",
    "generate_threat_stories",
    "ThreatPriorityLevel",
    "PrioritizedThreat",
    "ThreatRiskBreakdown",
    "prioritize_threats",
    "decompose_threat_risk",
    "EntityForecastContext",
    "assemble_forecast_context",
    "build_entity_timeline",
    "discover_entity_relationships",
    "ContradictionItem",
    "detect_contradictions",
    "investigate_entity",
    "MitigationActionType",
    "MitigationRecommendation",
    "generate_mitigation_recommendations",
    "IncidentInvestigation",
    "build_incident_investigation",
    "EvidenceGroundingState",
    "ThreatSemanticTier",
    "ThreatDifferentiationResult",
    "differentiate_threat",
    "WhatChangedItem",
    "build_what_changed",
    "BenignResolutionState",
    "BenignHypothesis",
    "evaluate_benign_hypotheses",
    "InvestigationQuestion",
    "generate_analyst_questions",
    "InvestigationValueReport",
    "compute_investigation_value",
    "DecisionPriority",
    "AnalystDecisionType",
    "DecisionChainItem",
    "AnalystDecision",
    "build_analyst_decisions",
    "IncidentEventEpistemicStatus",
    "IncidentPhaseType",
    "IncidentEventType",
    "IncidentUncertaintyLevel",
    "IncidentActor",
    "IncidentTarget",
    "IncidentTransition",
    "IncidentEvent",
    "IncidentPhase",
    "IncidentUncertainty",
    "EvidenceChainLink",
    "IncidentAssessment",
    "IncidentStory",
    "build_incident_story",
    "IncidentFingerprint",
    "extract_incident_fingerprint",
    "CorrelationRelationship",
    "CampaignEvolutionState",
    "IncidentCorrelation",
    "CampaignClusterTimelineEvent",
    "CampaignCluster",
    "correlate_incidents",
    "correlate_incident_set",
    "build_campaign_clusters",
    "QueryTarget",
    "QueryOperator",
    "TemporalRelation",
    "EpistemicScope",
    "QueryPredicate",
    "TemporalScope",
    "GraphTraversalScope",
    "QueryRequest",
    "QueryMatch",
    "QueryResult",
    "FieldDescriptor",
    "PREDICATE_REGISTRY",
    "get_field_descriptor",
    "list_registered_fields",
    "HuntTemplate",
    "HUNT_TEMPLATES",
    "get_hunt_templates",
    "get_template_by_id",
    "IntelligenceQueryEngine",
]


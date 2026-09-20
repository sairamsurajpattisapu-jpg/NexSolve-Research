export type Severity = 'high' | 'medium' | 'low'
export type AnalysisProvenance = 'reference' | 'uploaded'

export interface HealthResponse {
  service_status: string
  model_loaded: boolean
  model_version: string
  feature_count: number
  sequence_length: number
  K: number
  packet_features_available: boolean
}

export interface ValidationReport {
  status: string
  rows: number
  columns: string[]
  dtypes: Record<string, string>
  missing_columns: string[]
  null_counts: Record<string, number>
  null_ratios: Record<string, number>
  constant_columns: string[]
  numeric_ranges: Record<string, { min: number; max: number }>
  protocol_counts: Record<string, number>
  window: {
    unit: string
    seconds: number | null
    start_min: number | null
    start_max: number | null
    ordered: boolean
  }
  model_compatibility: {
    flow_features_available: boolean
    packet_features_available: boolean
    labels_available: boolean
    forecast_model_ready: boolean
    reason: string
  }
}

export interface WindowRow {
  window_start: number
  window_end: number
  packet_count: number
  tcp_count: number
  udp_count: number
  icmp_count: number
  tcp_retransmission_count: number
  tcp_retransmission_rate: number
  port_scan_score: number
  fragment_count: number
  fragment_ratio: number
  packet_size_mean: number
  payload_mean: number
  protocol_counts: Record<string, number>
}

export interface TrafficSummary {
  status: string
  windows: number
  packets: number
  tcp: number
  udp: number
  icmp: number
  retransmissions: number
  fragmented_packets: number
  flows?: number
  duration_seconds?: number
  protocol_counts: Record<string, number>
  windows_data?: WindowRow[]
}

export interface EvidenceItem {
  rule_id?: string
  type: string
  value: number
  metric?: string
  threshold?: number
  message: string
}

export interface Finding {
  finding_id: string
  window_id: number
  timestamp: string
  prediction: string
  attack_category: string
  detection_method?: string
  severity: Severity
  confidence: number | null
  risk_score: number
  evidence: EvidenceItem[]
  explanation?: string[]
  recommendation: string
}

export interface DetectionSummary {
  status: string
  detection_mode: string
  detection_method?: string
  model_prediction_available: boolean
  windows_analyzed: number
  detected_events: number
  risk_score: number
  average_window_risk: number
  threat_level: Severity
  findings: Finding[]
  risk_method: string
}

export type AnalysisStateType =
  | 'ANALYSIS_COMPLETE_FORECAST_READY'
  | 'ANALYSIS_COMPLETE_FORECAST_UNAVAILABLE'
  | 'ANALYSIS_REJECTED_INVALID_INPUT'

export interface ForecastSummaryContract {
  available: boolean
  status: string
  required_windows: number
  available_windows: number
  required_window_seconds: number
  message: string
}

export interface AnalysisResults {
  analysis_id: string
  status: string
  analysis_state?: AnalysisStateType
  forecast_summary?: ForecastSummaryContract
  source?: AnalysisSource
  upload?: { filename: string; size_bytes: number; format: string }
  validation: ValidationReport
  traffic: TrafficSummary
  detection: DetectionSummary
  behavioral_intelligence?: Record<string, unknown>
  network_intelligence?: {
    session_state?: Record<string, unknown>
    periodicity?: Record<string, unknown> | null
    flow_statistics?: Record<string, unknown>
    signature_evidence?: Record<string, unknown>
    evidence_summary?: Record<string, unknown>
  }
  evidence_graph?: EvidenceGraphPayload | null
  network_world_state?: NetworkWorldStatePayload | null
  episodes?: BehavioralEpisodePayload[] | null
  threat_views?: ThreatCentricViewPayload[] | null
  attack_states?: Array<Record<string, unknown>> | null
  change_signals?: Array<Record<string, unknown>> | null
  attack_kinematics?: Record<string, EntityKinematicTrajectoryPayload> | null
  entity_profiles?: Record<string, EntityBehaviorProfilePayload> | null
  patterns?: AttackPatternPayload[] | null
  campaigns?: AttackCampaignPayload[] | null
  threat_stories?: ThreatStoryPayload[] | null
  prioritized_threats?: PrioritizedThreatPayload[] | null
  forecast_context?: Record<string, EntityForecastContextPayload> | null
  baseline_deviations?: Array<Record<string, unknown>> | null
  tcp_session_metrics?: Record<string, unknown>
  flow_statistics?: Record<string, unknown>
  signature_evidence?: Record<string, unknown>
  investigation_sessions?: Record<string, unknown>[]
  threat_assessment?: Record<string, unknown>
  attack_progression?: AttackProgressionForecast | null
  attackProgression?: AttackProgressionForecast | null
  forecasts?: ForecastPoint[]
  attack_horizon?: AttackHorizonPayload | null
  attackHorizon?: AttackHorizonPayload | null
  evidence_chain?: EvidenceChainPayload | null
  evidenceChain?: EvidenceChainPayload | null
  confidence?: ForecastConfidencePayload | null
  unknown_behavior?: UnknownBehaviorPayload | null
  unknownBehavior?: UnknownBehaviorPayload | null
  abstention?: ForecastAbstentionPayload | null
  processing_metrics?: Record<string, number>
}

export interface AnalysisSource {
  name: string
  kind: string
  filename?: string
  size_bytes?: number
}

export interface AnalysisStatus {
  analysis_id: string
  status: string
  windows: number
}

export interface ReportResponse {
  report_id: string
  status: string
  metadata: AnalysisSource
  validation: ValidationReport
  traffic: TrafficSummary
  detection: DetectionSummary
}

export interface AnalysisData {
  results: AnalysisResults
  status: AnalysisStatus
  report: ReportResponse
  health: HealthResponse
}

export interface UploadedAnalysisResponse {
  analysis_id: string
  status: string
  analysis_state?: AnalysisStateType
  forecast_summary?: ForecastSummaryContract
  source: AnalysisSource
  upload: { filename: string; size_bytes: number; format: string }
  validation: ValidationReport
  traffic: TrafficSummary
  detection: DetectionSummary
  quality: Record<string, unknown>
  packet_count: number
  window_count: number
  duration_seconds: number
  protocol_summary: Record<string, number>
  findings: Finding[]
  summary: { packet_count: number; window_count: number; finding_count: number; threat_level: Severity }
  behavioral_intelligence?: Record<string, unknown>
  network_intelligence?: {
    session_state?: Record<string, unknown>
    periodicity?: Record<string, unknown> | null
    flow_statistics?: Record<string, unknown>
    signature_evidence?: Record<string, unknown>
    evidence_summary?: Record<string, unknown>
  }
  evidence_graph?: EvidenceGraphPayload | null
  network_world_state?: NetworkWorldStatePayload | null
  episodes?: BehavioralEpisodePayload[] | null
  threat_views?: ThreatCentricViewPayload[] | null
  attack_states?: Array<Record<string, unknown>> | null
  change_signals?: Array<Record<string, unknown>> | null
  attack_kinematics?: Record<string, EntityKinematicTrajectoryPayload> | null
  entity_profiles?: Record<string, EntityBehaviorProfilePayload> | null
  patterns?: AttackPatternPayload[] | null
  campaigns?: AttackCampaignPayload[] | null
  threat_stories?: ThreatStoryPayload[] | null
  prioritized_threats?: PrioritizedThreatPayload[] | null
  forecast_context?: Record<string, EntityForecastContextPayload> | null
  baseline_deviations?: Array<Record<string, unknown>> | null
  entity_investigations?: Record<string, InvestigationContextPayload> | null
  campaign_investigations?: Record<string, CampaignInvestigationPayload> | null
  threat_risk_breakdowns?: Record<string, ThreatRiskBreakdownPayload> | null
  incident_investigations?: IncidentInvestigationPayload[] | null
  mitigation_recommendations?: MitigationRecommendationPayload[] | null
  analyst_decisions?: AnalystDecisionPayload[] | null
  incident_story?: IncidentStoryPayload | null
  incident_fingerprint?: IncidentFingerprintPayload | null
  incident_correlations?: IncidentCorrelationPayload[] | null
  campaign_clusters?: CampaignClusterPayload[] | null
  hunt_templates?: HuntTemplatePayload[] | null
  query_predicates?: FieldDescriptorPayload[] | null
  tcp_session_metrics?: Record<string, unknown>

  flow_statistics?: Record<string, unknown>
  signature_evidence?: Record<string, unknown>
  investigation_sessions?: Record<string, unknown>[]
  threat_assessment?: Record<string, unknown>
  attack_progression?: AttackProgressionForecast | null
  attackProgression?: AttackProgressionForecast | null
  forecasts?: ForecastPoint[]
  attack_horizon?: AttackHorizonPayload | null
  attackHorizon?: AttackHorizonPayload | null
  evidence_chain?: EvidenceChainPayload | null
  evidenceChain?: EvidenceChainPayload | null
  confidence?: ForecastConfidencePayload | null
  unknown_behavior?: UnknownBehaviorPayload | null
  unknownBehavior?: UnknownBehaviorPayload | null
  abstention?: ForecastAbstentionPayload | null
  processing_metrics?: Record<string, number>
}

export type AttackHorizonStateType =
  | 'NO_ATTACK_FORECAST'
  | 'EARLY_SIGNAL'
  | 'SUSTAINED_ATTACK_FORECAST'
  | 'UNCERTAIN_FORECAST'
  | 'ABSTAINED'

export interface HorizonEvidence {
  horizon: number
  horizon_seconds: number
  predicted_timestamp: string | null
  attack_probability: number | null
  confidence: number | null
  predicted_stage: string | null
  above_threshold: boolean
  abstained: boolean
  reason?: string | null
}

export interface ConfidenceSummary {
  mean_confidence: number | null
  min_confidence: number | null
  max_confidence: number | null
  calibration_status: string
}

export interface AttackHorizonPayload {
  state: AttackHorizonStateType
  onset_horizon: number | null
  onset_timestamp: string | null
  lead_time_seconds: number | null
  horizon_windows: number
  horizon_seconds: number
  end_horizon: number | null
  end_timestamp: string | null
  decision_threshold: number
  temporal_consistency: number
  decay_observed: boolean
  confidence_summary: ConfidenceSummary
  evidence_chain: HorizonEvidence[]
  abstention_reason: string | null
  summary: string
  current_stage?: string | null
  escalation_horizon?: number | null
  lead_time_to_escalation_seconds?: number | null
  corroborating_findings?: string[]
}

export interface EvidenceAttributionPayload {
  predicted_stage: string
  mitre_technique: string
  behavioral_rationale: string
  top_observable_drivers: Array<{
    feature: string
    current_value: number
    predicted_value: number
    direction: string
    relative_change: number
    importance: string
    interpretation: string
  }>
  epistemic_certainty: string
  supporting_signals: string[]
}

export interface ForecastPoint {
  horizon: number
  lookaheadSeconds?: number
  attackProbability: number | null
  cumulativeRisk?: number | null
  riskLevel?: string
  predictedStage: string | null
  confidence: number | null
  uncertainty: number | null
  explanation: string[]
  topDrivers?: Array<{
    feature: string
    current_value: number
    predicted_value: number
    direction: string
    relative_change: number
    importance: string
    interpretation: string
  }>
  evidenceAttribution?: EvidenceAttributionPayload | null
}

export type PredictionType = 'STATE_PERSISTENCE' | 'DOWNSTREAM_PROGRESSION' | 'ABSTAINED'

export interface StageForecastPoint {
  horizon_minutes: number
  predicted_state: string
  predicted_technique?: string | null
  forecast_techniques: string[]
  prediction_type: PredictionType
  transition_probability: number | null
  baseline_probability?: number | null
  lead_time_seconds: number
  abstained: boolean
  abstention_reason?: string | null
  supporting_evidence: string[]
}

export interface AttackProgressionForecast {
  observed_state: string
  observed_techniques: string[]
  forecast_points: StageForecastPoint[]
  supported_horizons: number[]
  unsupported_horizons: number[]
  verdict: 'PARTIALLY_SUPPORTED' | 'SUPPORTED' | 'ABSTAINED'
  summary: string
  continuous_timeline?: Array<{
    step: number
    horizon_label: string
    horizon_minutes: number
    lead_time_seconds: number
    stage: string
    techniques: string[]
    prediction_type: string
    probability: number | null
    status: string
    evidence: string[]
  }>
}

export interface EvidenceItemPayload {
  evidence_id: string
  timestamp: string
  window_id: string | number | null
  evidence_type: string
  feature_name: string
  observed_value: number
  baseline_value: number | null
  delta: number | null
  relative_change: number | null
  direction: 'INCREASE' | 'DECREASE' | 'ANOMALOUS' | 'NEUTRAL' | 'STABLE'
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH'
  reliability: number
  source: string
  provenance: Record<string, unknown>
  explanation: string
  is_supporting: boolean
}

export interface EvidenceChainPayload {
  current_window_id: string | number | null
  current_timestamp: string
  forecast_horizon: number
  supporting: EvidenceItemPayload[]
  contradictory: EvidenceItemPayload[]
  evidence_strength: number
  evidence_quality: 'HIGH' | 'DEGRADED' | 'INSUFFICIENT' | 'MEDIUM'
  supporting_feature_count: number
  contradictory_feature_count: number
  provenance_complete: boolean
  explanation: string
  limitations: Array<string | { type: string; description: string; impact?: string }>
}

export interface ForecastConfidencePayload {
  forecast_score: number | null
  confidence_value: number | null
  confidence_state: 'CALIBRATED' | 'UNCALIBRATED' | 'LOW_SUPPORT' | 'HIGH_UNCERTAINTY' | 'WITHHELD' | 'UNKNOWN'
  evidence_strength: number
  calibration_status: 'UNSUPPORTED' | 'UNCALIBRATED' | 'CALIBRATED'
  uncertainty_level: 'LOW' | 'MEDIUM' | 'HIGH'
  explanation: string
}

export interface UnknownBehaviorPayload {
  classification: 'KNOWN_PATTERN' | 'WEAK_PATTERN' | 'UNKNOWN_BEHAVIOR'
  reason: string
  supporting_evidence: string[]
  contradictory_evidence: string[]
  coverage: number
  abstain_recommended: boolean
}

export interface ForecastAbstentionPayload {
  abstained: boolean
  reason: string | null
  severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  status: 'FORECAST_AVAILABLE' | 'FORECAST_AVAILABLE_BUT_UNCALIBRATED' | 'FORECAST_UNAVAILABLE'
  missing_requirements: string[]
  explanation: string
  observed_windows?: number | null
  required_windows?: number | null
  capture_duration_seconds?: number | null
  gap_seconds?: number | null
}

export interface ForecastResponse {
  currentState: Record<string, unknown>
  forecasts: ForecastPoint[]
  attack_horizon?: AttackHorizonPayload | null
  attackHorizon?: AttackHorizonPayload | null
  evidence_chain?: EvidenceChainPayload | null
  evidenceChain?: EvidenceChainPayload | null
  confidence?: ForecastConfidencePayload | null
  unknown_behavior?: UnknownBehaviorPayload | null
  unknownBehavior?: UnknownBehaviorPayload | null
  abstention?: ForecastAbstentionPayload | null
  attack_progression?: AttackProgressionForecast | null
  attackProgression?: AttackProgressionForecast | null
}

export interface GraphNodePayload {
  id: string
  node_type: string
  entity_key: string
  label: string
  scope: 'OBSERVED' | 'FORECAST' | 'METADATA'
  timestamp?: number | string | null
  window_id?: number | string | null
  properties: Record<string, unknown>
  provenance: Record<string, unknown>
}

export interface GraphEdgePayload {
  id: string
  source_id: string
  target_id: string
  edge_type: string
  scope: 'OBSERVED' | 'FORECAST' | 'METADATA'
  reason: string
  rule_id?: string | null
  properties: Record<string, unknown>
  supporting_evidence_ids: string[]
}

export interface EvidenceChainItem {
  chain_id: string
  terminal_node_id: string
  scope: 'OBSERVED' | 'FORECAST' | 'METADATA'
  title: string
  node_ids: string[]
  edge_ids: string[]
  explanation: string
  mitre_technique_id?: string | null
}

export interface EntityDossierPayload {
  entity_key: string
  total_associated_nodes: number
  inbound_peers: string[]
  outbound_peers: string[]
  targeted_ports: number[]
  attack_states: GraphNodePayload[]
  findings: GraphNodePayload[]
  sessions: GraphNodePayload[]
  behavior_signals: GraphNodePayload[]
}

export interface EvidenceGraphPayload {
  statistics: {
    total_nodes: number
    total_edges: number
    total_chains: number
    observed_node_count: number
    forecast_node_count: number
    nodes_by_type: Record<string, number>
    edges_by_type: Record<string, number>
  }
  nodes: GraphNodePayload[]
  edges: GraphEdgePayload[]
  chains: EvidenceChainItem[]
  dossiers?: Record<string, EntityDossierPayload>
}

export interface BehavioralEpisodePayload {
  episode_id: string
  title: string
  start_window: number
  end_window: number
  duration_seconds: number
  primary_entity: string
  source_ips: string[]
  destination_ips: string[]
  destination_ports: number[]
  flow_count: number
  session_count: number
  findings: string[]
  behavior_signals: string[]
  protocol_signals: string[]
  anomaly_signals: string[]
  attack_states: string[]
  mitre_techniques: string[]
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  description: string
}

export interface ThreatCentricViewPayload {
  entity_key: string
  threat_level: string
  current_attack_state: string
  mitre_techniques: string[]
  first_seen_window: number
  last_seen_window: number
  associated_peers: string[]
  targeted_ports: number[]
  total_sessions: number
  total_findings: number
  corroborating_modalities: string[]
  contradicting_evidence: string[]
  explanation_chain: string[]
  forecast_hypothesis?: string | null
}

export interface NetworkWorldStatePayload {
  capture_id: string
  total_packets: number
  total_flows: number
  total_windows: number
  duration_seconds: number
  active_entity_count: number
  active_session_count: number
  episodes: BehavioralEpisodePayload[]
  attack_states: Array<Record<string, unknown>>
  threat_views: ThreatCentricViewPayload[]
  change_signals: Array<Record<string, unknown>>
  forecast_points: Array<Record<string, unknown>>
  graph_summary: {
    nodes: number
    edges: number
    chains: number
  }
}

export interface AttackKinematicTransitionPayload {
  transition_id: string
  entity: string
  from_state: string
  to_state: string
  window_before: number
  window_after: number
  timestamp_before: number | null
  timestamp_after: number | null
  transition_type: string
  strength: number
  supporting_evidence_ids: string[]
  supporting_modalities: string[]
  observed_or_forecast: string
  explanation: string
}

export interface EntityKinematicTrajectoryPayload {
  entity: string
  current_state: string
  trajectory: string[]
  transitions: AttackKinematicTransitionPayload[]
  first_seen_window: number
  last_seen_window: number
  total_transitions: number
  unsupported_transition_count: number
  highest_severity_state: string
  summary: string
}

export interface EntityBehaviorProfilePayload {
  entity: string
  roles: string[]
  first_seen_window: number
  last_seen_window: number
  active_windows_count: number
  peer_count: number
  targeted_ports_count: number
  protocol_distribution: Record<string, number>
  packet_volume: number
  byte_volume: number
  connection_attempts: number
  successful_sessions: number
  failed_sessions: number
  reset_sessions: number
  failure_ratio: number
  beaconing_detected: boolean
  scan_detected: boolean
  volume_anomalies_detected: boolean
  associated_episodes: string[]
  mitre_techniques: string[]
  role_summary: string
}

export interface AttackPatternPayload {
  pattern_id: string
  pattern_type: string
  primary_entities: string[]
  target_entities: string[]
  targeted_ports: number[]
  time_window_range: number[]
  severity: string
  supporting_events: string[]
  supporting_features: Record<string, unknown>
  observed_or_forecast: string
  explanation: string
}

export interface AttackCampaignPayload {
  campaign_id: string
  title: string
  primary_entities: string[]
  target_entities: string[]
  targeted_ports: number[]
  start_window: number
  end_window: number
  duration_seconds: number
  constituent_episodes: string[]
  attack_states: string[]
  mitre_techniques: string[]
  severity: string
  correlation_reasons: string[]
  explanation: string
}

export interface NarrativeStagePayload {
  stage_title: string
  window_index: number
  narrative_text: string
  evidence_ids: string[]
  is_contradiction?: boolean
}

export interface ThreatStoryPayload {
  story_id: string
  entity: string
  headline: string
  threat_verdict: string
  initial_behavior: string
  behavior_changes: string[]
  attack_progression: string
  current_assessment: string
  forecast_projection: string
  stages: NarrativeStagePayload[]
  supporting_evidence: string[]
  contradicting_evidence: string[]
  uncertainties: string[]
  full_narrative_text: string
}

export interface PrioritizedThreatPayload {
  priority_id: string
  entity: string
  priority_level: string
  priority_rank: number
  primary_threat_type: string
  drivers: string[]
  mitigating_factors: string[]
  uncertainty_factors: string[]
  supporting_evidence_count: number
  associated_campaign_id?: string | null
  recommended_action: string
  explanation: string
}

export interface ThreatRiskBreakdownPayload {
  entity: string
  priority_level: string
  priority_rank: number
  base_severity_score: number
  attack_state_contribution: number
  kinematic_escalation_contribution: number
  target_breadth_contribution: number
  campaign_contribution: number
  mitigation_discount: number
  final_score: number
  drivers: string[]
  mitigating_factors: string[]
  uncertainty_factors: string[]
  recommended_action: string
}

export interface InvestigationSubjectPayload {
  subject_id: string
  subject_type: string
  label: string
  first_seen?: number | null
  last_seen?: number | null
  active_windows: number[]
  primary_roles: string[]
  inferred_attack_state: string
  current_priority: string
  associated_campaign_ids: string[]
  associated_pattern_ids: string[]
  summary: string
}

export interface InvestigationFindingPayload {
  finding_id: string
  title: string
  category: string
  severity: string
  window_index: number
  timestamp?: number | string | null
  observed_or_forecast: string
  description: string
  supporting_evidence_keys: string[]
}

export interface InvestigationTimelineEventPayload {
  event_id: string
  timestamp: number
  window_index: number
  event_type: string
  entity: string
  headline: string
  details: string
  severity: string
  observed_or_forecast: string
  source_modality: string
  supporting_evidence_keys: string[]
}

export interface InvestigationRelationshipPayload {
  relationship_id: string
  source_entity: string
  target_entity: string
  relationship_type: string
  supporting_reasons: string[]
  supporting_evidence: string[]
  first_seen?: number | null
  last_seen?: number | null
  observed_status: string
}

export interface InvestigationContextPayload {
  investigation_id: string
  subject: InvestigationSubjectPayload
  findings: InvestigationFindingPayload[]
  timeline: InvestigationTimelineEventPayload[]
  relationships: InvestigationRelationshipPayload[]
  contradictions: string[]
  mitigating_factors: string[]
  forecast_context_summary?: string | null
  recommended_action: string
}

export interface MitigationRecommendationPayload {
  recommendation_id: string
  action_type: string
  title: string
  target_entity: string
  urgency: string
  reason: string
  supporting_evidence: string[]
  operational_guidance: string
}

export interface IncidentInvestigationPayload {
  incident_id: string
  headline: string
  summary: string
  severity: string
  first_seen?: number | null
  last_seen?: number | null
  duration_seconds: number
  primary_entities: string[]
  target_entities: string[]
  targeted_ports: number[]
  associated_campaign_ids: string[]
  associated_pattern_ids: string[]
  attack_states: string[]
  observed_mitre_techniques: string[]
  timeline: InvestigationTimelineEventPayload[]
  contradictions: string[]
  mitigating_factors: string[]
  risk_breakdown?: ThreatRiskBreakdownPayload | null
  recommended_actions: MitigationRecommendationPayload[]
}

export interface CampaignInvestigationPayload {
  campaign: AttackCampaignPayload
  primary_entities: string[]
  target_entities: string[]
  targeted_ports: number[]
  active_window_range: number[]
  duration_seconds: number
  constituent_episodes: Array<Record<string, unknown>>
  progression_story: string
  key_findings: string[]
  recommended_action: string
}

export interface EntityForecastContextPayload {
  entity: string
  current_attack_state: string
  state_duration_windows: number
  kinematic_trajectory_length: number
  highest_observed_state: string
  active_behavior_changes_count: number
  associated_campaign_id?: string | null
  supported_forecast_horizons: number[]
  state_persistence_supported: boolean
  downstream_progression_supported: boolean
  abstention_reasons: string[]
  observed_context_summary: string
}


export type JobStatusType =
  | 'QUEUED'
  | 'PROCESSING'
  | 'COMPLETED'
  | 'FAILED'
  | 'ABORTED'
  | 'RESOURCE_LIMIT_EXCEEDED'

export type JobStageType =
  | 'INGESTION'
  | 'PARSING'
  | 'FLOW_RECONSTRUCTION'
  | 'WINDOWING'
  | 'NETWORK_STATE'
  | 'FORECAST'
  | 'EVIDENCE'
  | 'REPORT'
  | 'COMPLETE'

export interface JobError {
  code?: string
  message?: string
  status?: string
  resource?: string
  observed?: number
  limit?: number
  recoverable?: boolean
  explanation?: string
}

export interface JobStatusResponse {
  job_id: string
  filename?: string
  status: JobStatusType
  progress: number
  stage: JobStageType
  created_at: string
  started_at: string | null
  completed_at: string | null
  error: JobError | null
  processing_statistics?: {
    packets_processed?: number
    flows_processed?: number
    windows_processed?: number
    processing_seconds?: number
  }
}

// Security Analyst Decision Engine Types
export type DecisionPriorityTier = 'P0_CRITICAL' | 'P1_HIGH' | 'P2_MEDIUM' | 'P3_LOW' | 'INFORMATIONAL'
export type AnalystDecisionType = 'INVESTIGATE_ENTITY' | 'INVESTIGATE_CAMPAIGN' | 'INVESTIGATE_INCIDENT' | 'COLLECT_MORE_TELEMETRY'
export type EvidenceGroundingState = 'DIRECTLY_OBSERVED' | 'STRONGLY_SUPPORTED' | 'SUPPORTED' | 'WEAKLY_SUPPORTED' | 'CONTRADICTED' | 'INSUFFICIENT_EVIDENCE' | 'FORECAST_ONLY'
export type ThreatSemanticTier = 'NOISE' | 'ANOMALY' | 'SUSPICIOUS_BEHAVIOR' | 'SUPPORTED_RECONNAISSANCE' | 'ACTIVE_ATTACK_INDICATOR' | 'CAMPAIGN_ACTIVITY' | 'FORECAST_ONLY' | 'INSUFFICIENT_EVIDENCE'
export type BenignResolutionState = 'UNRESOLVED' | 'PARTIALLY_SUPPORTED' | 'SUPPORTED_BENIGN' | 'SUPPORTED_THREAT'

export interface ThreatDifferentiationPayload {
  semantic_tier: ThreatSemanticTier
  grounding_state: EvidenceGroundingState
  differentiating_factors: string[]
  contradicting_factors: string[]
  rationale: string
}

export interface WhatChangedItemPayload {
  change_type: string
  headline: string
  window_index: number
  description: string
  supporting_signals: string[]
}

export interface BenignHypothesisPayload {
  hypothesis_id: string
  title: string
  description: string
  resolution_state: BenignResolutionState
  supporting_factors: string[]
  contradicting_factors: string[]
}

export interface InvestigationQuestionPayload {
  question_id: string
  question: string
  context: string
  category: string
  suggested_checks: string[]
}

export interface InvestigationValuePayload {
  value_score: number
  priority_tier: string
  expected_uncertainty_reduction: string
  actionability: string
  recommended_next_step: string
}

export interface DecisionChainPayload {
  root_entity: string
  headline: string
  steps: Array<{
    step_id: string
    title: string
    description: string
    grounding: EvidenceGroundingState
  }>
}

export interface AnalystDecisionPayload {
  decision_id: string
  priority_tier: DecisionPriorityTier
  priority_rank: number
  decision_type: AnalystDecisionType
  target_id: string
  headline: string
  why_now: string
  confidence_grounding: EvidenceGroundingState
  supporting_evidence: string[]
  counter_hypotheses: string[]
  contradictions: string[]
  recommended_action: string
  investigation_value?: InvestigationValuePayload | null
  threat_differentiation?: ThreatDifferentiationPayload | null
  what_changed: WhatChangedItemPayload[]
  benign_hypotheses: BenignHypothesisPayload[]
  open_questions: InvestigationQuestionPayload[]
  decision_chain?: DecisionChainPayload | null
  provenance: Record<string, unknown>
}

// Deterministic Incident Reconstruction & Attack Story Engine Types
export type IncidentEventEpistemicStatus = 'OBSERVED' | 'INFERRED' | 'SUPPORTED' | 'FORECAST' | 'UNKNOWN'
export type IncidentPhaseType =
  | 'BASELINE'
  | 'INITIAL_ACTIVITY'
  | 'RECONNAISSANCE'
  | 'SCANNING'
  | 'ESCALATION'
  | 'ACTIVE_ATTACK'
  | 'CAMPAIGN_ACTIVITY'
  | 'CONTAINMENT_SIGNAL'
  | 'TERMINATION'
  | 'CAPTURE_BOUNDARY'
  | 'UNKNOWN'

export type IncidentEventType =
  | 'ENTITY_APPEARED'
  | 'ENTITY_ACTIVITY_STARTED'
  | 'ENTITY_ACTIVITY_INCREASED'
  | 'FANOUT_INCREASED'
  | 'PORT_SCAN_STARTED'
  | 'PORT_SCAN_ESCALATED'
  | 'RECONNAISSANCE_CONFIRMED'
  | 'BEHAVIOR_CHANGED'
  | 'TARGET_SET_EXPANDED'
  | 'ATTACK_INDICATOR_DETECTED'
  | 'CAMPAIGN_CONVERGENCE'
  | 'ATTACK_STATE_CHANGED'
  | 'ATTACK_ACTIVITY_TERMINATED'
  | 'CAPTURE_BOUNDARY'
  | 'FORECAST_AVAILABLE'
  | 'FORECAST_ABSTAINED'
  | 'CONTRADICTION_DETECTED'

export type IncidentUncertaintyLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'UNRESOLVED'

export interface IncidentActorPayload {
  entity: string
  roles: string[]
  first_seen_window: number
  last_seen_window: number
  packet_count: number
  session_count: number
  epistemic_status: IncidentEventEpistemicStatus
  evidence_keys: string[]
}

export interface IncidentTargetPayload {
  entity: string
  targeted_ports: number[]
  connection_count: number
  first_targeted_window: number
  last_targeted_window: number
  epistemic_status: IncidentEventEpistemicStatus
  evidence_keys: string[]
}

export interface IncidentTransitionPayload {
  transition_id: string
  from_state: string
  to_state: string
  window_index: number
  timestamp: number
  trigger_evidence: string[]
  supporting_metrics: Record<string, unknown>
  explanation: string
  grounding: EvidenceGroundingState
  epistemic_status: IncidentEventEpistemicStatus
}

export interface IncidentEventPayload {
  event_id: string
  timestamp: number
  window_index: number
  event_type: IncidentEventType
  actor: string
  target?: string | null
  observed_facts: string[]
  supporting_evidence_ids: string[]
  supporting_graph_nodes: string[]
  supporting_graph_edges: string[]
  attack_state: string
  mitre_technique?: string | null
  grounding: EvidenceGroundingState
  epistemic_status: IncidentEventEpistemicStatus
  uncertainty: IncidentUncertaintyLevel
  explanation: string
}

export interface IncidentPhasePayload {
  phase_id: string
  phase_type: IncidentPhaseType
  start_window: number
  end_window: number
  duration_seconds: number
  participating_entities: string[]
  targets: string[]
  dominant_behaviors: string[]
  evidence_ids: string[]
  supporting_attack_states: string[]
  supported_mitre_techniques: string[]
  grounding: EvidenceGroundingState
  epistemic_status: IncidentEventEpistemicStatus
  transition_reason: string
}

export interface IncidentUncertaintyPayload {
  uncertainty_id: string
  level: IncidentUncertaintyLevel
  category: string
  description: string
  impact_on_assessment: string
  suggested_clarification: string
}

export interface EvidenceChainLinkPayload {
  step_order: number
  stage_name: string
  description: string
  evidence_keys: string[]
  grounding: EvidenceGroundingState
}

export interface IncidentAssessmentPayload {
  classification: string
  severity: string
  start_window: number
  end_window: number
  duration_seconds: number
  termination_status: string
  what_changed_summary: string
  why_it_matters: string
  recommended_immediate_action: string
}

export interface IncidentStoryPayload {
  story_id: string
  title: string
  executive_summary: string
  narrative_paragraphs: string[]
  assessment: IncidentAssessmentPayload
  phases: IncidentPhasePayload[]
  events: IncidentEventPayload[]
  actors: IncidentActorPayload[]
  targets: IncidentTargetPayload[]
  transitions: IncidentTransitionPayload[]
  evidence_chain: EvidenceChainLinkPayload[]
  contradictions: string[]
  uncertainties: IncidentUncertaintyPayload[]
  observed_mitre_techniques: string[]
  inferred_mitre_techniques: string[]
  forecast_summary?: string | null
  next_investigation_actions: string[]
  provenance: Record<string, unknown>
}

// Cross-Incident Campaign Correlation Engine Types
export type CorrelationRelationship = 'RELATED_CAMPAIGN' | 'POSSIBLY_RELATED' | 'UNRELATED' | 'INSUFFICIENT_EVIDENCE'
export type CampaignEvolutionState =
  | 'REPEATED_RECONNAISSANCE'
  | 'EXPANDING_TARGET_SCOPE'
  | 'CHANGING_INFRASTRUCTURE'
  | 'ESCALATING_BEHAVIOR'
  | 'RECURRING_PATTERN'
  | 'STABLE_PATTERN'
  | 'UNCERTAIN_EVOLUTION'

export interface IncidentFingerprintPayload {
  incident_id: string
  capture_id: string
  actor_entities: string[]
  target_entities: string[]
  actor_roles: string[]
  targeted_ports: number[]
  protocol_distribution: Record<string, number>
  active_windows: number[]
  total_packets: number
  total_sessions: number
  total_flows: number
  fan_out_ratio: number
  failure_ratio: number
  attack_states: string[]
  observed_mitre_techniques: string[]
  episode_types: string[]
  dominant_category: string
  provenance: Record<string, unknown>
}

export interface IncidentCorrelationPayload {
  correlation_id: string
  incident_a: string
  incident_b: string
  relationship: CorrelationRelationship
  evolution: CampaignEvolutionState
  supporting_dimensions: string[]
  contradicting_dimensions: string[]
  neutral_dimensions: string[]
  supporting_signals: string[]
  contradicting_signals: string[]
  explanation: string
  uncertainty: string
  provenance: Record<string, unknown>
}

export interface CampaignClusterTimelineEventPayload {
  incident_id: string
  timestamp: number
  window_range: [number, number]
  dominant_attack_state: string
  actor_count: number
  target_count: number
  summary: string
}

export interface CampaignClusterPayload {
  cluster_id: string
  label: string
  member_incidents: string[]
  shared_characteristics: string[]
  unique_characteristics: string[]
  evolution: CampaignEvolutionState
  timeline: CampaignClusterTimelineEventPayload[]
  correlations: IncidentCorrelationPayload[]
  contradictions: string[]
  uncertainty: string
  campaign_assessment: string
  analyst_action: string
  provenance: Record<string, unknown>
}

// Threat Hunting & Intelligence Query Engine Types
export type QueryTargetType =
  | 'ENTITY'
  | 'EVENT'
  | 'INCIDENT'
  | 'CAMPAIGN'
  | 'EPISODE'
  | 'PHASE'
  | 'EVIDENCE'
  | 'BEHAVIOR'
  | 'TECHNIQUE'
  | 'GRAPH_NEIGHBOR'
  | 'EXPLANATION'

export type QueryOperatorType =
  | '='
  | '!='
  | '>'
  | '>='
  | '<'
  | '<='
  | 'IN'
  | 'NOT_IN'
  | 'CONTAINS'
  | 'STARTS_WITH'
  | 'ENDS_WITH'
  | 'EXISTS'
  | 'NOT_EXISTS'
  | 'BETWEEN'

export type TemporalRelationType =
  | 'DURING'
  | 'BEFORE'
  | 'AFTER'
  | 'WITHIN'
  | 'OVERLAPS'
  | 'ANY'

export type EpistemicScopeType =
  | 'OBSERVED_ONLY'
  | 'INFERRED_AND_SUPPORTED'
  | 'FORECAST_ONLY'
  | 'ALL'

export interface QueryPredicatePayload {
  field: string
  operator: QueryOperatorType
  value?: unknown
  value_to?: unknown
}

export interface TemporalScopePayload {
  relation?: TemporalRelationType
  start_time?: number | string | null
  end_time?: number | string | null
  window_range?: [number, number] | null
  reference_event_id?: string | null
  reference_window?: number | null
  window_delta?: number | null
}

export interface GraphTraversalScopePayload {
  start_node_id?: string | null
  entity_key?: string | null
  max_depth?: number
  edge_types?: string[]
  target_node_types?: string[]
}

export interface QueryRequestPayload {
  query_id?: string
  analysis_id?: string
  target: QueryTargetType
  predicates?: QueryPredicatePayload[]
  temporal?: TemporalScopePayload
  graph?: GraphTraversalScopePayload
  epistemic_scope?: EpistemicScopeType
  sort_by?: string | null
  sort_descending?: boolean
  limit?: number
  offset?: number
  explain?: boolean
}

export interface QueryMatchPayload {
  match_id: string
  target: QueryTargetType
  entity_key: string | null
  label: string
  primary_category: string
  semantic_state: string
  epistemic_status: string
  match_score: number
  time_window: [number | string | null, number | string | null]
  matched_predicates: string[]
  supporting_evidence: string[]
  contradicting_evidence: string[]
  uncertainties: string[]
  graph_node_ids: string[]
  graph_evidence_path: string[]
  properties: Record<string, unknown>
  analyst_decision_id?: string | null
  next_question?: string | null
}

export interface QueryResultPayload {
  query_id: string
  target: QueryTargetType
  total_matches: number
  matches: QueryMatchPayload[]
  truncated: boolean
  execution_duration_ms: number
  query_summary: string
  uncertainties: string[]
  applied_epistemic_scope: string
}

export interface HuntTemplatePayload {
  template_id: string
  name: string
  description: string
  target: QueryTargetType
  category: string
  mitre_techniques: string[]
  default_predicates: QueryPredicatePayload[]
  default_temporal?: TemporalScopePayload
  suggested_epistemic_scope: EpistemicScopeType
}

export interface FieldDescriptorPayload {
  name: string
  field_type: string
  description: string
  supported_operators: string[]
  applicable_targets: string[]
  example_value?: unknown
}

// ============================================================================
// TEMPORAL NETWORK WORLD MODEL & INTELLIGENCE STATE INTERFACES
// ============================================================================

export type RelationshipStatusType =
  | 'NEW'
  | 'PERSISTED'
  | 'NOT_OBSERVED_IN_WINDOW'
  | 'LAST_OBSERVED_AT_CAPTURE_BOUNDARY'

export type EntityWindowPresenceType =
  | 'ACTIVE'
  | 'NOT_OBSERVED_IN_WINDOW'
  | 'NEWLY_EMERGED'
  | 'LAST_OBSERVED_AT_CAPTURE_BOUNDARY'

export interface EntityTemporalStatePayload {
  entity_key: string
  entity_type: string
  presence: EntityWindowPresenceType
  window_index: number
  attack_state: string
  fanout: number
  port_diversity: number
  bytes_sent: number
  bytes_recv: number
  packets: number
  failure_ratio: number
  active_peers: string[]
  active_ports: number[]
  is_expanding_peers: boolean
  is_expanding_ports: boolean
  associated_findings_count: number
  composite_risk_score: number
}

export interface RelationshipTemporalStatePayload {
  relationship_id: string
  src_entity: string
  dst_entity: string
  dst_port: number | null
  protocol: string
  status: RelationshipStatusType
  first_seen_window: number
  last_seen_window: number
  window_index: number
  packet_count: number
  byte_count: number
  connection_count: number
  failed_attempts: number
}

export interface TemporalNetworkWindowPayload {
  window_id: string
  sequence_index: number
  start_time: number
  end_time: number
  duration_seconds: number
  packet_count: number
  flow_count: number
  tcp_retransmission_rate: number
  active_entity_count: number
  active_relationship_count: number
  change_signals_count: number
  dominant_attack_stage: string | null
  is_capture_boundary: boolean
}

export interface WorldStateSnapshotPayload {
  window_index: number
  window_id: string
  start_time: number
  end_time: number
  duration_seconds: number
  packet_count: number
  flow_count: number
  entities: Record<string, EntityTemporalStatePayload>
  relationships: Record<string, RelationshipTemporalStatePayload>
  behavior_changes: Array<Record<string, unknown>>
  attack_states: Array<Record<string, unknown>>
  evidence_keys: string[]
  is_capture_boundary: boolean
}

export interface WorldStateDiffPayload {
  window_a: number
  window_b: number
  entities_added: string[]
  entities_persisted: string[]
  entities_not_observed: string[]
  relationships_added: string[]
  relationships_not_observed: string[]
  attack_state_transitions: Array<{
    entity: string
    from_state: string
    to_state: string
    from_window: number
    to_window: number
  }>
  fanout_surges: Array<{
    entity: string
    baseline_fanout: number
    current_fanout: number
    increase: number
  }>
  volume_deltas: Array<{
    entity: string
    delta_packets: number
    delta_bytes: number
  }>
  new_evidence_keys: string[]
}

export interface TemporalNetworkWorldStatePayload {
  capture_id: string
  total_windows: number
  total_packets: number
  total_flows: number
  duration_seconds: number
  windows: TemporalNetworkWindowPayload[]
  snapshots: Record<string, WorldStateSnapshotPayload>
  entity_trajectories: Record<string, number[]>
  relationship_trajectories: Record<string, number[]>
  episodes: BehavioralEpisodePayload[]
  attack_states: Array<Record<string, unknown>>
  threat_views: ThreatCentricViewPayload[]
  change_signals: Array<Record<string, unknown>>
  forecast_points: Array<Record<string, unknown>>
  graph_summary: {
    nodes: number
    edges: number
    chains: number
  }
  incident_story_id?: string | null
  campaign_cluster_count?: number
}

export interface NetworkWorldStatePayload {
  capture_id: string
  total_packets: number
  total_flows: number
  total_windows: number
  duration_seconds: number
  active_entity_count: number
  active_session_count: number
  episodes: BehavioralEpisodePayload[]
  attack_states: Array<Record<string, unknown>>
  threat_views: ThreatCentricViewPayload[]
  change_signals: Array<Record<string, unknown>>
  forecast_points: Array<Record<string, unknown>>
  graph_summary: {
    nodes: number
    edges: number
    chains: number
  }
  temporal_world_state?: TemporalNetworkWorldStatePayload | null
}

// Model Artifact Metadata & Scientific Governance Types
export interface ModelInfoPayload {
  status: string
  model_name: string
  version: string
  feature_version: string
  feature_count: number
  canonical_features: string[]
  champion_baseline: {
    name: string
    formula: string
    status: string
    rationale: string
  }
  research_candidate: {
    name: string
    architecture: string
    status: string
    rationale: string
  }
  temporal_parameters: {
    window_duration_seconds: number
    lookback_windows: number
    lookback_seconds: number
    forecast_horizons: number[]
    max_horizon_seconds: number
  }
  datasets: {
    primary_benchmark: string
    cross_domain_evaluation: string
    rtt_policy: string
  }
  governance: {
    leakage_prevention: string
    zero_fabrication: string
  }
}

// Scientific Evaluation & Benchmark Types
export interface ModelBenchmarkScore {
  precision: number
  recall: number
  f1: number
  fpr: number
  balanced_accuracy: number
  roc_auc: number | string
  pr_auc: number | string
}

export interface EvaluationMetricsPayload {
  status: string
  dataset: string
  feature_contract: string
  evaluation_protocol: string
  model_comparison: Record<string, ModelBenchmarkScore>
  rollout_progression: {
    horizons?: Array<{
      horizon: number
      lookahead_seconds: number
      mean_squared_error: number
      mean_absolute_error: number
      brier_score?: number
    }>
    [key: string]: unknown
  }
  calibration: {
    brier_score?: number
    expected_calibration_error?: number
    reliability_bins?: Array<{
      bin_range: [number, number]
      mean_predicted_prob: number
      empirical_frequency: number
      sample_count: number
    }>
    [key: string]: unknown
  }
  unseen_attack_generalization: {
    unseen_attack_recall: number
    unseen_attack_precision: number
    unseen_attack_f1: number
    mean_state_transition_mse: number
  }
  forecast_lead_time: {
    median_lead_time_seconds: number
    median_lead_time_minutes: number
    mean_lead_time_seconds: number
    mean_lead_time_minutes: number
    min_lead_time_seconds: number
    max_lead_time_seconds: number
    percentile_25_seconds: number
    percentile_75_seconds: number
    sample_episodes: number
    definition: string
  }
  scientific_integrity_note: string
}

// What-If Defence Simulator Types
export interface SimulationInterventionPayload {
  type: 'isolate_host' | 'block_port' | 'rate_limit' | 'contain_ip'
  target: string
  intensity: number
}

export interface SimulationRequestPayload {
  analysis_id?: string
  interventions: SimulationInterventionPayload[]
}

export interface SimulationTrajectoryPoint {
  horizon: number
  lookaheadSeconds: number
  attackProbability: number
  cumulativeRisk: number
}

export interface SimulationResponsePayload {
  status: string
  mode: string
  analysis_id: string
  interventions_count: number
  applied_interventions: Array<{
    action: string
    feature_impact: string
    dampening_factor: number
  }>
  baseline_trajectory: SimulationTrajectoryPoint[]
  counterfactual_trajectory: SimulationTrajectoryPoint[]
  risk_reduction_pct: number
  label: string
  disclaimer: string
}

// Attack Replay Player Types
export interface ReplayScenarioSummaryPayload {
  id: string
  name: string
  threat_family: string
  capture_duration_seconds: number
  window_count: number
  forecast_trigger_window: number
  lead_time_seconds: number
  description: string
}

export interface ReplayFramePayload {
  window_index: number
  time_offset_seconds: number
  timestamp?: number
  timestamp_label: string
  phase: 'OBSERVED' | 'FORECAST' | string
  state_name: string
  packet_count: number
  flow_count: number
  byte_volume: number
  active_ports: number
  attack_probability: number
  cumulative_risk: number
  is_forecast_trigger: boolean
  events: string[]
}

export interface ReplayStreamPayload {
  status: string
  scenario_id: string
  total_frames: number
  window_duration_seconds: number
  forecast_trigger_index: number
  escalation_index: number
  lead_time_seconds: number
  frames: ReplayFramePayload[]
}

// Dynamic Network Graph Intelligence & Attack Propagation Types
export type GraphTemporalScope = 'OBSERVED' | 'FORECAST'

export type NodeRoleTag =
  | 'HIGH_ACTIVITY_NODE'
  | 'STRUCTURAL_CHANGE_NODE'
  | 'LATERAL_SOURCE'
  | 'SCAN_TARGET'
  | 'PERSISTENT_ENDPOINT'
  | 'NOMINAL_HOST'

export type GraphChangeType =
  | 'NEW_NODE'
  | 'NEW_EDGE'
  | 'SUDDEN_FAN_OUT'
  | 'PROTOCOL_SHIFT'
  | 'VOLUME_SPIKE'
  | 'CONNECTION_BURST'

export interface TemporalGraphNodePayload {
  node_id: string
  ip: string
  in_degree: number
  out_degree: number
  total_degree: number
  bytes_sent: number
  bytes_recv: number
  packets_sent: number
  packets_recv: number
  fan_out: number
  fan_in: number
  port_diversity: number
  active_ports: number[]
  peer_ips: string[]
  role_tags: NodeRoleTag[]
  activity_score: number
  structural_change_score: number
  is_external: boolean
  temporal_scope: GraphTemporalScope
}

export interface TemporalGraphEdgePayload {
  edge_id: string
  source_ip: string
  target_ip: string
  protocol: string
  target_port: number
  flow_count: number
  packet_count: number
  byte_count: number
  syn_count: number
  rst_count: number
  duration_seconds: number
  is_new_in_snapshot: boolean
  weight: number
  temporal_scope: GraphTemporalScope
}

export interface GraphChangeSignalPayload {
  change_type: GraphChangeType
  source_entity: string
  target_entity: string | null
  description: string
  severity: 'HIGH' | 'MEDIUM' | 'LOW'
  metric_delta: number
}

export interface GraphSnapshotMetricsPayload {
  node_count: number
  edge_count: number
  density: number
  max_fan_out: number
  max_fan_in: number
  mean_degree: number
  total_volume_bytes: number
  total_packets: number
  unique_subnets: number
  bipartite_ratio: number
}

export interface TemporalGraphSnapshotPayload {
  snapshot_index: number
  window_id: number
  timestamp_start: number
  timestamp_end: number
  scope: GraphTemporalScope
  metrics: GraphSnapshotMetricsPayload
  nodes: TemporalGraphNodePayload[]
  edges: TemporalGraphEdgePayload[]
  changes: GraphChangeSignalPayload[]
}

export interface ForecastGraphProjectionPayload {
  horizon_step: number
  horizon_seconds: number
  predicted_node_count: number
  predicted_edge_count: number
  predicted_density: number
  predicted_fanout_expansion: number
  active_threat_nodes: string[]
  potential_propagation_targets: string[]
  structural_indicators: string[]
  propagation_confidence: number
}

export interface TemporalGraphSequencePayload {
  status: string
  snapshot_count: number
  observed_snapshots: TemporalGraphSnapshotPayload[]
  forecast_projections: ForecastGraphProjectionPayload[]
  top_high_activity_nodes: TemporalGraphNodePayload[]
  top_structural_change_nodes: TemporalGraphNodePayload[]
  cumulative_nodes_count: number
  cumulative_edges_count: number
  graph_feature_vector: number[]
}

export interface FusedHorizonPointPayload {
  horizon: number
  step_attack_probability: number
  cumulative_risk: number
  risk_level: string
  predicted_stage: string
  confidence: number
  structural_indicators: string[]
  graph_density_trend: number
  fanout_expansion: number
  mode: string
}

export interface GraphFusionPayload {
  status: string
  active_mode: string
  graph_context_available: boolean
  fused_points: FusedHorizonPointPayload[]
  top_structural_drivers: string[]
  mitre_structural_attributions: Array<{
    technique_id: string
    technique_name: string
    tactic: string
    node_ip: string
    evidence: string
    confidence: number
  }>
}


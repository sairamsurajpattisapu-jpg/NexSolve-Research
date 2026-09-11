export type Severity = 'high' | 'medium' | 'low'

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

export interface AnalysisResults {
  analysis_id: string
  status: string
  source?: AnalysisSource
  upload?: { filename: string; size_bytes: number; format: string }
  validation: ValidationReport
  traffic: TrafficSummary
  detection: DetectionSummary
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
  forecasts?: ForecastPoint[]
  attack_horizon?: AttackHorizonPayload | null
  attackHorizon?: AttackHorizonPayload | null
  evidence_chain?: EvidenceChainPayload | null
  evidenceChain?: EvidenceChainPayload | null
  confidence?: ForecastConfidencePayload | null
  unknown_behavior?: UnknownBehaviorPayload | null
  unknownBehavior?: UnknownBehaviorPayload | null
  abstention?: ForecastAbstentionPayload | null
  is_demo?: boolean
  demo_scenario_id?: string
  demo_scenario_name?: string
  demo_scenario_description?: string
  demo_expected_behavior?: string
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
}

export interface ForecastPoint {
  horizon: number
  attackProbability: number | null
  predictedStage: string | null
  confidence: number | null
  uncertainty: number | null
  explanation: string[]
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

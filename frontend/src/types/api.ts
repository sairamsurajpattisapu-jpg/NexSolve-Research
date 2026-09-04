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
}

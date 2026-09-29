export type RiskClassification = 'LOW' | 'MODERATE' | 'ELEVATED' | 'CRITICAL' | 'WITHHELD'
export type AnalysisProvenance = 'live' | 'reference'
export type TelemetryFormat = 'pcap' | 'pcapng' | 'csv' | 'parquet' | 'reference'

export interface FeatureDescriptor {
  name: string
  value: number | string
  unit: string
  category: 'flow' | 'packet' | 'temporal'
  description: string
  delta?: number | null
  importance?: 'HIGH' | 'MEDIUM' | 'LOW'
}

export interface CanonicalForecastPoint {
  horizon: number
  lookaheadSeconds: number
  stepAttackProbability: number | null // P(attack at T+K)
  cumulativeRisk: number | null // P(any attack by T+K)
  riskLevel: RiskClassification
  predictedStage: string | null
  confidence: number | null
  uncertainty: number | null
  explanation: string[]
  topDrivers: Array<{
    feature: string
    currentValue: number
    predictedValue: number
    direction: string
    relativeChange: number
    importance: string
    interpretation: string
  }>
  evidenceAttribution?: {
    predictedStage: string
    mitreTechnique: string
    behavioralRationale: string
    topObservableDrivers: Array<{
      feature: string
      currentValue: number
      predictedValue: number
      direction: string
      relativeChange: number
      importance: string
      interpretation: string
    }>
    epistemicCertainty: string
    supportingSignals: string[]
  } | null
}

export interface EarlyWarningComposite {
  level: RiskClassification
  score: number // 0-100
  trend: 'INCREASING' | 'STABLE' | 'DECREASING'
  onsetHorizon: number
  leadTimeSeconds: number
  drivers: string[]
  methodDefinition: string
}

export interface ProgressionStage {
  step: number
  horizonMinutes: number
  leadTimeSeconds: number
  predictedState: string
  predictionType: 'STATE_PERSISTENCE' | 'DOWNSTREAM_PROGRESSION' | 'ABSTAINED'
  transitionProbability: number | null
  evidence: string[]
  abstained: boolean
  abstentionReason?: string | null
  mitreTechnique?: string | null
  behavioralRationale?: string | null
}

export interface MitreTechniqueMapping {
  techniqueId: string
  techniqueName: string
  tactic: string
  forecastStep: string
  interpretation: string
  evidence: string
  confidence?: number
  scope?: 'observed' | 'forecast' | 'supporting_evidence'
}

export interface ForecastValidationPoint {
  horizon: number
  lookaheadSeconds: number
  observedStateAtT0: string
  predictedProbability: number | null
  predictedStage: string | null
  actualSubsequentState: string | null
  actualThreatScore: number | null
  actualPacketCount?: number | null
  actualFlowCount?: number | null
  relationship: 'CONSISTENT' | 'DIVERGENT' | 'UNVALIDATED' | 'VALIDATION NOT AVAILABLE'
  validationStatus: 'VALIDATED' | 'VALIDATION NOT AVAILABLE'
  explanation: string
}

export interface ForecastValidation {
  status: 'VALIDATED' | 'PARTIALLY_VALIDATED' | 'VALIDATION NOT AVAILABLE'
  summary: string
  evaluatedHorizons: number
  unvalidatedHorizons: number
  points: ForecastValidationPoint[]
}

export interface FeatureExplanationItem {
  feature: string
  currentValue: number
  predictedValue: number
  direction: string
  relativeChange: number
  importance: 'HIGH' | 'MEDIUM' | 'LOW'
  interpretation: string
}

export interface EvidenceItemNode {
  name: string
  observed: number
  baseline: number | null
  delta: number | null
  direction: string
  severity: string
  isSupporting: boolean
  explanation: string
  reliability: number
}

export interface CanonicalAnalysis {
  id: string
  status: 'completed' | 'processing' | 'failed' | 'abstained'
  createdAt: string
  provenance: AnalysisProvenance
  provenanceLabel: string

  input: {
    filename: string
    format: TelemetryFormat
    sizeBytes: number
    captureDurationSeconds: number
    packetCount: number
    flowCount: number
    windowCount: number
  }

  processing: {
    status: string
    windows: number
    featureCount: number
    schemaVariant: string
    isCompatible: boolean
    compatibilityReason: string
    availableFeatures: string[]
    missingFeatures: string[]
    unreliableFeatures: string[]
    timings?: Record<string, number>
    errors?: string[]
  }

  currentState: {
    timestamp: string
    summary: {
      packets: number
      flows: number
      bytes: number
      uniqueSrcIps: number
      uniqueDstIps: number
      uniqueDstPorts: number
      protocols: Record<string, number>
      threatLevel: 'low' | 'medium' | 'high' | 'critical'
    }
    features: FeatureDescriptor[]
  }

  forecast: {
    isAvailable: boolean
    status: 'READY' | 'INSUFFICIENT_HISTORY' | 'NON_CONTIGUOUS_TIMESTAMPS' | 'GAPPED_HISTORY' | 'INCOMPATIBLE_FEATURES' | 'DATA_QUALITY_INSUFFICIENT' | 'ABSTAINED' | string
    requiredWindows: number
    availableWindows: number
    observedWindows?: number
    continuousWindows?: number
    message: string
    horizons: number[]
    points: CanonicalForecastPoint[]
    earlyWarning?: EarlyWarningComposite
    confidenceSummary?: {
      state: string
      calibrationStatus: string
      uncertaintyLevel: string
      meanConfidence: number | null
    }
    alternativeTrajectories?: Array<{
      scenarioName: string
      scenarioProbability: number
      description: string
      projectedRiskProfile: number[]
      projectedStages: string[]
    }>
    counterfactualSimulations?: Record<string, {
      description: string
      simulatedTrajectory: number[]
      expectedImpact: string
    }>
  }

  progression: {
    observedState: string
    verdict: string
    summary: string
    stages: ProgressionStage[]
  }

  mitre: {
    method: string
    disclaimer: string
    mappings: MitreTechniqueMapping[]
  }

  explanations: {
    method: string
    disclaimer: string
    drivers: FeatureExplanationItem[]
  }

  evidence: {
    configuration: {
      schemaVersion: string
      windowSeconds: number
      lookbackWindows: number
      forecastHorizonSteps: number
    }
    model: {
      champion: string
      researchHold: string
      inputDimension: number
      outputMode: string
      decisionThreshold: number
    }
    chain: {
      strength: number
      quality: string
      supporting: EvidenceItemNode[]
      contradictory: EvidenceItemNode[]
      limitations: string[]
    }
  }

  export: {
    jsonUrl: string
    htmlUrl: string
  }

  temporalGraph?: import('./api').TemporalGraphSequencePayload
  graphFusion?: import('./api').GraphFusionPayload
  networkRiskIndicators?: Array<{
    indicator_type: string
    entity: string
    observation: string
    severity: string
    evidence: string[]
  }>
  uncertaintyDiagnostics?: {
    epistemic_uncertainty?: number
    aleatoric_uncertainty?: number
    total_uncertainty?: number
    ood_score?: number
    is_ood?: boolean
    evidence_sufficiency_score?: number
  } | null
  forecastEngine?: {
    name: string
    version: string
    status: 'production' | 'research'
    isProductionReady: boolean
    forecastTarget?: string
    trainingProtocol?: string
    leadTimeSeconds?: number
    precursorDetected?: boolean
    validationVerdict?: string
    description?: string
  }
  validationComparison?: ForecastValidation
  sessions?: Array<{
    session_id: string
    src_ip: string
    src_port: number
    dst_ip: string
    dst_port: number
    protocol: string
    first_seen?: number
    last_seen?: number
    duration_seconds: number
    forward_packets: number
    reverse_packets: number
    total_packets: number
    forward_bytes?: number
    reverse_bytes?: number
    total_bytes: number
    behavioral_tags?: string[]
    mitre_techniques?: string[]
    risk_assessment?: string
    temporal_window_id?: string
  }>
  trafficSummary?: {
    packets: number
    flows: number
    windows: number
    tcp: number
    udp: number
    retransmissions: number
    protocol_counts?: Record<string, number>
    windows_data?: any[]
  }
  attackHorizon?: {
    lookahead_windows?: number
    lookahead_seconds?: number
    earliest_warning_horizon?: string
    risk_trajectory?: string
    state_transitions?: any[]
    evidence_signals?: string[]
  }
}


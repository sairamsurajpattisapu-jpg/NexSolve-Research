export type RiskClassification = 'LOW' | 'MODERATE' | 'ELEVATED' | 'CRITICAL' | 'WITHHELD'
export type AnalysisProvenance = 'live' | 'reference' | 'demo'
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
}

export interface MitreTechniqueMapping {
  techniqueId: string
  techniqueName: string
  tactic: string
  forecastStep: string
  interpretation: string
  evidence: string
  confidence?: number
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
  isDemo: boolean
  demoScenarioId?: string
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
    status: 'READY' | 'INSUFFICIENT_HISTORY' | 'INCOMPATIBLE_FEATURES' | 'ABSTAINED'
    requiredWindows: number
    availableWindows: number
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
}


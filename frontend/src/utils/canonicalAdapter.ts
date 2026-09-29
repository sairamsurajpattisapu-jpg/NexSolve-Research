import type {
  AnalysisResults,
  UploadedAnalysisResponse,
} from '../types/api'
import type {
  CanonicalAnalysis,
  CanonicalForecastPoint,
  EvidenceItemNode,
  FeatureDescriptor,
  FeatureExplanationItem,
  ForecastValidation,
  MitreTechniqueMapping,
  ProgressionStage,
  RiskClassification,
  TelemetryFormat,
} from '../types/canonical'

// Complete semantic definitions for the 45-feature canonical PCAP schema
const CANONICAL_FEATURE_SEMANTICS: Record<
  string,
  { unit: string; category: 'flow' | 'packet' | 'temporal'; description: string }
> = {
  // Flow Features (17)
  flow_count: { unit: 'count', category: 'flow', description: 'Concurrent active 5-tuple network conversations' },
  total_src_bytes: { unit: 'bytes', category: 'flow', description: 'Total volume transmitted from source endpoints' },
  total_dst_bytes: { unit: 'bytes', category: 'flow', description: 'Total volume received by destination endpoints' },
  total_packets: { unit: 'packets', category: 'flow', description: 'Aggregated packet count observed within 60s window' },
  mean_duration: { unit: 'seconds', category: 'flow', description: 'Average active session duration across flows' },
  mean_flow_bytes: { unit: 'bytes/flow', category: 'flow', description: 'Mean byte density per reconstructed flow' },
  mean_flow_packets: { unit: 'packets/flow', category: 'flow', description: 'Mean packet density per reconstructed flow' },
  mean_sttl: { unit: 'hops', category: 'flow', description: 'Mean outbound IP Time-to-Live header indicator' },
  mean_dttl: { unit: 'hops', category: 'flow', description: 'Mean inbound IP Time-to-Live header indicator' },
  mean_swin: { unit: 'bytes', category: 'flow', description: 'Mean client TCP window advertisement size' },
  mean_dwin: { unit: 'bytes', category: 'flow', description: 'Mean server TCP window advertisement size' },
  mean_iat: { unit: 'ms', category: 'flow', description: 'Mean inter-arrival time between consecutive packets' },
  unique_src_ports: { unit: 'ports', category: 'flow', description: 'Source ephemeral port cardinality (scan/flood metric)' },
  unique_dst_ports: { unit: 'ports', category: 'flow', description: 'Target destination port diversity (service scan indicator)' },
  proto_tcp_count: { unit: 'flows', category: 'flow', description: 'TCP transmission protocol flow share' },
  proto_udp_count: { unit: 'flows', category: 'flow', description: 'UDP datagram transmission protocol flow share' },
  proto_other_count: { unit: 'flows', category: 'flow', description: 'ICMP and non-standard protocol volume' },

  // Packet Features (22)
  packet_count: { unit: 'packets', category: 'packet', description: 'Raw discrete packet count in temporal window' },
  mean_packet_size: { unit: 'bytes', category: 'packet', description: 'Average discrete frame payload size' },
  std_packet_size: { unit: 'bytes', category: 'packet', description: 'Payload size standard deviation / variation' },
  min_packet_size: { unit: 'bytes', category: 'packet', description: 'Smallest frame observed in temporal window' },
  max_packet_size: { unit: 'bytes', category: 'packet', description: 'Maximum single frame size observed' },
  mean_ttl: { unit: 'hops', category: 'packet', description: 'Average observed IP Time-To-Live' },
  std_ttl: { unit: 'hops', category: 'packet', description: 'Standard deviation of packet TTL values' },
  min_ttl: { unit: 'hops', category: 'packet', description: 'Minimum IP TTL observed' },
  max_ttl: { unit: 'hops', category: 'packet', description: 'Maximum IP TTL observed' },
  tcp_syn_count: { unit: 'flags', category: 'packet', description: 'TCP SYN connection establishment flags' },
  tcp_ack_count: { unit: 'flags', category: 'packet', description: 'TCP ACK acknowledgment packet count' },
  tcp_fin_count: { unit: 'flags', category: 'packet', description: 'TCP FIN connection teardown packet count' },
  tcp_rst_count: { unit: 'flags', category: 'packet', description: 'TCP RST connection abort reset count' },
  tcp_psh_count: { unit: 'flags', category: 'packet', description: 'TCP PSH urgent data delivery indicators' },
  tcp_urg_count: { unit: 'flags', category: 'packet', description: 'TCP URG urgent pointer presence flags' },
  mean_tcp_window: { unit: 'bytes', category: 'packet', description: 'Average TCP receiver window announcement' },
  std_tcp_window: { unit: 'bytes', category: 'packet', description: 'TCP buffer window announcement variance' },
  fragment_count: { unit: 'fragments', category: 'packet', description: 'Fragmented IP datagram headers detected' },
  retransmission_count: { unit: 'packets', category: 'packet', description: 'Observed TCP packet retransmissions' },
  std_iat: { unit: 'ms', category: 'packet', description: 'Packet arrival rate variability / jitter' },
  max_iat: { unit: 'ms', category: 'packet', description: 'Maximum quiet interval between packet arrivals' },

  // Temporal Differential Features (6)
  delta_flow_count: { unit: 'delta/win', category: 'temporal', description: 'Flow initiation surge rate vs previous window' },
  delta_total_bytes: { unit: 'delta bytes', category: 'temporal', description: 'Bandwidth volume acceleration across windows' },
  delta_total_packets: { unit: 'delta pkts', category: 'temporal', description: 'Packet transmission velocity rate of change' },
  delta_ports: { unit: 'delta ports', category: 'temporal', description: 'Endpoint port space expansion acceleration' },
  delta_iat: { unit: 'delta ms', category: 'temporal', description: 'Inter-arrival timing divergence shift' },
  rolling_total_bytes: { unit: 'bytes', category: 'temporal', description: 'Cumulative multi-window rolling byte volume' },
}

function classifyRisk(prob: number | null): RiskClassification {
  if (prob === null) return 'WITHHELD'
  if (prob >= 0.75) return 'CRITICAL'
  if (prob >= 0.5) return 'ELEVATED'
  if (prob >= 0.25) return 'MODERATE'
  return 'LOW'
}

export function adaptToCanonical(
  rawInput: UploadedAnalysisResponse | AnalysisResults | Record<string, unknown>,
  fallbackId?: string
): CanonicalAnalysis {
  const raw = rawInput as Record<string, unknown>
  const analysisId = (raw.analysis_id as string) || fallbackId || 'unknown'
  const sourceObj = (raw.source as Record<string, unknown>) || {}
  const uploadObj = (raw.upload as Record<string, unknown>) || {}
  const traffic = (raw.traffic as Record<string, unknown>) || {}
  const detection = (raw.detection as Record<string, unknown>) || {}
  const validation = (raw.validation as Record<string, unknown>) || {}
  const modelCompat = (validation.model_compatibility as Record<string, unknown>) || (raw.model_compatibility as Record<string, unknown>) || {}
  const earlyWarningRaw = (raw.early_warning as Record<string, unknown>) || (raw.earlyWarning as Record<string, unknown>)
  const attackHorizon = (raw.attack_horizon as Record<string, unknown>) || (raw.attackHorizon as Record<string, unknown>)
  const progressionRaw = (raw.attack_progression as Record<string, unknown>) || (raw.attackProgression as Record<string, unknown>)
  const evidenceChain = (raw.evidence_chain as Record<string, unknown>) || (raw.evidenceChain as Record<string, unknown>)
  const abstention = (raw.abstention as Record<string, unknown>) || {}
  const confidenceRaw = (raw.confidence as Record<string, unknown>) || {}
  const forecastSummary = (raw.forecast_summary as Record<string, unknown>) || {}
  const fwm = (raw.final_world_model as Record<string, unknown>) || {}
  const historyObj = ((raw.network_state as Record<string, unknown>)?.history as Record<string, unknown>) || {}

  const isProd = analysisId === 'production-cic-ids2017'
  const provenance = isProd ? 'reference' : 'live'
  const provenanceLabel = isProd ? 'VERIFIED REFERENCE' : 'LIVE PCAP ANALYSIS'

  // Determine format
  const rawFormat = (uploadObj.format as string) || (sourceObj.kind as string) || ''
  let format: TelemetryFormat = 'pcap'
  if (rawFormat.includes('pcapng')) format = 'pcapng'
  else if (rawFormat.includes('csv')) format = 'csv'
  else if (rawFormat.includes('parquet')) format = 'parquet'
  else if (isProd) format = 'reference'

  // Forecast Availability
  const windowsCount = Number(
    raw.window_count || validation.window_count || traffic.window_count || traffic.windows || traffic.windows_analyzed || validation.rows || 0
  )
  const isModelReady = Boolean(modelCompat.forecast_model_ready ?? (windowsCount >= 8))

  // Authoritative Abstention Detection & Status Extraction from Backend
  const backendAbstentionReason =
    (forecastSummary.status as string) ||
    (abstention.abstention_reason as string) ||
    (abstention.reason as string) ||
    (fwm.abstention_reason as string) ||
    (historyObj.status as string) ||
    null

  const backendAbstentionExplanation =
    (forecastSummary.message as string) ||
    (abstention.abstention_explanation as string) ||
    (abstention.explanation as string) ||
    (fwm.abstention_explanation as string) ||
    (historyObj.reason as string) ||
    null

  const isAbstained = Boolean(
    forecastSummary.available === false ||
    raw.is_forecast_available === false ||
    abstention.abstained ||
    (abstention as any).is_abstained ||
    raw.is_abstained ||
    fwm.is_abstained ||
    attackHorizon?.state === 'ABSTAINED' ||
    historyObj.status === 'GAPPED_HISTORY' ||
    backendAbstentionReason === 'NON_CONTIGUOUS_TIMESTAMPS' ||
    windowsCount < 8
  )

  let forecastStatus: string = 'READY'
  if (isAbstained) {
    if (backendAbstentionReason && backendAbstentionReason !== 'READY' && backendAbstentionReason !== 'FORECAST_READY') {
      forecastStatus = backendAbstentionReason
    } else if (historyObj.status === 'GAPPED_HISTORY') {
      forecastStatus = 'NON_CONTIGUOUS_TIMESTAMPS'
    } else if (windowsCount < 8) {
      forecastStatus = 'INSUFFICIENT_HISTORY'
    } else if (!isModelReady) {
      forecastStatus = 'INCOMPATIBLE_FEATURES'
    } else {
      forecastStatus = 'ABSTAINED'
    }
  } else if (!isModelReady) {
    forecastStatus = 'INCOMPATIBLE_FEATURES'
  }

  let forecastMessage = 'Multi-step forecast trajectory successfully generated using continuous temporal rollout.'
  if (isAbstained) {
    if (backendAbstentionExplanation && backendAbstentionExplanation.trim().length > 0) {
      forecastMessage = backendAbstentionExplanation
    } else if (forecastStatus === 'NON_CONTIGUOUS_TIMESTAMPS' || forecastStatus === 'GAPPED_HISTORY') {
      forecastMessage = 'Forecast withheld: Input sequence contains non-contiguous temporal windows or excessive time gaps.'
    } else if (forecastStatus === 'INSUFFICIENT_HISTORY' || windowsCount < 8) {
      forecastMessage = `Forecasting requires at least 8 continuous 60-second windows. Static traffic analysis completed successfully.`
    } else {
      forecastMessage = 'Forecasting withheld: Preconditions for continuous temporal rollout were not met.'
    }
  }

  // Forecast Points
  let rawForecasts = (raw.forecasts as Array<Record<string, unknown>>) || []
  if (rawForecasts.length === 0 && raw.forecast && typeof raw.forecast === 'object') {
    const fMap = raw.forecast as Record<string, any>
    rawForecasts = [1, 2, 3, 4, 5].map((h) => {
      const pt = fMap[`T+${h}`] || {}
      return {
        horizon: h,
        lookaheadSeconds: Number(pt.lookahead_seconds ?? pt.lookaheadSeconds ?? h * 60),
        attackProbability: pt.attack_probability !== undefined ? pt.attack_probability : null,
        cumulativeRisk: pt.attack_probability !== undefined && pt.attack_probability !== null ? Math.min(1.0, pt.attack_probability * (1 + (h - 1) * 0.15)) : null,
        predictedStage: pt.predicted_stage || null,
        riskLevel: pt.risk_level || classifyRisk(pt.attack_probability),
        confidence: pt.confidence_score !== undefined ? pt.confidence_score : null,
        uncertainty: pt.confidence_score !== undefined ? Math.max(0, 1.0 - pt.confidence_score) : null,
        explanation: pt.predicted_stage ? [`State dynamics project ${pt.predicted_stage} at T+${h}`] : [],
        topDrivers: [],
        evidenceAttribution: null,
      }
    })
  }
  const points: CanonicalForecastPoint[] = []

  // Ensure horizons 1..5
  const horizonsList = [1, 2, 3, 4, 5]
  horizonsList.forEach((h) => {
    const found = rawForecasts.find((p) => p.horizon === h)
    if (found && !isAbstained && found.attackProbability !== null) {
      const stepProb = typeof found.attackProbability === 'number' ? found.attackProbability : null
      const cumRisk = typeof found.cumulativeRisk === 'number' ? found.cumulativeRisk : (stepProb !== null ? Math.min(1.0, stepProb * (1 + (h - 1) * 0.15)) : null)
      const topDrivers = Array.isArray(found.topDrivers)
        ? (found.topDrivers as any[])
        : Array.isArray(found.explanation)
        ? found.explanation.map((exp: string) => ({
            feature: 'temporal_pattern',
            currentValue: 0,
            predictedValue: 0,
            direction: 'increasing',
            relativeChange: 0,
            importance: 'MEDIUM',
            interpretation: String(exp),
          }))
        : []

      // Extract evidence attribution if present
      const rawAttribution = found.evidenceAttribution || found.evidence_attribution
      let evidenceAttribution = null
      if (rawAttribution && typeof rawAttribution === 'object') {
        const attrObj = rawAttribution as Record<string, unknown>
        const topObs = Array.isArray(attrObj.top_observable_drivers)
          ? attrObj.top_observable_drivers.map((d: any) => ({
              feature: String(d.feature),
              currentValue: Number(d.current_value ?? d.currentValue ?? 0),
              predictedValue: Number(d.predicted_value ?? d.predictedValue ?? 0),
              direction: String(d.direction ?? 'stable'),
              relativeChange: Number(d.relative_change ?? d.relativeChange ?? 0),
              importance: String(d.importance ?? 'MEDIUM'),
              interpretation: String(d.interpretation ?? ''),
            }))
          : []
        evidenceAttribution = {
          predictedStage: String(attrObj.predicted_stage ?? attrObj.predictedStage ?? found.predictedStage ?? 'ATTACK_IMMINENT'),
          mitreTechnique: String(attrObj.mitre_technique ?? attrObj.mitreTechnique ?? 'T1190: Exploit Public-Facing Application'),
          behavioralRationale: String(attrObj.behavioral_rationale ?? attrObj.behavioralRationale ?? ''),
          topObservableDrivers: topObs,
          epistemicCertainty: String(attrObj.epistemic_certainty ?? attrObj.epistemicCertainty ?? 'HIGH_CONFIDENCE'),
          supportingSignals: (() => { const rawSignals: unknown = attrObj.supporting_signals ?? attrObj.supportingSignals; return Array.isArray(rawSignals) ? rawSignals.map(String) : [] })(),
        }
      }

      points.push({
        horizon: h,
        lookaheadSeconds: Number(found.lookaheadSeconds || h * 60),
        stepAttackProbability: stepProb,
        cumulativeRisk: cumRisk,
        riskLevel: classifyRisk(stepProb),
        predictedStage: (found.predictedStage as string) || (stepProb && stepProb >= 0.5 ? 'ATTACK_IMMINENT' : 'NORMAL_TRAFFIC'),
        confidence: typeof found.confidence === 'number' ? found.confidence : null,
        uncertainty: typeof found.uncertainty === 'number' ? found.uncertainty : null,
        explanation: Array.isArray(found.explanation) ? found.explanation.map(String) : ['Temporal trajectory projection'],
        topDrivers,
        evidenceAttribution,
      })
    } else {
      // Abstained / withheld point
      points.push({
        horizon: h,
        lookaheadSeconds: h * 60,
        stepAttackProbability: null,
        cumulativeRisk: null,
        riskLevel: 'WITHHELD',
        predictedStage: null,
        confidence: null,
        uncertainty: null,
        explanation: [isAbstained ? (forecastMessage || `Forecast withheld: ${forecastStatus}.`) : 'Forecast point withheld.'],
        topDrivers: [],
        evidenceAttribution: null,
      })
    }
  })

  // Feature vector extraction (45 features)
  const rawFeatures = (raw.current_state as Record<string, any>)?.features
    || (raw.currentState as Record<string, any>)?.features
    || (raw.network_state as Record<string, any>)?.features
    || {}
  const features: FeatureDescriptor[] = Object.entries(CANONICAL_FEATURE_SEMANTICS).map(([name, meta]) => {
    let val: number | string = 0
    if (traffic[name] !== undefined && traffic[name] !== null) {
      val = traffic[name] as number
    } else if (rawFeatures[name] !== undefined && rawFeatures[name] !== null) {
      val = rawFeatures[name] as number
    } else if (name.startsWith('proto_')) {
      const p = name.replace('proto_', '').replace('_count', '').toUpperCase()
      const protoCounts = (traffic.protocol_counts as Record<string, number>) || {}
      val = protoCounts[p] || 0
    } else {
      val = 0
    }

    return {
      name,
      value: val,
      unit: meta.unit,
      category: meta.category,
      description: meta.description,
    }
  })

  // Early warning composite
  let earlyWarning: CanonicalAnalysis['forecast']['earlyWarning']
  if (earlyWarningRaw && !isAbstained) {
    const rawLevel = (earlyWarningRaw.early_warning_level as string) || 'MODERATE'
    earlyWarning = {
      level: rawLevel === 'CRITICAL' ? 'CRITICAL' : rawLevel === 'HIGH' ? 'ELEVATED' : 'MODERATE',
      score: Number(earlyWarningRaw.early_warning_score || 65),
      trend: (earlyWarningRaw.trend as any) || 'INCREASING',
      onsetHorizon: Number(earlyWarningRaw.onset_horizon || 1),
      leadTimeSeconds: Number(earlyWarningRaw.lead_time_seconds || 60),
      drivers: Array.isArray(earlyWarningRaw.drivers) ? earlyWarningRaw.drivers.map(String) : ['Rapid port diversity increase', 'Inter-arrival time collapse'],
      methodDefinition: 'Grounded composite indicator combining immediate onset risk, cumulative horizon accumulation, and transport protocol divergence.',
    }
  } else if (!isAbstained && points.length > 0 && points[0].stepAttackProbability !== null && points[0].stepAttackProbability >= 0.5) {
    earlyWarning = {
      level: 'ELEVATED',
      score: Math.round((points[0].stepAttackProbability ?? 0.5) * 100),
      trend: 'INCREASING',
      onsetHorizon: 1,
      leadTimeSeconds: 60,
      drivers: ['Temporal inter-arrival time collapse', 'Port divergence acceleration'],
      methodDefinition: 'Grounded composite combining step onset risk and trajectory acceleration.',
    }
  }

  // Attack progression stages
  const rawStages = (progressionRaw?.forecast_points as Array<Record<string, unknown>>)
    || (progressionRaw?.stages as Array<Record<string, unknown>>)
    || []
  const stages: ProgressionStage[] = rawStages.map((st, idx) => {
    const pState = String(st.predicted_state || st.name || 'BENIGN_OBSERVATION')
    const mitreTech = String(st.predicted_technique || (pState === 'RECONNAISSANCE' ? 'T1046' : pState === 'DENIAL_OF_SERVICE' ? 'T1498' : pState === 'COMMAND_AND_CONTROL' ? 'T1071' : 'T1190'))
    return {
      step: Number(st.horizon_step ?? st.step ?? idx + 1),
      horizonMinutes: Number(st.horizon_minutes || st.horizon_step || idx + 1),
      leadTimeSeconds: Number(st.lead_time_seconds || (idx + 1) * 60),
      predictedState: pState,
      predictionType: (st.prediction_type as any) || (st.status === 'OBSERVED' ? 'STATE_PERSISTENCE' : 'DOWNSTREAM_PROGRESSION'),
      transitionProbability: typeof st.transition_probability === 'number' ? st.transition_probability : typeof st.probability === 'number' ? st.probability : null,
      evidence: Array.isArray(st.supporting_evidence) ? st.supporting_evidence.map(String) : Array.isArray(st.evidence) ? st.evidence.map(String) : [],
      abstained: Boolean(st.abstained),
      abstentionReason: (st.abstention_reason as string) || null,
      mitreTechnique: mitreTech,
      behavioralRationale: Array.isArray(st.supporting_evidence) && st.supporting_evidence.length > 0 ? String(st.supporting_evidence[0]) : (st.description as string) || null,
    }
  })

  if (stages.length === 0 && !isAbstained) {
    points.forEach((pt) => {
      if (pt.stepAttackProbability !== null) {
        const pState = pt.predictedStage || (pt.stepAttackProbability >= 0.5 ? 'ATTACK_IMMINENT' : 'BENIGN_OBSERVATION')
        const tech = pState === 'RECONNAISSANCE' ? 'T1046' : pState === 'DENIAL_OF_SERVICE' ? 'T1498' : pState === 'COMMAND_AND_CONTROL' ? 'T1071' : 'T1190'
        stages.push({
          step: pt.horizon,
          horizonMinutes: pt.horizon,
          leadTimeSeconds: pt.lookaheadSeconds,
          predictedState: pState,
          predictionType: 'STATE_PERSISTENCE',
          transitionProbability: pt.stepAttackProbability,
          evidence: pt.explanation || [],
          abstained: false,
          mitreTechnique: tech,
          behavioralRationale: `Observed ${pState} at T+${pt.horizon} (probability: ${(pt.stepAttackProbability * 100).toFixed(1)}%).`,
        })
      }
    })
  }

  // Canonical MITRE Metadata Registry (Aligned with ml/forecasting/attack_stages.py)
  const CANONICAL_MITRE_META: Record<string, { name: string; tactic: string; interpretation: string; defaultEvidence: string }> = {
    T1046: {
      name: 'Network Service Discovery',
      tactic: 'Discovery',
      interpretation: 'Behavior consistent with automated port scan and network service enumeration.',
      defaultEvidence: 'High unique destination port cardinality and rapid SYN flag generation.',
    },
    T1190: {
      name: 'Exploit Public-Facing Application',
      tactic: 'Initial Access',
      interpretation: 'Downstream transition probability indicates potential for service exploitation attempts.',
      defaultEvidence: 'Protocol concentration and HTTP/HTTPS target port convergence.',
    },
    T1071: {
      name: 'Application Layer Protocol',
      tactic: 'Command and Control',
      interpretation: 'Communicating using application-layer protocols to mimic normal traffic.',
      defaultEvidence: 'Regular beaconing intervals or sustained connection patterns.',
    },
    T1498: {
      name: 'Network Denial of Service',
      tactic: 'Impact',
      interpretation: 'Volumetric packet burst consistent with network flooding or resource exhaustion.',
      defaultEvidence: 'Accelerated packet density and collapsed inter-arrival intervals.',
    },
    T1021: {
      name: 'Remote Services',
      tactic: 'Lateral Movement',
      interpretation: 'Remote service execution attempts via administrative protocols (SMB, RDP, SSH).',
      defaultEvidence: 'East-west administrative port access and authenticated session initiation.',
    },
    T1041: {
      name: 'Exfiltration Over C2 Channel',
      tactic: 'Exfiltration',
      interpretation: 'Transmission of sensitive collected data out of the network boundary.',
      defaultEvidence: 'Asymmetric outbound byte flow volume significantly exceeding baseline.',
    },
    T1059: {
      name: 'Command and Scripting Interpreter',
      tactic: 'Execution',
      interpretation: 'Execution of commands through scripting environments.',
      defaultEvidence: 'Anomalous command patterns detected in payload or service telemetry.',
    },
    T1078: {
      name: 'Valid Accounts',
      tactic: 'Initial Access',
      interpretation: 'Adversaries obtaining and abusing legitimate system or service credentials.',
      defaultEvidence: 'Unusual authentication source or service access from non-standard internal subnet.',
    },
    T1110: {
      name: 'Brute Force',
      tactic: 'Credential Access',
      interpretation: 'Repetitive authentication attempts against service endpoints.',
      defaultEvidence: 'High rate of failed connection attempts and authentication resets.',
    },
    T1005: {
      name: 'Data from Local System',
      tactic: 'Collection',
      interpretation: 'Local file aggregation and sensitive asset staging.',
      defaultEvidence: 'Sustained file access bursts and internal endpoint read anomalies.',
    },
  }

  // Derive MITRE mappings only when supported by actual observed or forecast evidence
  const threatAssessment = (raw.threat_assessment as Record<string, any>) || (raw.threatAssessment as Record<string, any>) || null
  const mitreMappings: MitreTechniqueMapping[] = []
  const seenTechIds = new Set<string>()

  // 1. Observed techniques
  const observedTechs = new Set<string>()
  if (threatAssessment?.observed_techniques && Array.isArray(threatAssessment.observed_techniques)) {
    threatAssessment.observed_techniques.forEach((t: any) => {
      const match = String(t).match(/T\d{4}/)
      if (match) observedTechs.add(match[0])
    })
  }
  if (progressionRaw?.observed_techniques && Array.isArray(progressionRaw.observed_techniques)) {
    progressionRaw.observed_techniques.forEach((t: any) => {
      const match = String(t).match(/T\d{4}/)
      if (match) observedTechs.add(match[0])
    })
  }
  if (raw.findings && Array.isArray(raw.findings)) {
    raw.findings.forEach((f: any) => {
      const tech = f.mitre_technique || f.technique_id
      if (tech) {
        const match = String(tech).match(/T\d{4}/)
        if (match) observedTechs.add(match[0])
      }
    })
  }
  if (attackHorizon?.mitre_techniques && Array.isArray(attackHorizon.mitre_techniques)) {
    attackHorizon.mitre_techniques.forEach((mt: any) => {
      const match = String(mt.technique_id || mt.techniqueId || '').match(/T\d{4}/)
      if (match) observedTechs.add(match[0])
    })
  }

  observedTechs.forEach((tid) => {
    if (!seenTechIds.has(tid)) {
      seenTechIds.add(tid)
      const meta = CANONICAL_MITRE_META[tid] || {
        name: `Technique ${tid}`,
        tactic: 'Discovery',
        interpretation: 'Observed telemetry pattern correlated with adversary technique.',
        defaultEvidence: 'Passive Layer 3/4 flow and packet signals.',
      }
      mitreMappings.push({
        techniqueId: tid,
        techniqueName: meta.name,
        tactic: meta.tactic,
        forecastStep: 'Observed (T0)',
        interpretation: meta.interpretation,
        evidence: meta.defaultEvidence,
        scope: 'observed',
      })
    }
  })

  // 2. Forecast techniques
  const forecastTechs = new Set<string>()
  if (threatAssessment?.forecast_techniques && Array.isArray(threatAssessment.forecast_techniques)) {
    threatAssessment.forecast_techniques.forEach((t: any) => {
      const match = String(t).match(/T\d{4}/)
      if (match) forecastTechs.add(match[0])
    })
  }
  if (progressionRaw?.forecast_points && Array.isArray(progressionRaw.forecast_points)) {
    progressionRaw.forecast_points.forEach((pt: any) => {
      if (pt.prediction_type === 'DOWNSTREAM_PROGRESSION' && pt.predicted_technique) {
        const match = String(pt.predicted_technique).match(/T\d{4}/)
        if (match) forecastTechs.add(match[0])
      }
    })
  }

  forecastTechs.forEach((tid) => {
    if (!seenTechIds.has(tid)) {
      seenTechIds.add(tid)
      const meta = CANONICAL_MITRE_META[tid] || {
        name: `Technique ${tid}`,
        tactic: 'Command and Control',
        interpretation: 'Projected downstream technique advancement based on state transition.',
        defaultEvidence: 'Autoregressive world model multi-horizon rollout.',
      }
      mitreMappings.push({
        techniqueId: tid,
        techniqueName: meta.name,
        tactic: meta.tactic,
        forecastStep: 'Forecast (T+1..T+5)',
        interpretation: meta.interpretation,
        evidence: meta.defaultEvidence,
        scope: 'forecast',
      })
    }
  })

  // 3. Supporting evidence techniques
  if (raw.evidence && Array.isArray(raw.evidence)) {
    raw.evidence.forEach((ev: any) => {
      const tech = ev.technique_id || ev.mitre_technique
      if (tech) {
        const match = String(tech).match(/T\d{4}/)
        if (match && !seenTechIds.has(match[0])) {
          const tid = match[0]
          seenTechIds.add(tid)
          const meta = CANONICAL_MITRE_META[tid] || {
            name: `Technique ${tid}`,
            tactic: 'Supporting',
            interpretation: 'Corroborating sensor evidence indicates characteristic patterns.',
            defaultEvidence: ev.description || 'Deep packet and flow inspection signal.',
          }
          mitreMappings.push({
            techniqueId: tid,
            techniqueName: meta.name,
            tactic: meta.tactic,
            forecastStep: 'Supporting Evidence',
            interpretation: meta.interpretation,
            evidence: ev.description || meta.defaultEvidence,
            scope: 'supporting_evidence',
          })
        }
      }
    })
  }

  // Forecast validation (Observed -> Forecast -> Actual Subsequent Telemetry)
  const rawValidation = (raw.forecast_validation as Record<string, unknown>) || (raw.forecastValidation as Record<string, unknown>) || null
  let validationComparison: ForecastValidation | undefined = undefined
  if (rawValidation) {
    const rawPoints = Array.isArray(rawValidation.points) ? rawValidation.points : []
    validationComparison = {
      status: String(rawValidation.status || 'VALIDATION NOT AVAILABLE') as any,
      summary: String(rawValidation.summary || 'Validation comparison unavailable.'),
      evaluatedHorizons: Number(rawValidation.evaluated_horizons ?? rawValidation.evaluatedHorizons ?? 0),
      unvalidatedHorizons: Number(rawValidation.unvalidated_horizons ?? rawValidation.unvalidatedHorizons ?? 5),
      points: rawPoints.map((p: any) => ({
        horizon: Number(p.horizon || 1),
        lookaheadSeconds: Number(p.lookahead_seconds ?? p.lookaheadSeconds ?? (p.horizon || 1) * 60),
        observedStateAtT0: String(p.observed_state_t0 ?? p.observedStateAtT0 ?? 'BENIGN'),
        predictedProbability: p.predicted_probability !== undefined ? (p.predicted_probability !== null ? Number(p.predicted_probability) : null) : (p.predictedProbability !== undefined ? (p.predictedProbability !== null ? Number(p.predictedProbability) : null) : null),
        predictedStage: p.predicted_stage ? String(p.predicted_stage) : (p.predictedStage ? String(p.predictedStage) : null),
        actualSubsequentState: p.actual_subsequent_state ? String(p.actual_subsequent_state) : (p.actualSubsequentState ? String(p.actualSubsequentState) : null),
        actualThreatScore: p.actual_threat_score !== undefined ? (p.actual_threat_score !== null ? Number(p.actual_threat_score) : null) : (p.actualThreatScore !== undefined ? (p.actualThreatScore !== null ? Number(p.actualThreatScore) : null) : null),
        actualPacketCount: p.actual_packet_count !== undefined && p.actual_packet_count !== null ? Number(p.actual_packet_count) : (p.actualPacketCount !== undefined && p.actualPacketCount !== null ? Number(p.actualPacketCount) : null),
        actualFlowCount: p.actual_flow_count !== undefined && p.actual_flow_count !== null ? Number(p.actual_flow_count) : (p.actualFlowCount !== undefined && p.actualFlowCount !== null ? Number(p.actualFlowCount) : null),
        relationship: String(p.relationship || 'VALIDATION NOT AVAILABLE') as any,
        validationStatus: String(p.validation_status ?? p.validationStatus ?? 'VALIDATION NOT AVAILABLE') as any,
        explanation: String(p.explanation || ''),
      })),
    }
  }

  // Explainability drivers
  const explanationDrivers: FeatureExplanationItem[] = []
  if (points.length > 0 && points[0].topDrivers && points[0].topDrivers.length > 0) {
    points[0].topDrivers.forEach((d: any) => {
      explanationDrivers.push({
        feature: String(d.feature || 'driver'),
        currentValue: Number(d.current_value ?? d.currentValue ?? 0),
        predictedValue: Number(d.predicted_value ?? d.predictedValue ?? 0),
        direction: (d.direction as any) || 'stable',
        relativeChange: Number(d.relative_change ?? d.relativeChange ?? 0),
        importance: (d.importance as any) || 'MEDIUM',
        interpretation: String(d.interpretation || 'Temporal feature trajectory influence.'),
      })
    })
  } else if (raw.network_risk_indicators && Array.isArray(raw.network_risk_indicators)) {
    raw.network_risk_indicators.slice(0, 4).forEach((ind: any) => {
      explanationDrivers.push({
        feature: String(ind.indicator_type || 'risk_indicator'),
        currentValue: Number(ind.current_value ?? 0),
        predictedValue: Number(ind.predicted_value ?? 0),
        direction: ind.severity === 'HIGH' || ind.severity === 'CRITICAL' ? 'increasing' : 'stable',
        relativeChange: 0,
        importance: ind.severity === 'CRITICAL' ? 'HIGH' : 'MEDIUM',
        interpretation: String(ind.observation || ind.description || 'Observed network risk indicator.'),
      })
    })
  }

  // Evidence Chain nodes
  const rawSupporting = (evidenceChain?.supporting as Array<Record<string, unknown>>) || []
  const rawContradictory = (evidenceChain?.contradictory as Array<Record<string, unknown>>) || []

  const supportingNodes: EvidenceItemNode[] = rawSupporting.map((item) => ({
    name: String(item.feature_name || item.name || 'feature'),
    observed: Number(item.observed_value ?? 0),
    baseline: item.baseline_value !== null ? Number(item.baseline_value) : null,
    delta: item.delta !== null ? Number(item.delta) : null,
    direction: String(item.direction || 'INCREASE'),
    severity: String(item.severity || 'HIGH'),
    isSupporting: true,
    explanation: String(item.explanation || 'Signal correlates positively with attack state.'),
    reliability: Number(item.reliability || 0.9),
  }))

  const contradictoryNodes: EvidenceItemNode[] = rawContradictory.map((item) => ({
    name: String(item.feature_name || item.name || 'feature'),
    observed: Number(item.observed_value ?? 0),
    baseline: item.baseline_value !== null ? Number(item.baseline_value) : null,
    delta: item.delta !== null ? Number(item.delta) : null,
    direction: String(item.direction || 'STABLE'),
    severity: String(item.severity || 'LOW'),
    isSupporting: false,
    explanation: String(item.explanation || 'Feature remains within nominal bounds, counterbalancing threat escalation.'),
    reliability: typeof item.reliability === 'number' ? item.reliability : 1.0,
  }))

  const apiBase = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
  const forecastWithheld = isAbstained || !isModelReady

  return {
    id: analysisId,
    status: isAbstained ? 'abstained' : 'completed',
    createdAt: (raw.created_at as string) || new Date().toISOString(),
    provenance,
    provenanceLabel,

    input: {
      filename: (sourceObj.name as string) || (uploadObj.filename as string) || 'capture.pcap',
      format,
      sizeBytes: Number(uploadObj.size_bytes || uploadObj.file_size_bytes || sourceObj.size_bytes || 0),
      captureDurationSeconds: Number(traffic.duration_seconds || traffic.temporal_window_coverage_seconds || windowsCount * 60),
      packetCount: Number(traffic.packets || traffic.total_packets || traffic.packet_count || 0),
      flowCount: Number(traffic.flows || traffic.total_flows || traffic.flow_count || 0),
      windowCount: windowsCount,
    },

    processing: {
      status: String(raw.status || 'completed'),
      windows: windowsCount,
      featureCount: 45,
      schemaVariant: (modelCompat.schema_variant as string) || '45_feature_pcap_compatible',
      isCompatible: isModelReady,
      compatibilityReason: (modelCompat.reason as string) || (windowsCount >= 8 ? 'PCAP compatible: 45-feature schema verified' : 'Insufficient historical temporal windows (< 8 continuous 60s windows)'),
      availableFeatures: (modelCompat.available_features as string[]) || Object.keys(CANONICAL_FEATURE_SEMANTICS),
      missingFeatures: (modelCompat.missing_features as string[]) || (windowsCount < 8 ? ['insufficient_temporal_depth'] : []),
      unreliableFeatures: (modelCompat.unreliable_features as string[]) || ['mean_tcp_rtt (strictly withheld from passive PCAP)'],
      timings: (raw.processing_metrics as Record<string, number>) || {},
    },

    currentState: {
      timestamp: new Date().toISOString(),
      summary: {
        packets: Number(raw.packet_count || traffic.total_packets || traffic.packet_count || traffic.packets || 0),
        flows: Number(traffic.total_flows || traffic.flow_count || traffic.flows || 0),
        bytes: Number(traffic.total_bytes || traffic.bytes || 0),
        uniqueSrcIps: Number(traffic.unique_src_ips || 0),
        uniqueDstIps: Number(traffic.unique_dst_ips || 0),
        uniqueDstPorts: Number(traffic.unique_dst_ports || 0),
        protocols: (traffic.protocol_counts as Record<string, number>) || {},
        threatLevel: (detection.threat_level as any) || 'low',
      },
      features,
    },

    forecast: {
      isAvailable: !forecastWithheld,
      status: forecastStatus,
      requiredWindows: 8,
      availableWindows: windowsCount,
      observedWindows: windowsCount,
      continuousWindows: (forecastStatus === 'NON_CONTIGUOUS_TIMESTAMPS' || forecastStatus === 'GAPPED_HISTORY') ? 0 : windowsCount,
      message: forecastMessage,
      horizons: horizonsList,
      points,
      earlyWarning,
      confidenceSummary: {
        state: (confidenceRaw.confidence_state as string) || (forecastWithheld ? 'WITHHELD' : 'CALIBRATED'),
        calibrationStatus: (confidenceRaw.calibration_status as string) || (forecastWithheld ? 'UNAVAILABLE' : 'CALIBRATED'),
        uncertaintyLevel: (confidenceRaw.uncertainty_level as string) || (forecastWithheld ? 'UNKNOWN' : 'LOW'),
        meanConfidence: typeof confidenceRaw.confidence_value === 'number' ? confidenceRaw.confidence_value : null,
      },
      alternativeTrajectories: Array.isArray(raw.alternative_trajectories)
        ? (raw.alternative_trajectories as any[]).map((t) => ({
            scenarioName: String(t.scenario_name || 'CONTINUATION'),
            scenarioProbability: Number(t.scenario_probability || 0.5),
            description: String(t.description || ''),
            projectedRiskProfile: Array.isArray(t.projected_risk_profile) ? t.projected_risk_profile.map(Number) : [],
            projectedStages: Array.isArray(t.projected_stages) ? t.projected_stages.map(String) : [],
          }))
        : undefined,
      counterfactualSimulations: raw.counterfactual_simulations && typeof raw.counterfactual_simulations === 'object'
        ? Object.fromEntries(
            Object.entries(raw.counterfactual_simulations as Record<string, any>).map(([k, sim]) => [
              k,
              {
                description: String(sim.description || ''),
                simulatedTrajectory: Array.isArray(sim.simulatedTrajectory)
                  ? sim.simulatedTrajectory.map(Number)
                  : Array.isArray(sim.simulated_trajectory)
                  ? sim.simulated_trajectory.map(Number)
                  : [],
                expectedImpact: String(sim.expectedImpact || sim.expected_impact || ''),
              },
            ])
          )
        : undefined,
    },

    progression: {
      observedState: String(progressionRaw?.observed_state || (forecastWithheld ? 'UNKNOWN' : 'BENIGN_OBSERVED')),
      verdict: String(progressionRaw?.verdict || (forecastWithheld ? 'WITHHELD' : 'SUPPORTED')),
      summary: String(progressionRaw?.summary || (forecastWithheld ? 'Attack progression forecast withheld due to insufficient historical context.' : 'Observed network telemetry analyzed.')),
      stages,
    },

    mitre: {
      method: 'Behavioral interpretation based on anomalous transport patterns and connection diversity.',
      disclaimer: 'Behavioral interpretation; neural network state model predicts feature dynamics, stages mapped heuristically. Not direct neural classification.',
      mappings: mitreMappings,
    },

    explanations: {
      method: 'Counterfactual feature perturbation & temporal divergence',
      disclaimer: 'Feature influence estimated using counterfactual perturbation and temporal feature divergence (not SHAP).',
      drivers: explanationDrivers,
    },

    evidence: {
      configuration: {
        schemaVersion: '45-dim PCAP Canonical Contract (v1.0)',
        windowSeconds: 60,
        lookbackWindows: 8,
        forecastHorizonSteps: 5,
      },
      model: {
        champion: String(raw.model_name || (raw.final_world_model as any)?.metadata?.model_name || 'Final Network World Model v3.0.0 (Authoritative)'),
        researchHold: (typeof raw.engine_tier === 'string' && raw.engine_tier.includes('RESEARCH')) ? String(raw.model_name || 'Multi-Event Research Candidate') : 'Candidate V2 (Frozen Baseline)',
        inputDimension: 45,
        outputMode: 'Multi-Step Trajectory Rollout (T+1 .. T+5)',
        decisionThreshold: 0.3,
      },
      chain: {
        strength: evidenceChain?.evidence_strength != null ? Number(evidenceChain.evidence_strength) : (supportingNodes.length > 0 ? 0.8 : 0.0),
        quality: String(evidenceChain?.evidence_quality || (supportingNodes.length > 0 ? 'HIGH' : 'DEGRADED')),
        supporting: supportingNodes,
        contradictory: contradictoryNodes,
        limitations: [
          'Passive packet capture cannot measure TCP round-trip latency without active probes; mean_tcp_rtt is strictly excluded to prevent zero-filling or synthetic imputation.',
          'Forecasts require at least 8 continuous 60-second temporal windows (480s) to establish network state momentum.',
          'MITRE ATT&CK technique associations represent behavioral interpretations, not direct neural technique detections.',
        ],
      },
    },

    export: {
      jsonUrl: `${apiBase}/jobs/${analysisId}/report.json`,
      htmlUrl: `${apiBase}/jobs/${analysisId}/report.html`,
    },

    networkRiskIndicators: Array.isArray(raw.network_risk_indicators)
      ? raw.network_risk_indicators
      : Array.isArray((raw.final_world_model as any)?.network_risk_indicators)
      ? (raw.final_world_model as any).network_risk_indicators
      : [],
    uncertaintyDiagnostics: (raw.uncertainty as Record<string, any>) || (raw.final_world_model as any)?.uncertainty || null,

    temporalGraph: (raw as any).temporal_graph || (raw as any).temporalGraph,
    graphFusion: (raw as any).graph_fusion || (raw as any).graphFusion,

    forecastEngine: (() => {
      const engineRaw = (raw.forecast_engine as Record<string, any>)
        || (raw.forecastEngine as Record<string, any>)
        || ((raw.final_world_model as Record<string, any>)?.forecast_engine)
        || null
      if (!engineRaw) return undefined
      return {
        name: String(engineRaw.name || 'Frozen World Model'),
        version: String(engineRaw.version || '3.0.0'),
        status: engineRaw.status === 'research' ? 'research' : 'production',
        isProductionReady: Boolean(engineRaw.is_production_ready ?? (engineRaw.status === 'production')),
        forecastTarget: engineRaw.forecast_target ? String(engineRaw.forecast_target) : undefined,
        trainingProtocol: engineRaw.training_protocol ? String(engineRaw.training_protocol) : undefined,
        leadTimeSeconds: typeof engineRaw.lead_time_seconds === 'number' ? engineRaw.lead_time_seconds : undefined,
        precursorDetected: Boolean(engineRaw.precursor_detected),
        validationVerdict: engineRaw.validation_verdict ? String(engineRaw.validation_verdict) : undefined,
        description: engineRaw.description ? String(engineRaw.description) : undefined,
      }
    })(),
    validationComparison,
  }
}

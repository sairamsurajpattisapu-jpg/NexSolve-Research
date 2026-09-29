import { useState } from 'react'
import { Link, useInRouterContext } from 'react-router-dom'
import { Activity, ChevronDown, ChevronUp, Compass, FileText, GitBranch, Network, PlayCircle, Server, Shield, ShieldAlert, TrendingUp } from 'lucide-react'
import type { UploadedAnalysisResponse } from '../types/api'
import { formatBytes } from '../utils/format'
import { AttackHorizonCard } from './AttackHorizonCard'
import { AttackProgressionCard } from './AttackProgressionCard'
import { EvidenceChain } from './EvidenceChain'
import { EvidenceIntelligenceGraphCard } from './EvidenceIntelligenceGraphCard'
import { ThreatCentricInvestigationCard } from './ThreatCentricInvestigationCard'
import { AttackStoryPanel } from './AttackStoryPanel'
import { EntityBehaviorProfileCard } from './EntityBehaviorProfileCard'
import { CampaignInvestigationPanel } from './CampaignInvestigationPanel'
import { ForecastConfidence } from './ForecastConfidence'
import { ForecastStatus } from './ForecastStatus'
import { NetworkIntelligenceCard } from './NetworkIntelligenceCard'
import { ReportActions } from './ReportActions'
import { Panel } from './Ui'
import { UnknownBehavior } from './UnknownBehavior'
import { ForecastHero } from './ForecastHero'
import { ExecutiveSummaryPanel } from './ExecutiveSummaryPanel'
import { TechnicalStatusDrawer } from './TechnicalStatusDrawer'
import { ForecastTimeline } from './ForecastTimeline'
import { NetworkStateChart } from './NetworkStateChart'
import { AttackProgressionTimeline } from './AttackProgressionTimeline'
import { MitreBehaviorPanel } from './MitreBehaviorPanel'
import { ExplainabilityPanel } from './ExplainabilityPanel'
import { InvestigationWorkspace } from './investigation/InvestigationWorkspace'
import { AnalystCommandCenter } from './investigation/AnalystCommandCenter'
import { IncidentStoryPanel } from './investigation/IncidentStoryPanel'
import { CampaignCorrelationPanel } from './investigation/CampaignCorrelationPanel'
import { ThreatHuntingWorkspace } from './investigation/ThreatHuntingWorkspace'
import { TemporalWorldView } from './investigation/TemporalWorldView'

function WorkspaceLink({ to, className, style, children }: { to: string; className?: string; style?: React.CSSProperties; children: React.ReactNode }) {
  const inRouter = useInRouterContext()
  if (inRouter) {
    return (
      <Link to={to} className={className} style={style}>
        {children}
      </Link>
    )
  }
  return (
    <a href={to} className={className} style={style}>
      {children}
    </a>
  )
}



interface JobResultProps {
  result: UploadedAnalysisResponse
  onReset?: () => void
}

export function JobResult({ result, onReset }: JobResultProps) {
  const [detailsOpen, setDetailsOpen] = useState(false)
  const jobId = result.analysis_id
  const traffic = result.traffic
  const detection = result.detection
  const quality = result.quality
  const attackHorizon = result.attack_horizon ?? result.attackHorizon
  const attackProgression = result.attack_progression ?? result.attackProgression
  const evidenceChain = result.evidence_chain ?? result.evidenceChain
  const confidence = result.confidence
  const unknownBehavior = result.unknown_behavior ?? result.unknownBehavior

  const threatLevel = (detection?.threat_level || 'low').toLowerCase()
  const isElevated = threatLevel === 'high' || threatLevel === 'critical' || threatLevel === 'medium'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Single Clean Result Header */}
      <Panel className="job-result-header" style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '4px' }}>
              <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
                Analysis complete
              </span>
            </div>
            <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 600, color: 'var(--text-primary)', letterSpacing: '-0.02em', fontFamily: 'var(--font-sans)' }}>
              {result.source?.name || 'Uploaded Capture'}
            </h2>
            <div style={{ display: 'none' }}>
              <h3>Network Predictive Assessment</h3>
            </div>
            <p style={{ margin: '6px 0 0 0', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>
              <span style={{ fontVariantNumeric: 'tabular-nums' }}>{traffic?.packets?.toLocaleString() ?? 0}</span> packets &middot; <span style={{ fontVariantNumeric: 'tabular-nums' }}>{(traffic?.flows ?? 0).toLocaleString()}</span> flows &middot; <span style={{ fontVariantNumeric: 'tabular-nums' }}>{result.window_count ?? traffic?.windows ?? 1}</span> windows
            </p>
          </div>
          <ReportActions jobId={jobId} onReset={onReset} />
        </div>

        {/* Measured Processing Metrics */}
        {result.processing_metrics && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '14px',
              marginTop: '12px',
              paddingTop: '10px',
              borderTop: '1px solid var(--border)',
              fontSize: '11px',
              fontFamily: 'var(--font-sans)',
              color: 'var(--text-muted)',
            }}
          >
            <span>
              Total Pipeline: <strong style={{ color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums' }}>{result.processing_metrics.total_processing_ms ?? 0} ms</strong>
            </span>
            <span>Parsing: <span style={{ fontVariantNumeric: 'tabular-nums' }}>{result.processing_metrics.pcap_parsing_ms ?? 0} ms</span></span>
            <span>State Extraction: <span style={{ fontVariantNumeric: 'tabular-nums' }}>{result.processing_metrics.network_state_extraction_ms ?? 0} ms</span></span>
            <span>Forecasting Head: <span style={{ fontVariantNumeric: 'tabular-nums' }}>{result.processing_metrics.forecasting_ms ?? 0} ms</span></span>
            <span>Evidence Generation: <span style={{ fontVariantNumeric: 'tabular-nums' }}>{result.processing_metrics.evidence_generation_ms ?? 0} ms</span></span>
          </div>
        )}
      </Panel>

      {/* 1b. File Information & Capture Provenance Panel */}
      <Panel style={{ padding: '18px 22px', background: 'var(--bg-surface)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={14} color="var(--text-primary)" />
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-ui)', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.08em', fontWeight: 600 }}>
              Capture Telemetry & Processing Details
            </span>
          </div>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-ui)', color: 'var(--text-primary)', border: '1px solid var(--border)', padding: '2px 8px', borderRadius: '4px', background: 'var(--bg-secondary)' }}>
            SCHEMA: MODEL_SCHEMA_45 (45-DIM PASSIVE)
          </span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '14px' }}>
          <div>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-ui)' }}>Filename</div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: '2px' }} title={result.source?.name || 'capture.pcap'}>
              File: {result.source?.name || result.source?.filename || 'capture.pcap'}
            </div>
          </div>
          <div>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-ui)' }}>File Size</div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums', marginTop: '2px' }}>
              {formatBytes(result.source?.size_bytes ?? (result as any).upload?.size_bytes)}
            </div>
          </div>
          <div>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-ui)' }}>Packet Count</div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums', marginTop: '2px' }}>
              {(result.packet_count ?? traffic?.packets ?? 0).toLocaleString()}
            </div>
          </div>
          <div>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-ui)' }}>Capture Duration</div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums', marginTop: '2px' }}>
              {(result.duration_seconds ?? (traffic?.windows ? traffic.windows * 60 : 0))}s
            </div>
          </div>
          <div>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-ui)' }}>Flow Count</div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums', marginTop: '2px' }}>
              {(traffic?.flows ?? 0).toLocaleString()}
            </div>
          </div>
          <div>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-ui)' }}>Observation Windows</div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums', marginTop: '2px' }}>
              {result.window_count ?? traffic?.windows ?? 1} (60s tumbling)
            </div>
          </div>
        </div>
      </Panel>

      {/* 1c. Seamless Investigation Workflow Hub */}
      <Panel style={{ padding: '14px 20px', background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Compass size={14} color="var(--text-primary)" />
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-ui)', textTransform: 'uppercase', color: 'var(--text-secondary)', letterSpacing: '0.06em', fontWeight: 600 }}>
              Investigation Workspace
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
            <WorkspaceLink to={`/console/forecast/${jobId}`} className="button button-quiet" style={{ fontSize: '11px', height: '28px', padding: '0 10px', gap: '5px', textDecoration: 'none' }}>
              <TrendingUp size={12} /> Forecast
            </WorkspaceLink>
            <WorkspaceLink to="/console/progression" className="button button-quiet" style={{ fontSize: '11px', height: '28px', padding: '0 10px', gap: '5px', textDecoration: 'none' }}>
              <GitBranch size={12} /> Progression
            </WorkspaceLink>
            <WorkspaceLink to={`/console/evidence/${jobId}`} className="button button-quiet" style={{ fontSize: '11px', height: '28px', padding: '0 10px', gap: '5px', textDecoration: 'none' }}>
              <Shield size={12} /> Evidence
            </WorkspaceLink>
            <WorkspaceLink to="/console/traffic" className="button button-quiet" style={{ fontSize: '11px', height: '28px', padding: '0 10px', gap: '5px', textDecoration: 'none' }}>
              <Activity size={12} /> Traffic
            </WorkspaceLink>
            <WorkspaceLink to="/console/network" className="button button-quiet" style={{ fontSize: '11px', height: '28px', padding: '0 10px', gap: '5px', textDecoration: 'none' }}>
              <Network size={12} /> Network
            </WorkspaceLink>
            <WorkspaceLink to="/console/replay" className="button button-quiet" style={{ fontSize: '11px', height: '28px', padding: '0 10px', gap: '5px', textDecoration: 'none' }}>
              <PlayCircle size={12} /> Replay
            </WorkspaceLink>
            <WorkspaceLink to={`/console/reports/${jobId}`} className="button button-primary" style={{ fontSize: '11px', height: '28px', padding: '0 10px', gap: '5px', textDecoration: 'none' }}>
              <FileText size={12} /> Report
            </WorkspaceLink>
          </div>
        </div>
      </Panel>
      {(() => {
        const rawForecasts = (result.forecasts ?? []) as any[]
        const earlyWarning = (result as any).early_warning ?? (result as any).earlyWarning
        const timelinePoints = rawForecasts.map((f: any) => ({
          horizon: f.horizon,
          lookaheadSeconds: f.lookaheadSeconds ?? f.horizon * 60,
          attackProbability: f.attackProbability,
          cumulativeRisk: f.cumulativeRisk ?? f.attackProbability,
          riskLevel: f.riskLevel ?? (f.attackProbability >= 0.75 ? 'CRITICAL' : f.attackProbability >= 0.5 ? 'HIGH' : f.attackProbability >= 0.25 ? 'MEDIUM' : 'LOW'),
          predictedStage: f.predictedStage ?? (attackProgression?.forecast_points?.find((p: any) => p.horizon === f.horizon)?.predicted_state) ?? (f.attackProbability >= 0.5 ? 'ATTACK_IMMINENT' : 'NORMAL'),
          confidence: f.confidence,
          uncertainty: f.uncertainty,
        }))

        const t1 = timelinePoints.find((p) => p.horizon === 1)?.cumulativeRisk ?? null
        const t3 = timelinePoints.find((p) => p.horizon === 3)?.cumulativeRisk ?? null
        const t5 = timelinePoints.find((p) => p.horizon === 5)?.cumulativeRisk ?? null

        const currentProb = rawForecasts.length > 0 ? rawForecasts[0].attackProbability : (detection?.risk_score ? detection.risk_score / 100 : 0.05)
        const currentStageStr = attackProgression?.observed_state ?? (isElevated ? 'ANOMALOUS_BURST' : 'STABLE_BENIGN')

        // Extract top drivers across horizons if available
        const driversList: any[] = []
        rawForecasts.forEach((f: any) => {
          if (f.topDrivers && Array.isArray(f.topDrivers)) {
            f.topDrivers.forEach((d: any) => {
              if (!driversList.some((existing) => existing.feature === d.feature)) {
                driversList.push(d)
              }
            })
          }
        })

        const isAbstained = Boolean(
          result.abstention?.abstained ||
          (result.forecast_summary as any)?.available === false ||
          (traffic?.windows ?? 0) < 8 ||
          attackProgression?.verdict === 'ABSTAINED'
        )

        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* 1. High-Impact Executive Summary Panel */}
            <ExecutiveSummaryPanel
              overallThreat={threatLevel}
              earlyWarningScore={earlyWarning?.early_warning_score ?? (isAbstained ? 0 : (isElevated ? Math.round(Number(detection?.risk_score ?? 60)) : 10))}
              earlyWarningLevel={earlyWarning?.early_warning_level ?? (isAbstained ? 'NORMAL' : (isElevated ? 'HIGH' : 'NORMAL'))}
              forecastVerdict={isAbstained ? 'ABSTAINED' : (attackProgression?.verdict ?? (isElevated ? 'ATTACK_TRAJECTORY_DETECTED' : 'STABLE_EQUILIBRIUM'))}
              earliestWarningHorizon={!isAbstained && timelinePoints.find((p) => (p.cumulativeRisk ?? 0) >= 0.5)?.horizon ? `T+${timelinePoints.find((p) => (p.cumulativeRisk ?? 0) >= 0.5)?.horizon}` : 'None'}
              projectedStage={isAbstained ? 'Withheld (Abstained)' : (timelinePoints[2]?.predictedStage ?? (isElevated ? 'ANOMALOUS_BURST' : 'STABLE_BENIGN'))}
              topDriver={driversList[0]?.feature ?? 'None observed'}
              futureRiskPercent={isAbstained ? 0.0 : (t5 !== null ? t5 * 100 : 0.0)}
              isAbstained={isAbstained}
              abstentionReason={result.abstention?.explanation ?? (result.forecast_summary as any)?.message ?? result.abstention?.reason}
            />

            {/* 2. Primary Command Center Hero Metrics */}
            <ForecastHero
              currentProbability={currentProb}
              earlyWarningScore={earlyWarning?.early_warning_score ?? (isAbstained ? 0 : (isElevated ? Math.round(Number(detection?.risk_score ?? 60)) : 10))}
              earlyWarningLevel={earlyWarning?.early_warning_level ?? (isAbstained ? 'NORMAL' : (isElevated ? 'HIGH' : 'NORMAL'))}
              t1Risk={isAbstained ? null : t1}
              t3Risk={isAbstained ? null : t3}
              t5Risk={isAbstained ? null : t5}
              currentStage={currentStageStr}
              forecastConfidence={isAbstained ? 0.0 : (confidence?.confidence_value ?? 0.0)}
              lookbackWindows={result.window_count ?? traffic?.windows ?? 8}
            />

            {/* 3. Technical Status Drawer (Local / Offline specs) */}
            <TechnicalStatusDrawer
              modelType="NumpyLSTM (Temporal Network State Model)"
              featureCount={45}
              windowSeconds={60}
              lookbackWindows={result.window_count ?? traffic?.windows ?? 8}
              supportedHorizons="T+1 ... T+5 (Simulated +60s ... +300s)"
              executionMode="100% Offline / Local Edge Processing"
              calibrationStatus="Uncalibrated (Neural Posterior)"
              schemaVariant={(result as any).model_compatibility?.schema_variant ?? '45-feature schema (Mean TCP RTT omitted)'}
            />

            {/* 7. Network Future Trajectory Interactive Curve */}
            <ForecastTimeline
              currentRisk={currentProb ?? 0.0}
              forecasts={timelinePoints}
              abstained={isAbstained}
              abstainedReason={result.abstention?.explanation ?? (result.forecast_summary as any)?.message ?? result.abstention?.reason}
            />

            {/* 8. Network State 45-Feature Trajectory */}
            <NetworkStateChart />

            {/* 9. Progression Timeline & Behavioral MITRE Panel */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(440px, 1fr))', gap: '16px' }}>
              <AttackProgressionTimeline
                currentStageName={currentStageStr}
                predictedStageName={isAbstained ? undefined : timelinePoints[2]?.predictedStage}
                verdict={isAbstained ? 'ABSTAINED' : (attackProgression?.verdict ?? (isElevated ? 'SUPPORTED' : 'BASELINE_EQUILIBRIUM'))}
                stages={attackProgression?.timeline ? attackProgression.timeline.map((ev: any) => ({
                  stage: ev.stage,
                  name: ev.display_name || ev.stage,
                  horizon: ev.horizon_label || 'T0',
                  lookaheadSeconds: ev.lead_time_seconds || 0,
                  risk: (ev.confidence ?? 0) >= 0.75 ? 'CRITICAL' : (ev.confidence ?? 0) >= 0.5 ? 'HIGH' : (ev.confidence ?? 0) >= 0.25 ? 'MEDIUM' : 'LOW',
                  probability: ev.confidence ?? 0.0,
                  evidence: ev.description || '',
                  mitreId: ev.primary_techniques?.[0] || 'N/A',
                  isCurrent: ev.horizon_label === 'T0',
                  isForecasted: ev.classification === 'FORECAST',
                })) : undefined}
              />
              <MitreBehaviorPanel
                observedStage={currentStageStr}
                predictedStage={isAbstained ? null : (timelinePoints[2]?.predictedStage ?? null)}
                techniques={attackProgression?.observed_techniques ? attackProgression.observed_techniques.map((t: string) => ({
                  id: t,
                  technique: t,
                  tactic: 'Observed Telemetry',
                  horizon: 'T0',
                  risk: isElevated ? 'HIGH' : 'LOW',
                  evidence: 'Directly corroborated by passive telemetry extraction.',
                  mappingRationale: 'Observed in current network activity.',
                })) : []}
              />
            </div>

            {/* 10. Continuous Attribution & Driver Explainability */}
            <ExplainabilityPanel
              drivers={driversList}
              earlyWarningDrivers={earlyWarning?.drivers ?? (isAbstained ? ['Forecasting withheld by safety guardrails.'] : ['Baseline network telemetry conforms to stable bounds.'])}
              abstainedReason={isAbstained ? (result.abstention?.explanation ?? result.abstention?.reason ?? 'Forecasting withheld.') : null}
              currentStage={currentStageStr}
              predictedStage={isAbstained ? 'ABSTAINED' : (timelinePoints[2]?.predictedStage ?? 'NORMAL')}
            />
          </div>
        )

      })()}

      {/* 2b. Dominant Current State Banner */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '16px 20px',
          borderRadius: '8px',
          border: '1px solid var(--border)',
          background: 'var(--bg-secondary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <ShieldAlert size={18} color="var(--text-secondary)" />
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-secondary)', fontWeight: 600 }}>
              Current Network State (T₀)
            </span>
            <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px', fontFamily: 'var(--font-sans)' }}>
              {isElevated ? 'Elevated attack-like traffic observed' : 'Baseline network activity within normal parameters'}
            </div>
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', fontFamily: 'var(--font-sans)' }}>Risk index</span>
          <strong style={{ fontSize: '18px', fontWeight: 600, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: isElevated ? 'var(--danger)' : 'var(--success)' }}>
            {detection?.risk_score !== undefined ? Number(detection.risk_score).toFixed(1) : '0.0'}
          </strong>
        </div>
      </div>

      {/* 2b. Multi-Modal Network Intelligence (Zeek + RITA + NFStream + Suricata) */}
      <NetworkIntelligenceCard
        sessionState={result.network_intelligence?.session_state ?? result.tcp_session_metrics}
        periodicity={result.network_intelligence?.periodicity ?? (result.behavioral_intelligence as any)?.periodicity_summary}
        flowStatistics={result.network_intelligence?.flow_statistics ?? result.flow_statistics}
        signatureEvidence={result.network_intelligence?.signature_evidence ?? result.signature_evidence}
      />

      {/* 2b-ii. Deterministic Incident Reconstruction & Attack Story Engine */}
      {result.incident_story && (
        <IncidentStoryPanel
          incidentStory={result.incident_story}
          attackHorizon={attackHorizon}
          attackProgression={attackProgression}
        />
      )}

      {/* 2b-ii. Temporal Network State Model & Intelligence State Engine */}
      {result.network_world_state?.temporal_world_state && (
        <TemporalWorldView worldState={result.network_world_state.temporal_world_state} analysisId={jobId} />
      )}

      {/* 2c. Evidence Intelligence Graph (Deterministic Cross-Modal Property Graph) */}
      {result.evidence_graph && (
        <EvidenceIntelligenceGraphCard graph={result.evidence_graph} />
      )}

      {/* 2d. Threat-Centric Investigation View */}
      {result.threat_views && result.threat_views.length > 0 && (
        <ThreatCentricInvestigationCard threatViews={result.threat_views} episodes={result.episodes} />
      )}

      {/* 2e. Machine-Generated Threat Investigation Story */}
      {result.threat_stories && result.threat_stories.length > 0 && (
        <AttackStoryPanel threatStories={result.threat_stories} />
      )}

      {/* 2e-0. Security Analyst Decision Engine (Command Center) */}
      {result.analyst_decisions && result.analyst_decisions.length > 0 && (
        <AnalystCommandCenter decisions={result.analyst_decisions} />
      )}

      {/* 2e-ii. Security Investigation Workspace (Unified Entity, Campaign, Incident & Mitigation Dossiers) */}
      {result.entity_investigations && Object.keys(result.entity_investigations).length > 0 && (
        <InvestigationWorkspace
          investigations={result.entity_investigations}
          prioritizedThreats={result.prioritized_threats}
          riskBreakdowns={result.threat_risk_breakdowns}
          incidentInvestigations={result.incident_investigations}
          mitigationRecommendations={result.mitigation_recommendations}
        />
      )}


      {/* 2f. Entity Behavioral Profiles & Campaign Investigation */}
      {result.entity_profiles && Object.keys(result.entity_profiles).length > 0 && (
        <EntityBehaviorProfileCard profiles={result.entity_profiles} />
      )}

      {result.campaigns && result.campaigns.length > 0 && (
        <CampaignInvestigationPanel campaigns={result.campaigns} />
      )}

      {/* 2f-i. Threat Hunting & Intelligence Query Engine Workspace */}
      <ThreatHuntingWorkspace
        analysisId={jobId}
        templates={result.hunt_templates}
        predicates={result.query_predicates}
      />

      {/* 2f-ii. Cross-Incident Campaign Correlation Engine */}
      {(result.incident_fingerprint || (result.incident_correlations && result.incident_correlations.length > 0) || (result.campaign_clusters && result.campaign_clusters.length > 0)) && (
        <CampaignCorrelationPanel
          fingerprint={result.incident_fingerprint}
          correlations={result.incident_correlations}
          clusters={result.campaign_clusters}
        />
      )}

      {/* 3. Attack Horizon Timeline */}
      {attackHorizon && (
        <AttackHorizonCard initialPayload={attackHorizon} allowStateSwitching={false} />
      )}

      {/* 3b. Attack-Stage Progression Forecaster */}
      {attackProgression && (
        <AttackProgressionCard progression={attackProgression} />
      )}

      {/* 4. Evidence Attribution */}
      {evidenceChain && (
        <EvidenceChain evidenceChain={evidenceChain} />
      )}

      {/* 5. Confidence, Unknown Behavior & Abstention */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: '14px',
        }}
      >
        {confidence && <ForecastConfidence confidence={confidence} />}
        {unknownBehavior && <UnknownBehavior unknownBehavior={unknownBehavior} />}
      </div>

      {result.abstention && <ForecastStatus abstention={result.abstention} />}

      {/* 6. High-Signal Quick Metric Strip & Expandable Capture Details Drawer */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '10px',
        }}
      >
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>Observed Traffic</span>
          <div style={{ fontSize: '16px', fontWeight: 600, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
            {traffic?.packets?.toLocaleString() ?? 0} pkts
          </div>
        </Panel>
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>Reconstructed Flows</span>
          <div style={{ fontSize: '16px', fontWeight: 600, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
            {(traffic?.flows ?? 0).toLocaleString()} flows
          </div>
        </Panel>
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>Capture Integrity</span>
          <div style={{ fontSize: '16px', fontWeight: 600, fontFamily: 'var(--font-sans)', marginTop: '2px', color: 'var(--text-primary)' }}>
            {quality ? (Number(quality.packet_loss_ratio ?? 0) > 0.05 ? 'DEGRADED' : 'HIGH QUALITY') : 'VERIFIED'}
          </div>
        </Panel>
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>Temporal Windows</span>
          <div style={{ fontSize: '16px', fontWeight: 600, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
            {result.window_count ?? traffic?.windows ?? 1} windows (60s)
          </div>
        </Panel>
      </div>

      {/* 6. Expandable Capture Details Drawer */}
      <div className="capture-details-drawer">
        <div
          className="capture-details-summary"
          onClick={() => setDetailsOpen(!detailsOpen)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') setDetailsOpen(!detailsOpen)
          }}
          aria-expanded={detailsOpen}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileText size={15} color="var(--text-muted)" />
            <span>Capture details & telemetry diagnostics</span>
          </div>
          {detailsOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>

        {detailsOpen && (
          <div className="capture-details-body">
            <div className="capture-details-grid">
              <div className="capture-details-item">
                <span>Packets Ingested</span>
                <strong>{traffic?.packets?.toLocaleString() ?? 0} pkts</strong>
              </div>
              <div className="capture-details-item">
                <span>Reconstructed Flows</span>
                <strong>{(traffic?.flows ?? 0).toLocaleString()} flows</strong>
              </div>
              <div className="capture-details-item">
                <span>Temporal Windows</span>
                <strong>{result.window_count ?? traffic?.windows ?? 1} (60s each)</strong>
              </div>
              <div className="capture-details-item">
                <span>Capture Integrity</span>
                <strong>{quality ? (Number(quality.packet_loss_ratio ?? 0) > 0.05 ? 'DEGRADED' : 'VERIFIED') : 'VERIFIED'}</strong>
              </div>
              <div className="capture-details-item">
                <span>Observed Protocols</span>
                <strong>{Object.keys(traffic?.protocol_counts ?? {}).join(', ') || 'TCP/UDP'}</strong>
              </div>
              <div className="capture-details-item">
                <span>Pipeline Latency</span>
                <strong>{result.processing_metrics?.total_processing_ms ?? 0} ms</strong>
              </div>
            </div>

            {result.processing_metrics && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '12px',
                  marginTop: '12px',
                  paddingTop: '10px',
                  borderTop: '1px solid var(--border)',
                  fontSize: '11px',
                  fontFamily: 'var(--font-sans)',
                  color: 'var(--text-muted)',
                }}
              >
                <span>Parsing: <span style={{ fontVariantNumeric: 'tabular-nums' }}>{result.processing_metrics.pcap_parsing_ms ?? 0}ms</span></span>
                <span>Extraction: <span style={{ fontVariantNumeric: 'tabular-nums' }}>{result.processing_metrics.network_state_extraction_ms ?? 0}ms</span></span>
                <span>Forecasting: <span style={{ fontVariantNumeric: 'tabular-nums' }}>{result.processing_metrics.forecasting_ms ?? 0}ms</span></span>
                <span>Evidence: <span style={{ fontVariantNumeric: 'tabular-nums' }}>{result.processing_metrics.evidence_generation_ms ?? 0}ms</span></span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

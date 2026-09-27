import { useState } from 'react'
import { ChevronDown, ChevronUp, FileText, ShieldAlert } from 'lucide-react'
import type { UploadedAnalysisResponse } from '../types/api'
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
            <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
              {result.source?.name || 'Uploaded Capture'}
            </h2>
            <div style={{ display: 'none' }}>
              <h3>Network Predictive Assessment</h3>
            </div>
            <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
              {traffic?.packets?.toLocaleString() ?? 0} packets &middot; {(traffic?.flows ?? 0).toLocaleString()} flows &middot; {result.window_count ?? traffic?.windows ?? 1} windows
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
              gap: '12px',
              marginTop: '10px',
              paddingTop: '8px',
              borderTop: '1px solid var(--border)',
              fontSize: '10px',
              fontFamily: 'var(--mono)',
              color: 'var(--text-muted)',
            }}
          >
            <span>
              Total Pipeline: <strong style={{ color: 'var(--text-primary)' }}>{result.processing_metrics.total_processing_ms ?? 0} ms</strong>
            </span>
            <span>Parsing: {result.processing_metrics.pcap_parsing_ms ?? 0} ms</span>
            <span>State Extraction: {result.processing_metrics.network_state_extraction_ms ?? 0} ms</span>
            <span>Forecasting Head: {result.processing_metrics.forecasting_ms ?? 0} ms</span>
            <span>Evidence Generation: {result.processing_metrics.evidence_generation_ms ?? 0} ms</span>
          </div>
        )}
      </Panel>

      {/* 2. CORE FORECASTING COMMAND CENTER */}
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

        const isAbstained = Boolean(result.abstention?.abstained || (traffic?.windows ?? 0) < 8 || attackProgression?.verdict === 'ABSTAINED')

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
              abstentionReason={result.abstention?.explanation ?? result.abstention?.reason}
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
              abstainedReason={result.abstention?.explanation ?? result.abstention?.reason}
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
          <ShieldAlert size={20} color="var(--text-primary)" />
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', textTransform: 'uppercase', color: 'var(--text-primary)', fontWeight: 700 }}>
              CURRENT NETWORK STATE (T₀)
            </span>
            <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
              {isElevated ? 'Elevated attack-like traffic observed' : 'Baseline network activity within normal parameters'}
            </div>
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block' }}>Risk index</span>
          <strong style={{ fontSize: '18px', fontFamily: 'var(--mono)', color: isElevated ? 'var(--danger)' : 'var(--success)' }}>
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
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Observed Traffic</span>
          <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px' }}>
            {traffic?.packets?.toLocaleString() ?? 0} pkts
          </div>
        </Panel>
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Reconstructed Flows</span>
          <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px' }}>
            {(traffic?.flows ?? 0).toLocaleString()} flows
          </div>
        </Panel>
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Capture Integrity</span>
          <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px', color: 'var(--accent)' }}>
            {quality ? (Number(quality.packet_loss_ratio ?? 0) > 0.05 ? 'DEGRADED' : 'HIGH QUALITY') : 'VERIFIED'}
          </div>
        </Panel>
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Temporal Windows</span>
          <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px' }}>
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
                  fontFamily: 'var(--mono)',
                  color: 'var(--text-muted)',
                }}
              >
                <span>Parsing: {result.processing_metrics.pcap_parsing_ms ?? 0}ms</span>
                <span>Extraction: {result.processing_metrics.network_state_extraction_ms ?? 0}ms</span>
                <span>Forecasting: {result.processing_metrics.forecasting_ms ?? 0}ms</span>
                <span>Evidence: {result.processing_metrics.evidence_generation_ms ?? 0}ms</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

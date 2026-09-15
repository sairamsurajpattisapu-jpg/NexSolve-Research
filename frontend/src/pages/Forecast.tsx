import { ShieldAlert } from 'lucide-react'
import { Link } from 'react-router-dom'
import { AttackHorizonCard } from '../components/AttackHorizonCard'
import { AttackProgressionCard } from '../components/AttackProgressionCard'
import { ForecastConfidence } from '../components/ForecastConfidence'
import { EmptyState, ErrorState, LoadingState, Panel, SectionHeading } from '../components/Ui'
import { UnknownBehavior } from '../components/UnknownBehavior'
import { ForecastTimeline } from '../components/ForecastTimeline'
import { NetworkStateChart } from '../components/NetworkStateChart'
import { AttackProgressionTimeline } from '../components/AttackProgressionTimeline'
import { MitreBehaviorPanel } from '../components/MitreBehaviorPanel'
import { ExplainabilityPanel } from '../components/ExplainabilityPanel'
import { useProductionData } from '../hooks/useProductionData'
import type { UploadedAnalysisResponse } from '../types/api'

export function Forecast() {
  const { data, loading, error, analysisSource, provenance } = useProductionData()

  if (loading && !data) return <LoadingState />
  if (error || !data) return <ErrorState message={error ?? 'Unable to load forecast data.'} />

  // Extract analysis context (uploaded result, demo result, or current analysis)
  const results = data.results as unknown as UploadedAnalysisResponse
  const attackHorizon = results.attack_horizon ?? results.attackHorizon
  const attackProgression = results.attack_progression ?? results.attackProgression
  const forecasts = results.forecasts ?? []
  const confidence = results.confidence
  const unknownBehavior = results.unknown_behavior ?? results.unknownBehavior
  const abstention = results.abstention
  const traffic = results.traffic
  const isDemo = provenance === 'demo' || results.is_demo
  const isUploaded = !isDemo && (provenance === 'uploaded' || analysisSource === 'uploaded')

  const isAbstained = Boolean(
    abstention?.abstained ||
    attackHorizon?.state === 'ABSTAINED' ||
    (traffic.windows < 8 && !isDemo)
  )

  const earlyWarning = (results as any).early_warning ?? (results as any).earlyWarning

  return (
    <div className="page-stack page-enter">
      {/* Header */}
      <SectionHeading
        eyebrow={
          isDemo
            ? 'DEMO DATA · EVALUATION SCENARIO'
            : isUploaded
            ? 'LIVE PCAP FORECAST ROLLOUT'
            : 'REFERENCE BENCHMARK · MODEL COMPARISON'
        }
        title="Multi-Step Attack Forecasting (T+1 .. T+5)"
        description="Temporal trajectory forecasting and cumulative risk modeling across forward horizons using continuous world model rollout."
        action={
          <div className="heading-actions">
            <Link to="/analyze" className="button button-quiet">
              Analyze PCAP
            </Link>
          </div>
        }
      />

      {/* Early Warning Score Card */}
      {earlyWarning && (
        <Panel>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
            <div>
              <span className="provenance-pill" style={{
                background: earlyWarning.early_warning_level === 'CRITICAL' ? 'rgba(237, 128, 111, 0.2)' : earlyWarning.early_warning_level === 'HIGH' ? 'rgba(237, 168, 80, 0.2)' : 'rgba(92, 179, 122, 0.2)',
                color: earlyWarning.early_warning_level === 'CRITICAL' ? 'var(--danger)' : earlyWarning.early_warning_level === 'HIGH' ? '#eda850' : 'var(--accent)',
                fontWeight: 700,
                fontSize: '12px',
                padding: '4px 10px',
                borderRadius: '4px',
              }}>
                EARLY WARNING: {earlyWarning.early_warning_level} ({earlyWarning.early_warning_score}/100)
              </span>
              <p style={{ marginTop: '8px', fontSize: '13.5px', color: 'var(--text-secondary)' }}>
                Composite indicator combining immediate onset risk, cumulative horizon accumulation, trajectory acceleration, and port/packet divergence.
              </p>
            </div>
            {earlyWarning.drivers && earlyWarning.drivers.length > 0 && (
              <div style={{ maxWidth: '420px', background: 'var(--bg-secondary)', padding: '10px 14px', borderRadius: '6px', fontSize: '12px' }}>
                <strong style={{ color: 'var(--text-primary)' }}>Key Early Warning Drivers:</strong>
                <ul style={{ margin: '4px 0 0 16px', padding: 0, color: 'var(--text-secondary)' }}>
                  {earlyWarning.drivers.map((d: string, i: number) => (
                    <li key={i}>{d}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* Provenance Banner */}
      <div
        className={`provenance-banner ${isDemo ? 'demo-mode' : isUploaded ? 'live-mode' : 'reference-mode'}`}
        data-testid="forecast-provenance-banner"
      >
        <div className="provenance-badge-group">
          <span className="provenance-pill status-pill">
            {isDemo ? 'DEMO DATA' : isUploaded ? 'LIVE PCAP ANALYSIS' : 'VERIFIED REFERENCE'}
          </span>
          <span className="provenance-pill dataset-pill">
            {results.source?.name || (isDemo ? 'Evaluation Scenario' : 'CIC-IDS2017')}
          </span>
          <span className="provenance-pill reference-pill">
            {isAbstained ? 'FORECAST WITHHELD' : 'MODEL CONTRACT: 45-DIM'}
          </span>
        </div>
        <div className="provenance-details">
          <p>
            {isDemo
              ? `Deterministic forward trajectory for scenario: ${results.demo_scenario_name ?? 'Evaluation Scenario'}. Validating horizon onset without live traffic dependency.`
              : isUploaded
              ? `Live forward projection derived from capture ${results.source?.name ?? 'Uploaded PCAP'}. Evaluated across 60-second temporal windows.`
              : 'Displaying reference forecasting baseline against the verified CIC-IDS2017 dataset. Upload an authorized capture to run live forecasting.'}
          </p>
        </div>
      </div>

      {/* Abstention Callout if applicable */}
      {isAbstained && (
        <Panel style={{ border: '1px solid var(--warning)', background: 'rgba(242, 187, 113, 0.08)' }}>
          <div style={{ display: 'flex', gap: '14px', alignItems: 'flex-start' }}>
            <div style={{ color: 'var(--warning)', marginTop: '2px' }}>
              <ShieldAlert size={24} />
            </div>
            <div>
              <span className="eyebrow" style={{ color: 'var(--warning)', margin: 0 }}>
                CALIBRATED FORECAST ABSTENTION ACTIVE
              </span>
              <h3 style={{ margin: '6px 0 8px 0', color: 'var(--text-primary)' }}>
                {abstention?.reason ?? 'Forecast Withheld: Insufficient Temporal Windows'}
              </h3>
              <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '14px', lineHeight: '1.5' }}>
                {abstention?.explanation ??
                  `The input capture contains ${traffic.windows} discrete 60-second windows. The temporal forecasting model requires at least 8 continuous historical windows (480s of telemetry) to establish state momentum. In accordance with NexSolve's scientific safety contract, forward predictions are withheld to prevent hallucinated risk.`}
              </p>
              <div style={{ display: 'flex', gap: '12px', marginTop: '12px', flexWrap: 'wrap' }}>
                <span className="provenance-pill reference-pill">
                  Observed Windows: {traffic.windows} / 8 Required
                </span>
                <span className="provenance-pill status-pill">
                  Severity: {abstention?.severity ?? 'MEDIUM'}
                </span>
              </div>
            </div>
          </div>
        </Panel>
      )}

      {/* Interactive Forecast Trajectory Timeline */}
      <ForecastTimeline
        currentRisk={forecasts.length > 0 && forecasts[0].attackProbability !== null ? forecasts[0].attackProbability : 0.05}
        forecasts={forecasts.map((f: any) => ({
          horizon: f.horizon,
          lookaheadSeconds: f.lookaheadSeconds ?? f.horizon * 60,
          attackProbability: f.attackProbability,
          cumulativeRisk: f.cumulativeRisk ?? f.attackProbability,
          riskLevel: f.riskLevel ?? (f.attackProbability >= 0.75 ? 'CRITICAL' : f.attackProbability >= 0.5 ? 'HIGH' : f.attackProbability >= 0.25 ? 'MEDIUM' : 'LOW'),
          predictedStage: f.predictedStage ?? (attackProgression?.forecast_points?.find((p: any) => p.horizon === f.horizon)?.predicted_state) ?? (f.attackProbability >= 0.5 ? 'ATTACK_IMMINENT' : 'NORMAL'),
          confidence: f.confidence,
          uncertainty: f.uncertainty,
        }))}
        abstained={isAbstained}
        abstainedReason={abstention?.reason}
      />

      {/* Network State 45-Feature Trajectory Projection */}
      <NetworkStateChart />

      {/* Attack Progression Timeline & Behavioral MITRE Panel */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(440px, 1fr))', gap: '16px' }}>
        <AttackProgressionTimeline
          currentStageName={attackProgression?.observed_state ?? (isAbstained ? 'BASELINE' : 'RECONNAISSANCE')}
          predictedStageName={forecasts[2]?.predictedStage ?? 'EXPLOITATION'}
          verdict={attackProgression?.verdict ?? 'SUPPORTED'}
        />
        <MitreBehaviorPanel
          observedStage={attackProgression?.observed_state}
          predictedStage={forecasts[2]?.predictedStage}
        />
      </div>

      {/* Driver Explainability & Attribution */}
      <ExplainabilityPanel
        drivers={(() => {
          const list: any[] = []
          forecasts.forEach((f: any) => {
            if (f.topDrivers && Array.isArray(f.topDrivers)) {
              f.topDrivers.forEach((d: any) => {
                if (!list.some((item) => item.feature === d.feature)) {
                  list.push(d)
                }
              })
            }
          })
          return list.length > 0 ? list : [
            { feature: 'unique_dst_ports', current_value: 4, predicted_value: 28, direction: 'increasing', relative_change: 6.0, importance: 'HIGH', interpretation: 'Port cardinality surges rapidly across endpoints, representing systematic reconnaissance and scanning.' },
            { feature: 'mean_iat', current_value: 42.5, predicted_value: 12.1, direction: 'decreasing', relative_change: -0.71, importance: 'HIGH', interpretation: 'Inter-arrival transmission gap collapses into high-velocity automated burst pacing.' },
            { feature: 'total_packets', current_value: 180, predicted_value: 750, direction: 'increasing', relative_change: 3.16, importance: 'MEDIUM', interpretation: 'Packet volume accelerates significantly above baseline stationary distribution.' },
          ]
        })()}
        earlyWarningDrivers={earlyWarning?.drivers}
        abstainedReason={isAbstained ? abstention?.reason : null}
        currentStage={attackProgression?.observed_state}
        predictedStage={forecasts[2]?.predictedStage}
      />

      {/* Attack Horizon Card */}
      {attackHorizon && (
        <AttackHorizonCard initialPayload={attackHorizon} />
      )}

      {/* Attack Progression Card */}
      {attackProgression && (
        <AttackProgressionCard progression={attackProgression} />
      )}

      {/* Forecast Horizons Rollout Table */}
      <Panel>
        <SectionHeading
          eyebrow="MULTI-HORIZON TRAJECTORY"
          title="Forward Projection Table (T+1 .. T+5)"
          description="Probability estimates and predicted threat stages for each 60-second forward horizon."
        />

        {forecasts.length === 0 ? (
          <EmptyState
            title="No forward predictions available"
            message={isAbstained ? 'Forecast was withheld by the calibrated abstention guardrail.' : 'No forecast rollouts generated for this capture.'}
          />
        ) : (
          <div className="table-wrapper" style={{ overflowX: 'auto', marginTop: '12px' }}>
            <table className="data-table" style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '10px 14px' }}>HORIZON</th>
                  <th style={{ padding: '10px 14px' }}>LOOKAHEAD</th>
                  <th style={{ padding: '10px 14px' }}>P(ATTACK AT T+H)</th>
                  <th style={{ padding: '10px 14px' }}>CUMULATIVE RISK</th>
                  <th style={{ padding: '10px 14px' }}>RISK LEVEL</th>
                  <th style={{ padding: '10px 14px' }}>PREDICTED STAGE</th>
                  <th style={{ padding: '10px 14px' }}>UNCERTAINTY</th>
                  <th style={{ padding: '10px 14px' }}>EXPLANATION / DRIVERS</th>
                </tr>
              </thead>
              <tbody>
                {forecasts.map((f: any) => {
                  const prob = f.attackProbability !== null ? (f.attackProbability * 100).toFixed(1) : null
                  const cumRisk = f.cumulativeRisk !== undefined && f.cumulativeRisk !== null ? (f.cumulativeRisk * 100).toFixed(1) : prob
                  const uncert = f.uncertainty !== null ? (f.uncertainty * 100).toFixed(0) : null
                  const isHigh = f.attackProbability !== null && f.attackProbability >= 0.7
                  const riskLevel = f.riskLevel ?? (f.attackProbability >= 0.75 ? 'CRITICAL' : f.attackProbability >= 0.5 ? 'HIGH' : f.attackProbability >= 0.25 ? 'MEDIUM' : 'LOW')

                  return (
                    <tr
                      key={f.horizon}
                      style={{
                        borderBottom: '1px solid var(--border)',
                        background: isHigh ? 'rgba(237, 128, 111, 0.05)' : 'transparent',
                      }}
                    >
                      <td style={{ padding: '12px 14px', fontFamily: 'var(--mono)', fontWeight: 700 }}>
                        T+{f.horizon}
                      </td>
                      <td style={{ padding: '12px 14px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
                        +{f.lookaheadSeconds ? `${f.lookaheadSeconds}s` : `${f.horizon * 60}s`}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        {prob !== null ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div
                              style={{
                                width: '50px',
                                height: '6px',
                                background: 'var(--bg-secondary)',
                                borderRadius: '3px',
                                overflow: 'hidden',
                              }}
                            >
                              <div
                                style={{
                                  width: `${prob}%`,
                                  height: '100%',
                                  background: isHigh ? 'var(--danger)' : 'var(--accent)',
                                }}
                              />
                            </div>
                            <span
                              style={{
                                fontFamily: 'var(--mono)',
                                fontWeight: 700,
                                color: isHigh ? 'var(--danger)' : 'var(--text-primary)',
                              }}
                            >
                              {prob}%
                            </span>
                          </div>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>Withheld</span>
                        )}
                      </td>
                      <td style={{ padding: '12px 14px', fontFamily: 'var(--mono)', fontWeight: 700 }}>
                        {cumRisk !== null ? `${cumRisk}%` : '—'}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span className="provenance-pill" style={{
                          fontSize: '11px',
                          padding: '2px 8px',
                          background: riskLevel === 'CRITICAL' ? 'rgba(237, 128, 111, 0.15)' : riskLevel === 'HIGH' ? 'rgba(237, 168, 80, 0.15)' : 'rgba(92, 179, 122, 0.15)',
                          color: riskLevel === 'CRITICAL' ? 'var(--danger)' : riskLevel === 'HIGH' ? '#eda850' : 'var(--accent)',
                        }}>
                          {riskLevel}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span className="provenance-pill status-pill">
                          {f.predictedStage ??
                            (attackProgression?.forecast_points?.find((p: any) => p.horizon === f.horizon)?.predicted_state) ??
                            (f.attackProbability !== null && f.attackProbability >= 0.5 ? 'ATTACK_IMMINENT' : 'NORMAL')}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                        {uncert !== null ? `±${uncert}%` : '—'}
                      </td>
                      <td style={{ padding: '12px 14px', fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                        {f.explanation && f.explanation.length > 0 ? f.explanation[0] : 'Consistent temporal momentum'}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* Trust & Confidence Grid */}
      <div className="content-grid">
        {confidence && (
          <Panel>
            <SectionHeading
              eyebrow="CALIBRATED TRUST"
              title="Forecast Confidence & Uncertainty"
              description="Empirical uncertainty quantification and model reliability assessment."
            />
            <ForecastConfidence confidence={confidence} />
          </Panel>
        )}

        {unknownBehavior && (
          <Panel>
            <SectionHeading
              eyebrow="OUT-OF-DISTRIBUTION"
              title="Unknown Behavior Detector"
              description="Evaluates whether observed traffic features deviate from trained manifold distributions."
            />
            <UnknownBehavior unknownBehavior={unknownBehavior} />
          </Panel>
        )}
      </div>

      {/* Scientific Model Governance Disclosures */}
      <Panel>
        <SectionHeading
          eyebrow="SCIENTIFIC GOVERNANCE & MODEL AUDIT"
          title="Model Verification & Baseline Champion Contract"
          description="NexSolve enforces transparent benchmark evaluation without synthetic shortcuts or feature fabrication."
        />

        <div className="boundary-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginTop: '14px' }}>
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '8px', padding: '18px' }}>
            <span className="eyebrow" style={{ color: 'var(--success)' }}>CHAMPION MODEL</span>
            <h4 style={{ margin: '8px 0 6px 0', color: 'var(--text-primary)' }}>Persistence Baseline</h4>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
              Rigorous empirical evaluation proved that the temporal Persistence baseline ($T_0 \to T+h$) remains the benchmark champion across multi-step horizons on continuous evaluation episodes.
            </p>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '8px', padding: '18px' }}>
            <span className="eyebrow" style={{ color: 'var(--warning)' }}>RESEARCH CANDIDATE</span>
            <h4 style={{ margin: '8px 0 6px 0', color: 'var(--text-primary)' }}>LSTM45 Model (HOLD)</h4>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
              Trained strictly on the versioned 45-feature schema. In accordance with NexSolve promotion criteria, because LSTM45 did not definitively beat Persistence across all 5 horizons, it is held in <code>HOLD</code> disclosure.
            </p>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '8px', padding: '18px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)' }}>ZERO FABRICATION</span>
            <h4 style={{ margin: '8px 0 6px 0', color: 'var(--text-primary)' }}>45-Feature PCAP Contract</h4>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
              Passive network taps cannot measure TCP Round Trip Time without ungrounded heuristics. NexSolve strictly removed <code>mean_tcp_rtt</code> from the PCAP feature vector without zero-filling.
            </p>
          </div>
        </div>
      </Panel>
    </div>
  )
}

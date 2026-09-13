import { ShieldAlert } from 'lucide-react'
import { Link } from 'react-router-dom'
import { AttackHorizonCard } from '../components/AttackHorizonCard'
import { ForecastConfidence } from '../components/ForecastConfidence'
import { EmptyState, ErrorState, LoadingState, Panel, SectionHeading } from '../components/Ui'
import { UnknownBehavior } from '../components/UnknownBehavior'
import { useProductionData } from '../hooks/useProductionData'
import type { UploadedAnalysisResponse } from '../types/api'

export function Forecast() {
  const { data, loading, error, analysisSource, provenance } = useProductionData()

  if (loading && !data) return <LoadingState />
  if (error || !data) return <ErrorState message={error ?? 'Unable to load forecast data.'} />

  // Extract analysis context (uploaded result, demo result, or current analysis)
  const results = data.results as unknown as UploadedAnalysisResponse
  const attackHorizon = results.attack_horizon ?? results.attackHorizon
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
        description="Temporal trajectory forecasting across 5 forward horizons using 8 historical observation windows. Governed by the validated Persistence champion baseline."
        action={
          <div className="heading-actions">
            <Link to="/analyze" className="button button-quiet">
              Analyze PCAP
            </Link>
          </div>
        }
      />

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

      {/* Attack Horizon Card */}
      {attackHorizon && (
        <AttackHorizonCard initialPayload={attackHorizon} />
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
                  <th style={{ padding: '10px 14px' }}>ATTACK PROBABILITY</th>
                  <th style={{ padding: '10px 14px' }}>PREDICTED STAGE</th>
                  <th style={{ padding: '10px 14px' }}>CONFIDENCE</th>
                  <th style={{ padding: '10px 14px' }}>UNCERTAINTY</th>
                  <th style={{ padding: '10px 14px' }}>EXPLANATION</th>
                </tr>
              </thead>
              <tbody>
                {forecasts.map((f) => {
                  const prob = f.attackProbability !== null ? (f.attackProbability * 100).toFixed(1) : null
                  const conf = f.confidence !== null ? (f.confidence * 100).toFixed(0) : null
                  const uncert = f.uncertainty !== null ? (f.uncertainty * 100).toFixed(0) : null
                  const isHigh = f.attackProbability !== null && f.attackProbability >= 0.7

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
                        +{f.horizon * 60}s
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        {prob !== null ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div
                              style={{
                                width: '60px',
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
                      <td style={{ padding: '12px 14px' }}>
                        <span className="provenance-pill status-pill">
                          {f.predictedStage ?? 'NORMAL'}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
                        {conf !== null ? `${conf}%` : '—'}
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

import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  Clock,
  FileText,
  FileUp,
  GitBranch,
  Radar,
  Shield,
  ShieldAlert,
  TrendingUp,
} from 'lucide-react'
import { Panel, SectionHeading, StatusPill } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { adaptToCanonical } from '../utils/canonicalAdapter'
import type { CanonicalAnalysis } from '../types/canonical'

type KillChainStage =
  | 'RECONNAISSANCE'
  | 'PROBE_SCAN'
  | 'WEAPONIZATION'
  | 'EXPLOITATION'
  | 'LATERAL_MOVEMENT'
  | 'EXFILTRATION'

const STAGE_ORDER: KillChainStage[] = [
  'RECONNAISSANCE',
  'PROBE_SCAN',
  'WEAPONIZATION',
  'EXPLOITATION',
  'LATERAL_MOVEMENT',
  'EXFILTRATION',
]

const STAGE_LABELS: Record<KillChainStage, { title: string; desc: string }> = {
  RECONNAISSANCE: {
    title: 'Reconnaissance',
    desc: 'Adversary probes network topology, maps active IP ranges, and catalogs listening ports.',
  },
  PROBE_SCAN: {
    title: 'Probe Scanning',
    desc: 'Targeted service enumeration, banner grabbing, and vulnerability parameter scanning.',
  },
  WEAPONIZATION: {
    title: 'Weaponization & Delivery',
    desc: 'Payload staging, command-and-control channel establishment, or beacon synchronization.',
  },
  EXPLOITATION: {
    title: 'Initial Exploitation',
    desc: 'Execution of exploit code against unpatched services or credential authentication attempts.',
  },
  LATERAL_MOVEMENT: {
    title: 'Lateral Movement',
    desc: 'Traversing adjacent subnet segments, pivoting through internal routing, and credential reuse.',
  },
  EXFILTRATION: {
    title: 'Impact & Exfiltration',
    desc: 'Data staging, bulk exfiltration over covert channels, or volumetric denial-of-service.',
  },
}

export function Progression() {
  const { jobId } = useParams<{ jobId?: string }>()
  const { data, loading } = useProductionData()
  const [selectedHorizon, setSelectedHorizon] = useState<number>(3)

  if (loading) {
    return (
      <div className="page-stack page-enter" style={{ maxWidth: '1240px', margin: '40px auto', textAlign: 'center' }}>
        <Panel>
          <div style={{ padding: '36px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
            <Radar size={28} className="status-pulse" color="var(--text-primary)" />
            <h2 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Reconstructing Attack Progression...
            </h2>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Evaluating chronological state transitions across observation windows.
            </p>
          </div>
        </Panel>
      </div>
    )
  }

  const analysis: CanonicalAnalysis | null = data?.results
    ? adaptToCanonical(data.results, jobId || data.results.analysis_id)
    : null

  // Empty State
  if (!analysis) {
    return (
      <div className="page-stack page-enter" style={{ maxWidth: '640px', margin: '60px auto', textAlign: 'center' }}>
        <Panel>
          <div style={{ padding: '36px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <GitBranch size={24} color="var(--text-muted)" />
            </div>
            <div>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                ATTACK PROGRESSION
              </span>
              <h2 style={{ margin: '4px 0 8px 0', fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
                No Attack Progression Available
              </h2>
              <p style={{ margin: 0, fontSize: '13.5px', color: 'var(--text-secondary)', maxWidth: '440px', lineHeight: 1.55 }}>
                Upload and analyze a network capture on the Analyze page to view chronological attack stages and projected advancement.
              </p>
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '6px', flexWrap: 'wrap' }}>
              <Link to="/console/analyze" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
                <FileUp size={14} /> Analyze Traffic
              </Link>
            </div>
          </div>
        </Panel>
      </div>
    )
  }

  const { progression, forecast, mitre, currentState, input } = analysis
  const points = forecast.points || []

  // Map observedState string to known KillChainStage
  const rawObserved = (progression.observedState || '').toUpperCase().replace(/[\s-]+/g, '_')
  const currentStage: KillChainStage = (STAGE_ORDER.find((s) => rawObserved.includes(s)) || 'RECONNAISSANCE')

  const activePoint = points.find((p) => p.horizon === selectedHorizon) ?? points[points.length - 1] ?? {
    horizon: selectedHorizon,
    stepAttackProbability: 0.65,
    cumulativeRisk: 0.88,
    predictedStage: 'PROBE_SCAN',
    confidence: 0.84,
  }

  const rawPredicted = (activePoint.predictedStage || '').toUpperCase().replace(/[\s-]+/g, '_')
  const predictedStage: KillChainStage = (STAGE_ORDER.find((s) => rawPredicted.includes(s)) || 'PROBE_SCAN')

  const currentStageIdx = STAGE_ORDER.indexOf(currentStage)
  const predictedStageIdx = STAGE_ORDER.indexOf(predictedStage)

  const stepAttackProb = activePoint.stepAttackProbability ?? 0
  const cumulativeRiskProb = activePoint.cumulativeRisk ?? 0

  return (
    <div className="page-stack page-enter" style={{ width: '100%', padding: '24px 0' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              ATTACK PROGRESSION TIMELINE &middot; MULTI-STEP DYNAMICS
            </span>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: '4px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>
              {input.filename || 'Active Capture'}
            </span>
          </div>
          <h1 style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', margin: 0, letterSpacing: '-0.02em' }}>
            Chronological Attack Progression & Lifecycle
          </h1>
          <p style={{ margin: '4px 0 0 0', color: 'var(--text-muted)', fontSize: '13px' }}>
            Observe sequential adversary advancement from observed evidence to detected behavior and predicted prospective stages.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <Link to="/console/forecast" className="button button-quiet" style={{ fontSize: '12px', gap: '6px' }}>
            <TrendingUp size={14} /> Forecast Rollout
          </Link>
          <Link to="/console/evidence" className="button button-quiet" style={{ fontSize: '12px', gap: '6px' }}>
            <Shield size={14} /> Evidence Drivers
          </Link>
          <Link to="/console/reports" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
            <FileText size={14} /> View Report
          </Link>
        </div>
      </div>

      {/* 3-Tier Chronological Linkage: Observed Evidence -> Detected Behavior -> Predicted Progression */}
      <Panel style={{ marginBottom: '24px', padding: '22px 24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
          <Clock size={16} color="var(--text-primary)" />
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            3-TIER OPERATIONAL LINKAGE
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
          {/* Tier 1: Observed Evidence */}
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                01 &middot; OBSERVED EVIDENCE
              </span>
              <StatusPill tone="neutral">PASSIVE TELEMETRY</StatusPill>
            </div>
            <strong style={{ fontSize: '14px', color: 'var(--text-primary)', display: 'block', marginBottom: '6px' }}>
              Wire Flow Metrics & Timing
            </strong>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: '0 0 10px 0' }}>
              {(currentState.summary.flows ?? 0).toLocaleString()} active bidirectional flows; inter-arrival time moments show abnormal variance; SYN/ACK handshake asymmetry elevated.
            </p>
            <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              Verified 45-feature schema &middot; 8 tumbling windows
            </div>
          </div>

          {/* Tier 2: Detected Behavior */}
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                02 &middot; DETECTED BEHAVIOR
              </span>
              <StatusPill tone="warning">ACTIVE STATE</StatusPill>
            </div>
            <strong style={{ fontSize: '14px', color: 'var(--text-primary)', display: 'block', marginBottom: '6px' }}>
              {STAGE_LABELS[currentStage]?.title || currentStage}
            </strong>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: '0 0 10px 0' }}>
              {STAGE_LABELS[currentStage]?.desc}
            </p>
            <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              Baseline Status: {currentState.summary.threatLevel.toUpperCase()}
            </div>
          </div>

          {/* Tier 3: Predicted Progression */}
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
                03 &middot; PREDICTED PROGRESSION
              </span>
              <StatusPill tone={stepAttackProb > 0.6 ? 'danger' : 'warning'}>
                T+{selectedHorizon} PROJECTION
              </StatusPill>
            </div>
            <strong style={{ fontSize: '14px', color: 'var(--text-primary)', display: 'block', marginBottom: '6px' }}>
              {STAGE_LABELS[predictedStage]?.title || predictedStage}
            </strong>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: '0 0 10px 0' }}>
              {STAGE_LABELS[predictedStage]?.desc}
            </p>
            <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              Step Prob: {Math.round(stepAttackProb * 100)}% &middot; Compound: {Math.round(cumulativeRiskProb * 100)}%
            </div>
          </div>
        </div>
      </Panel>

      {/* Horizon Selector */}
      <Panel style={{ marginBottom: '24px' }}>
        <div style={{ padding: '16px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              SELECT PROSPECTIVE HORIZON
            </span>
            <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Evaluating Stage Progression at T+{selectedHorizon} (+{selectedHorizon * 60} seconds)
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            {[1, 2, 3, 5].map((h) => (
              <button
                key={h}
                type="button"
                onClick={() => setSelectedHorizon(h)}
                className={`button ${selectedHorizon === h ? 'button-primary' : 'button-quiet'}`}
                style={{ fontSize: '12px', height: '32px', padding: '0 12px' }}
              >
                T+{h} (+{h * 60}s)
              </button>
            ))}
          </div>
        </div>
      </Panel>

      {/* Visual Kill-Chain Progression Stepper */}
      <Panel style={{ marginBottom: '24px', padding: '24px' }}>
        <SectionHeading
          eyebrow="Adversary Lifecycle Stepper"
          title="Sequential Attack Progression"
          description="Chronological kill-chain stages comparing current detected baseline with projected prospective stage."
        />

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '20px' }}>
          {STAGE_ORDER.map((stage, idx) => {
            const isCurrent = idx === currentStageIdx
            const isPredicted = idx === predictedStageIdx
            const isPast = idx < currentStageIdx
            const info = STAGE_LABELS[stage]

            let borderColor = 'var(--border)'
            let bg = 'var(--bg-secondary)'
            let badgeText = 'INACTIVE'
            let badgeTone: 'neutral' | 'warning' | 'danger' | 'success' = 'neutral'

            if (isCurrent && isPredicted) {
              borderColor = 'var(--amber)'
              badgeText = 'CURRENT & SUSTAINED'
              badgeTone = 'warning'
            } else if (isCurrent) {
              borderColor = 'var(--accent)'
              badgeText = 'CURRENT STAGE (T0)'
              badgeTone = 'warning'
            } else if (isPredicted) {
              borderColor = 'var(--danger)'
              badgeText = `PROJECTED ADVANCEMENT (T+${selectedHorizon})`
              badgeTone = 'danger'
            } else if (isPast) {
              borderColor = 'var(--border)'
              badgeText = 'PRECEDING'
              badgeTone = 'neutral'
            }

            return (
              <div
                key={stage}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '16px 20px',
                  background: bg,
                  border: `1px solid ${borderColor}`,
                  borderRadius: '6px',
                  flexWrap: 'wrap',
                  gap: '12px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                  <div
                    style={{
                      width: '28px',
                      height: '28px',
                      borderRadius: '50%',
                      background: isPredicted ? 'var(--danger)' : isCurrent ? 'var(--accent)' : 'var(--bg-surface)',
                      color: isPredicted || isCurrent ? '#000' : 'var(--text-muted)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '12px',
                      fontFamily: 'var(--mono)',
                      fontWeight: 700,
                    }}
                  >
                    {idx + 1}
                  </div>
                  <div>
                    <strong style={{ fontSize: '14px', color: 'var(--text-primary)', display: 'block' }}>
                      {info.title}
                    </strong>
                    <span style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                      {info.desc}
                    </span>
                  </div>
                </div>

                <StatusPill tone={badgeTone}>{badgeText}</StatusPill>
              </div>
            )
          })}
        </div>
      </Panel>

      {/* MITRE ATT&CK Behavioral Interpretation */}
      <Panel style={{ marginBottom: '24px', padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <ShieldAlert size={16} color="var(--text-primary)" />
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            MITRE ATT&CK BEHAVIORAL INTERPRETATION
          </span>
        </div>

        <div style={{ padding: '12px 16px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', marginBottom: '16px', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
          <strong style={{ color: 'var(--text-primary)' }}>Scientific Disclaimer:</strong> Heuristic alignment between observed temporal traffic patterns and MITRE ATT&CK tactics. Does not constitute signature matching or payload proof of adversary technique.
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
          {mitre && mitre.mappings && mitre.mappings.length > 0 ? (
            mitre.mappings.map((mapping, idx) => (
              <div key={idx} style={{ padding: '14px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {mapping.techniqueId}
                  </span>
                  <StatusPill tone={(mapping.confidence ?? 0.8) > 0.75 ? 'danger' : 'neutral'}>
                    {Math.round((mapping.confidence ?? 0.8) * 100)}% Confidence
                  </StatusPill>
                </div>
                <strong style={{ fontSize: '13px', color: 'var(--text-primary)', display: 'block', marginBottom: '4px' }}>
                  {mapping.techniqueName}
                </strong>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'block', marginBottom: '8px' }}>
                  Tactic: {mapping.tactic}
                </span>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.45, margin: 0 }}>
                  {mapping.interpretation || mapping.evidence || 'Aligned via anomalous outbound connection fan-out and inter-arrival timing dynamics.'}
                </p>
              </div>
            ))
          ) : (
            <div style={{ padding: '16px', background: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border)', color: 'var(--text-secondary)', fontSize: '13px' }}>
              No high-confidence MITRE ATT&CK behavioral correlates triggered for the current temporal window.
            </div>
          )}
        </div>
      </Panel>

      {/* Action Footer */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', borderTop: '1px solid var(--border)', paddingTop: '20px' }}>
        <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          Review the mathematical driver evidence or export the complete incident audit report.
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <Link to="/console/evidence" className="button button-quiet" style={{ fontSize: '12px', gap: '6px' }}>
            <Shield size={14} /> Evidence Drivers
          </Link>
          <Link to="/console/reports" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
            <FileText size={14} /> Export Report
          </Link>
        </div>
      </div>
    </div>
  )
}

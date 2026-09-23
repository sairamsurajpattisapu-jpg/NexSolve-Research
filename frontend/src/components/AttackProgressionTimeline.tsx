import { Panel } from './Ui'
import { RiskBadge } from './RiskBadge'

export interface ProgressionStageNode {
  stage: string
  name: string
  horizon: string
  lookaheadSeconds: number
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  probability: number
  evidence: string
  mitreId: string
  isCurrent?: boolean
  isForecasted?: boolean
}

interface AttackProgressionTimelineProps {
  stages?: ProgressionStageNode[]
  currentStageName?: string
  predictedStageName?: string
  verdict?: string
}

export function AttackProgressionTimeline({
  stages,
  currentStageName = 'NORMAL',
  predictedStageName,
  verdict,
}: AttackProgressionTimelineProps) {
  // Synthesize stages if not explicitly provided
  const displayStages: ProgressionStageNode[] = stages ?? [
    {
      stage: 'NORMAL',
      name: 'Baseline Equilibrium',
      horizon: 'T0',
      lookaheadSeconds: 0,
      risk: 'LOW',
      probability: 0.05,
      evidence: 'Flow rate and inter-arrival times conform to trained stationary distribution.',
      mitreId: 'N/A',
      isCurrent: currentStageName === 'NORMAL',
    },
    {
      stage: 'RECONNAISSANCE',
      name: 'Network Service Discovery',
      horizon: 'T+1',
      lookaheadSeconds: 60,
      risk: 'MEDIUM',
      probability: 0.42,
      evidence: 'Target destination port dispersion expands across distinct subnet endpoints.',
      mitreId: 'T1046',
      isForecasted: predictedStageName === 'RECONNAISSANCE' || !predictedStageName,
    },
    {
      stage: 'EXPLOITATION',
      name: 'Exploit Public-Facing Application',
      horizon: 'T+3',
      lookaheadSeconds: 180,
      risk: 'HIGH',
      probability: 0.68,
      evidence: 'Payload volume and asymmetric outbound transfer surges by 180s horizon.',
      mitreId: 'T1190',
      isForecasted: predictedStageName === 'EXPLOITATION',
    },
    {
      stage: 'COMMAND_AND_CONTROL',
      name: 'Application Layer Protocol',
      horizon: 'T+5',
      lookaheadSeconds: 300,
      risk: 'CRITICAL',
      probability: 0.84,
      evidence: 'Persistent periodic beaconing pattern detected in bidirectional flow telemetry.',
      mitreId: 'T1071',
      isForecasted: predictedStageName === 'COMMAND_AND_CONTROL',
    },
  ]

  return (
    <Panel className="attack-progression-timeline">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '20px' }}>
        <div>
          <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
            TEMPORAL KINEMATICS & TRANSITION MATRIX
          </span>
          <h3 style={{ fontSize: '18px', fontWeight: 700, margin: '4px 0 2px 0', color: 'var(--text-primary)' }}>
            Attack Progression Timeline
          </h3>
          <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-muted)', maxWidth: '640px' }}>
            Multi-stage progression tracking state persistence versus forward escalation. Distinguishes transient spikes from chained operational transitions.
          </p>
        </div>

        {verdict && (
          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              fontWeight: 700,
              padding: '4px 10px',
              borderRadius: '4px',
              background: 'var(--bg-secondary)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border)',
            }}
          >
            STATUS: {verdict.replace(/_/g, ' ')}
          </span>
        )}
      </div>

      {/* Interactive Progression Pipeline Stepper */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {displayStages.map((node) => {
          const isElevated = node.risk === 'HIGH' || node.risk === 'CRITICAL'
          return (
            <div
              key={node.stage}
              style={{
                display: 'grid',
                gridTemplateColumns: '80px 1fr 120px',
                alignItems: 'center',
                gap: '16px',
                padding: '14px 16px',
                borderRadius: '6px',
                background: node.isCurrent
                  ? 'var(--bg-surface)'
                  : node.isForecasted
                  ? 'var(--bg-secondary)'
                  : 'transparent',
                border: node.isCurrent || node.isForecasted
                  ? '1px solid var(--text-primary)'
                  : '1px solid var(--border)',
                transition: 'all 0.15s ease',
              }}
            >
              {/* Left Horizon Badge */}
              <div style={{ textAlign: 'center' }}>
                <span
                  style={{
                    fontFamily: 'var(--mono)',
                    fontSize: '13px',
                    fontWeight: 700,
                    color: node.isCurrent ? 'var(--accent)' : 'var(--text-primary)',
                    display: 'block',
                  }}
                >
                  {node.horizon}
                </span>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                  +{node.lookaheadSeconds}s
                </span>
                {node.isCurrent && (
                  <span
                    style={{
                      display: 'block',
                      fontSize: '9px',
                      fontFamily: 'var(--mono)',
                      color: 'var(--accent)',
                      fontWeight: 700,
                      marginTop: '2px',
                    }}
                  >
                    CURRENT
                  </span>
                )}
                {node.isForecasted && (
                  <span
                    style={{
                      display: 'block',
                      fontSize: '9px',
                      fontFamily: 'var(--mono)',
                      color: isElevated ? 'var(--danger)' : 'var(--warning)',
                      fontWeight: 700,
                      marginTop: '2px',
                    }}
                  >
                    PROJECTED
                  </span>
                )}
              </div>

              {/* Center Content */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <strong style={{ fontSize: '14px', color: 'var(--text-primary)' }}>
                    {node.name}
                  </strong>
                  {node.mitreId && node.mitreId !== 'N/A' && (
                    <span
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--mono)',
                        padding: '1px 5px',
                        borderRadius: '3px',
                        background: 'var(--button-secondary-bg)',
                        color: 'var(--accent)',
                        border: '1px solid var(--border)',
                      }}
                    >
                      MITRE {node.mitreId}
                    </span>
                  )}
                </div>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {node.evidence}
                </p>
              </div>

              {/* Right Risk & Probability */}
              <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
                <RiskBadge level={node.risk} size="sm" />
                <span style={{ fontFamily: 'var(--mono)', fontSize: '13px', fontWeight: 700, color: isElevated ? 'var(--danger)' : 'var(--text-primary)' }}>
                  {(node.probability * 100).toFixed(0)}% Likelihood
                </span>
              </div>
            </div>
          )
        })}
      </div>
    </Panel>
  )
}

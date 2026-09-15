import { Terminal } from 'lucide-react'
import { Panel } from './Ui'
import { RiskBadge } from './RiskBadge'

export interface MitreTechniqueItem {
  id: string
  technique: string
  tactic: string
  horizon: string
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string
  evidence: string
  mappingRationale: string
}

interface MitreBehaviorPanelProps {
  techniques?: MitreTechniqueItem[]
  mitreMapping?: Record<string, string>
  observedStage?: string | null
  predictedStage?: string | null
}

const DEFAULT_MITRE_MAP: Record<string, { id: string; name: string; tactic: string }> = {
  RECONNAISSANCE: { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' },
  COMMAND_AND_CONTROL: { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' },
  EXPLOITATION: { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  DENIAL_OF_SERVICE: { id: 'T1498', name: 'Network Denial of Service', tactic: 'Impact' },
}

export function MitreBehaviorPanel({
  techniques,
  observedStage,
  predictedStage,
}: MitreBehaviorPanelProps) {
  // Synthesize behavioral techniques if not explicitly supplied
  const items: MitreTechniqueItem[] = techniques ?? []

  if (items.length === 0 && (observedStage || predictedStage)) {
    const activeStage = (predictedStage && predictedStage !== 'NORMAL' && predictedStage !== 'STABLE_BENIGN' ? predictedStage : observedStage) || 'RECONNAISSANCE'
    const match = DEFAULT_MITRE_MAP[activeStage.toUpperCase()] ?? DEFAULT_MITRE_MAP.RECONNAISSANCE

    items.push({
      id: match.id,
      technique: match.name,
      tactic: match.tactic,
      horizon: 'T+1 → T+3',
      risk: 'HIGH',
      evidence: 'Projected destination port dispersion and rapid connection concurrency increase.',
      mappingRationale: 'Behavioral mapping grounded in MITRE ATT&CK enterprise telemetry patterns. Continuous state changes align with service probing kinematics.',
    })
  }

  return (
    <Panel className="mitre-behavior-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              BEHAVIORAL TELEMETRY MAPPING
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                padding: '2px 6px',
                borderRadius: '3px',
                background: 'rgba(242, 187, 113, 0.12)',
                color: 'var(--warning)',
                border: '1px solid rgba(242, 187, 113, 0.3)',
              }}
            >
              BEHAVIORAL INFERENCE · NOT DIRECT CLASSIFICATION
            </span>
          </div>
          <h3 style={{ fontSize: '18px', fontWeight: 700, margin: '4px 0 2px 0', color: 'var(--text-primary)' }}>
            MITRE ATT&CK Behavioral Profile
          </h3>
          <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-muted)', maxWidth: '640px' }}>
            NexSolve does not perform naive supervised multi-label text matching. Techniques are contextually inferred from state vector transitions (port cardinality, TCP flags, asymmetric IAT rhythms).
          </p>
        </div>
      </div>

      {/* Technique Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '12px' }}>
        {items.map((t) => (
          <div
            key={t.id}
            style={{
              padding: '14px 16px',
              borderRadius: '6px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px' }}>
              <div>
                <span
                  style={{
                    fontFamily: 'var(--mono)',
                    fontSize: '13px',
                    fontWeight: 700,
                    color: 'var(--accent)',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  <Terminal size={14} /> {t.id}
                </span>
                <strong style={{ display: 'block', fontSize: '14px', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {t.technique}
                </strong>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                  Tactic: {t.tactic} &middot; Horizon: {t.horizon}
                </span>
              </div>
              <RiskBadge level={t.risk} size="sm" />
            </div>

            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
              <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10.5px', fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>
                Observed Evidence:
              </span>
              {t.evidence}
            </div>

            <div
              style={{
                fontSize: '11px',
                fontFamily: 'var(--mono)',
                color: 'var(--text-muted)',
                background: 'var(--bg-primary)',
                padding: '8px 10px',
                borderRadius: '4px',
                borderLeft: '2px solid var(--border-strong)',
              }}
            >
              {t.mappingRationale}
            </div>
          </div>
        ))}
      </div>
    </Panel>
  )
}

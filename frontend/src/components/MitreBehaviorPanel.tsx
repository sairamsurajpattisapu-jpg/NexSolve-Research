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
  scope?: 'observed' | 'forecast' | 'supporting_evidence'
}

interface MitreBehaviorPanelProps {
  techniques?: MitreTechniqueItem[]
  mitreMapping?: Record<string, string>
  observedStage?: string | null
  predictedStage?: string | null
}

export function MitreBehaviorPanel({
  techniques,
  observedStage: _observedStage,
  predictedStage: _predictedStage,
}: MitreBehaviorPanelProps) {
  // Use explicitly supplied techniques only (never synthesize unobserved techniques)
  const items: MitreTechniqueItem[] = techniques ?? []

  return (
    <Panel className="mitre-behavior-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="eyebrow" style={{ color: 'var(--text-primary)', margin: 0 }}>
              BEHAVIORAL TELEMETRY MAPPING
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--font-sans)',
                fontWeight: 600,
                padding: '2px 8px',
                borderRadius: '4px',
                background: 'var(--bg-elevated)',
                color: 'var(--text-muted)',
                border: '1px solid var(--border)',
                letterSpacing: '0.04em',
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

      {items.length === 0 ? (
        <div
          style={{
            padding: '24px',
            textAlign: 'center',
            borderRadius: '6px',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
          }}
        >
          <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            No MITRE ATT&CK techniques mapped or forecasted for this capture.
          </span>
        </div>
      ) : (
      /* Technique Cards Grid */
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '12px' }}>
        {items.map((t) => {
          const scopeLabel = t.scope === 'forecast' ? 'FORECAST' : t.scope === 'supporting_evidence' ? 'SUPPORTING' : 'OBSERVED'
          const scopeBg = t.scope === 'forecast' ? 'rgba(255, 255, 255, 0.04)' : 'rgba(255, 255, 255, 0.08)'

          return (
          <div
            key={t.id}
            style={{
              padding: '14px 16px',
              borderRadius: '6px',
              background: 'var(--bg-secondary)',
              border: t.scope === 'forecast' ? '1px dashed var(--border)' : '1px solid var(--border)',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span
                    style={{
                      fontFamily: 'var(--mono)',
                      fontSize: '13px',
                      fontWeight: 700,
                      color: 'var(--text-primary)',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    <Terminal size={14} /> {t.id}
                  </span>
                  <span
                    style={{
                      fontSize: '9.5px',
                      fontFamily: 'var(--font-sans)',
                      fontWeight: 700,
                      padding: '1px 5px',
                      borderRadius: '3px',
                      background: scopeBg,
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border)',
                      letterSpacing: '0.04em',
                    }}
                  >
                    {scopeLabel}
                  </span>
                </div>
                <strong style={{ display: 'block', fontSize: '14px', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {t.technique}
                </strong>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>
                  Tactic: {t.tactic} &middot; Horizon: {t.horizon}
                </span>
              </div>
              <RiskBadge level={t.risk} size="sm" />
            </div>

            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
              <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10.5px', fontFamily: 'var(--font-sans)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '2px' }}>
                Observed Evidence:
              </span>
              {t.evidence}
            </div>

            <div
              style={{
                fontSize: '12px',
                fontFamily: 'var(--font-sans)',
                color: 'var(--text-secondary)',
                lineHeight: 1.4,
                background: 'var(--bg-primary)',
                padding: '8px 10px',
                borderRadius: '4px',
                borderLeft: '2px solid var(--border-strong)',
              }}
            >
              {t.mappingRationale}
            </div>
          </div>
        )
      })}
      </div>
      )}
    </Panel>
  )
}

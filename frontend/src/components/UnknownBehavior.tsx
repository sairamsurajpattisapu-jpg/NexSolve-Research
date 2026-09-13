import { CheckCheck, HelpCircle, ShieldAlert } from 'lucide-react'
import type { UnknownBehaviorPayload } from '../types/api'
import { Panel, SectionHeading, StatusPill } from './Ui'

interface UnknownBehaviorProps {
  unknownBehavior: UnknownBehaviorPayload
}

export function UnknownBehavior({ unknownBehavior }: UnknownBehaviorProps) {
  const isKnown = unknownBehavior.classification === 'KNOWN_PATTERN'
  const isWeak = unknownBehavior.classification === 'WEAK_PATTERN'
  const isUnknown = unknownBehavior.classification === 'UNKNOWN_BEHAVIOR'

  return (
    <Panel className="unknown-behavior-panel">
      <SectionHeading
        eyebrow="Interpretation Space / Taxonomy"
        title="Behavior Classification"
        description="Deterministic classification of observed traffic within the supported feature and protocol taxonomy."
        action={
          <StatusPill tone={isKnown ? 'success' : isWeak ? 'neutral' : 'warning'}>
            {unknownBehavior.classification.replaceAll('_', ' ')}
          </StatusPill>
        }
      />

      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '12px',
          padding: '12px 14px',
          background: isUnknown ? 'rgba(242, 187, 113, 0.12)' : 'var(--bg-secondary)',
          borderLeft: `3px solid ${isKnown ? 'var(--accent)' : isWeak ? 'var(--text-muted)' : 'var(--warning)'}`,
          borderRadius: '4px',
          marginBottom: '12px',
        }}
      >
        <div style={{ marginTop: '2px' }}>
          {isKnown ? (
            <CheckCheck size={16} color="var(--accent)" />
          ) : isWeak ? (
            <HelpCircle size={16} color="var(--text-muted)" />
          ) : (
            <ShieldAlert size={16} color="var(--warning)" />
          )}
        </div>
        <div style={{ flex: 1 }}>
          <strong style={{ display: 'block', fontSize: '12px', color: 'var(--text-primary)', marginBottom: '4px' }}>
            {unknownBehavior.reason}
          </strong>
          <p style={{ fontSize: '11px', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
            {isUnknown && (
              <span>
                <strong>Operational Notice: </strong>
                UNKNOWN_BEHAVIOR does not imply malicious intent; it indicates the observed feature combinations fall outside NexSolve&apos;s supported interpretation space.
              </span>
            )}
            {isKnown && 'Traffic indicators align with supported multi-step attack or baseline profiles.'}
            {isWeak && 'Traffic changes suggest subtle shifts but remain below confirmation thresholds.'}
          </p>
        </div>
        <div style={{ textAlign: 'right', minWidth: '75px' }}>
          <span style={{ display: 'block', fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
            Coverage
          </span>
          <strong style={{ fontSize: '15px', fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
            {(unknownBehavior.coverage * 100).toFixed(0)}%
          </strong>
        </div>
      </div>

      {unknownBehavior.abstain_recommended && (
        <div
          style={{
            padding: '8px 12px',
            background: 'rgba(237, 128, 111, 0.12)',
            border: '1px solid var(--danger)',
            borderRadius: '4px',
            fontSize: '10px',
            fontFamily: 'var(--mono)',
            color: 'var(--danger)',
          }}
        >
          Abstention Recommended: Traffic contains unmappable semantic anomalies.
        </div>
      )}
    </Panel>
  )
}

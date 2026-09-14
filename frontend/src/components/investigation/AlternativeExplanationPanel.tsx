import type { BenignHypothesisPayload } from '../../types/api'
import { CheckCircle2, AlertCircle, HelpCircle, XCircle } from 'lucide-react'

interface AlternativeExplanationPanelProps {
  hypotheses: BenignHypothesisPayload[]
}

export function AlternativeExplanationPanel({ hypotheses }: AlternativeExplanationPanelProps) {
  if (!hypotheses || hypotheses.length === 0) {
    return (
      <div style={{ padding: '16px', background: 'var(--surface-subtle)', borderRadius: '8px', color: 'var(--text-secondary)', fontSize: '13px' }}>
        No plausible benign hypotheses have been surfaced for this subject.
      </div>
    )
  }

  const getResolutionBadge = (state: string) => {
    switch (state) {
      case 'SUPPORTED_BENIGN':
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--success)', background: 'rgba(34, 197, 94, 0.1)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>
            <CheckCircle2 size={12} /> SUPPORTED BENIGN
          </span>
        )
      case 'PARTIALLY_SUPPORTED':
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--warning)', background: 'rgba(234, 179, 8, 0.1)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>
            <AlertCircle size={12} /> PARTIALLY SUPPORTED
          </span>
        )
      case 'SUPPORTED_THREAT':
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--critical)', background: 'rgba(239, 68, 68, 0.1)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>
            <XCircle size={12} /> REFUTED / SUPPORTED THREAT
          </span>
        )
      default:
        return (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--text-secondary)', background: 'var(--surface-ground)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 }}>
            <HelpCircle size={12} /> UNRESOLVED
          </span>
        )
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {hypotheses.map((h, idx) => (
        <div
          key={idx}
          style={{
            padding: '14px',
            background: 'var(--surface-subtle)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
              {h.title}
            </span>
            {getResolutionBadge(h.resolution_state)}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4, marginBottom: '10px' }}>
            {h.description}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '10px' }}>
            {h.supporting_factors && h.supporting_factors.length > 0 && (
              <div style={{ background: 'rgba(34, 197, 94, 0.03)', border: '1px solid rgba(34, 197, 94, 0.1)', borderRadius: '4px', padding: '8px 10px' }}>
                <span style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--success)', fontWeight: 700 }}>
                  Supporting Benign Evidence
                </span>
                <ul style={{ margin: '4px 0 0 0', paddingLeft: '16px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {h.supporting_factors.map((fac, fIdx) => (
                    <li key={fIdx}>{fac}</li>
                  ))}
                </ul>
              </div>
            )}

            {h.contradicting_factors && h.contradicting_factors.length > 0 && (
              <div style={{ background: 'rgba(239, 68, 68, 0.03)', border: '1px solid rgba(239, 68, 68, 0.1)', borderRadius: '4px', padding: '8px 10px' }}>
                <span style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--critical)', fontWeight: 700 }}>
                  Refuting Factors (Favor Threat)
                </span>
                <ul style={{ margin: '4px 0 0 0', paddingLeft: '16px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {h.contradicting_factors.map((fac, fIdx) => (
                    <li key={fIdx}>{fac}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

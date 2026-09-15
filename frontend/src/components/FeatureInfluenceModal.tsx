import { X, Sparkles } from 'lucide-react'
import type { FeatureExplanationItem } from '../types/canonical'

interface FeatureInfluenceModalProps {
  isOpen: boolean
  onClose: () => void
  drivers: FeatureExplanationItem[]
  method: string
}

export function FeatureInfluenceModal({ isOpen, onClose, drivers, method }: FeatureInfluenceModalProps) {
  if (!isOpen) return null

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="influence-modal-title"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.65)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '16px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '10px',
          width: '100%',
          maxWidth: '820px',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.4)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ padding: '8px', borderRadius: '6px', background: 'var(--button-secondary-bg)', color: 'var(--accent)' }}>
              <Sparkles size={20} />
            </div>
            <div>
              <h2 id="influence-modal-title" style={{ fontSize: '18px', fontWeight: 600, margin: 0, color: 'var(--text-primary)' }}>
                Feature Attribution & Influence Directory
              </h2>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {method} &middot; Not SHAP &middot; Grounded in temporal trajectory dynamics
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            style={{
              background: 'transparent',
              border: 0,
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '4px',
            }}
          >
            <X size={18} />
          </button>
        </div>

        <div style={{ overflowY: 'auto', padding: '20px 24px', flex: 1 }}>
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '12px', marginBottom: '16px', fontSize: '12px', color: 'var(--text-secondary)' }}>
            <strong>Methodology Note:</strong> Feature influence represents the directional sensitivity of the multi-step rollout model under single-dimension perturbation. It highlights features whose temporal delta shifts the forward attack probability most significantly.
          </div>

          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                <th style={{ padding: '8px 10px' }}>FEATURE</th>
                <th style={{ padding: '8px 10px' }}>INFLUENCE</th>
                <th style={{ padding: '8px 10px' }}>OBSERVED</th>
                <th style={{ padding: '8px 10px' }}>PREDICTED (T+5)</th>
                <th style={{ padding: '8px 10px' }}>DELTA SHIFT</th>
                <th style={{ padding: '8px 10px' }}>INTERPRETATION</th>
              </tr>
            </thead>
            <tbody>
              {drivers.map((d) => {
                const isHigh = d.importance === 'HIGH'
                const isMed = d.importance === 'MEDIUM'
                return (
                  <tr key={d.feature} style={{ borderBottom: '1px solid var(--border)', fontSize: '12.5px' }}>
                    <td style={{ padding: '10px', fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {d.feature}
                    </td>
                    <td style={{ padding: '10px' }}>
                      <span
                        style={{
                          fontSize: '11px',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontFamily: 'var(--mono)',
                          fontWeight: 600,
                          background: isHigh ? 'rgba(237, 128, 111, 0.15)' : isMed ? 'rgba(237, 168, 80, 0.15)' : 'rgba(92, 179, 122, 0.15)',
                          color: isHigh ? 'var(--danger)' : isMed ? '#eda850' : 'var(--accent)',
                        }}
                      >
                        {d.importance}
                      </span>
                    </td>
                    <td style={{ padding: '10px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
                      {d.currentValue}
                    </td>
                    <td style={{ padding: '10px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', fontWeight: 600 }}>
                      {d.predictedValue}
                    </td>
                    <td style={{ padding: '10px', fontFamily: 'var(--mono)', color: d.relativeChange >= 0 ? 'var(--danger)' : 'var(--accent)' }}>
                      {d.relativeChange >= 0 ? `+${(d.relativeChange * 100).toFixed(0)}%` : `${(d.relativeChange * 100).toFixed(0)}%`} ({d.direction})
                    </td>
                    <td style={{ padding: '10px', color: 'var(--text-secondary)', fontSize: '12px' }}>
                      {d.interpretation}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

import type { WhatChangedItemPayload } from '../../types/api'
import { GitCommit, TrendingUp, AlertCircle, Radio, Clock } from 'lucide-react'

interface WhatChangedPanelProps {
  items: WhatChangedItemPayload[]
}

export function WhatChangedPanel({ items }: WhatChangedPanelProps) {
  if (!items || items.length === 0) {
    return (
      <div style={{ padding: '16px', background: 'var(--surface-subtle)', borderRadius: '8px', color: 'var(--text-secondary)', fontSize: '13px' }}>
        No abrupt kinematic jumps, volume surges, or baseline deviations detected for this subject.
      </div>
    )
  }

  const getIcon = (changeType: string) => {
    switch (changeType) {
      case 'STATE_JUMP':
        return <TrendingUp size={16} style={{ color: 'var(--accent)' }} />
      case 'FAN_OUT_SURGE':
        return <AlertCircle size={16} style={{ color: 'var(--warning)' }} />
      case 'BASELINE_DEVIATION':
        return <Clock size={16} style={{ color: 'var(--accent-muted)' }} />
      case 'CAMPAIGN_CONVERGENCE':
        return <Radio size={16} style={{ color: 'var(--critical)' }} />
      default:
        return <GitCommit size={16} style={{ color: 'var(--text-secondary)' }} />
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      {items.map((item, idx) => (
        <div
          key={idx}
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
            padding: '12px 14px',
            background: 'var(--surface-subtle)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
          }}
        >
          <div style={{ marginTop: '2px' }}>{getIcon(item.change_type)}</div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                {item.headline}
              </span>
              <span
                style={{
                  fontSize: '11px',
                  fontFamily: 'var(--mono)',
                  background: 'var(--surface-ground)',
                  padding: '2px 6px',
                  borderRadius: '4px',
                  color: 'var(--text-secondary)',
                }}
              >
                Window {item.window_index}
              </span>
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              {item.description}
            </div>
            {item.supporting_signals && item.supporting_signals.length > 0 && (
              <div style={{ marginTop: '8px', display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {item.supporting_signals.map((sig, sIdx) => (
                  <span
                    key={sIdx}
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--mono)',
                      background: 'rgba(255, 255, 255, 0.05)',
                      padding: '2px 6px',
                      borderRadius: '3px',
                      color: 'var(--text-muted)',
                    }}
                  >
                    {sig}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

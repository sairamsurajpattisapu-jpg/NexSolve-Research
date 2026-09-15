import { useState } from 'react'
import { X, Search, Database } from 'lucide-react'
import type { FeatureDescriptor } from '../types/canonical'

interface FeatureVectorModalProps {
  isOpen: boolean
  onClose: () => void
  features: FeatureDescriptor[]
  timestamp: string
}

export function FeatureVectorModal({ isOpen, onClose, features, timestamp }: FeatureVectorModalProps) {
  const [filter, setFilter] = useState<'all' | 'flow' | 'packet' | 'temporal'>('all')
  const [query, setQuery] = useState('')

  if (!isOpen) return null

  const filtered = features.filter((f) => {
    if (filter !== 'all' && f.category !== filter) return false
    if (query.trim()) {
      const q = query.toLowerCase()
      return f.name.toLowerCase().includes(q) || f.description.toLowerCase().includes(q)
    }
    return true
  })

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="vector-modal-title"
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
          maxWidth: '900px',
          maxHeight: '88vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.4)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ padding: '8px', borderRadius: '6px', background: 'var(--button-secondary-bg)', color: 'var(--accent)' }}>
              <Database size={20} />
            </div>
            <div>
              <h2 id="vector-modal-title" style={{ fontSize: '18px', fontWeight: 600, margin: 0, color: 'var(--text-primary)' }}>
                Observed Network State: 45-Feature Vector
              </h2>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Canonical passive PCAP contract &middot; Window snapshot: {timestamp}
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

        {/* Filter bar */}
        <div style={{ padding: '12px 24px', borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', gap: '6px' }}>
            {(['all', 'flow', 'packet', 'temporal'] as const).map((cat) => (
              <button
                key={cat}
                type="button"
                className={`button button-quiet ${filter === cat ? 'active' : ''}`}
                onClick={() => setFilter(cat)}
                style={{
                  fontSize: '11px',
                  padding: '4px 10px',
                  height: 'auto',
                  border: filter === cat ? '1px solid var(--accent)' : '1px solid var(--border)',
                  background: filter === cat ? 'var(--button-secondary-bg)' : 'transparent',
                }}
              >
                {cat.toUpperCase()} ({cat === 'all' ? features.length : features.filter((f) => f.category === cat).length})
              </button>
            ))}
          </div>

          <div style={{ position: 'relative', width: '220px' }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search features..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{
                width: '100%',
                padding: '6px 10px 6px 30px',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                fontSize: '12px',
                color: 'var(--text-primary)',
              }}
            />
          </div>
        </div>

        {/* Feature Table */}
        <div style={{ overflowY: 'auto', padding: '0 24px 20px 24px', flex: 1 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', marginTop: '12px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                <th style={{ padding: '8px 10px' }}>FEATURE NAME</th>
                <th style={{ padding: '8px 10px' }}>CATEGORY</th>
                <th style={{ padding: '8px 10px' }}>OBSERVED VALUE</th>
                <th style={{ padding: '8px 10px' }}>UNIT</th>
                <th style={{ padding: '8px 10px' }}>SEMANTIC MEANING</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr key={f.name} style={{ borderBottom: '1px solid var(--border)', fontSize: '12.5px' }}>
                  <td style={{ padding: '10px', fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--accent)' }}>
                    {f.name}
                  </td>
                  <td style={{ padding: '10px' }}>
                    <span
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--mono)',
                        padding: '2px 6px',
                        borderRadius: '3px',
                        background: 'var(--bg-secondary)',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {f.category}
                    </span>
                  </td>
                  <td style={{ padding: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {typeof f.value === 'number' ? (Number.isInteger(f.value) ? f.value : f.value.toFixed(3)) : f.value}
                  </td>
                  <td style={{ padding: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', fontSize: '11px' }}>
                    {f.unit}
                  </td>
                  <td style={{ padding: '10px', color: 'var(--text-secondary)', fontSize: '12px' }}>
                    {f.description}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

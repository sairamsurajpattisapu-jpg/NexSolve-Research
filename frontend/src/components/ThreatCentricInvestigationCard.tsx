import { useState } from 'react'
import { CheckCircle, AlertTriangle } from 'lucide-react'
import type { ThreatCentricViewPayload, BehavioralEpisodePayload } from '../types/api'
import { Panel } from './Ui'

interface ThreatCentricInvestigationCardProps {
  threatViews?: ThreatCentricViewPayload[] | null
  episodes?: BehavioralEpisodePayload[] | null
}

export function ThreatCentricInvestigationCard({ threatViews }: ThreatCentricInvestigationCardProps) {
  const [selectedEntityIdx, setSelectedEntityIdx] = useState(0)

  if (!threatViews || threatViews.length === 0) {
    return null
  }

  const activeView = threatViews[selectedEntityIdx] || threatViews[0]
  const isHighRisk = activeView.threat_level === 'HIGH' || activeView.threat_level === 'CRITICAL'

  return (
    <Panel style={{ padding: '16px 20px', border: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="eyebrow" style={{ color: 'var(--danger)', margin: 0 }}>
              Threat-Centric Investigation
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid var(--danger)',
                padding: '1px 6px',
                borderRadius: '3px',
                color: 'var(--danger)',
                fontWeight: 700,
              }}
            >
              MULTI-MODAL ATTRIBUTION
            </span>
          </div>
          <h3 style={{ margin: '4px 0 0 0', fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Targeted Threat Entity Intelligence
          </h3>
        </div>

        {/* Entity Selector Pills if multiple */}
        {threatViews.length > 1 && (
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {threatViews.map((tv, idx) => (
              <button
                key={tv.entity_key}
                onClick={() => setSelectedEntityIdx(idx)}
                style={{
                  padding: '4px 8px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'var(--mono)',
                  cursor: 'pointer',
                  border: idx === selectedEntityIdx ? '1px solid var(--accent)' : '1px solid var(--border)',
                  background: idx === selectedEntityIdx ? 'var(--accent-muted)' : 'var(--bg-secondary)',
                  color: idx === selectedEntityIdx ? 'var(--accent)' : 'var(--text-muted)',
                }}
              >
                {tv.entity_key}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Primary Threat Summary Box */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '12px',
          marginTop: '14px',
          background: 'var(--bg-secondary)',
          padding: '12px 14px',
          borderRadius: '6px',
          border: '1px solid var(--border)',
        }}
      >
        <div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>
            Primary Target Entity
          </div>
          <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)', marginTop: '2px' }}>
            {activeView.entity_key}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Active in Windows {activeView.first_seen_window}..{activeView.last_seen_window}
          </div>
        </div>

        <div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>
            Inferred Attack State
          </div>
          <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--mono)', color: isHighRisk ? 'var(--danger)' : 'var(--success)', marginTop: '2px' }}>
            {activeView.current_attack_state}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
            {activeView.mitre_techniques.length > 0 ? `MITRE: ${activeView.mitre_techniques.join(', ')}` : 'Empirical MITRE mapping'}
          </div>
        </div>

        <div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>
            Corroborating Modalities
          </div>
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '4px' }}>
            {activeView.corroborating_modalities.map((mod) => (
              <span
                key={mod}
                style={{
                  fontSize: '9px',
                  fontFamily: 'var(--mono)',
                  background: 'rgba(56, 189, 248, 0.1)',
                  color: 'var(--accent)',
                  border: '1px solid var(--accent)',
                  padding: '1px 5px',
                  borderRadius: '3px',
                }}
              >
                {mod}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Investigation Explanation Chain ("Why This Threat?") */}
      <div style={{ marginTop: '16px' }}>
        <h4 style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', margin: '0 0 8px 0' }}>
          Deterministic Investigation Chain (Why NexSolve Thinks This)
        </h4>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {activeView.explanation_chain.map((step, idx) => (
            <div
              key={idx}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '8px',
                fontSize: '12px',
                lineHeight: '1.4',
                color: 'var(--text-primary)',
              }}
            >
              <CheckCircle size={14} color="var(--teal)" style={{ marginTop: '2px', flexShrink: 0 }} />
              <span>{step}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Contradicting Evidence & Context */}
      {activeView.contradicting_evidence && activeView.contradicting_evidence.length > 0 && (
        <div style={{ marginTop: '14px', background: 'rgba(234, 179, 8, 0.08)', padding: '10px 12px', borderRadius: '4px', border: '1px solid rgba(234, 179, 8, 0.3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 700, color: 'var(--warning)', fontFamily: 'var(--mono)' }}>
            <AlertTriangle size={13} />
            <span>Contradicting Evidence & Benign Exceptions</span>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px', lineHeight: '1.4' }}>
            {activeView.contradicting_evidence.join(' ')}
          </div>
        </div>
      )}

      {/* Forecast Hypothesis */}
      {activeView.forecast_hypothesis && (
        <div style={{ marginTop: '12px', fontSize: '11px', fontFamily: 'var(--mono)', color: '#c084fc' }}>
          <strong>Forecast Projection:</strong> {activeView.forecast_hypothesis}
        </div>
      )}
    </Panel>
  )
}

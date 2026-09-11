import { CheckCircle2, FileSearch, HelpCircle, XCircle } from 'lucide-react'
import type { EvidenceChainPayload } from '../types/api'
import { Panel, SectionHeading, StatusPill } from './Ui'

interface EvidenceChainProps {
  evidenceChain: EvidenceChainPayload
}

export function EvidenceChain({ evidenceChain }: EvidenceChainProps) {
  const isHighQuality = evidenceChain.evidence_quality === 'HIGH'
  const isInsufficient = evidenceChain.evidence_quality === 'INSUFFICIENT'

  return (
    <Panel className="evidence-chain-panel">
      <SectionHeading
        eyebrow="Explainability / Feature Semantics"
        title="Why This Forecast (Evidence Intelligence)"
        description="Deterministic server-side evidence extraction comparing current traffic state with recent lookback history."
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--muted)' }}>
              Quality:
            </span>
            <StatusPill tone={isHighQuality ? 'success' : isInsufficient ? 'danger' : 'warning'}>
              {evidenceChain.evidence_quality}
            </StatusPill>
          </div>
        }
      />

      {/* Evidence Strength & Summary */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '12px',
          marginBottom: '16px',
        }}
      >
        <div className="metric-card metric-accent" style={{ padding: '12px', minHeight: 'auto' }}>
          <div className="metric-top">
            <span>Evidence Strength</span>
            <FileSearch size={14} />
          </div>
          <strong style={{ fontSize: '22px', marginTop: '6px' }}>
            {evidenceChain.evidence_strength.toFixed(2)}
          </strong>
          <small>Consistency & volume score (NOT an attack probability)</small>
        </div>

        <div className="metric-card" style={{ padding: '12px', minHeight: 'auto' }}>
          <div className="metric-top">
            <span>Supporting Signals</span>
            <CheckCircle2 size={14} color="var(--teal)" />
          </div>
          <strong style={{ fontSize: '22px', marginTop: '6px', color: 'var(--teal)' }}>
            {evidenceChain.supporting_feature_count}
          </strong>
          <small>Observed feature increases & persistence</small>
        </div>

        <div className="metric-card" style={{ padding: '12px', minHeight: 'auto' }}>
          <div className="metric-top">
            <span>Contradictory Signals</span>
            <XCircle size={14} color={evidenceChain.contradictory_feature_count > 0 ? 'var(--red)' : 'var(--muted)'} />
          </div>
          <strong
            style={{
              fontSize: '22px',
              marginTop: '6px',
              color: evidenceChain.contradictory_feature_count > 0 ? 'var(--red)' : 'var(--muted)',
            }}
          >
            {evidenceChain.contradictory_feature_count}
          </strong>
          <small>Signals conflicting with the primary forecast</small>
        </div>
      </div>

      {/* Supporting Evidence List */}
      <div style={{ marginBottom: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
          <CheckCircle2 size={13} color="var(--teal)" />
          <strong style={{ fontSize: '11px', fontFamily: 'var(--mono)', textTransform: 'uppercase', color: 'var(--teal)', letterSpacing: '0.05em' }}>
            Supporting Evidence ({evidenceChain.supporting.length})
          </strong>
        </div>
        {evidenceChain.supporting.length === 0 ? (
          <p style={{ fontSize: '11px', color: 'var(--muted)', fontStyle: 'italic', margin: '4px 0 0 16px' }}>
            No corroborating traffic anomalies observed.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {evidenceChain.supporting.map((item) => (
              <div
                key={item.evidence_id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '8px',
                  padding: '8px 10px',
                  background: 'rgba(104, 225, 216, 0.05)',
                  borderLeft: '3px solid var(--teal)',
                  borderRadius: '3px',
                  fontSize: '11px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '180px' }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--teal)', fontWeight: 700 }}>
                    [{item.evidence_type}]
                  </span>
                  <span style={{ color: 'var(--white)', fontWeight: 600 }}>{item.feature_name}</span>
                </div>
                <div style={{ flex: 1, color: 'var(--subtle)', fontSize: '11px' }}>
                  {item.explanation}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--mono)', fontSize: '10px' }}>
                  <span style={{ color: 'var(--muted)' }}>
                    Observed: <strong style={{ color: 'var(--white)' }}>{item.observed_value}</strong> (base: {item.baseline_value})
                  </span>
                  {item.relative_change !== null && (
                    <span style={{ color: 'var(--teal)', fontWeight: 700 }}>
                      +{Math.abs(item.relative_change * 100).toFixed(1)}%
                    </span>
                  )}
                  <span style={{ color: 'var(--muted)', fontSize: '9px' }}>
                    rel: {(item.reliability ?? 1.0).toFixed(1)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Contradictory Evidence List */}
      <div style={{ marginBottom: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
          <HelpCircle size={13} color="var(--amber)" />
          <strong style={{ fontSize: '11px', fontFamily: 'var(--mono)', textTransform: 'uppercase', color: 'var(--amber)', letterSpacing: '0.05em' }}>
            Contradictory Evidence & Capture Limitations ({evidenceChain.contradictory.length})
          </strong>
        </div>
        {evidenceChain.contradictory.length === 0 ? (
          <p style={{ fontSize: '11px', color: 'var(--muted)', fontStyle: 'italic', margin: '4px 0 0 16px' }}>
            None detected; observed signals are directionally consistent.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {evidenceChain.contradictory.map((item) => (
              <div
                key={item.evidence_id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '8px',
                  padding: '8px 10px',
                  background: 'rgba(237, 128, 111, 0.06)',
                  borderLeft: '3px solid var(--red)',
                  borderRadius: '3px',
                  fontSize: '11px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: '180px' }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--red)', fontWeight: 700 }}>
                    [{item.evidence_type}]
                  </span>
                  <span style={{ color: 'var(--white)', fontWeight: 600 }}>{item.feature_name}</span>
                </div>
                <div style={{ flex: 1, color: 'var(--subtle)', fontSize: '11px' }}>
                  {item.explanation}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--mono)', fontSize: '10px' }}>
                  <span style={{ color: 'var(--muted)' }}>
                    Observed: <strong style={{ color: 'var(--white)' }}>{item.observed_value}</strong> (base: {item.baseline_value})
                  </span>
                  <span style={{ color: 'var(--red)', fontWeight: 700 }}>
                    CONFLICT
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Capture Limitations */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', textTransform: 'uppercase', color: 'var(--muted)', letterSpacing: '0.05em' }}>
            Capture Limitations ({evidenceChain.limitations?.length ?? 0})
          </span>
        </div>
        {(!evidenceChain.limitations || evidenceChain.limitations.length === 0) ? (
          <p style={{ fontSize: '11px', color: 'var(--muted)', fontStyle: 'italic', margin: '4px 0 0 16px' }}>
            No packet loss, truncation, or protocol gaps identified in current capture window.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {evidenceChain.limitations.map((lim, idx) => {
              const limType = typeof lim === 'string' ? 'LIMITATION' : lim.type
              const limDesc = typeof lim === 'string' ? lim : lim.description
              const limImpact = typeof lim === 'string' ? null : lim.impact
              return (
                <div
                  key={typeof lim === 'string' ? `${lim}-${idx}` : (lim.type || idx)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    padding: '6px 8px',
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid var(--line)',
                    borderRadius: '3px',
                    fontSize: '10px',
                    fontFamily: 'var(--mono)',
                  }}
                >
                  <span style={{ color: 'var(--amber)', minWidth: '110px' }}>[{limType}]</span>
                  <span style={{ color: 'var(--subtle)', flex: 1 }}>{limDesc}</span>
                  {limImpact && <span style={{ color: 'var(--muted)' }}>Impact: {limImpact}</span>}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Provenance & Limitations Footer */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginTop: '14px',
          paddingTop: '10px',
          borderTop: '1px solid var(--line)',
          fontSize: '9px',
          fontFamily: 'var(--mono)',
          color: 'var(--muted)',
        }}
      >
        <span>
          Window: {evidenceChain.current_window_id ?? 'Live Observation'} &middot; {evidenceChain.current_timestamp}
        </span>
        <span>
          Provenance: {evidenceChain.provenance_complete ? 'Complete' : 'Partial'}
        </span>
      </div>
    </Panel>
  )
}

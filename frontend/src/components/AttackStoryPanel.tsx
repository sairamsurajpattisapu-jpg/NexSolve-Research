import { useState } from 'react'
import { Panel } from './Ui'
import type { ThreatStoryPayload } from '../types/api'
import { FileText, ChevronRight, AlertTriangle, ShieldCheck } from 'lucide-react'

interface AttackStoryPanelProps {
  threatStories?: ThreatStoryPayload[] | null
}

export const AttackStoryPanel: React.FC<AttackStoryPanelProps> = ({ threatStories }) => {
  const [selectedIdx, setSelectedIdx] = useState<number>(0)

  if (!threatStories || threatStories.length === 0) {
    return null
  }

  const currentStory = threatStories[selectedIdx] || threatStories[0]

  return (
    <Panel
      className="attack-story-panel"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
        padding: '16px',
        border: '1px solid var(--border)',
        borderRadius: '8px',
        background: 'var(--bg-panel)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <FileText size={18} color="var(--accent)" />
          <span style={{ fontWeight: 700, fontSize: '14px', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
            Threat Investigation Story
          </span>
          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              padding: '2px 8px',
              borderRadius: '4px',
              border: '1px solid var(--border)',
              color: 'var(--text-muted)',
            }}
          >
            {threatStories.length} Structured Narratives
          </span>
        </div>

        {threatStories.length > 1 && (
          <div style={{ display: 'flex', gap: '6px' }}>
            {threatStories.map((s, idx) => (
              <button
                key={s.story_id}
                onClick={() => setSelectedIdx(idx)}
                style={{
                  padding: '3px 8px',
                  fontSize: '11px',
                  fontFamily: 'var(--mono)',
                  borderRadius: '4px',
                  border: idx === selectedIdx ? '1px solid var(--accent)' : '1px solid var(--border)',
                  background: idx === selectedIdx ? 'var(--accent-glow)' : 'transparent',
                  color: idx === selectedIdx ? 'var(--accent)' : 'var(--text-muted)',
                  cursor: 'pointer',
                }}
              >
                {s.entity}
              </button>
            ))}
          </div>
        )}
      </div>

      <div style={{ padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: '6px', borderLeft: '3px solid var(--accent)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
          <span style={{ fontWeight: 600, fontSize: '13px' }}>{currentStory.headline}</span>
          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: '4px',
              background:
                currentStory.threat_verdict === 'CONFIRMED_THREAT'
                  ? 'rgba(239, 68, 68, 0.15)'
                  : currentStory.threat_verdict === 'SUSPICIOUS'
                  ? 'rgba(245, 158, 11, 0.15)'
                  : 'rgba(16, 185, 129, 0.15)',
              color:
                currentStory.threat_verdict === 'CONFIRMED_THREAT'
                  ? 'var(--danger)'
                  : currentStory.threat_verdict === 'SUSPICIOUS'
                  ? 'var(--warning)'
                  : 'var(--success)',
              border:
                currentStory.threat_verdict === 'CONFIRMED_THREAT'
                  ? '1px solid var(--danger)'
                  : currentStory.threat_verdict === 'SUSPICIOUS'
                  ? '1px solid var(--warning)'
                  : '1px solid var(--success)',
            }}
          >
            {currentStory.threat_verdict}
          </span>
        </div>
        <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
          {currentStory.current_assessment}
        </p>
      </div>

      {/* Narrative Stages Timeline */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
        <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
          Chronological Investigation Milestones
        </span>
        {currentStory.stages.map((st, i) => (
          <div
            key={i}
            style={{
              display: 'flex',
              gap: '10px',
              padding: '8px 12px',
              background: st.is_contradiction ? 'rgba(56, 189, 248, 0.05)' : 'var(--bg-card)',
              borderRadius: '6px',
              border: st.is_contradiction ? '1px dashed var(--accent)' : '1px solid var(--border)',
              fontSize: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', minWidth: '140px', gap: '6px' }}>
              <ChevronRight size={13} color="var(--accent)" />
              <span style={{ fontWeight: 600, fontFamily: 'var(--mono)', fontSize: '11px' }}>{st.stage_title}</span>
            </div>
            <div style={{ flex: 1, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              {st.narrative_text}
            </div>
          </div>
        ))}
      </div>

      {/* Contradictions & Forecast Projection */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px', marginTop: '6px' }}>
        <div style={{ padding: '10px 12px', background: 'var(--bg-subtle)', borderRadius: '6px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
            <ShieldCheck size={14} color="var(--success)" />
            <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>
              Contradictions & Mitigations
            </span>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {currentStory.contradicting_evidence && currentStory.contradicting_evidence.length > 0
              ? currentStory.contradicting_evidence.join('; ')
              : 'No contradictory benign telemetry identified.'}
          </span>
        </div>

        <div style={{ padding: '10px 12px', background: 'var(--bg-subtle)', borderRadius: '6px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
            <AlertTriangle size={14} color="var(--warning)" />
            <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>
              Forecast Horizon Projection
            </span>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {currentStory.forecast_projection}
          </span>
        </div>
      </div>
    </Panel>
  )
}

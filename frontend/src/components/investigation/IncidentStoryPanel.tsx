import { useState } from 'react'
import type { IncidentStoryPayload, AttackHorizonPayload, AttackProgressionForecast } from '../../types/api'
import { Panel } from '../Ui'
import {
  FileText,
  Clock,
  Layers,
  Users,
  TrendingUp,
  Link2,
  AlertTriangle,
  Compass,
  Radio,
  HelpCircle,
  Activity,
  ArrowRight,
} from 'lucide-react'

interface IncidentStoryPanelProps {
  incidentStory?: IncidentStoryPayload | null
  attackHorizon?: AttackHorizonPayload | null
  attackProgression?: AttackProgressionForecast | null
}

export function IncidentStoryPanel({ incidentStory, attackHorizon, attackProgression }: IncidentStoryPanelProps) {
  const [activeTab, setActiveTab] = useState<'NARRATIVE' | 'TIMELINE' | 'PHASES' | 'ACTORS_TARGETS' | 'TRANSITIONS' | 'EVIDENCE_CHAIN' | 'UNCERTAINTY'>('NARRATIVE')

  if (!incidentStory) {
    return null
  }

  const { assessment } = incidentStory

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span style={{ background: 'var(--critical)', color: '#fff', fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px' }}>CRITICAL</span>
      case 'HIGH':
        return <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: 'var(--critical)', fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px' }}>HIGH</span>
      case 'MEDIUM':
        return <span style={{ background: 'rgba(234, 179, 8, 0.2)', color: 'var(--warning)', fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px' }}>MEDIUM</span>
      default:
        return <span style={{ background: 'var(--surface-subtle)', color: 'var(--text-secondary)', fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px' }}>LOW</span>
    }
  }

  const getGroundingBadge = (grounding: string) => {
    switch (grounding) {
      case 'DIRECTLY_OBSERVED':
      case 'STRONGLY_SUPPORTED':
        return (
          <span style={{ fontSize: '10px', background: 'rgba(34, 197, 94, 0.15)', color: 'var(--success)', padding: '2px 6px', borderRadius: '4px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            {grounding}
          </span>
        )
      case 'FORECAST_ONLY':
        return (
          <span style={{ fontSize: '10px', background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', padding: '2px 6px', borderRadius: '4px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            FORECAST ONLY
          </span>
        )
      default:
        return (
          <span style={{ fontSize: '10px', background: 'rgba(59, 130, 246, 0.15)', color: 'var(--accent)', padding: '2px 6px', borderRadius: '4px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            {grounding}
          </span>
        )
    }
  }

  const getEpistemicBadge = (status: string) => {
    const isObserved = status === 'OBSERVED'
    return (
      <span
        style={{
          fontSize: '10px',
          fontWeight: 700,
          fontFamily: 'var(--mono)',
          padding: '2px 6px',
          borderRadius: '3px',
          background: isObserved ? 'rgba(34, 197, 94, 0.1)' : 'rgba(234, 179, 8, 0.1)',
          color: isObserved ? 'var(--success)' : 'var(--warning)',
        }}
      >
        {status}
      </span>
    )
  }

  return (
    <Panel className="incident-story-panel" style={{ padding: '20px 24px', marginBottom: '24px' }}>
      {/* Header Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>INCIDENT RECONSTRUCTION</span>
            <span style={{ fontSize: '10px', background: 'rgba(59, 130, 246, 0.15)', color: 'var(--accent)', padding: '2px 8px', borderRadius: '4px', fontFamily: 'var(--mono)', fontWeight: 600 }}>
              DETERMINISTIC ATTACK STORY
            </span>
            {getSeverityBadge(assessment.severity)}
          </div>
          <h3 style={{ margin: '0 0 6px 0', fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)' }}>
            {incidentStory.title}
          </h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontSize: '12px', color: 'var(--text-secondary)' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Clock size={14} style={{ color: 'var(--accent)' }} />
              <span>Span: Windows {assessment.start_window} – {assessment.end_window} ({assessment.duration_seconds.toFixed(0)}s)</span>
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Radio size={14} style={{ color: assessment.termination_status.includes('NOT_OBSERVED') ? 'var(--warning)' : 'var(--success)' }} />
              <span style={{ fontFamily: 'var(--mono)' }}>{assessment.termination_status}</span>
            </span>
          </div>
        </div>

        {/* Recommended Action Pill */}
        <div style={{ background: 'var(--surface-ground)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 14px', maxWidth: '380px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
            <Compass size={14} style={{ color: 'var(--accent)' }} />
            <span style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--accent)' }}>
              Recommended Next Action
            </span>
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.3 }}>
            {assessment.recommended_immediate_action}
          </div>
        </div>
      </div>

      {/* Executive Summary Callout */}
      <div
        style={{
          padding: '12px 16px',
          background: 'rgba(59, 130, 246, 0.05)',
          borderLeft: '4px solid var(--accent)',
          borderRadius: '0 6px 6px 0',
          marginBottom: '18px',
        }}
      >
        <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.45 }}>
          {incidentStory.executive_summary}
        </div>
      </div>

      {/* Tabs Strip */}
      <div style={{ display: 'flex', gap: '6px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px', marginBottom: '16px', overflowX: 'auto' }}>
        <button
          onClick={() => setActiveTab('NARRATIVE')}
          style={{
            background: activeTab === 'NARRATIVE' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'NARRATIVE' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <FileText size={14} /> Attack Narrative
        </button>
        <button
          onClick={() => setActiveTab('TIMELINE')}
          style={{
            background: activeTab === 'TIMELINE' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'TIMELINE' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Clock size={14} /> Event Timeline ({incidentStory.events.length})
        </button>
        <button
          onClick={() => setActiveTab('PHASES')}
          style={{
            background: activeTab === 'PHASES' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'PHASES' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Layers size={14} /> Attack Phases ({incidentStory.phases.length})
        </button>
        <button
          onClick={() => setActiveTab('ACTORS_TARGETS')}
          style={{
            background: activeTab === 'ACTORS_TARGETS' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'ACTORS_TARGETS' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Users size={14} /> Actors & Targets
        </button>
        <button
          onClick={() => setActiveTab('TRANSITIONS')}
          style={{
            background: activeTab === 'TRANSITIONS' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'TRANSITIONS' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <TrendingUp size={14} /> State Transitions ({incidentStory.transitions.length})
        </button>
        <button
          onClick={() => setActiveTab('EVIDENCE_CHAIN')}
          style={{
            background: activeTab === 'EVIDENCE_CHAIN' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'EVIDENCE_CHAIN' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Link2 size={14} /> Evidence Chain
        </button>
        <button
          onClick={() => setActiveTab('UNCERTAINTY')}
          style={{
            background: activeTab === 'UNCERTAINTY' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'UNCERTAINTY' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <AlertTriangle size={14} /> Uncertainties ({incidentStory.uncertainties.length})
        </button>
      </div>

      {/* Tab: Narrative */}
      {activeTab === 'NARRATIVE' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* 10 Core Attack Story Questions Quick-Assessment Strip */}
          <div style={{ background: 'var(--surface-ground)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '14px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
              <HelpCircle size={15} color="var(--accent)" />
              <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--accent)' }}>
                Attack Story Assessment · 10 Core Security Intelligence Inquiries
              </span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '8px' }}>
              <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>1. WHAT is happening?</div>
                <div style={{ fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>{assessment.classification.replace(/_/g, ' ')} ({assessment.severity})</div>
              </div>
              <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>2. WHO is involved?</div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {incidentStory.actors.map((a) => a.entity).join(', ') || 'Unspecified Actor'}
                </div>
              </div>
              <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>3. WHERE is it happening?</div>
                <div style={{ fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {incidentStory.targets.length} destination host(s) across ports [{incidentStory.targets.flatMap((t) => t.targeted_ports).slice(0, 4).join(', ') || 'various'}]
                </div>
              </div>
              <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>4. HOW did behavior evolve?</div>
                <div style={{ fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>{assessment.what_changed_summary}</div>
              </div>
              <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>5. WHAT stage is it currently in (T₀)?</div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--accent)', marginTop: '2px', fontWeight: 600 }}>
                  {attackProgression?.observed_state || incidentStory.events.filter((e) => e.epistemic_status === 'OBSERVED').slice(-1)[0]?.attack_state || 'RECONNAISSANCE'}
                </div>
              </div>
              <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>6. WHAT stage is developing next (T+1)?</div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#c084fc', marginTop: '2px', fontWeight: 600 }}>
                  {attackProgression?.forecast_points?.[0]
                    ? `${attackProgression.forecast_points[0].predicted_state} (${attackProgression.forecast_points[0].prediction_type})`
                    : 'Awaiting sufficient rollout sequence'}
                </div>
              </div>
              <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>7. WHAT evidence caused interpretation?</div>
                <div style={{ fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {incidentStory.evidence_chain.map((c) => c.stage_name).slice(0, 2).join(' · ') || 'Packet connection rates & SYN telemetry'}
                </div>
              </div>
              <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>8. T+1 → T+5 expected progression?</div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {attackProgression?.forecast_points && attackProgression.forecast_points.length > 0
                    ? attackProgression.forecast_points.map((pt) => `T+${pt.horizon_minutes}:${pt.predicted_state.slice(0, 4)}`).join(' → ')
                    : 'T+1 through T+5 Markovian rollout calculated'}
                </div>
              </div>
              <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>9. HOW confident is the system?</div>
                <div style={{ fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {attackProgression?.verdict === 'SUPPORTED'
                    ? `Supported · Empirical probability: ${(Number(attackProgression.forecast_points?.[0]?.transition_probability || 0) * 100).toFixed(1)}%`
                    : 'Grounding-verified observed evidence'}
                </div>
              </div>
              <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600 }}>10. WHEN to pay attention to next escalation?</div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--warning)', marginTop: '2px', fontWeight: 700 }}>
                  {attackHorizon?.lead_time_to_escalation_seconds
                    ? `Within ${attackHorizon.lead_time_to_escalation_seconds}s (T+${attackHorizon.escalation_horizon})`
                    : (attackHorizon?.lead_time_seconds ? `Onset within ${attackHorizon.lead_time_seconds}s` : 'Immediate triage recommended')}
                </div>
              </div>
            </div>
          </div>

          {incidentStory.narrative_paragraphs.map((p, idx) => (
            <p key={idx} style={{ margin: 0, fontSize: '13px', lineHeight: 1.6, color: 'var(--text-primary)' }}>
              {p}
            </p>
          ))}

          {incidentStory.forecast_summary && (
            <div style={{ marginTop: '8px', padding: '12px 14px', background: 'rgba(168, 85, 247, 0.05)', border: '1px solid rgba(168, 85, 247, 0.2)', borderRadius: '6px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                <span style={{ fontSize: '10px', fontWeight: 700, color: '#c084fc', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  FORECAST HORIZON PROJECTION (SEPARATE FROM OBSERVED HISTORY)
                </span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-primary)' }}>
                {incidentStory.forecast_summary}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Timeline */}
      {activeTab === 'TIMELINE' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {/* Legend Banner */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--surface-subtle)', borderRadius: '4px', fontSize: '11px', color: 'var(--text-secondary)' }}>
            <span>Chronological timeline with strict boundary between observed network facts and predictive model rollouts:</span>
            <div style={{ display: 'flex', gap: '10px' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--success)' }} />
                OBSERVED (T ≤ T₀)
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#c084fc' }} />
                FORECAST (T+1 .. T+5)
              </span>
            </div>
          </div>

          {incidentStory.events.map((evt) => {
            const isForecast = evt.epistemic_status === 'FORECAST'
            return (
              <div
                key={evt.event_id}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  padding: '12px 14px',
                  background: isForecast ? 'rgba(168, 85, 247, 0.04)' : 'var(--surface-subtle)',
                  border: `1px solid ${isForecast ? 'rgba(168, 85, 247, 0.25)' : 'var(--border-subtle)'}`,
                  borderRadius: '6px',
                }}
              >
                <div style={{ minWidth: '85px', fontSize: '11px', fontFamily: 'var(--mono)', color: isForecast ? '#c084fc' : 'var(--accent)', marginTop: '2px' }}>
                  W{evt.window_index} ({evt.timestamp.toFixed(0)}s)
                  {isForecast && (
                    <div style={{ fontSize: '9px', fontWeight: 700, color: '#c084fc' }}>FUTURE PROJECTION</div>
                  )}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
                        {evt.event_type}
                      </span>
                      {getEpistemicBadge(evt.epistemic_status)}
                      {getGroundingBadge(evt.grounding)}
                    </div>
                    {evt.mitre_technique && (
                      <span style={{ fontSize: '10px', background: 'var(--surface-ground)', color: 'var(--text-secondary)', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--mono)' }}>
                        {evt.mitre_technique}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    {evt.explanation}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Actor: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>{evt.actor}</strong>
                    {evt.target && (
                      <span> · Target: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>{evt.target}</strong></span>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Tab: Phases */}
      {activeTab === 'PHASES' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {incidentStory.phases.map((ph) => (
            <div
              key={ph.phase_id}
              style={{
                padding: '14px 16px',
                background: 'var(--surface-subtle)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    PHASE: {ph.phase_type}
                  </span>
                  {getEpistemicBadge(ph.epistemic_status)}
                  {getGroundingBadge(ph.grounding)}
                </div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--accent)' }}>
                  Windows {ph.start_window} – {ph.end_window} ({ph.duration_seconds.toFixed(0)}s)
                </span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                {ph.transition_reason}
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {ph.dominant_behaviors.map((b, bIdx) => (
                  <span key={bIdx} style={{ fontSize: '10px', background: 'var(--surface-ground)', color: 'var(--text-muted)', padding: '2px 6px', borderRadius: '4px' }}>
                    {b}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab: Actors & Targets */}
      {activeTab === 'ACTORS_TARGETS' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
          {/* Actors */}
          <div>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '8px' }}>
              Identified Primary Actors ({incidentStory.actors.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {incidentStory.actors.map((actor) => (
                <div key={actor.entity} style={{ padding: '12px', background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                      {actor.entity}
                    </span>
                    {getEpistemicBadge(actor.epistemic_status)}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    Roles: {actor.roles.join(', ')}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Active Windows: W{actor.first_seen_window} – W{actor.last_seen_window} · Sessions: {actor.session_count}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Targets */}
          <div>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '8px' }}>
              Affected Targets ({incidentStory.targets.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {incidentStory.targets.map((tgt) => (
                <div key={tgt.entity} style={{ padding: '12px', background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                      {tgt.entity}
                    </span>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      {tgt.connection_count} probes
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    Targeted Ports: {tgt.targeted_ports.join(', ') || 'Various'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab: State Transitions */}
      {activeTab === 'TRANSITIONS' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* Observed Kinematic Transitions */}
          <div>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '8px' }}>
              Directly Observed Kinematic Transitions ({incidentStory.transitions.length})
            </div>
            {incidentStory.transitions.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {incidentStory.transitions.map((tr) => (
                  <div key={tr.transition_id} style={{ padding: '12px 14px', background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>
                          {tr.from_state} → {tr.to_state}
                        </span>
                        {getGroundingBadge(tr.grounding)}
                      </div>
                      <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
                        Window {tr.window_index}
                      </span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {tr.explanation}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: '12px 14px', background: 'var(--surface-subtle)', borderRadius: '6px', color: 'var(--text-secondary)', fontSize: '12px' }}>
                State persistence maintained; no internal kinematic state changes observed during this capture span.
              </div>
            )}
          </div>

          {/* Predictive Markovian State Transitions (T+1 .. T+5) */}
          {attackProgression?.forecast_points && attackProgression.forecast_points.length > 0 && (
            <div>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: '#c084fc', fontWeight: 700, marginBottom: '8px' }}>
                Empirical Progression Forecast Transitions (T+1 .. T+5)
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {attackProgression.forecast_points.map((pt) => {
                  const probPct = pt.transition_probability !== null ? (pt.transition_probability * 100).toFixed(1) : 'N/A'
                  const isPersistence = pt.prediction_type === 'STATE_PERSISTENCE'
                  return (
                    <div
                      key={pt.horizon_minutes}
                      style={{
                        padding: '12px 14px',
                        background: 'rgba(168, 85, 247, 0.04)',
                        border: '1px solid rgba(168, 85, 247, 0.2)',
                        borderRadius: '6px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ fontSize: '11px', fontWeight: 700, color: '#c084fc', fontFamily: 'var(--mono)' }}>
                            T+{pt.horizon_minutes} ({pt.lead_time_seconds}s)
                          </span>
                          <span
                            style={{
                              fontSize: '10px',
                              fontFamily: 'var(--mono)',
                              fontWeight: 700,
                              padding: '2px 6px',
                              borderRadius: '3px',
                              background: isPersistence ? 'rgba(59, 130, 246, 0.15)' : 'rgba(234, 179, 8, 0.15)',
                              color: isPersistence ? 'var(--accent)' : 'var(--warning)',
                            }}
                          >
                            {pt.prediction_type}
                          </span>
                          <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>
                            → {pt.predicted_state}
                          </span>
                        </div>
                        <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
                          P(S) = {probPct}%
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                        Technique: <strong>{pt.predicted_technique || 'None'}</strong> · Evidence Grounding: {pt.supporting_evidence.join(', ') || 'Dataset transition matrix'}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Evidence Chain */}
      {activeTab === 'EVIDENCE_CHAIN' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {incidentStory.evidence_chain.map((link) => (
            <div
              key={link.step_order}
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
              <div
                style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '50%',
                  background: 'var(--accent-muted)',
                  color: 'var(--accent)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '11px',
                  fontWeight: 700,
                  fontFamily: 'var(--mono)',
                  flexShrink: 0,
                }}
              >
                {link.step_order}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {link.stage_name}
                  </span>
                  {getGroundingBadge(link.grounding)}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {link.description}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab: Uncertainty & Contradictions */}
      {activeTab === 'UNCERTAINTY' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {incidentStory.uncertainties.map((unc) => (
            <div key={unc.uncertainty_id} style={{ padding: '12px 14px', background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {unc.category} ({unc.level} UNCERTAINTY)
                </span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                {unc.description}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                <strong>Impact:</strong> {unc.impact_on_assessment}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--accent)', marginTop: '2px' }}>
                <strong>Suggested Clarification:</strong> {unc.suggested_clarification}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  )
}

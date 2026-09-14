import type { InvestigationQuestionPayload } from '../../types/api'
import { HelpCircle, CheckSquare, Search } from 'lucide-react'

interface InvestigationQuestionsPanelProps {
  questions: InvestigationQuestionPayload[]
}

export function InvestigationQuestionsPanel({ questions }: InvestigationQuestionsPanelProps) {
  if (!questions || questions.length === 0) {
    return (
      <div style={{ padding: '16px', background: 'var(--surface-subtle)', borderRadius: '8px', color: 'var(--text-secondary)', fontSize: '13px' }}>
        No critical unresolved questions identified for this decision.
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {questions.map((q, idx) => (
        <div
          key={idx}
          style={{
            padding: '14px',
            background: 'var(--surface-subtle)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', marginBottom: '6px' }}>
            <HelpCircle size={16} style={{ color: 'var(--accent)', marginTop: '2px', flexShrink: 0 }} />
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {q.question}
                </span>
                <span
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--mono)',
                    background: 'var(--accent-muted)',
                    color: 'var(--accent)',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    textTransform: 'uppercase',
                  }}
                >
                  {q.category}
                </span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4, marginBottom: '8px' }}>
                {q.context}
              </div>

              {q.suggested_checks && q.suggested_checks.length > 0 && (
                <div style={{ background: 'var(--surface-ground)', borderRadius: '4px', padding: '8px 10px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                    <Search size={12} style={{ color: 'var(--text-muted)' }} />
                    <span style={{ fontSize: '10px', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      Suggested Telemetry & Validation Checks
                    </span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {q.suggested_checks.map((check, cIdx) => (
                      <div key={cIdx} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                        <CheckSquare size={12} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                        <span>{check}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

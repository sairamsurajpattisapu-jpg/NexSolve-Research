import { useState } from 'react'
import type { AnalystDecisionPayload } from '../../types/api'
import { Panel } from '../Ui'
import { DecisionDetailPanel } from './DecisionDetailPanel'
import {
  Compass,
  AlertTriangle,
  Flame,
} from 'lucide-react'

interface AnalystCommandCenterProps {
  decisions?: AnalystDecisionPayload[] | null
}

export function AnalystCommandCenter({ decisions }: AnalystCommandCenterProps) {
  const decisionList = decisions || []
  const [selectedId, setSelectedId] = useState<string | null>(
    decisionList.length > 0 ? decisionList[0].decision_id : null
  )

  if (!decisionList || decisionList.length === 0) {
    return null
  }

  const currentDecision =
    decisionList.find((d) => d.decision_id === selectedId) || decisionList[0]

  const p0Count = decisionList.filter((d) => d.priority_tier === 'P0_CRITICAL').length
  const p1Count = decisionList.filter((d) => d.priority_tier === 'P1_HIGH').length
  const p2Count = decisionList.filter((d) => d.priority_tier === 'P2_MEDIUM').length

  const getTierColor = (tier: string) => {
    switch (tier) {
      case 'P0_CRITICAL':
        return 'var(--critical)'
      case 'P1_HIGH':
        return '#f97316' // Orange
      case 'P2_MEDIUM':
        return 'var(--warning)'
      default:
        return 'var(--accent)'
    }
  }

  return (
    <Panel className="analyst-command-center" style={{ padding: '20px 24px', marginBottom: '24px' }}>
      {/* Title & Status Strip */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '16px',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              DECISION INTELLIGENCE
            </span>
            <span
              style={{
                fontSize: '10px',
                background: 'rgba(59, 130, 246, 0.15)',
                color: 'var(--accent)',
                padding: '2px 8px',
                borderRadius: '4px',
                fontFamily: 'var(--mono)',
                fontWeight: 600,
              }}
            >
              TRIAGE & RESPONSE
            </span>
          </div>
          <h3 style={{ margin: '4px 0 0 0', fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Security Analyst Command Center
          </h3>
        </div>

        {/* Priority Counts */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {p0Count > 0 && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                padding: '4px 10px',
                borderRadius: '6px',
              }}
            >
              <Flame size={14} style={{ color: 'var(--critical)' }} />
              <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--critical)' }}>
                {p0Count} P0 CRITICAL
              </span>
            </div>
          )}
          {p1Count > 0 && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: 'rgba(249, 115, 22, 0.15)',
                border: '1px solid rgba(249, 115, 22, 0.3)',
                padding: '4px 10px',
                borderRadius: '6px',
              }}
            >
              <AlertTriangle size={14} style={{ color: '#f97316' }} />
              <span style={{ fontSize: '11px', fontWeight: 700, color: '#f97316' }}>
                {p1Count} P1 HIGH
              </span>
            </div>
          )}
          {p2Count > 0 && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: 'rgba(234, 179, 8, 0.15)',
                border: '1px solid rgba(234, 179, 8, 0.3)',
                padding: '4px 10px',
                borderRadius: '6px',
              }}
            >
              <Compass size={14} style={{ color: 'var(--warning)' }} />
              <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--warning)' }}>
                {p2Count} P2 MEDIUM
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Main Grid: Decision Queue on Left, Decision Detail on Right */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, 340px) 1fr', gap: '20px', alignItems: 'start' }}>
        {/* Decision Queue */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '2px' }}>
            Prioritized Decision Queue ({decisionList.length})
          </div>
          {decisionList.map((dec) => {
            const isSelected = dec.decision_id === currentDecision.decision_id
            const tierColor = getTierColor(dec.priority_tier)
            return (
              <div
                key={dec.decision_id}
                onClick={() => setSelectedId(dec.decision_id)}
                style={{
                  padding: '12px 14px',
                  background: isSelected ? 'var(--surface-subtle)' : 'var(--surface-ground)',
                  border: isSelected ? `2px solid ${tierColor}` : '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                  position: 'relative',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span
                      style={{
                        fontSize: '10px',
                        fontWeight: 700,
                        color: tierColor,
                        fontFamily: 'var(--mono)',
                      }}
                    >
                      #{dec.priority_rank} {dec.priority_tier}
                    </span>
                  </div>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                    {dec.decision_type.replace('INVESTIGATE_', '')}
                  </span>
                </div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', lineHeight: 1.3, marginBottom: '4px' }}>
                  {dec.headline}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', fontFamily: 'var(--mono)' }}>
                  Target: {dec.target_id}
                </div>
              </div>
            )
          })}
        </div>

        {/* Selected Decision Detail */}
        <div>
          <DecisionDetailPanel decision={currentDecision} />
        </div>
      </div>
    </Panel>
  )
}

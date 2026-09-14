import { useState } from 'react'
import type { AnalystDecisionPayload } from '../../types/api'
import { WhatChangedPanel } from './WhatChangedPanel'
import { AlternativeExplanationPanel } from './AlternativeExplanationPanel'
import { InvestigationQuestionsPanel } from './InvestigationQuestionsPanel'
import {
  ShieldAlert,
  HelpCircle,
  TrendingUp,
  AlertTriangle,
  Compass,
  Target,
  FileCheck2,
} from 'lucide-react'

interface DecisionDetailPanelProps {
  decision: AnalystDecisionPayload
}

export function DecisionDetailPanel({ decision }: DecisionDetailPanelProps) {
  const [activeTab, setActiveTab] = useState<'DECISION_CHAIN' | 'WHAT_CHANGED' | 'BENIGN_HYPOTHESES' | 'OPEN_QUESTIONS' | 'EVIDENCE'>('DECISION_CHAIN')

  const getGroundingBadge = (grounding: string) => {
    switch (grounding) {
      case 'DIRECTLY_OBSERVED':
      case 'STRONGLY_SUPPORTED':
        return (
          <span style={{ fontSize: '11px', background: 'rgba(34, 197, 94, 0.15)', color: 'var(--success)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            {grounding}
          </span>
        )
      case 'SUPPORTED':
        return (
          <span style={{ fontSize: '11px', background: 'rgba(59, 130, 246, 0.15)', color: 'var(--accent)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            {grounding}
          </span>
        )
      case 'CONTRADICTED':
      case 'INSUFFICIENT_EVIDENCE':
        return (
          <span style={{ fontSize: '11px', background: 'rgba(239, 68, 68, 0.15)', color: 'var(--critical)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            {grounding}
          </span>
        )
      default:
        return (
          <span style={{ fontSize: '11px', background: 'rgba(234, 179, 8, 0.15)', color: 'var(--warning)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            {grounding}
          </span>
        )
    }
  }

  const getTierBadge = (tier: string) => {
    switch (tier) {
      case 'P0_CRITICAL':
        return <span style={{ background: 'var(--critical)', color: '#fff', fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px' }}>P0 CRITICAL</span>
      case 'P1_HIGH':
        return <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: 'var(--critical)', fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px' }}>P1 HIGH</span>
      case 'P2_MEDIUM':
        return <span style={{ background: 'rgba(234, 179, 8, 0.2)', color: 'var(--warning)', fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px' }}>P2 MEDIUM</span>
      case 'P3_LOW':
        return <span style={{ background: 'var(--surface-subtle)', color: 'var(--text-secondary)', fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px' }}>P3 LOW</span>
      default:
        return <span style={{ background: 'var(--surface-subtle)', color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px' }}>INFO</span>
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Header Banner */}
      <div
        style={{
          background: 'var(--surface-subtle)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '16px 20px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              {getTierBadge(decision.priority_tier)}
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
                RANK #{decision.priority_rank}
              </span>
              <span style={{ fontSize: '11px', background: 'var(--surface-ground)', color: 'var(--text-secondary)', padding: '2px 6px', borderRadius: '4px' }}>
                {decision.decision_type}
              </span>
              {getGroundingBadge(decision.confidence_grounding)}
            </div>
            <h4 style={{ margin: '0 0 6px 0', fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              {decision.headline}
            </h4>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Target size={14} style={{ color: 'var(--accent)' }} />
              <span>Target Entity / Campaign: <strong style={{ fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>{decision.target_id}</strong></span>
            </div>
          </div>

          {/* Investigation Value Card */}
          {decision.investigation_value && (
            <div
              style={{
                background: 'var(--surface-ground)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '10px 14px',
                minWidth: '220px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span style={{ fontSize: '10px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', fontWeight: 700 }}>
                  Investigation Value
                </span>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
                  {decision.investigation_value.value_score.toFixed(2)}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '2px' }}>
                Uncertainty: <strong style={{ color: 'var(--text-primary)' }}>{decision.investigation_value.expected_uncertainty_reduction}</strong>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                Actionability: <strong style={{ color: 'var(--text-primary)' }}>{decision.investigation_value.actionability}</strong>
              </div>
            </div>
          )}
        </div>

        {/* Why Now Callout */}
        <div
          style={{
            marginTop: '14px',
            padding: '10px 14px',
            background: 'rgba(59, 130, 246, 0.05)',
            borderLeft: '3px solid var(--accent)',
            borderRadius: '0 6px 6px 0',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
            <Compass size={14} style={{ color: 'var(--accent)' }} />
            <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--accent)', fontWeight: 700 }}>
              Why Investigate Now?
            </span>
          </div>
          <div style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.4 }}>
            {decision.why_now}
          </div>
        </div>

        {/* Action Recommendation */}
        <div
          style={{
            marginTop: '10px',
            padding: '10px 14px',
            background: 'rgba(34, 197, 94, 0.05)',
            borderLeft: '3px solid var(--success)',
            borderRadius: '0 6px 6px 0',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <FileCheck2 size={16} style={{ color: 'var(--success)', flexShrink: 0 }} />
          <div style={{ fontSize: '12px', color: 'var(--text-primary)' }}>
            <strong>Recommended Immediate Step:</strong> {decision.recommended_action}
          </div>
        </div>
      </div>

      {/* Semantic Tier and Grounding Differentiation Banner */}
      {decision.threat_differentiation && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '10px',
            padding: '10px 16px',
            background: 'var(--surface-ground)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            fontSize: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Semantic Tier:</span>
            <span style={{ fontWeight: 700, color: 'var(--accent)', fontFamily: 'var(--mono)' }}>
              {decision.threat_differentiation.semantic_tier}
            </span>
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '11px', maxWidth: '600px', lineHeight: 1.3 }}>
            {decision.threat_differentiation.rationale}
          </div>
        </div>
      )}

      {/* Tabs Strip */}
      <div style={{ display: 'flex', gap: '6px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px', overflowX: 'auto' }}>
        <button
          onClick={() => setActiveTab('DECISION_CHAIN')}
          style={{
            background: activeTab === 'DECISION_CHAIN' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'DECISION_CHAIN' ? '#fff' : 'var(--text-secondary)',
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
          <TrendingUp size={14} /> Decision Chain
        </button>
        <button
          onClick={() => setActiveTab('WHAT_CHANGED')}
          style={{
            background: activeTab === 'WHAT_CHANGED' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'WHAT_CHANGED' ? '#fff' : 'var(--text-secondary)',
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
          <ShieldAlert size={14} /> What Changed ({decision.what_changed.length})
        </button>
        <button
          onClick={() => setActiveTab('BENIGN_HYPOTHESES')}
          style={{
            background: activeTab === 'BENIGN_HYPOTHESES' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'BENIGN_HYPOTHESES' ? '#fff' : 'var(--text-secondary)',
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
          <AlertTriangle size={14} /> Benign Hypotheses ({decision.benign_hypotheses.length})
        </button>
        <button
          onClick={() => setActiveTab('OPEN_QUESTIONS')}
          style={{
            background: activeTab === 'OPEN_QUESTIONS' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'OPEN_QUESTIONS' ? '#fff' : 'var(--text-secondary)',
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
          <HelpCircle size={14} /> Open Questions ({decision.open_questions.length})
        </button>
      </div>

      {/* Tab Contents */}
      {activeTab === 'DECISION_CHAIN' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {decision.decision_chain && decision.decision_chain.steps.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {decision.decision_chain.steps.map((step, sIdx) => (
                <div
                  key={sIdx}
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
                    {sIdx + 1}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {step.title}
                      </span>
                      {getGroundingBadge(step.grounding)}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                      {step.description}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ padding: '16px', background: 'var(--surface-subtle)', borderRadius: '8px', color: 'var(--text-secondary)', fontSize: '13px' }}>
              No multi-step decision chain constructed.
            </div>
          )}

          {/* Supporting Evidence Bullets */}
          {decision.supporting_evidence.length > 0 && (
            <div style={{ marginTop: '8px', padding: '12px 16px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', fontWeight: 700 }}>
                Primary Supporting Evidence
              </span>
              <ul style={{ margin: '6px 0 0 0', paddingLeft: '18px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                {decision.supporting_evidence.map((ev, eIdx) => (
                  <li key={eIdx} style={{ marginBottom: '3px' }}>{ev}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {activeTab === 'WHAT_CHANGED' && (
        <WhatChangedPanel items={decision.what_changed} />
      )}

      {activeTab === 'BENIGN_HYPOTHESES' && (
        <AlternativeExplanationPanel hypotheses={decision.benign_hypotheses} />
      )}

      {activeTab === 'OPEN_QUESTIONS' && (
        <InvestigationQuestionsPanel questions={decision.open_questions} />
      )}
    </div>
  )
}

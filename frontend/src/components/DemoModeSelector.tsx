import { CheckCircle2, Play, Sparkles, X } from 'lucide-react'
import { useState } from 'react'
import { DEMO_SCENARIOS_META, DEMO_SCENARIO_PAYLOADS } from '../fixtures/demoScenarios'
import { api } from '../services/api'
import type { UploadedAnalysisResponse } from '../types/api'
import { Panel, SectionHeading } from './Ui'

interface DemoModeSelectorProps {
  onSelectScenario: (scenarioResult: UploadedAnalysisResponse) => void
  onClose?: () => void
}

export function DemoModeSelector({ onSelectScenario, onClose }: DemoModeSelectorProps) {
  const [selectedId, setSelectedId] = useState<string>('EARLY_ATTACK_SIGNAL')
  const [loading, setLoading] = useState<boolean>(false)

  const selectedMeta = DEMO_SCENARIOS_META.find((m) => m.id === selectedId) ?? DEMO_SCENARIOS_META[0]

  const handleRunScenario = async (scenarioId: string) => {
    setLoading(true)
    try {
      // First try live API endpoint
      const result = await api.getDemoScenarioResult(scenarioId)
      onSelectScenario(result)
    } catch {
      // Deterministic offline fallback if backend API is not responding
      const fallback = DEMO_SCENARIO_PAYLOADS[scenarioId] ?? DEMO_SCENARIO_PAYLOADS.NORMAL_TRAFFIC
      onSelectScenario(fallback)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Panel className="demo-mode-panel">
      <SectionHeading
        eyebrow="SIH Evaluation Mode / Deterministic Scenarios"
        title="Interactive Judge Demonstration"
        description="Experience NexSolve's predictive intelligence, attack horizon, and abstention mechanics instantaneously without processing external PCAP files."
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
                padding: '4px 10px',
                borderRadius: '4px',
                background: 'var(--accent-muted)',
                color: 'var(--accent)',
                border: '1px solid var(--accent)',
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                fontWeight: 700,
                letterSpacing: '0.05em',
              }}
            >
              <Sparkles size={12} /> DEMO MODE ACTIVE
            </span>
            {onClose && (
              <button
                type="button"
                className="button button-quiet"
                style={{ padding: '5px 10px', fontSize: '11px' }}
                onClick={onClose}
                aria-label="Exit Demo Mode"
              >
                <X size={14} /> Exit Demo
              </button>
            )}
          </div>
        }
      />

      {/* Scenario Selector Tabs */}
      <div
        role="tablist"
        aria-label="Demo scenarios"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(135px, 1fr))',
          gap: '8px',
          marginTop: '12px',
          marginBottom: '16px',
        }}
      >
        {DEMO_SCENARIOS_META.map((scenario) => {
          const isSelected = scenario.id === selectedId
          return (
            <button
              key={scenario.id}
              type="button"
              role="tab"
              aria-selected={isSelected}
              className={`button button-quiet ${isSelected ? 'active' : ''}`}
              style={{
                padding: '8px 10px',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-start',
                gap: '4px',
                textAlign: 'left',
                borderRadius: '6px',
                borderColor: isSelected ? 'var(--accent)' : 'var(--border)',
                background: isSelected ? 'var(--accent-muted)' : 'var(--button-secondary-bg)',
                color: isSelected ? 'var(--accent)' : 'var(--text-primary)',
              }}
              onClick={() => {
                setSelectedId(scenario.id)
                void handleRunScenario(scenario.id)
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
                <span
                  style={{
                    fontSize: '9px',
                    fontFamily: 'var(--mono)',
                    fontWeight: 700,
                    letterSpacing: '0.04em',
                    color: isSelected ? 'var(--accent)' : 'var(--text-muted)',
                  }}
                >
                  {scenario.badge}
                </span>
                {isSelected && <CheckCircle2 size={12} color="var(--accent)" />}
              </div>
              <strong
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  color: isSelected ? 'var(--text-primary)' : 'var(--text-secondary)',
                  lineHeight: 1.25,
                }}
              >
                {scenario.name}
              </strong>
            </button>
          )
        })}
      </div>

      {/* Selected Scenario Information Card */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '14px',
          padding: '14px 16px',
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: '6px',
        }}
      >
        <div>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Scenario Context
          </span>
          <h4 style={{ margin: '4px 0 6px 0', fontSize: '13px', color: 'var(--text-primary)' }}>
            {selectedMeta.name}
          </h4>
          <p style={{ margin: 0, fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            {selectedMeta.description}
          </p>
        </div>

        <div>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase' }}>
            Expected Evaluation Behavior
          </span>
          <p
            style={{
              margin: '4px 0 0 0',
              fontSize: '11px',
              color: 'var(--text-primary)',
              lineHeight: 1.5,
              background: 'var(--accent-muted)',
              padding: '8px 10px',
              borderRadius: '4px',
              borderLeft: '3px solid var(--accent)',
            }}
          >
            {selectedMeta.expected_behavior}
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '14px' }}>
        <button
          type="button"
          className="button"
          disabled={loading}
          onClick={() => void handleRunScenario(selectedId)}
          style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
        >
          <Play size={13} /> {loading ? 'Loading scenario...' : `Load ${selectedMeta.name}`}
        </button>
      </div>
    </Panel>
  )
}

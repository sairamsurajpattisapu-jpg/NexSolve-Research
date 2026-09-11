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
                gap: '4px',
                padding: '3px 8px',
                borderRadius: '4px',
                background: 'rgba(104, 225, 216, 0.15)',
                color: 'var(--teal)',
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
                style={{ padding: '4px 8px', fontSize: '11px' }}
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
          gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
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
                borderRadius: '5px',
                borderColor: isSelected ? 'var(--teal)' : 'var(--line)',
                background: isSelected ? 'rgba(104, 225, 216, 0.08)' : 'rgba(255, 255, 255, 0.01)',
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
                    color: isSelected ? 'var(--teal)' : 'var(--muted)',
                  }}
                >
                  {scenario.badge}
                </span>
                {isSelected && <CheckCircle2 size={12} color="var(--teal)" />}
              </div>
              <strong
                style={{
                  fontSize: '11px',
                  color: isSelected ? 'var(--white)' : 'var(--subtle)',
                  lineHeight: 1.2,
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
          padding: '12px 14px',
          background: 'rgba(0, 0, 0, 0.25)',
          border: '1px solid var(--line)',
          borderRadius: '4px',
        }}
      >
        <div>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--muted)', textTransform: 'uppercase' }}>
            Scenario Context
          </span>
          <h4 style={{ margin: '4px 0 6px 0', fontSize: '13px', color: 'var(--white)' }}>
            {selectedMeta.name}
          </h4>
          <p style={{ margin: 0, fontSize: '11px', color: 'var(--subtle)', lineHeight: 1.5 }}>
            {selectedMeta.description}
          </p>
        </div>

        <div>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--teal)', textTransform: 'uppercase' }}>
            Expected Evaluation Behavior
          </span>
          <p
            style={{
              margin: '4px 0 0 0',
              fontSize: '11px',
              color: 'var(--white)',
              lineHeight: 1.5,
              background: 'rgba(104, 225, 216, 0.04)',
              padding: '6px 8px',
              borderRadius: '3px',
              borderLeft: '2px solid var(--teal)',
            }}
          >
            {selectedMeta.expected_behavior}
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '12px' }}>
        <button
          type="button"
          className="button"
          disabled={loading}
          onClick={() => void handleRunScenario(selectedId)}
          style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          <Play size={13} /> {loading ? 'Loading scenario...' : `Load ${selectedMeta.name}`}
        </button>
      </div>
    </Panel>
  )
}

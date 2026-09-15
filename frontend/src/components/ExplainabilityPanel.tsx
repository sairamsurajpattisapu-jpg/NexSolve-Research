import { useState } from 'react'
import { AlertCircle, Lightbulb } from 'lucide-react'
import { FeatureDriver, type DriverItem } from './FeatureDriver'
import { Panel } from './Ui'

interface ExplainabilityPanelProps {
  drivers?: DriverItem[]
  earlyWarningDrivers?: string[]
  abstainedReason?: string | null
  currentStage?: string | null
  predictedStage?: string | null
}

export function ExplainabilityPanel({
  drivers = [],
  earlyWarningDrivers = [],
  abstainedReason,
  currentStage,
  predictedStage,
}: ExplainabilityPanelProps) {
  const [filter, setFilter] = useState<'ALL' | 'HIGH' | 'MEDIUM'>('ALL')

  const filteredDrivers = drivers.filter((d) => {
    if (filter === 'ALL') return true
    return d.importance.toUpperCase() === filter
  })

  return (
    <Panel className="explainability-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              CONTINUOUS ATTRIBUTION & INTERPRETABILITY
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                padding: '2px 6px',
                borderRadius: '3px',
                background: 'var(--accent-muted)',
                color: 'var(--accent)',
              }}
            >
              ZERO-HALLUCINATION
            </span>
          </div>
          <h3 style={{ fontSize: '18px', fontWeight: 700, margin: '4px 0 2px 0', color: 'var(--text-primary)' }}>
            Why is NexSolve Predicting This?
          </h3>
          <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-muted)', maxWidth: '640px' }}>
            Decomposing forward state projections into grounded network telemetry deltas. Rankings isolate dominant volumetric, kinematic, and flag perturbations driving forecast escalation.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '6px' }}>
          {(['ALL', 'HIGH', 'MEDIUM'] as const).map((lvl) => (
            <button
              key={lvl}
              type="button"
              className={`button button-quiet ${filter === lvl ? 'active' : ''}`}
              style={{ padding: '4px 10px', fontSize: '10px', fontFamily: 'var(--mono)' }}
              onClick={() => setFilter(lvl)}
            >
              {lvl === 'ALL' ? 'All Drivers' : `${lvl} Delta`}
            </button>
          ))}
        </div>
      </div>

      {/* High-Level Progression Summary if available */}
      {(currentStage || predictedStage) && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '10px 14px',
            borderRadius: '6px',
            background: 'rgba(104, 225, 216, 0.05)',
            border: '1px solid rgba(104, 225, 216, 0.2)',
            marginBottom: '14px',
            fontSize: '12px',
            fontFamily: 'var(--mono)',
          }}
        >
          <Lightbulb size={16} color="var(--accent)" />
          <span>
            Transition Context:{' '}
            <strong style={{ color: 'var(--text-primary)' }}>{currentStage || 'BASELINE'}</strong>
            {' → '}
            <strong style={{ color: 'var(--danger)' }}>{predictedStage || 'ATTACK_IMMINENT'}</strong>
          </span>
        </div>
      )}

      {/* Abstained state banner */}
      {abstainedReason && (
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: '10px',
            padding: '12px 14px',
            borderRadius: '6px',
            background: 'rgba(242, 187, 113, 0.08)',
            border: '1px solid rgba(242, 187, 113, 0.3)',
            marginBottom: '14px',
          }}
        >
          <AlertCircle size={16} color="var(--warning)" style={{ marginTop: '2px' }} />
          <div>
            <strong style={{ fontSize: '12px', color: 'var(--warning)', display: 'block' }}>
              Safety Gate Withheld Predictions
            </strong>
            <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
              {abstainedReason}
            </p>
          </div>
        </div>
      )}

      {/* Early Warning Synthesis Bullets */}
      {earlyWarningDrivers.length > 0 && (
        <div style={{ marginBottom: '16px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Multi-Signal Synthesis
          </span>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: '8px',
              marginTop: '6px',
            }}
          >
            {earlyWarningDrivers.map((driverStr, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '8px',
                  padding: '8px 12px',
                  borderRadius: '4px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  fontSize: '11.5px',
                  color: 'var(--text-secondary)',
                }}
              >
                <span style={{ color: 'var(--accent)', fontWeight: 700 }}>•</span>
                <span>{driverStr}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Ranked Feature Drivers List */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Ranked Feature Drivers ({filteredDrivers.length})
          </span>
          <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
            Ranked by |Relative Delta|
          </span>
        </div>

        {filteredDrivers.length === 0 ? (
          <div
            style={{
              padding: '24px',
              textAlign: 'center',
              borderRadius: '6px',
              background: 'var(--bg-secondary)',
              border: '1px dashed var(--border)',
              fontSize: '12.5px',
              color: 'var(--text-muted)',
            }}
          >
            No high-significance feature deltas detected for the selected threshold. Network state dynamics remain near equilibrium.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {filteredDrivers.map((driver, index) => (
              <FeatureDriver key={driver.feature} driver={driver} rank={index + 1} />
            ))}
          </div>
        )}
      </div>
    </Panel>
  )
}

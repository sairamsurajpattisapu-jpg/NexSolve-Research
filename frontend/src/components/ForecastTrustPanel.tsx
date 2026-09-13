import { SlidersHorizontal } from 'lucide-react'
import { useState } from 'react'
import { forecastTrustFixtures } from '../fixtures/forecastTrustFixtures'
import type { ForecastResponse } from '../types/api'
import { AttackHorizonCard } from './AttackHorizonCard'
import { AttackProgressionCard } from './AttackProgressionCard'
import { EvidenceChain } from './EvidenceChain'
import { ForecastConfidence } from './ForecastConfidence'
import { ForecastStatus } from './ForecastStatus'
import { Panel } from './Ui'
import { UnknownBehavior } from './UnknownBehavior'

interface ForecastTrustPanelProps {
  initialResponse?: ForecastResponse
  allowFixtureSwitching?: boolean
}

export function ForecastTrustPanel({
  initialResponse,
  allowFixtureSwitching = true,
}: ForecastTrustPanelProps) {
  const [selectedFixtureId, setSelectedFixtureId] = useState<string>('sustainedForecast')

  const activeFixture = forecastTrustFixtures[selectedFixtureId] ?? forecastTrustFixtures.sustainedForecast
  const currentResponse: ForecastResponse = initialResponse ?? activeFixture.response

  const attackHorizon = currentResponse.attack_horizon ?? currentResponse.attackHorizon
  const attackProgression = currentResponse.attack_progression ?? currentResponse.attackProgression
  const evidenceChain = currentResponse.evidence_chain ?? currentResponse.evidenceChain
  const confidence = currentResponse.confidence
  const unknownBehavior = currentResponse.unknown_behavior ?? currentResponse.unknownBehavior
  const abstention = currentResponse.abstention

  return (
    <div className="forecast-trust-container" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Interactive Scenario Fixture Switcher */}
      {allowFixtureSwitching && !initialResponse && (
        <Panel className="filter-panel">
          <div style={{ width: '100%' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <SlidersHorizontal size={14} color="var(--teal)" />
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', fontWeight: 600 }}>
                Interactive Trust Layer Scenario Fixtures (11 Scenarios):
              </span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
              {Object.values(forecastTrustFixtures).map((fix) => (
                <button
                  key={fix.id}
                  type="button"
                  className={`button button-quiet ${selectedFixtureId === fix.id ? 'active' : ''}`}
                  style={{
                    padding: '4px 8px',
                    fontSize: '9px',
                    fontFamily: 'var(--mono)',
                    borderColor: selectedFixtureId === fix.id ? 'var(--accent)' : 'var(--border)',
                    color: selectedFixtureId === fix.id ? 'var(--accent)' : 'var(--text-secondary)',
                    background: selectedFixtureId === fix.id ? 'var(--accent-muted)' : 'var(--button-secondary-bg)',
                  }}
                  onClick={() => setSelectedFixtureId(fix.id)}
                >
                  {fix.title.split('. ')[1] ?? fix.title}
                </button>
              ))}
            </div>
          </div>
          <div style={{ marginTop: '8px', fontSize: '10px', color: 'var(--muted)', fontStyle: 'italic' }}>
            {activeFixture.description}
          </div>
          </div>
        </Panel>
      )}

      {/* 1. Attack Horizon Card */}
      {attackHorizon && (
        <AttackHorizonCard initialPayload={attackHorizon} allowStateSwitching={false} />
      )}

      {/* 1b. Attack-Stage Progression Card */}
      {attackProgression && (
        <AttackProgressionCard progression={attackProgression} />
      )}

      {/* 2. Evidence Chain (Why This Forecast) */}
      {evidenceChain && <EvidenceChain evidenceChain={evidenceChain} />}

      {/* 3. Grid for Confidence & Unknown Behavior */}
      <div
        className="content-grid"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '14px',
        }}
      >
        {confidence && <ForecastConfidence confidence={confidence} />}
        {unknownBehavior && <UnknownBehavior unknownBehavior={unknownBehavior} />}
      </div>

      {/* 4. Forecast Status & Availability Gate */}
      {abstention && <ForecastStatus abstention={abstention} />}
    </div>
  )
}

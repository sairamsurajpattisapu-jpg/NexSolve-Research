import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { EvidenceChain } from '../components/EvidenceChain'
import { ForecastConfidence } from '../components/ForecastConfidence'
import { ForecastStatus } from '../components/ForecastStatus'
import { ForecastTrustPanel } from '../components/ForecastTrustPanel'
import { UnknownBehavior } from '../components/UnknownBehavior'
import { forecastTrustFixtures } from '../fixtures/forecastTrustFixtures'

describe('Forecast Trust Layer Components', () => {
  it('EvidenceChain renders supporting and contradictory evidence cleanly', () => {
    const fixture = forecastTrustFixtures.contradictoryEvidence.response.evidence_chain!
    render(<EvidenceChain evidenceChain={fixture} />)

    expect(screen.getByText('Why This Forecast (Evidence Intelligence)')).toBeInTheDocument()
    expect(screen.getByText('0.10')).toBeInTheDocument()
    expect(screen.getByText(/Contradictory Evidence/)).toBeInTheDocument()
    expect(screen.getByText(/Source data volume decreased 99.8%/)).toBeInTheDocument()
  })

  it('ForecastConfidence enforces uncalibrated separation and displays uncertainty', () => {
    const fixture = forecastTrustFixtures.sustainedForecast.response.confidence!
    render(<ForecastConfidence confidence={fixture} />)

    expect(screen.getByText('Confidence & Calibration')).toBeInTheDocument()
    expect(screen.getByText('0.82')).toBeInTheDocument()
    expect(screen.getByText('Uncalibrated')).toBeInTheDocument()
    expect(screen.getByText('LOW')).toBeInTheDocument()
    expect(screen.getByText(/score reflects raw model margin/)).toBeInTheDocument()
  })

  it('UnknownBehavior displays classification, reason, and coverage', () => {
    const fixture = forecastTrustFixtures.unknownBehavior.response.unknown_behavior!
    render(<UnknownBehavior unknownBehavior={fixture} />)

    expect(screen.getByText('Behavior Classification')).toBeInTheDocument()
    expect(screen.getByText('UNKNOWN BEHAVIOR')).toBeInTheDocument()
    expect(screen.getByText(/Unsupported protocol behavior/)).toBeInTheDocument()
    expect(screen.getByText('35%')).toBeInTheDocument()
  })

  it('ForecastStatus displays abstention reason and missing requirements when abstained', () => {
    const fixture = forecastTrustFixtures.insufficientHistory.response.abstention!
    render(<ForecastStatus abstention={fixture} />)

    expect(screen.getByText('Forecast Availability Status')).toBeInTheDocument()
    expect(screen.getByText(/Forecast Abstained: INSUFFICIENT_HISTORY/)).toBeInTheDocument()
    expect(screen.getByText(/insufficient history: sequence length 3 is less than required 8 windows/)).toBeInTheDocument()
  })

  it('ForecastTrustPanel switches between all 11 scenario fixtures seamlessly', () => {
    render(<ForecastTrustPanel />)

    // Initial is Sustained Forecast
    expect(screen.getByText(/Strong multi-step attack progression/)).toBeInTheDocument()
    expect(screen.getByText('Sustained Attack Forecast')).toBeInTheDocument()

    // Switch to Contradictory Evidence
    fireEvent.click(screen.getByRole('button', { name: 'Contradictory Evidence' }))
    expect(screen.getByText(/Model predicts attack, but observed volume collapsed/)).toBeInTheDocument()
    expect(screen.getByText(/Contradictory Evidence & Capture Limitations/)).toBeInTheDocument()

    // Switch to Unknown Behavior
    fireEvent.click(screen.getByRole('button', { name: 'Unknown Behavior' }))
    expect(screen.getByText(/Unsupported protocol flood/)).toBeInTheDocument()
    expect(screen.getByText('UNKNOWN BEHAVIOR')).toBeInTheDocument()

    // Switch to Insufficient History
    fireEvent.click(screen.getByRole('button', { name: 'Insufficient History' }))
    expect(screen.getByText(/Only 3 observation windows observed/)).toBeInTheDocument()
    expect(screen.getByText(/Forecast Abstained: INSUFFICIENT_HISTORY/)).toBeInTheDocument()

    // Switch to No Attack Forecast
    fireEvent.click(screen.getByRole('button', { name: 'No Attack Forecast' }))
    expect(screen.getByText(/Clean baseline traffic expected/)).toBeInTheDocument()
    expect(screen.getAllByText('No Attack Forecast').length).toBeGreaterThanOrEqual(1)
  })
})

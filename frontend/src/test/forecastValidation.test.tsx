import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ForecastValidationCard } from '../components/ForecastValidationCard'
import type { ForecastValidation } from '../types/canonical'

describe('Forecast Validation Presentation Suite (Observed -> Forecast -> Actual)', () => {
  it('renders ForecastValidationCard with PARTIALLY_VALIDATED status for 10-window capture', () => {
    const mockValidation: ForecastValidation = {
      status: 'PARTIALLY_VALIDATED',
      summary: '2 of 5 forecast horizons validated against subsequent capture observation windows. 3 horizon(s) extend beyond capture duration.',
      evaluatedHorizons: 2,
      unvalidatedHorizons: 3,
      points: [
        {
          horizon: 1,
          lookaheadSeconds: 60,
          observedStateAtT0: 'RECONNAISSANCE',
          predictedProbability: 0.025,
          predictedStage: 'BENIGN',
          actualSubsequentState: 'BENIGN',
          actualThreatScore: 15.0,
          actualPacketCount: 220,
          actualFlowCount: 18,
          relationship: 'CONSISTENT',
          validationStatus: 'VALIDATED',
          explanation: 'Subsequent capture window confirms projected trajectory.',
        },
        {
          horizon: 2,
          lookaheadSeconds: 120,
          observedStateAtT0: 'RECONNAISSANCE',
          predictedProbability: 0.188,
          predictedStage: 'COMMAND_AND_CONTROL',
          actualSubsequentState: 'BENIGN',
          actualThreatScore: 18.0,
          actualPacketCount: 215,
          actualFlowCount: 16,
          relationship: 'DIVERGENT',
          validationStatus: 'VALIDATED',
          explanation: 'Subsequent capture window shows divergent trajectory.',
        },
        {
          horizon: 3,
          lookaheadSeconds: 180,
          observedStateAtT0: 'RECONNAISSANCE',
          predictedProbability: 0.38,
          predictedStage: 'BENIGN',
          actualSubsequentState: null,
          actualThreatScore: null,
          actualPacketCount: null,
          actualFlowCount: null,
          relationship: 'VALIDATION NOT AVAILABLE',
          validationStatus: 'VALIDATION NOT AVAILABLE',
          explanation: 'Capture concludes after 10 windows (600s). No subsequent physical telemetry recorded for horizon T+3.',
        },
      ],
    }

    render(<ForecastValidationCard validation={mockValidation} />)

    expect(screen.getByText(/FORECAST VALIDATION AUDIT/i)).toBeInTheDocument()
    expect(screen.getByText(/PARTIALLY_VALIDATED/i)).toBeInTheDocument()
    expect(screen.getByText(/2 \/ 5/i)).toBeInTheDocument()
    expect(screen.getByText('T+1')).toBeInTheDocument()
    expect(screen.getByText('T+2')).toBeInTheDocument()
    expect(screen.getByText('T+3')).toBeInTheDocument()
    expect(screen.getByText('CONSISTENT')).toBeInTheDocument()
    expect(screen.getByText('DIVERGENT')).toBeInTheDocument()
  })

  it('renders truthful VALIDATION NOT AVAILABLE when forecasting was withheld for short PCAP', () => {
    const mockValidation: ForecastValidation = {
      status: 'VALIDATION NOT AVAILABLE',
      summary: 'Forecasting withheld (Insufficient historical sequence). No forward trajectories available for empirical validation.',
      evaluatedHorizons: 0,
      unvalidatedHorizons: 5,
      points: [
        {
          horizon: 1,
          lookaheadSeconds: 60,
          observedStateAtT0: 'BENIGN',
          predictedProbability: null,
          predictedStage: null,
          actualSubsequentState: null,
          actualThreatScore: null,
          relationship: 'VALIDATION NOT AVAILABLE',
          validationStatus: 'VALIDATION NOT AVAILABLE',
          explanation: 'Validation not available: forecasting withheld.',
        },
      ],
    }

    render(<ForecastValidationCard validation={mockValidation} isAbstained={true} />)

    expect(screen.getByText(/FORECAST VALIDATION AUDIT/i)).toBeInTheDocument()
    expect(screen.getAllByText(/VALIDATION NOT AVAILABLE/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/0 \/ 5/i)).toBeInTheDocument()
  })
})

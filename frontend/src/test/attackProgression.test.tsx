import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AttackProgressionCard } from '../components/AttackProgressionCard'
import type { AttackProgressionForecast } from '../types/api'

describe('AttackProgressionCard Component', () => {
  it('renders STATE_PERSISTENCE accurately with empirical transition probabilities and zero fabricated techniques', () => {
    const progression: AttackProgressionForecast = {
      observed_state: 'RECONNAISSANCE',
      observed_techniques: ['T1046'],
      supported_horizons: [1, 3, 5],
      unsupported_horizons: [10, 15],
      verdict: 'PARTIALLY_SUPPORTED',
      summary: 'Observed active RECONNAISSANCE. Forecasting supported for T+1m, T+3m, T+5m; abstained for T+10m, T+15m.',
      forecast_points: [
        {
          horizon_minutes: 1,
          predicted_state: 'RECONNAISSANCE',
          predicted_technique: 'T1046',
          forecast_techniques: [],
          prediction_type: 'STATE_PERSISTENCE',
          transition_probability: 0.975,
          baseline_probability: 0.165,
          lead_time_seconds: 60,
          abstained: false,
          abstention_reason: null,
          supporting_evidence: ['Observed RECONNAISSANCE at T. Empirical persistence across 1-step horizon yields P=0.975.'],
        },
        {
          horizon_minutes: 3,
          predicted_state: 'RECONNAISSANCE',
          predicted_technique: 'T1046',
          forecast_techniques: [],
          prediction_type: 'STATE_PERSISTENCE',
          transition_probability: 0.924,
          baseline_probability: 0.165,
          lead_time_seconds: 180,
          abstained: false,
          abstention_reason: null,
          supporting_evidence: ['Observed RECONNAISSANCE at T. Empirical persistence across 3-step horizon yields P=0.924.'],
        },
        {
          horizon_minutes: 5,
          predicted_state: 'RECONNAISSANCE',
          predicted_technique: 'T1046',
          forecast_techniques: [],
          prediction_type: 'STATE_PERSISTENCE',
          transition_probability: 0.873,
          baseline_probability: 0.165,
          lead_time_seconds: 300,
          abstained: false,
          abstention_reason: null,
          supporting_evidence: ['Observed RECONNAISSANCE at T. Empirical persistence across 5-step horizon yields P=0.873.'],
        },
        {
          horizon_minutes: 10,
          predicted_state: 'UNKNOWN_STATE',
          predicted_technique: null,
          forecast_techniques: [],
          prediction_type: 'ABSTAINED',
          transition_probability: 0.0,
          baseline_probability: 0.0,
          lead_time_seconds: 600,
          abstained: true,
          abstention_reason: 'UNSUPPORTED_HORIZON: horizon T+10m lacks empirical replication',
          supporting_evidence: [],
        },
        {
          horizon_minutes: 15,
          predicted_state: 'UNKNOWN_STATE',
          predicted_technique: null,
          forecast_techniques: [],
          prediction_type: 'ABSTAINED',
          transition_probability: 0.0,
          baseline_probability: 0.0,
          lead_time_seconds: 900,
          abstained: true,
          abstention_reason: 'UNSUPPORTED_HORIZON: horizon T+15m lacks empirical replication',
          supporting_evidence: [],
        },
      ],
    }

    render(<AttackProgressionCard progression={progression} />)

    // Title and observed anchor
    expect(screen.getByText('Attack-Stage Progression Forecaster')).toBeInTheDocument()
    expect(screen.getByText(/Observed State \(Ground Truth @ T0\)/i)).toBeInTheDocument()
    expect(screen.getAllByText('RECONNAISSANCE').length).toBe(4)
    expect(screen.getByText('T1046')).toBeInTheDocument()

    // Verdict
    expect(screen.getByText('PARTIALLY SUPPORTED')).toBeInTheDocument()

    // State Persistence labels
    expect(screen.getAllByText('STATE PERSISTENCE').length).toBe(3)
    expect(screen.getAllByText(/Active Ongoing Stage:/i).length).toBe(3)

    // Exact empirical probabilities displayed without arbitrary confidence
    expect(screen.getByText('97.5%')).toBeInTheDocument()
    expect(screen.getByText('92.4%')).toBeInTheDocument()
    expect(screen.getByText('87.3%')).toBeInTheDocument()
    expect(screen.getAllByText(/Empirical persistence probability:/i).length).toBe(3)

    // Abstentions at K=10 and K=15
    expect(screen.getAllByText('ABSTAINED').length).toBe(2)
    expect(screen.getByText(/horizon T\+10m lacks empirical replication/i)).toBeInTheDocument()
    expect(screen.getByText(/horizon T\+15m lacks empirical replication/i)).toBeInTheDocument()

    // Verify NO "confidence" score or label rendered in progression card
    expect(screen.queryByText(/confidence:/i)).toBeNull()
    expect(screen.queryByText(/calibrated confidence/i)).toBeNull()
  })

  it('renders generic DOWNSTREAM_PROGRESSION when cross-stage transition is present', () => {
    const progression: AttackProgressionForecast = {
      observed_state: 'RECONNAISSANCE',
      observed_techniques: ['T1046'],
      supported_horizons: [1],
      unsupported_horizons: [],
      verdict: 'SUPPORTED',
      summary: 'Empirical cross-stage transition demonstrated.',
      forecast_points: [
        {
          horizon_minutes: 1,
          predicted_state: 'COMMAND_AND_CONTROL',
          predicted_technique: 'T1071',
          forecast_techniques: ['T1071'],
          prediction_type: 'DOWNSTREAM_PROGRESSION',
          transition_probability: 0.425,
          baseline_probability: 0.165,
          lead_time_seconds: 60,
          abstained: false,
          abstention_reason: null,
          supporting_evidence: ['Empirical progression demonstrated from RECONNAISSANCE to COMMAND_AND_CONTROL.'],
        },
      ],
    }

    render(<AttackProgressionCard progression={progression} />)

    expect(screen.getByText('DOWNSTREAM PROGRESSION')).toBeInTheDocument()
    expect(screen.getByText('Predicted Next Stage:')).toBeInTheDocument()
    expect(screen.getByText('COMMAND AND CONTROL')).toBeInTheDocument()
    expect(screen.getByText('42.5%')).toBeInTheDocument()
    expect(screen.getByText(/Empirical transition probability:/i)).toBeInTheDocument()
    expect(screen.getByText('Predicted Techniques:')).toBeInTheDocument()
  })

  it('renders ABSTAINED forecast correctly with abstention reason', () => {
    const progression: AttackProgressionForecast = {
      observed_state: 'BENIGN_OBSERVATION',
      observed_techniques: [],
      supported_horizons: [],
      unsupported_horizons: [1, 3, 5],
      verdict: 'ABSTAINED',
      summary: 'Forecasting abstained: insufficient contiguous window history.',
      forecast_points: [
        {
          horizon_minutes: 1,
          predicted_state: 'UNKNOWN_STATE',
          predicted_technique: null,
          forecast_techniques: [],
          prediction_type: 'ABSTAINED',
          transition_probability: 0.0,
          baseline_probability: 0.0,
          lead_time_seconds: 60,
          abstained: true,
          abstention_reason: 'INSUFFICIENT_HISTORY: minimum 8 contiguous windows required',
          supporting_evidence: [],
        },
      ],
    }

    render(<AttackProgressionCard progression={progression} />)

    expect(screen.getByText('Progression Abstained')).toBeInTheDocument()
    expect(screen.getByText(/INSUFFICIENT_HISTORY: minimum 8 contiguous windows required/i)).toBeInTheDocument()
  })

  it('renders Phase 2 canonical transitions, classification badge, and validation audit', () => {
    const progression: AttackProgressionForecast = {
      observed_state: 'RECONNAISSANCE',
      canonical_stage: 'RECONNAISSANCE',
      classification: 'OBSERVED',
      stage_confidence: 0.88,
      technique_confidence: 0.85,
      observed_techniques: ['T1046'],
      supported_horizons: [1],
      unsupported_horizons: [],
      verdict: 'SUPPORTED',
      summary: 'Validated 15-stage canonical progression.',
      forecast_points: [
        {
          horizon_minutes: 1,
          predicted_state: 'INITIAL_ACCESS',
          predicted_technique: 'T1190',
          forecast_techniques: ['T1190'],
          prediction_type: 'DOWNSTREAM_PROGRESSION',
          transition_probability: 0.80,
          lead_time_seconds: 60,
          abstained: false,
          supporting_evidence: ['Public-facing exploit observed.'],
        },
      ],
      transitions: [
        {
          from_stage: 'RECONNAISSANCE',
          to_stage: 'INITIAL_ACCESS',
          timestamp: 1710000000,
          confidence: 0.80,
          transition_type: 'FORECAST',
          status: 'VALID',
          reason: 'Expected sequential forward progression',
        },
      ],
      validation: {
        valid: true,
        issues: [],
        warnings: [],
        event_count: 1,
        transition_count: 1,
      },
    }

    render(<AttackProgressionCard progression={progression} />)

    expect(screen.getByText('OBSERVED')).toBeInTheDocument()
    expect(screen.getByText(/Evaluated State Transition Kinematics/i)).toBeInTheDocument()
    expect(screen.getByText('VALID')).toBeInTheDocument()
    expect(screen.getByText('AUDIT: PASSED (VALID)')).toBeInTheDocument()
  })
})

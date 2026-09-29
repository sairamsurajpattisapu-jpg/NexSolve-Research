import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { ForecastConsole } from '../components/ForecastConsole'
import {
  checkForecastTrajectoryExists,
  computeContextStatusText,
  Layout,
} from '../components/Layout'
import * as useProductionDataModule from '../hooks/useProductionData'
import { adaptToCanonical } from '../utils/canonicalAdapter'

describe('NexSolve Forecast Status Contradiction & Small-PCAP UX Fix', () => {
  const smallPcapPayload = {
    analysis_id: 'job-small-pcap-2-windows',
    status: 'completed',
    analysis_state: 'ANALYSIS_COMPLETE_FORECAST_UNAVAILABLE',
    forecast_status: 'FORECAST_ABSTAINED',
    is_forecast_available: false,
    source: {
      name: 'file.pcap',
      filename: 'file.pcap',
      kind: 'uploaded_pcap',
      size_bytes: 4096,
    },
    upload: {
      filename: 'file.pcap',
      format: 'pcap',
      size_bytes: 4096,
    },
    validation: {
      status: 'VALID',
      rows: 2,
      columns: [],
      dtypes: {},
      missing_columns: [],
      null_counts: {},
      null_ratios: {},
      constant_columns: [],
      numeric_ranges: {},
      protocol_counts: { TCP: 20 },
      window: {
        unit: 'UTC epoch seconds',
        seconds: 60,
        start_min: 1700000000,
        start_max: 1700000060,
        ordered: true,
      },
      model_compatibility: {
        flow_features_available: false,
        packet_features_available: true,
        labels_available: false,
        forecast_model_ready: false,
        reason: 'Insufficient temporal depth (2 / 8 windows)',
        available_features: [],
        missing_features: ['insufficient_temporal_depth'],
        unreliable_features: [],
      },
    },
    traffic: {
      packets: 20,
      flows: 2,
      windows: 2,
      duration_seconds: 120,
      protocol_counts: { TCP: 20 },
    },
    detection: {
      findings: [],
      detected_events: 0,
      threat_level: 'low',
      risk_score: 5.0,
    },
    abstention: {
      abstained: true,
      operational_tier: 'ABSTAINED',
      reason: 'INSUFFICIENT_HISTORY',
      explanation:
        'Forecast withheld: Forecasting requires at least 8 continuous 60-second windows. Capture provides 2 windows. Static traffic analysis completed successfully.',
    },
    forecast_summary: {
      available: false,
      status: 'INSUFFICIENT_HISTORY',
      required_windows: 8,
      available_windows: 2,
      required_window_seconds: 60,
      message:
        'Forecasting requires at least 8 continuous 60-second windows. Static traffic analysis completed successfully.',
    },
    forecasts: [
      { horizon: 1, attack_probability: null, abstained: true },
      { horizon: 2, attack_probability: null, abstained: true },
      { horizon: 3, attack_probability: null, abstained: true },
      { horizon: 4, attack_probability: null, abstained: true },
      { horizon: 5, attack_probability: null, abstained: true },
    ],
    attack_horizon: {
      state: 'ABSTAINED',
      onset_horizon: null,
      lead_time_seconds: null,
      horizon_windows: 0,
      horizon_seconds: 0,
    },
  }

  const validSufficientPayload = {
    ...smallPcapPayload,
    analysis_id: 'job-sufficient-pcap-10-windows',
    analysis_state: 'ANALYSIS_COMPLETE_FORECAST_READY',
    forecast_status: 'FORECAST_READY',
    is_forecast_available: true,
    traffic: {
      ...smallPcapPayload.traffic,
      windows: 10,
      duration_seconds: 600,
    },
    abstention: {
      abstained: false,
    },
    forecast_summary: {
      available: true,
      status: 'READY',
      required_windows: 8,
      available_windows: 10,
      required_window_seconds: 60,
      message: 'Forecast rollouts generated successfully by Final Network World Model.',
    },
    forecasts: [
      { horizon: 1, attack_probability: 0.12, abstained: false },
      { horizon: 2, attack_probability: 0.15, abstained: false },
      { horizon: 3, attack_probability: 0.18, abstained: false },
      { horizon: 4, attack_probability: 0.22, abstained: false },
      { horizon: 5, attack_probability: 0.25, abstained: false },
    ],
    attack_horizon: {
      state: 'NO_ATTACK_FORECAST',
      onset_horizon: null,
      lead_time_seconds: null,
      horizon_windows: 5,
      horizon_seconds: 300,
    },
  }

  describe('1. checkForecastTrajectoryExists helper', () => {
    it('returns false when forecast is withheld due to insufficient history (2 windows)', () => {
      expect(checkForecastTrajectoryExists(smallPcapPayload)).toBe(false)
    })

    it('returns true when an actual forecast trajectory exists with T+1..T+5 results', () => {
      expect(checkForecastTrajectoryExists(validSufficientPayload)).toBe(true)
    })

    it('returns false for non-contiguous timestamp captures', () => {
      const gappedPayload = {
        ...validSufficientPayload,
        is_forecast_available: false,
        forecast_status: 'FORECAST_ABSTAINED',
        forecast_summary: {
          available: false,
          status: 'NON_CONTIGUOUS_TIMESTAMPS',
        },
      }
      expect(checkForecastTrajectoryExists(gappedPayload)).toBe(false)
    })

    it('returns false when forecasts array has null attack probabilities', () => {
      const nullProbPayload = {
        ...validSufficientPayload,
        forecasts: [
          { horizon: 1, attack_probability: null, abstained: false },
          { horizon: 2, attack_probability: null, abstained: false },
        ],
      }
      expect(checkForecastTrajectoryExists(nullProbPayload)).toBe(false)
    })
  })

  describe('2. computeContextStatusText status mapping', () => {
    it('returns "Analyzing Telemetry" when statusLabel is ANALYZING', () => {
      expect(computeContextStatusText('ANALYZING', true, smallPcapPayload)).toBe('Analyzing Telemetry')
    })

    it('returns "Ready" when no capture is active', () => {
      expect(computeContextStatusText('READY', false, null)).toBe('Ready')
    })

    it('returns "Analysis Complete" (NEVER "Forecast Ready") for small-pcap with withheld forecast', () => {
      const status = computeContextStatusText('READY', true, smallPcapPayload)
      expect(status).toBe('Analysis Complete')
      expect(status).not.toBe('Forecast Ready')
    })

    it('returns "Analysis Complete" for non-contiguous timestamp captures', () => {
      const nonContiguousPayload = {
        ...smallPcapPayload,
        forecast_summary: {
          available: false,
          status: 'NON_CONTIGUOUS_TIMESTAMPS',
        },
      }
      expect(computeContextStatusText('READY', true, nonContiguousPayload)).toBe('Analysis Complete')
    })

    it('returns "Forecast Ready" ONLY when valid sufficient capture has full trajectory', () => {
      expect(computeContextStatusText('READY', true, validSufficientPayload)).toBe('Forecast Ready')
    })

    it('returns "Analysis Failed" for failed capture processing', () => {
      const failedPayload = {
        status: 'failed',
        validation: { status: 'INVALID' },
      }
      expect(computeContextStatusText('READY', true, failedPayload)).toBe('Analysis Failed')
    })

    it('returns "Analysis Rejected" for rejected uploads', () => {
      const rejectedPayload = {
        status: 'rejected',
        analysis_state: 'ANALYSIS_REJECTED_INVALID_INPUT',
      }
      expect(computeContextStatusText('READY', true, rejectedPayload)).toBe('Analysis Rejected')
    })
  })

  describe('3. Top Application Status Bar (Layout.tsx)', () => {
    it('renders "Status: Analysis Complete" (and NOT "Forecast Ready") for small-pcap live capture', () => {
      vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
        data: {
          results: smallPcapPayload,
        } as any,
        loading: false,
        error: null,
        analysisSource: 'uploaded',
        provenance: 'uploaded',
        isReferenceDataset: false,
        isLiveCapture: true,
        analysisId: 'job-small-pcap-2-windows',
        apiConnected: true,
        uploadError: null,
        reload: vi.fn(),
        analyzePcap: vi.fn(),
        clearUploadedAnalysis: vi.fn(),
        clearUploadError: vi.fn(),
        setUploadedAnalysis: vi.fn(),
      })

      render(
        <MemoryRouter initialEntries={['/console']}>
          <Routes>
            <Route element={<Layout status="READY" />}>
              <Route path="/console" element={<div>Console Page Content</div>} />
            </Route>
          </Routes>
        </MemoryRouter>
      )

      const contextStrip = screen.getByTestId('navigation-context-strip')
      expect(contextStrip).toBeInTheDocument()
      expect(contextStrip).toHaveTextContent('Analysis:file.pcap')
      expect(contextStrip).toHaveTextContent('Status:Analysis Complete')
      expect(contextStrip).not.toHaveTextContent('Forecast Ready')
    })

    it('renders "Status: Forecast Ready" when forecast trajectory is actually available', () => {
      vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
        data: {
          results: validSufficientPayload,
        } as any,
        loading: false,
        error: null,
        analysisSource: 'uploaded',
        provenance: 'uploaded',
        isReferenceDataset: false,
        isLiveCapture: true,
        analysisId: 'job-sufficient-pcap-10-windows',
        apiConnected: true,
        uploadError: null,
        reload: vi.fn(),
        analyzePcap: vi.fn(),
        clearUploadedAnalysis: vi.fn(),
        clearUploadError: vi.fn(),
        setUploadedAnalysis: vi.fn(),
      })

      render(
        <MemoryRouter initialEntries={['/console']}>
          <Routes>
            <Route element={<Layout status="READY" />}>
              <Route path="/console" element={<div>Console Page Content</div>} />
            </Route>
          </Routes>
        </MemoryRouter>
      )

      const contextStrip = screen.getByTestId('navigation-context-strip')
      expect(contextStrip).toBeInTheDocument()
      expect(contextStrip).toHaveTextContent('Status:Forecast Ready')
    })
  })

  describe('4. Small-PCAP UX Presentation (ForecastConsole.tsx)', () => {
    it('renders truthful ANALYSIS COMPLETE reassurance with monochrome editorial styling', () => {
      const canonical = adaptToCanonical(smallPcapPayload as any, 'job-small-pcap-2-windows')
      expect(canonical.forecast.isAvailable).toBe(false)
      expect(canonical.forecast.status).toBe('INSUFFICIENT_HISTORY')

      render(<ForecastConsole analysis={canonical} />)

      // Reassure user that static analysis completed successfully
      expect(screen.getByText('ANALYSIS COMPLETE')).toBeInTheDocument()
      expect(screen.getByText('Static traffic analysis completed.')).toBeInTheDocument()

      // Epistemic safety guardrail & reason
      expect(screen.getByText('Forecast unavailable')).toBeInTheDocument()
      expect(screen.getByText('Insufficient temporal history.')).toBeInTheDocument()
      expect(
        screen.getByText(
          'This capture contains only 2 usable temporal windows. Forecasting requires at least 8 continuous 60-second windows.'
        )
      ).toBeInTheDocument()

      // Observed vs Required blocks
      expect(screen.getByText('2 windows')).toBeInTheDocument()
      expect(screen.getByText('8 continuous windows')).toBeInTheDocument()

      // Small amber indicator container presence
      const banner = screen.getByTestId('forecast-abstention-banner')
      expect(banner).toBeInTheDocument()
      expect(banner).toHaveStyle({ borderLeft: '2px solid rgba(245, 158, 11, 0.6)' })
    })
  })
})

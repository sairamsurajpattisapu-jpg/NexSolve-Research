import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { JobProgress } from '../components/JobProgress'
import { JobResult } from '../components/JobResult'
import { ReportActions } from '../components/ReportActions'
import type { JobStatusResponse, UploadedAnalysisResponse } from '../types/api'

describe('JobProgress Component', () => {
  it('renders deterministic progress and stage label', () => {
    const job: JobStatusResponse = {
      job_id: 'job-test-101',
      status: 'PROCESSING',
      stage: 'PARSING',
      progress: 0.25,
      created_at: '2026-09-10T06:00:00Z',
      started_at: '2026-09-10T06:00:01Z',
      completed_at: null,
      error: null,
      processing_statistics: {
        packets_processed: 120,
        windows_processed: 2,
        processing_seconds: 0.45,
      },
    }

    render(<JobProgress job={job} />)

    expect(screen.getByText('Parsing Frames & Packets')).toBeInTheDocument()
    expect(screen.getByText('25% Deterministic Progress')).toBeInTheDocument()
    expect(screen.getByText(/120 pkts/)).toBeInTheDocument()
    expect(screen.getByText(/2 windows/)).toBeInTheDocument()
    expect(screen.getByText(/0.45s runtime/)).toBeInTheDocument()
  })

  it('renders RESOURCE_LIMIT_EXCEEDED banner with specific resource details', () => {
    const job: JobStatusResponse = {
      job_id: 'job-test-overflow',
      status: 'RESOURCE_LIMIT_EXCEEDED',
      stage: 'PARSING',
      progress: 0.25,
      created_at: '2026-09-10T06:00:00Z',
      started_at: '2026-09-10T06:00:01Z',
      completed_at: '2026-09-10T06:00:02Z',
      error: {
        status: 'RESOURCE_LIMIT_EXCEEDED',
        resource: 'packet_count',
        observed: 150000,
        limit: 100000,
        explanation: 'Observed packet count exceeded safe boundary.',
      },
    }

    render(<JobProgress job={job} />)

    expect(screen.getByText('Resource Limit Exceeded')).toBeInTheDocument()
    expect(screen.getByText(/Safety Boundary Enforced \(packet_count\):/)).toBeInTheDocument()
    expect(screen.getByText(/Observed: 150000 · Limit: 100000/)).toBeInTheDocument()
  })

  it('renders FAILED state with human-readable error message', () => {
    const job: JobStatusResponse = {
      job_id: 'job-test-fail',
      status: 'FAILED',
      stage: 'WINDOWING',
      progress: 0.55,
      created_at: '2026-09-10T06:00:00Z',
      started_at: '2026-09-10T06:00:01Z',
      completed_at: '2026-09-10T06:00:03Z',
      error: {
        code: 'PROCESSING_FAILED',
        message: 'Malformed frame headers encountered.',
      },
    }

    render(<JobProgress job={job} />)

    expect(screen.getByText('Processing Halted')).toBeInTheDocument()
    expect(screen.getByText(/Malformed frame headers encountered/)).toBeInTheDocument()
  })
})

describe('ReportActions Component', () => {
  it('renders download links and fires onReset', () => {
    const onReset = vi.fn()
    render(<ReportActions jobId="job-rep-999" onReset={onReset} />)

    const htmlLink = screen.getByRole('link', { name: /Open HTML Report/i })
    expect(htmlLink).toHaveAttribute('href', expect.stringContaining('/jobs/job-rep-999/report.html'))

    const jsonLink = screen.getByRole('link', { name: /Download JSON/i })
    expect(jsonLink).toHaveAttribute('href', expect.stringContaining('/jobs/job-rep-999/report.json'))

    const resetBtn = screen.getByRole('button', { name: /Upload Another/i })
    fireEvent.click(resetBtn)
    expect(onReset).toHaveBeenCalled()
  })
})

describe('JobResult Component', () => {
  it('renders completed analysis with metric cards and Trust Layer elements', () => {
    const mockResult: UploadedAnalysisResponse = {
      analysis_id: 'job-complete-123',
      status: 'completed',
      source: {
        name: 'test_traffic.pcap',
        kind: 'uploaded_pcap',
        filename: 'test_traffic.pcap',
        size_bytes: 4096,
      },
      upload: {
        filename: 'test_traffic.pcap',
        size_bytes: 4096,
        format: 'pcap',
      },
      validation: {
        status: 'VALID',
        rows: 3,
        columns: ['packet_length'],
        dtypes: { packet_length: 'float64' },
        missing_columns: [],
        null_counts: {},
        null_ratios: {},
        constant_columns: [],
        numeric_ranges: {},
        protocol_counts: { TCP: 400, UDP: 100 },
        window: { unit: 'UTC epoch seconds', seconds: 60, start_min: 0, start_max: 180, ordered: true },
        model_compatibility: {
          flow_features_available: false,
          packet_features_available: true,
          labels_available: false,
          forecast_model_ready: false,
          reason: 'Missing flow features',
        },
      },
      traffic: {
        status: 'VALID',
        packets: 500,
        flows: 45,
        windows: 3,
        tcp: 400,
        udp: 100,
        icmp: 0,
        fragmented_packets: 0,
        retransmissions: 2,
        protocol_counts: { TCP: 400, UDP: 100 },
      },
      packet_count: 500,
      window_count: 3,
      duration_seconds: 180,
      protocol_summary: { TCP: 400, UDP: 100 },
      findings: [],
      summary: {
        packet_count: 500,
        window_count: 3,
        finding_count: 1,
        threat_level: 'low',
      },
      detection: {
        status: 'completed',
        threat_level: 'low',
        detected_events: 1,
        findings: [],
        risk_score: 1.2,
        windows_analyzed: 3,
        average_window_risk: 0.4,
        detection_mode: 'heuristics',
        risk_method: 'packet_heuristics',
        model_prediction_available: false,
      },
      quality: {
        capture_id: 'pcap-123',
        parsed_packets: 500,
        total_packets_observed: 500,
        malformed_packets: 0,
        truncated_packets: 0,
        reordered_packets: 0,
        packet_loss_ratio: 0,
      },
      attack_horizon: {
        state: 'NO_ATTACK_FORECAST',
        onset_horizon: null,
        onset_timestamp: null,
        lead_time_seconds: null,
        horizon_windows: 0,
        horizon_seconds: 0,
        end_horizon: null,
        end_timestamp: null,
        decision_threshold: 0.5,
        temporal_consistency: 0,
        decay_observed: false,
        confidence_summary: {
          mean_confidence: null,
          min_confidence: null,
          max_confidence: null,
          calibration_status: 'UNSUPPORTED',
        },
        evidence_chain: [],
        abstention_reason: null,
        summary: 'No attack activity predicted.',
      },
      evidence_chain: {
        current_window_id: 'w-1',
        current_timestamp: '2026-09-10T06:00:00Z',
        forecast_horizon: 0,
        supporting: [],
        contradictory: [],
        evidence_strength: 0,
        evidence_quality: 'HIGH',
        supporting_feature_count: 0,
        contradictory_feature_count: 0,
        provenance_complete: true,
        explanation: 'Baseline traffic observed.',
        limitations: [],
      },
      confidence: {
        forecast_score: 0.1,
        confidence_value: null,
        confidence_state: 'UNCALIBRATED',
        evidence_strength: 0,
        calibration_status: 'UNSUPPORTED',
        uncertainty_level: 'LOW',
        explanation: 'Score is uncalibrated.',
      },
      unknown_behavior: {
        classification: 'KNOWN_PATTERN',
        reason: 'Clean baseline network traffic.',
        supporting_evidence: [],
        contradictory_evidence: [],
        coverage: 1.0,
        abstain_recommended: false,
      },
      abstention: {
        abstained: false,
        reason: null,
        severity: 'LOW',
        status: 'FORECAST_AVAILABLE_BUT_UNCALIBRATED',
        missing_requirements: [],
        explanation: 'All requirements met.',
      },
      attackProgression: {
        observed_state: 'BENIGN_OBSERVATION',
        observed_techniques: [],
        forecast_points: [
          {
            horizon_minutes: 1,
            predicted_state: 'BENIGN_OBSERVATION',
            predicted_technique: null,
            forecast_techniques: [],
            prediction_type: 'STATE_PERSISTENCE',
            transition_probability: 0.992,
            baseline_probability: 0.85,
            lead_time_seconds: 60,
            abstained: false,
            abstention_reason: null,
            supporting_evidence: ['Ongoing benign baseline network telemetry.'],
          },
        ],
        supported_horizons: [1],
        unsupported_horizons: [10, 15],
        verdict: 'SUPPORTED',
        summary: 'Benign baseline traffic continues across T+1.',
      },
    }

    render(<JobResult result={mockResult} />)

    expect(screen.getByText('Network Predictive Assessment')).toBeInTheDocument()
    expect(screen.getByText('test_traffic.pcap')).toBeInTheDocument()
    expect(screen.getByText('500 pkts')).toBeInTheDocument()
    expect(screen.getByText('45 flows')).toBeInTheDocument()
    expect(screen.getByText('HIGH QUALITY')).toBeInTheDocument()
    expect(screen.getByText('KNOWN PATTERN')).toBeInTheDocument()
    expect(screen.getByText('Attack-Stage Progression Forecaster')).toBeInTheDocument()
    expect(screen.getByText('STATE PERSISTENCE')).toBeInTheDocument()
    expect(screen.getByText('99.2%')).toBeInTheDocument()
  })
})

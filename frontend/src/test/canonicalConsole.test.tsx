import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { CsvRequirementsModal } from '../components/CsvRequirementsModal'
import { ForecastConsole } from '../components/ForecastConsole'
import { adaptToCanonical } from '../utils/canonicalAdapter'

const mockUploadedPayload = {
  analysis_id: 'job-canonical-test',
  status: 'COMPLETED',
  source: {
    name: 'test_capture.pcap',
    kind: 'pcap',
    filename: 'test_capture.pcap',
    size_bytes: 524288,
  },
  upload: {
    filename: 'test_capture.pcap',
    format: 'PCAP',
    file_size_bytes: 524288,
    file_hash_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
  validation: {
    status: 'VALID',
    is_valid: true,
    packet_count: 2277,
    window_count: 10,
    model_compatibility: {
      compatible: true,
      feature_count: 45,
      missing_features: [],
      mean_tcp_rtt_status: 'NOT_OBSERVED_PRESERVED',
    },
  },
  traffic: {
    total_packets: 2277,
    packet_count: 2277,
    total_flows: 283,
    flow_count: 283,
    duration_seconds: 600,
    total_bytes: 184520,
    mean_packet_rate: 3.795,
  },
  detection: {
    threat_level: 'HIGH',
    overall_confidence: 0.88,
  },
  early_warning: {
    early_warning_score: 84.5,
    lead_time_seconds: 120,
    top_contributing_features: [
      {
        feature_name: 'tcp_syn_count',
        feature_label: 'TCP SYN Flag Volume',
        contribution_score: 0.92,
        baseline_value: 12,
        current_value: 412,
        difference_pct: 3333.3,
        direction: 'INCREASING',
      },
      {
        feature_name: 'unique_dst_ports',
        feature_label: 'Destination Port Spread',
        contribution_score: 0.78,
        baseline_value: 4,
        current_value: 48,
        difference_pct: 1100.0,
        direction: 'INCREASING',
      },
    ],
  },
  attack_horizon: {
    attack_detected: true,
    severity: 'IMMINENT',
    horizon_steps: [
      { step: 1, horizon_seconds: 60, attack_probability: 0.82, cumulative_risk: 0.82, in_horizon: true, risk_classification: 'CRITICAL' },
      { step: 2, horizon_seconds: 120, attack_probability: 0.89, cumulative_risk: 0.98, in_horizon: true, risk_classification: 'CRITICAL' },
      { step: 3, horizon_seconds: 180, attack_probability: 0.94, cumulative_risk: 0.999, in_horizon: true, risk_classification: 'CRITICAL' },
      { step: 5, horizon_seconds: 300, attack_probability: 0.76, cumulative_risk: 1.0, in_horizon: true, risk_classification: 'CRITICAL' },
    ],
    peak_step: 3,
    mitre_techniques: [
      {
        technique_id: 'T1046',
        technique_name: 'Network Service Discovery',
        tactic: 'Discovery',
        confidence: 0.89,
        justification: 'Elevated unique destination port count indicates horizontal sweep.',
      },
      {
        technique_id: 'T1498',
        technique_name: 'Network Denial of Service',
        tactic: 'Impact',
        confidence: 0.82,
        justification: 'Sharp SYN flag surge without corresponding ACK completions.',
      },
    ],
  },
  attack_progression: {
    stages: [
      { name: 'Initial Reconnaissance', description: 'Port and service discovery', probability: 0.92, status: 'OBSERVED', horizon_step: 0 },
      { name: 'Service Probing & Vulnerability Scanning', description: 'Application version probing', probability: 0.86, status: 'PREDICTED', horizon_step: 1 },
      { name: 'Exploitation & Breach Execution', description: 'Service compromise attempt', probability: 0.74, status: 'PREDICTED', horizon_step: 2 },
    ],
    predicted_next_stage: 'Service Probing & Vulnerability Scanning',
    progression_confidence: 0.85,
  },
  evidence_chain: {
    supporting: [
      {
        metric_name: 'tcp_syn_count',
        description: 'TCP SYN count surged 3333% above normal baseline.',
        observed_value: 412,
        baseline_value: 12,
        deviation_sigma: 4.8,
        direction: 'SUPPORTING',
      },
    ],
    contradictory: [
      {
        metric_name: 'total_dst_bytes',
        description: 'Outbound payload volume remains below exfiltration threshold.',
        observed_value: 1540,
        baseline_value: 2000,
        deviation_sigma: -0.4,
        direction: 'CONTRADICTORY',
      },
    ],
  },
  model_compatibility: {
    compatible: true,
    feature_count: 45,
    features: {
      flow_count: 283,
      packet_count: 2277,
      tcp_syn_count: 412,
      tcp_ack_count: 140,
      unique_dst_ports: 48,
    },
  },
}

describe('Canonical Adapter & ForecastConsole Integration', () => {
  it('correctly adapts backend payload into CanonicalAnalysis', () => {
    const canonical = adaptToCanonical(mockUploadedPayload, 'job-canonical-test')

    expect(canonical.id).toBe('job-canonical-test')
    expect(canonical.input.filename).toBe('test_capture.pcap')
    expect(canonical.currentState.summary.packets).toBe(2277)
    expect(canonical.currentState.summary.flows).toBe(283)
    expect(canonical.forecast.points.length).toBeGreaterThanOrEqual(4)
    expect(canonical.forecast.earlyWarning?.score).toBe(84.5)
    expect(canonical.mitre.mappings.length).toBeGreaterThanOrEqual(1)
    expect(canonical.progression.stages.length).toBeGreaterThanOrEqual(2)
  })

  it('renders ForecastConsole with distinct Point Probability vs Cumulative Risk', () => {
    const canonical = adaptToCanonical(mockUploadedPayload, 'job-canonical-test')
    render(<ForecastConsole analysis={canonical} />)

    // Verify Point Probability vs Cumulative Risk panels exist and show clear distinction
    expect(screen.getByText(/STEP ATTACK PROBABILITY/i)).toBeInTheDocument()
    expect(screen.getByText(/CUMULATIVE FUTURE RISK/i)).toBeInTheDocument()

    // Verify Early Warning Composite
    expect(screen.getByText(/EARLY WARNING INDICATOR/i)).toBeInTheDocument()
    expect(screen.getByText(/ONSET LEAD TIME/i)).toBeInTheDocument()
    expect(screen.getByText(/120s/)).toBeInTheDocument()

    // Verify Scientific Model Governance Notice
    expect(screen.getByText('CHAMPION MODEL')).toBeInTheDocument()
    expect(screen.getByText('Persistence Baseline')).toBeInTheDocument()
    expect(screen.getByText(/LSTM45 Model \(HOLD\)/)).toBeInTheDocument()

    // Verify Expand View toggle
    const presToggle = screen.getByRole('button', { name: /Expand View/i })
    expect(presToggle).toBeInTheDocument()
    fireEvent.click(presToggle)
    expect(screen.getByRole('button', { name: /Standard View/i })).toBeInTheDocument()

    // Verify Export buttons
    expect(screen.getByRole('link', { name: /JSON/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Printable Report/i })).toBeInTheDocument()
  })

  it('opens and closes Feature Vector Modal with 45 features and definitions', () => {
    const canonical = adaptToCanonical(mockUploadedPayload, 'job-canonical-test')
    render(<ForecastConsole analysis={canonical} />)

    const viewVectorBtn = screen.getByRole('button', { name: /View Full Feature Vector/i })
    fireEvent.click(viewVectorBtn)

    expect(screen.getByText(/Observed Network State: 45-Feature Vector/i)).toBeInTheDocument()

    const closeBtn = screen.getByRole('button', { name: /Close modal/i })
    fireEvent.click(closeBtn)
    expect(screen.queryByText(/Observed Network State: 45-Feature Vector/i)).not.toBeInTheDocument()
  })

  it('opens and closes Explainability Driver Modal', () => {
    const canonical = adaptToCanonical(mockUploadedPayload, 'job-canonical-test')
    render(<ForecastConsole analysis={canonical} />)

    const viewExplainBtn = screen.getByRole('button', { name: /View All Features/i })
    fireEvent.click(viewExplainBtn)

    expect(screen.getByText(/Feature Attribution & Influence Directory/i)).toBeInTheDocument()
    expect(screen.getByText(/Methodology Note:/i)).toBeInTheDocument()

    const closeBtn = screen.getByRole('button', { name: /Close modal/i })
    fireEvent.click(closeBtn)
    expect(screen.queryByText(/Feature Attribution & Influence Directory/i)).not.toBeInTheDocument()
  })

  it('renders CSV Requirements Modal with column contracts', () => {
    const onClose = () => {}
    render(<CsvRequirementsModal isOpen={true} onClose={onClose} />)

    expect(screen.getByText(/CSV Telemetry Contract & Requirements/i)).toBeInTheDocument()
    expect(screen.getByText(/Temporal Requirements/i)).toBeInTheDocument()
    expect(screen.getByText(/Required Core Telemetry Columns/i)).toBeInTheDocument()
    expect(screen.getByText(/Scientific Honesty & Feature Imputation Policy/i)).toBeInTheDocument()
  })
})

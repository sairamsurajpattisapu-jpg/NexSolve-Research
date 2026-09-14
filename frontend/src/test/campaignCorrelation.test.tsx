import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CampaignCorrelationPanel } from '../components/investigation/CampaignCorrelationPanel'
import type {
  IncidentFingerprintPayload,
  IncidentCorrelationPayload,
  CampaignClusterPayload,
} from '../types/api'

describe('CampaignCorrelationPanel', () => {
  const mockFingerprint: IncidentFingerprintPayload = {
    incident_id: 'inc_test_01',
    capture_id: 'cap_friday_01',
    actor_entities: ['192.168.1.105'],
    target_entities: ['172.16.0.2', '172.16.0.5'],
    actor_roles: ['SUSPECT'],
    targeted_ports: [80, 443, 8080],
    protocol_distribution: { TCP: 100, HTTP: 45 },
    active_windows: [0, 1, 2, 3],
    total_packets: 2277,
    total_sessions: 15,
    total_flows: 45,
    fan_out_ratio: 2.5,
    failure_ratio: 0.1,
    attack_states: ['RECONNAISSANCE', 'EXPLOITATION'],
    observed_mitre_techniques: ['T1046', 'T1110'],
    episode_types: ['HTTP_BRUTEFORCE', 'PERIODIC_BEACON'],
    dominant_category: 'Reconnaissance',
    provenance: {},
  }

  const mockCorrelation: IncidentCorrelationPayload = {
    correlation_id: 'corr_01',
    incident_a: 'inc_test_01',
    incident_b: 'inc_test_02',
    relationship: 'RELATED_CAMPAIGN',
    evolution: 'CHANGING_INFRASTRUCTURE',
    supporting_dimensions: ['TARGET_OVERLAP', 'PORT_PATTERN_SIMILARITY'],
    contradicting_dimensions: [],
    neutral_dimensions: ['TEMPORAL_PROXIMITY'],
    supporting_signals: ['Identical targeted ports [80, 443]', 'Matching HTTP brute-force signature'],
    contradicting_signals: [],
    explanation: 'Correlated through shared target selection and behavior.',
    uncertainty: 'Empirical match',
    provenance: {},
  }

  const mockCluster: CampaignClusterPayload = {
    cluster_id: 'cluster_alpha',
    label: 'Multi-Stage Web Recon & Exploitation',
    member_incidents: ['inc_test_01', 'inc_test_02'],
    shared_characteristics: ['Port 80/443 targeting', 'HTTP brute-force'],
    unique_characteristics: [],
    evolution: 'CHANGING_INFRASTRUCTURE',
    timeline: [
      {
        incident_id: 'inc_test_01',
        timestamp: 1600000000,
        window_range: [0, 9],
        dominant_attack_state: 'RECONNAISSANCE',
        actor_count: 1,
        target_count: 5,
        summary: 'Initial reconnaissance scan',
      }
    ],
    correlations: [mockCorrelation],
    contradictions: [],
    uncertainty: 'Validated',
    campaign_assessment: 'Active multi-stage reconnaissance campaign.',
    analyst_action: 'Block actor subnet and inspect web logs.',
    provenance: {},
  }

  it('renders correctly with fingerprint and correlations', () => {
    render(
      <CampaignCorrelationPanel
        fingerprint={mockFingerprint}
        correlations={[mockCorrelation]}
        clusters={[mockCluster]}
      />
    )

    expect(screen.getByText(/CAMPAIGN INTELLIGENCE/i)).toBeInTheDocument()
    expect(screen.getByText(/1 CAMPAIGN CLUSTER/i)).toBeInTheDocument()
    expect(screen.getByText('Multi-Stage Web Recon & Exploitation')).toBeInTheDocument()
    expect(screen.getByText(/CHANGING INFRASTRUCTURE/i)).toBeInTheDocument()
  })

  it('renders single incident state when no correlations exist', () => {
    render(
      <CampaignCorrelationPanel
        fingerprint={mockFingerprint}
        correlations={[]}
        clusters={[]}
      />
    )

    expect(screen.getByText('Single Incident Session Analyzed')).toBeInTheDocument()
    expect(screen.getByText(/isolated incident session/i)).toBeInTheDocument()
  })
})

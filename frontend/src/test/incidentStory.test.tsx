import { render, screen, fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { IncidentStoryPanel } from '../components/investigation/IncidentStoryPanel'
import type { IncidentStoryPayload } from '../types/api'

const mockStory: IncidentStoryPayload = {
  story_id: 'story-test-101',
  title: 'Incident Reconstruction: Network Reconnaissance by 192.168.1.50',
  executive_summary: 'Observed reconnaissance incident involving 192.168.1.50 targeting 8 internal hosts.',
  narrative_paragraphs: [
    'Activity commenced with baseline connectivity and escalated into systematic reconnaissance targeting 8 hosts.',
    'Temporal kinematic analysis established an escalation into RECONNAISSANCE state (MITRE T1046).',
    'Observed reconnaissance activity remains active up to window 10; termination is not observed.',
  ],
  assessment: {
    classification: 'NETWORK_SERVICE_RECONNAISSANCE',
    severity: 'MEDIUM',
    start_window: 2,
    end_window: 10,
    duration_seconds: 600,
    termination_status: 'TERMINATION_NOT_OBSERVED_CAPTURE_BOUNDARY',
    what_changed_summary: 'Rapid horizontal destination expansion and port sweep onset at window 2.',
    why_it_matters: 'Adversary sweep actively enumerating listening services and identifying attack surface.',
    recommended_immediate_action: 'Quarantine primary scanning host 192.168.1.50.',
  },
  phases: [
    {
      phase_id: 'p_base',
      phase_type: 'BASELINE',
      start_window: 0,
      end_window: 1,
      duration_seconds: 120,
      participating_entities: ['192.168.1.50'],
      targets: [],
      dominant_behaviors: ['Baseline connection establishment'],
      evidence_ids: ['traffic_summary'],
      supporting_attack_states: ['BENIGN'],
      supported_mitre_techniques: [],
      grounding: 'DIRECTLY_OBSERVED',
      epistemic_status: 'OBSERVED',
      transition_reason: 'Normal initial communication profile.',
    },
    {
      phase_id: 'p_recon',
      phase_type: 'RECONNAISSANCE',
      start_window: 2,
      end_window: 9,
      duration_seconds: 480,
      participating_entities: ['192.168.1.50'],
      targets: ['10.0.0.1', '10.0.0.2'],
      dominant_behaviors: ['Sweep port scanning', 'High SYN attempt rates'],
      evidence_ids: ['finding_scan_1'],
      supporting_attack_states: ['RECONNAISSANCE'],
      supported_mitre_techniques: ['T1046'],
      grounding: 'DIRECTLY_OBSERVED',
      epistemic_status: 'OBSERVED',
      transition_reason: 'Significant fan-out surge and heuristic port-sweep detections.',
    },
    {
      phase_id: 'p_bound',
      phase_type: 'CAPTURE_BOUNDARY',
      start_window: 10,
      end_window: 10,
      duration_seconds: 0,
      participating_entities: [],
      targets: [],
      dominant_behaviors: ['Capture boundary limit'],
      evidence_ids: ['capture_time_boundary'],
      supporting_attack_states: ['BOUNDARY_LIMIT'],
      supported_mitre_techniques: [],
      grounding: 'DIRECTLY_OBSERVED',
      epistemic_status: 'OBSERVED',
      transition_reason: 'Activity continues to the capture boundary; termination not observed.',
    },
  ],
  events: [
    {
      event_id: 'e1',
      timestamp: 0,
      window_index: 0,
      event_type: 'ENTITY_APPEARED',
      actor: '192.168.1.50',
      target: null,
      observed_facts: ['Entity appeared in window 0'],
      supporting_evidence_ids: ['e_init'],
      supporting_graph_nodes: ['ip_192.168.1.50'],
      supporting_graph_edges: [],
      attack_state: 'BENIGN',
      mitre_technique: null,
      grounding: 'DIRECTLY_OBSERVED',
      epistemic_status: 'OBSERVED',
      uncertainty: 'LOW',
      explanation: 'First observed network traffic for 192.168.1.50.',
    },
    {
      event_id: 'e2',
      timestamp: 120,
      window_index: 2,
      event_type: 'PORT_SCAN_STARTED',
      actor: '192.168.1.50',
      target: '10.0.0.1',
      observed_facts: ['Observed SYN sweep across multiple ports'],
      supporting_evidence_ids: ['find_scan'],
      supporting_graph_nodes: ['ip_192.168.1.50'],
      supporting_graph_edges: [],
      attack_state: 'RECONNAISSANCE',
      mitre_technique: 'T1046',
      grounding: 'DIRECTLY_OBSERVED',
      epistemic_status: 'OBSERVED',
      uncertainty: 'LOW',
      explanation: 'Onset of systematic sweep scanning behavior.',
    },
  ],
  actors: [
    {
      entity: '192.168.1.50',
      roles: ['EXTERNAL_CLIENT'],
      first_seen_window: 0,
      last_seen_window: 9,
      packet_count: 500,
      session_count: 120,
      epistemic_status: 'OBSERVED',
      evidence_keys: ['prof_192.168.1.50'],
    },
  ],
  targets: [
    {
      entity: '10.0.0.1',
      targeted_ports: [80, 443, 8080],
      connection_count: 45,
      first_targeted_window: 2,
      last_targeted_window: 9,
      epistemic_status: 'OBSERVED',
      evidence_keys: ['ip_10.0.0.1'],
    },
  ],
  transitions: [
    {
      transition_id: 'tr_1',
      from_state: 'BENIGN',
      to_state: 'RECONNAISSANCE',
      window_index: 2,
      timestamp: 120,
      trigger_evidence: ['fanout_surge'],
      supporting_metrics: { strength: 1.0 },
      explanation: 'Kinematic state transition from BENIGN to RECONNAISSANCE.',
      grounding: 'STRONGLY_SUPPORTED',
      epistemic_status: 'SUPPORTED',
    },
  ],
  evidence_chain: [
    {
      step_order: 1,
      stage_name: 'Raw Telemetry Observation',
      description: 'Direct observation of network flows and session connections.',
      evidence_keys: ['session_metrics'],
      grounding: 'DIRECTLY_OBSERVED',
    },
    {
      step_order: 2,
      stage_name: 'Attack State Escalation',
      description: 'Kinematic state shift into RECONNAISSANCE.',
      evidence_keys: ['kinematics_trajectory'],
      grounding: 'STRONGLY_SUPPORTED',
    },
  ],
  contradictions: [],
  uncertainties: [
    {
      uncertainty_id: 'u1',
      level: 'MODERATE',
      category: 'CAPTURE_BOUNDARY',
      description: 'Active reconnaissance continues up to final packet of capture.',
      impact_on_assessment: 'Post-boundary exploitation status unobserved.',
      suggested_clarification: 'Inspect continuous SIEM logs beyond capture end.',
    },
  ],
  observed_mitre_techniques: ['T1046 Network Service Scanning'],
  inferred_mitre_techniques: [],
  forecast_summary: 'T+1 Markovian forecast predicts RECONNAISSANCE persistence (97.5%).',
  next_investigation_actions: ['Quarantine host 192.168.1.50.'],
  provenance: {},
}

describe('IncidentStoryPanel Component', () => {
  it('renders executive summary, title, and termination boundary status', () => {
    render(<IncidentStoryPanel incidentStory={mockStory} />)

    expect(screen.getByText(/Incident Reconstruction: Network Reconnaissance by 192.168.1.50/)).toBeInTheDocument()
    expect(screen.getByText(/TERMINATION_NOT_OBSERVED_CAPTURE_BOUNDARY/)).toBeInTheDocument()
    expect(screen.getByText(/Observed reconnaissance incident involving 192.168.1.50 targeting 8 internal hosts/)).toBeInTheDocument()
    expect(screen.getByText(/Quarantine primary scanning host 192.168.1.50/)).toBeInTheDocument()
  })

  it('navigates through incident tabs cleanly', () => {
    render(<IncidentStoryPanel incidentStory={mockStory} />)

    // Check Timeline tab
    const timelineBtn = screen.getByRole('button', { name: /Event Timeline/i })
    fireEvent.click(timelineBtn)
    expect(screen.getByText('PORT_SCAN_STARTED')).toBeInTheDocument()
    expect(screen.getByText('T1046')).toBeInTheDocument()

    // Check Phases tab
    const phasesBtn = screen.getByRole('button', { name: /Attack Phases/i })
    fireEvent.click(phasesBtn)
    expect(screen.getByText('PHASE: RECONNAISSANCE')).toBeInTheDocument()
    expect(screen.getByText('PHASE: CAPTURE_BOUNDARY')).toBeInTheDocument()

    // Check Actors & Targets tab
    const actorsBtn = screen.getByRole('button', { name: /Actors & Targets/i })
    fireEvent.click(actorsBtn)
    expect(screen.getByText('192.168.1.50')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()

    // Check Evidence Chain tab
    const chainBtn = screen.getByRole('button', { name: /Evidence Chain/i })
    fireEvent.click(chainBtn)
    expect(screen.getByText('Raw Telemetry Observation')).toBeInTheDocument()
    expect(screen.getByText('Attack State Escalation')).toBeInTheDocument()
  })
})

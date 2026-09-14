import { render, screen, fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TemporalWorldView } from '../components/investigation/TemporalWorldView'
import type { TemporalNetworkWorldStatePayload } from '../types/api'

const mockWorldState: TemporalNetworkWorldStatePayload = {
  capture_id: 'test-capture-world-1',
  total_windows: 3,
  total_packets: 1500,
  total_flows: 120,
  duration_seconds: 180,
  windows: [
    {
      window_id: 'win_0',
      sequence_index: 0,
      start_time: 0,
      end_time: 60,
      duration_seconds: 60,
      packet_count: 500,
      flow_count: 40,
      tcp_retransmission_rate: 0.01,
      active_entity_count: 2,
      active_relationship_count: 1,
      change_signals_count: 0,
      dominant_attack_stage: 'BENIGN',
      is_capture_boundary: false,
    },
    {
      window_id: 'win_1',
      sequence_index: 1,
      start_time: 60,
      end_time: 120,
      duration_seconds: 60,
      packet_count: 600,
      flow_count: 50,
      tcp_retransmission_rate: 0.02,
      active_entity_count: 3,
      active_relationship_count: 2,
      change_signals_count: 1,
      dominant_attack_stage: 'RECONNAISSANCE',
      is_capture_boundary: false,
    },
    {
      window_id: 'win_2',
      sequence_index: 2,
      start_time: 120,
      end_time: 180,
      duration_seconds: 60,
      packet_count: 400,
      flow_count: 30,
      tcp_retransmission_rate: 0.01,
      active_entity_count: 2,
      active_relationship_count: 1,
      change_signals_count: 0,
      dominant_attack_stage: 'RECONNAISSANCE',
      is_capture_boundary: true,
    },
  ],
  snapshots: {
    '0': {
      window_index: 0,
      window_id: 'win_0',
      start_time: 0,
      end_time: 60,
      duration_seconds: 60,
      packet_count: 500,
      flow_count: 40,
      entities: {
        '208.111.178.163': {
          entity_key: '208.111.178.163',
          entity_type: 'IP',
          presence: 'NEWLY_EMERGED',
          window_index: 0,
          attack_state: 'BENIGN',
          fanout: 2,
          port_diversity: 2,
          bytes_sent: 500,
          bytes_recv: 200,
          packets: 10,
          failure_ratio: 0.0,
          active_peers: ['192.168.10.50'],
          active_ports: [80],
          is_expanding_peers: false,
          is_expanding_ports: false,
          associated_findings_count: 0,
          composite_risk_score: 10.0,
        },
      },
      relationships: {
        '208.111.178.163->192.168.10.50:80/TCP': {
          relationship_id: '208.111.178.163->192.168.10.50:80/TCP',
          src_entity: '208.111.178.163',
          dst_entity: '192.168.10.50',
          dst_port: 80,
          protocol: 'TCP',
          status: 'NEW',
          first_seen_window: 0,
          last_seen_window: 0,
          window_index: 0,
          packet_count: 10,
          byte_count: 700,
          connection_count: 1,
          failed_attempts: 0,
        },
      },
      behavior_changes: [],
      attack_states: [],
      evidence_keys: [],
      is_capture_boundary: false,
    },
    '1': {
      window_index: 1,
      window_id: 'win_1',
      start_time: 60,
      end_time: 120,
      duration_seconds: 60,
      packet_count: 600,
      flow_count: 50,
      entities: {
        '208.111.178.163': {
          entity_key: '208.111.178.163',
          entity_type: 'IP',
          presence: 'ACTIVE',
          window_index: 1,
          attack_state: 'RECONNAISSANCE',
          fanout: 12,
          port_diversity: 20,
          bytes_sent: 5000,
          bytes_recv: 500,
          packets: 80,
          failure_ratio: 0.75,
          active_peers: ['192.168.10.50', '192.168.10.51', '192.168.10.52'],
          active_ports: [80, 443, 22],
          is_expanding_peers: true,
          is_expanding_ports: true,
          associated_findings_count: 2,
          composite_risk_score: 92.0,
        },
      },
      relationships: {},
      behavior_changes: [{ change_type: 'PORT_FANOUT_SURGE', magnitude: 10 }],
      attack_states: [],
      evidence_keys: ['ev_scan'],
      is_capture_boundary: false,
    },
  },
  entity_trajectories: {
    '208.111.178.163': [0, 1, 2],
    '192.168.10.50': [0, 1],
  },
  relationship_trajectories: {
    '208.111.178.163->192.168.10.50:80/TCP': [0, 1],
  },
  episodes: [],
  attack_states: [],
  threat_views: [],
  change_signals: [],
  forecast_points: [
    { horizon_step: 1, predicted_stage: 'RECONNAISSANCE', attack_probability: 0.85, scope: 'FORECAST' },
  ],
  graph_summary: { nodes: 15, edges: 12, chains: 2 },
}

describe('TemporalWorldView Component', () => {
  it('renders Temporal Network World Model header and window scrubbers cleanly', () => {
    render(<TemporalWorldView worldState={mockWorldState} />)

    expect(screen.getByText('Temporal Network World Model')).toBeInTheDocument()
    expect(screen.getByText(/OBSERVED GROUND TRUTH/i)).toBeInTheDocument()
    expect(screen.getByText(/W0/)).toBeInTheDocument()
    expect(screen.getByText(/W1/)).toBeInTheDocument()
    expect(screen.getByText(/W2/)).toBeInTheDocument()
  })

  it('switches to What Changed (Temporal Diff) tab and computes deterministic state delta', () => {
    render(<TemporalWorldView worldState={mockWorldState} />)

    const diffTab = screen.getByText(/What Changed \(Temporal Diff\)/i)
    fireEvent.click(diffTab)

    expect(screen.getByText(/Deterministic delta between/i)).toBeInTheDocument()
    expect(screen.getByText(/Attack State Transitions Detected/i)).toBeInTheDocument()
    expect(screen.getAllByText('208.111.178.163').length).toBeGreaterThan(0)
    expect(screen.getByText(/transitioned from/i)).toBeInTheDocument()
    expect(screen.getAllByText(/RECONNAISSANCE/i).length).toBeGreaterThan(0)
  })

  it('switches to Entity Trajectories tab and displays presence heatstrips', () => {
    render(<TemporalWorldView worldState={mockWorldState} />)

    const trajTab = screen.getByText(/Entity Trajectories/i)
    fireEvent.click(trajTab)

    expect(screen.getByText('208.111.178.163')).toBeInTheDocument()
    expect(screen.getByText('192.168.10.50')).toBeInTheDocument()
    expect(screen.getByText('3/3 wins')).toBeInTheDocument()
  })
})

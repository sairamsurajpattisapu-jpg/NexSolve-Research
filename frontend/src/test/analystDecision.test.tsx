import { render, screen, fireEvent } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AnalystCommandCenter } from '../components/investigation/AnalystCommandCenter'
import type { AnalystDecisionPayload } from '../types/api'

const mockDecisions: AnalystDecisionPayload[] = [
  {
    decision_id: 'decision-1',
    priority_tier: 'P0_CRITICAL',
    priority_rank: 1,
    decision_type: 'INVESTIGATE_ENTITY',
    target_id: '192.168.1.50',
    headline: 'Prioritize Investigation of 192.168.1.50',
    why_now: 'Entity escalated across states with high target fan-out in window 4.',
    confidence_grounding: 'STRONGLY_SUPPORTED',
    supporting_evidence: ['Reconnaissance scanning across 15 ports', 'Beaconing pattern with 120s interval'],
    counter_hypotheses: ['Internal vulnerability scanner'],
    contradictions: [],
    recommended_action: 'Quarantine host and inspect process memory.',
    investigation_value: {
      value_score: 0.88,
      priority_tier: 'P0_CRITICAL',
      expected_uncertainty_reduction: 'HIGH (4 distinct ambiguities resolved)',
      actionability: 'IMMEDIATE',
      recommended_next_step: 'Collect endpoint process logs.',
    },
    threat_differentiation: {
      semantic_tier: 'ACTIVE_ATTACK_INDICATOR',
      grounding_state: 'STRONGLY_SUPPORTED',
      differentiating_factors: ['Multiple distinct attack indicators confirmed'],
      contradicting_factors: [],
      rationale: 'Telemetry meets active attack criteria with high severity.',
    },
    what_changed: [
      {
        change_type: 'STATE_JUMP',
        headline: 'Kinematic Jump: BENIGN -> RECONNAISSANCE',
        window_index: 4,
        description: 'Transitioned directly to active port scan state.',
        supporting_signals: ['SYN scan on port 445'],
      },
      {
        change_type: 'FAN_OUT_SURGE',
        headline: 'Target Fan-Out Surge: 1 -> 14 destinations',
        window_index: 4,
        description: 'Sudden horizontal connection expansion.',
        supporting_signals: ['14 unique destinations in 60s'],
      },
    ],
    benign_hypotheses: [
      {
        hypothesis_id: 'H1',
        title: 'Authorized Vulnerability Scanner / Discovery Scan',
        description: 'Host might be a Nessus or Qualys scanner.',
        resolution_state: 'SUPPORTED_THREAT',
        supporting_factors: ['High destination breadth'],
        contradicting_factors: ['Target host is an engineering workstation (not scanner IP)'],
      },
    ],
    open_questions: [
      {
        question_id: 'Q1',
        question: 'Is 192.168.1.50 an authorized security scanning appliance?',
        context: 'High connection attempts on sensitive ports.',
        category: 'AUTHORIZATION',
        suggested_checks: ['Verify CMDB asset inventory for vulnerability scanning role'],
      },
    ],
    decision_chain: {
      root_entity: '192.168.1.50',
      headline: 'Multi-stage decision path from scan to persistence',
      steps: [
        {
          step_id: 'S1',
          title: 'Direct Observation of Sweep Scanning',
          description: 'Observed 14 destination IPs probed on port 445.',
          grounding: 'DIRECTLY_OBSERVED',
        },
        {
          step_id: 'S2',
          title: 'Escalation to Inferred Attack State',
          description: 'Transition to RECONNAISSANCE state confirmed.',
          grounding: 'STRONGLY_SUPPORTED',
        },
      ],
    },
    provenance: {},
  },
]

describe('AnalystCommandCenter Component', () => {
  it('renders command center with P0 priority count and headline', () => {
    render(<AnalystCommandCenter decisions={mockDecisions} />)

    expect(screen.getByText('Security Analyst Command Center')).toBeInTheDocument()
    expect(screen.getByText('1 P0 CRITICAL')).toBeInTheDocument()
    expect(screen.getAllByText(/Prioritize Investigation of 192.168.1.50/).length).toBeGreaterThan(0)
    expect(screen.getByText(/Entity escalated across states with high target fan-out in window 4/)).toBeInTheDocument()
    expect(screen.getByText(/Quarantine host and inspect process memory/)).toBeInTheDocument()
  })

  it('switches between decision detail tabs cleanly', () => {
    render(<AnalystCommandCenter decisions={mockDecisions} />)

    // Check What Changed Tab
    const whatChangedBtn = screen.getByRole('button', { name: /What Changed/i })
    fireEvent.click(whatChangedBtn)
    expect(screen.getByText(/Kinematic Jump: BENIGN -> RECONNAISSANCE/)).toBeInTheDocument()
    expect(screen.getByText(/Target Fan-Out Surge: 1 -> 14 destinations/)).toBeInTheDocument()

    // Check Benign Hypotheses Tab
    const benignBtn = screen.getByRole('button', { name: /Benign Hypotheses/i })
    fireEvent.click(benignBtn)
    expect(screen.getByText(/Authorized Vulnerability Scanner/)).toBeInTheDocument()
    expect(screen.getByText(/REFUTED \/ SUPPORTED THREAT/)).toBeInTheDocument()

    // Check Open Questions Tab
    const questionsBtn = screen.getByRole('button', { name: /Open Questions/i })
    fireEvent.click(questionsBtn)
    expect(screen.getByText(/Is 192.168.1.50 an authorized security scanning appliance/)).toBeInTheDocument()
    expect(screen.getByText(/Verify CMDB asset inventory/)).toBeInTheDocument()
  })
})

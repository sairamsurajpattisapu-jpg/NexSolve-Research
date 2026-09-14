import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, afterEach } from 'vitest'
import { ThreatHuntingWorkspace } from '../components/investigation/ThreatHuntingWorkspace'
import type { QueryResultPayload } from '../types/api'

afterEach(() => vi.restoreAllMocks())

describe('ThreatHuntingWorkspace Component', () => {
  const mockQueryResult: QueryResultPayload = {
    query_id: 'q_test_1',
    target: 'ENTITY',
    total_matches: 2,
    matches: [
      {
        match_id: 'm_1',
        target: 'ENTITY',
        entity_key: '208.111.178.163',
        label: '208.111.178.163',
        primary_category: 'Reconnaissance',
        semantic_state: 'RECONNAISSANCE',
        epistemic_status: 'OBSERVED',
        match_score: 9.5,
        time_window: [1, 5],
        matched_predicates: ['entity.port_diversity >= 5'],
        supporting_evidence: ['T1046 Network Service Scanning', 'SYN probe sweep'],
        contradicting_evidence: [],
        uncertainties: ['TERMINATION_NOT_OBSERVED_CAPTURE_BOUNDARY'],
        graph_node_ids: ['node_208_111_178_163'],
        graph_evidence_path: ['208.111.178.163', 'T1046', 'SYN_SCAN'],
        properties: {
          failure_ratio: 0.85,
          port_diversity: 12,
        },
        analyst_decision_id: 'DEC-001',
      },
    ],
    truncated: false,
    execution_duration_ms: 3.42,
    query_summary: 'Found 1 entity match across 1 predicate.',
    uncertainties: ['Single-capture evaluation.'],
    applied_epistemic_scope: 'OBSERVED_ONLY',
  }

  it('renders workspace with pre-built hunt packs', () => {
    render(<ThreatHuntingWorkspace analysisId="test_analysis_1" />)
    expect(screen.getByText(/Threat Hunting & Multi-Modal Intelligence Query/i)).toBeInTheDocument()
    expect(screen.getByText(/High Destination-Port & Host Fan-Out/i)).toBeInTheDocument()
    expect(screen.getByText(/Confirmed Reconnaissance Entities/i)).toBeInTheDocument()
  })

  it('renders initialResults and match drilldown seamlessly', () => {
    render(
      <ThreatHuntingWorkspace
        analysisId="test_analysis_1"
        initialResults={mockQueryResult}
      />
    )

    expect(screen.getAllByText(/208.111.178.163/i).length).toBeGreaterThan(0)
    expect(screen.getByText(/MATCH INSPECTOR/i)).toBeInTheDocument()
    expect(screen.getByText(/T1046 Network Service Scanning/i)).toBeInTheDocument()
    expect(screen.getByText(/WHY THIS MATCHED/i)).toBeInTheDocument()
  })

  it('triggers query execution via run query button', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify(mockQueryResult), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    )

    render(<ThreatHuntingWorkspace analysisId="test_analysis_1" />)

    const runBtn = screen.getByRole('button', { name: /Run Query/i })
    fireEvent.click(runBtn)

    await waitFor(() => {
      expect(fetch).toHaveBeenCalled()
    })
  })
})

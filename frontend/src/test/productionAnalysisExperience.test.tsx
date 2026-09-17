import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { AnalysisPipelineVisualizer } from '../components/AnalysisPipelineVisualizer'
import { GlobalErrorState } from '../components/GlobalErrorState'
import { Layout } from '../components/Layout'
import { api } from '../services/api'
import { useJobPolling } from '../hooks/useJobPolling'
import { renderHook } from '@testing-library/react'

describe('Production Analysis Experience & Backend Invisibility Suite', () => {
  it('1. App shell renders immediately with product status language', () => {
    render(
      <MemoryRouter>
        <Layout status="API connected" />
      </MemoryRouter>
    )

    // Verify brand, navigation, and product language status
    expect(screen.getByText('NexSolve')).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: /Primary navigation/i })).toBeInTheDocument()
    expect(screen.getByText('READY')).toBeInTheDocument()
    const statusPill = screen.getByTitle(/Ready for analysis/i)
    expect(statusPill).toBeInTheDocument()
  })

  it('2. App shell displays calm product message when service is temporarily unavailable', () => {
    render(
      <MemoryRouter>
        <Layout status="TEMPORARILY UNAVAILABLE" />
      </MemoryRouter>
    )

    expect(screen.getByText('TEMPORARILY UNAVAILABLE')).toBeInTheDocument()
    const statusPill = screen.getByTitle(/Analysis service temporarily unavailable/i)
    expect(statusPill).toBeInTheDocument()

    // Verify zero developer infrastructure strings
    expect(screen.queryByText(/backend offline/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/api offline/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/start fastapi/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/8001/i)).not.toBeInTheDocument()
  })

  it('3. AnalysisPipelineVisualizer renders all 8 exact requested stages', () => {
    render(
      <AnalysisPipelineVisualizer
        jobId="test-job-123"
        stage="RECONSTRUCT"
        progress={0.35}
        job={{
          job_id: 'test-job-123',
          status: 'RUNNING',
          stage: 'FLOW_RECONSTRUCTION',
          progress: 0.35,
          created_at: '2026-09-17T00:00:00Z',
          updated_at: '2026-09-17T00:00:05Z',
          processing_statistics: {
            packets_processed: 1450,
            flows_processed: 128,
            windows_processed: 4,
          },
        } as any}
      />
    )

    // Verify all 8 stage names are present
    expect(screen.getByText('INGEST')).toBeInTheDocument()
    expect(screen.getByText('NORMALIZE')).toBeInTheDocument()
    expect(screen.getAllByText('RECONSTRUCT').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('REPRESENT')).toBeInTheDocument()
    expect(screen.getByText('ANALYZE')).toBeInTheDocument()
    expect(screen.getByText('SIMULATE')).toBeInTheDocument()
    expect(screen.getByText('FORECAST')).toBeInTheDocument()
    expect(screen.getByText('EXPLAIN')).toBeInTheDocument()

    // Verify real telemetry is rendered without faked percentages
    expect(screen.getByText('1,450')).toBeInTheDocument()
    expect(screen.getByText('128')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.getByText('35%')).toBeInTheDocument()
  })

  it('4. AnalysisPipelineVisualizer renders completed state smoothly', () => {
    const onReady = vi.fn()
    render(
      <AnalysisPipelineVisualizer
        jobId="test-job-complete"
        stage="COMPLETE"
        progress={1.0}
        job={{
          job_id: 'test-job-complete',
          status: 'COMPLETED',
          stage: 'COMPLETE',
          progress: 1.0,
          created_at: '2026-09-17T00:00:00Z',
          updated_at: '2026-09-17T00:00:10Z',
        } as any}
        isComplete={true}
        onReady={onReady}
      />
    )

    expect(screen.getByText(/ANALYSIS COMPLETE → FORECAST READY/i)).toBeInTheDocument()
    expect(screen.getByText('100%')).toBeInTheDocument()

    const openBtn = screen.getByRole('button', { name: /Open Forecast/i })
    fireEvent.click(openBtn)
    expect(onReady).toHaveBeenCalled()
  })

  it('5. GlobalErrorState presents clean product copy with collapsible technical diagnostics', () => {
    render(
      <MemoryRouter>
        <GlobalErrorState
          code="INSUFFICIENT_HISTORY"
          explanation="Not enough continuous temporal history was available to produce a reliable forecast."
          technicalDetails="Exception: Window count 2 < required lookback 8 in sequence generator"
        />
      </MemoryRouter>
    )

    expect(screen.getByText(/Not enough continuous temporal history/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Technical Diagnostics/i })).toBeInTheDocument()

    // Diagnostics collapsed initially
    expect(screen.queryByText(/Exception: Window count/i)).not.toBeInTheDocument()

    // Expand diagnostics
    fireEvent.click(screen.getByRole('button', { name: /Technical Diagnostics/i }))
    expect(screen.getByText(/Exception: Window count 2 < required lookback 8/i)).toBeInTheDocument()
  })

  it('6. useJobPolling prefetches results automatically when job completes', async () => {
    vi.spyOn(api, 'getJobStatus').mockResolvedValueOnce({
      job_id: 'job-prefetch-test',
      status: 'COMPLETED',
      stage: 'COMPLETE',
      progress: 1.0,
      created_at: '2026-09-17T00:00:00Z',
      updated_at: '2026-09-17T00:00:10Z',
    } as any)

    vi.spyOn(api, 'getJobResult').mockResolvedValueOnce({
      analysis_id: 'job-prefetch-test',
      status: 'COMPLETED',
      traffic: {
        total_packets: 100,
        flow_count: 10,
        packet_count: 100,
        total_flows: 10,
        duration_seconds: 60,
        total_bytes: 5000,
        mean_packet_rate: 1.6,
      },
      detection: { threat_level: 'LOW', overall_confidence: 0.9 },
    } as any)

    const { result } = renderHook(() => useJobPolling('job-prefetch-test'))

    await waitFor(() => {
      expect(result.current.isComplete).toBe(true)
    })

    expect(result.current.result).not.toBeNull()
    expect(result.current.result?.id).toBe('job-prefetch-test')
  })

  it('7. useJobPolling initiates bounded reconnect attempts on transient network glitches', async () => {
    vi.spyOn(api, 'getJobStatus').mockRejectedValue(new Error('Failed to fetch'))
    vi.spyOn(api, 'getJobResult').mockRejectedValue(new Error('Failed to fetch'))

    const { result } = renderHook(() => useJobPolling('job-reconnect-test'))

    await waitFor(() => {
      expect(result.current.isReconnecting).toBe(true)
      expect(result.current.reconnectAttempt).toBeGreaterThanOrEqual(1)
    })
  })
})

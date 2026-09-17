import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { AnalysisPipelineVisualizer, PIPELINE_STAGES } from '../components/AnalysisPipelineVisualizer'
import { JobProgress } from '../components/JobProgress'
import type { JobStatusResponse } from '../types/api'

describe('PCAP Processing Pipeline & ETA Execution Suite', () => {
  const sampleJob: JobStatusResponse = {
    job_id: 'job-test-pcap-889',
    filename: 'network_attack_eval.pcap',
    status: 'PROCESSING',
    stage: 'WINDOWING',
    progress: 0.55,
    created_at: '2026-09-17T12:00:00Z',
    started_at: '2026-09-17T12:00:01Z',
    completed_at: null,
    error: null,
    processing_statistics: {
      packets_processed: 85200,
      flows_processed: 1420,
      windows_processed: 8,
      processing_seconds: 4.2,
    },
  }

  it('renders all 12 canonical pipeline stages with active status', () => {
    render(
      <MemoryRouter>
        <AnalysisPipelineVisualizer
          jobId="job-test-pcap-889"
          stage="WINDOWING"
          progress={0.55}
          job={sampleJob}
          isReconnecting={false}
          isComplete={false}
        />
      </MemoryRouter>
    )

    // Verify all 12 stage labels are present
    PIPELINE_STAGES.forEach((st) => {
      expect(screen.getAllByText(st.label).length).toBeGreaterThan(0)
    })

    // Verify progress percentage
    expect(screen.getByText('55%')).toBeInTheDocument()

    // Verify telemetry metrics
    expect(screen.getByText('85,200')).toBeInTheDocument()
    expect(screen.getByText('8 Windows')).toBeInTheDocument()
  })

  it('renders PROCESSING CONTINUES when connection is reconnecting', () => {
    render(
      <MemoryRouter>
        <AnalysisPipelineVisualizer
          jobId="job-test-pcap-889"
          stage="WINDOWING"
          progress={0.55}
          job={sampleJob}
          isReconnecting={true}
          reconnectAttempt={3}
          isComplete={false}
        />
      </MemoryRouter>
    )

    expect(screen.getAllByText(/PROCESSING CONTINUES/).length).toBeGreaterThan(0)
    expect(screen.getByText(/Attempt 3\/10/)).toBeInTheDocument()
  })

  it('displays estimated remaining time in AnalysisPipelineVisualizer', () => {
    render(
      <MemoryRouter>
        <AnalysisPipelineVisualizer
          jobId="job-test-pcap-889"
          stage="WINDOWING"
          progress={0.55}
          job={sampleJob}
          isReconnecting={false}
          isComplete={false}
        />
      </MemoryRouter>
    )

    expect(screen.getByText('ESTIMATED REMAINING')).toBeInTheDocument()
    expect(screen.getByText('ELAPSED TIME')).toBeInTheDocument()
  })

  it('displays elapsed and remaining time in JobProgress component', () => {
    render(
      <JobProgress job={sampleJob} />
    )

    expect(screen.getByText(/Elapsed:/)).toBeInTheDocument()
    expect(screen.getByText(/Remaining:/)).toBeInTheDocument()
    expect(screen.getByText('55% Deterministic Progress')).toBeInTheDocument()
  })

  // Requirement 8: Processing Pipeline Tests
  it('renders each stage active appropriately across the canonical stages', () => {
    const testStages = [
      { stage: 'UPLOAD', title: 'UPLOADING CAPTURE' },
      { stage: 'VALIDATE', title: 'VALIDATING CAPTURE' },
      { stage: 'INGEST', title: 'INGESTING CAPTURE' },
      { stage: 'NORMALIZE', title: 'NORMALIZING FRAMES' },
      { stage: 'RECONSTRUCT', title: 'RECONSTRUCTING FLOWS' },
      { stage: 'WINDOWS', title: 'BUILDING TEMPORAL WINDOWS' },
      { stage: 'FEATURES', title: 'EXTRACTING CANONICAL FEATURES' },
      { stage: 'NETWORK_STATE', title: 'RECONSTRUCTING NETWORK STATE' },
      { stage: 'THREAT_ANALYSIS', title: 'EVALUATING THREAT BEHAVIORS' },
      { stage: 'FORECAST', title: 'GENERATING FORECAST' },
      { stage: 'EVIDENCE', title: 'COMPILING EVIDENCE CHAIN' },
      { stage: 'COMPLETE', title: 'ANALYSIS COMPLETE' },
    ]

    for (const { stage, title } of testStages) {
      const { unmount } = render(
        <MemoryRouter>
          <AnalysisPipelineVisualizer
            jobId="stage-test-job"
            stage={stage}
            progress={stage === 'COMPLETE' ? 1.0 : 0.4}
            job={{ ...sampleJob, stage, progress: stage === 'COMPLETE' ? 1.0 : 0.4 } as any}
            isComplete={stage === 'COMPLETE'}
          />
        </MemoryRouter>
      )
      expect(screen.getByText(title)).toBeInTheDocument()
      unmount()
    }
  })

  it('does NOT display "8 Windows" when windows telemetry is missing', () => {
    const jobWithoutWindows: JobStatusResponse = {
      ...sampleJob,
      processing_statistics: {
        packets_processed: 5000,
        // no windows_processed
      },
    }

    render(
      <MemoryRouter>
        <AnalysisPipelineVisualizer
          jobId="job-no-windows"
          stage="INGEST"
          progress={0.1}
          job={jobWithoutWindows}
        />
      </MemoryRouter>
    )

    // Must NOT display fabricated 8 Windows
    expect(screen.queryByText('8 Windows')).not.toBeInTheDocument()
    expect(screen.getByText('Calculating...')).toBeInTheDocument()
  })

  it('does not fabricate percentage when progress is missing', () => {
    const jobWithoutProgress: JobStatusResponse = {
      ...sampleJob,
      progress: 0,
    }

    render(
      <MemoryRouter>
        <AnalysisPipelineVisualizer
          jobId="job-no-progress"
          stage="INGEST"
          progress={0}
          job={jobWithoutProgress}
        />
      </MemoryRouter>
    )

    // Should display PROCESSING instead of a fabricated percentage
    expect(screen.getAllByText(/PROCESSING/).length).toBeGreaterThan(0)
    expect(screen.queryByText('0%')).not.toBeInTheDocument()
  })

  it('missing ETA displays Calculating... instead of stage-weighted estimate', () => {
    render(
      <MemoryRouter>
        <AnalysisPipelineVisualizer
          jobId="job-no-eta"
          stage="FORECAST"
          progress={0}
          job={{ ...sampleJob, stage: 'FORECAST', progress: 0 }}
        />
      </MemoryRouter>
    )

    expect(screen.getByText('Calculating...')).toBeInTheDocument()
  })

  it('HTTP timeout (isReconnecting) does NOT classify the job as FAILED', () => {
    render(
      <MemoryRouter>
        <AnalysisPipelineVisualizer
          jobId="job-transport-timeout"
          stage="FLOW_RECONSTRUCTION"
          progress={0.4}
          job={sampleJob}
          isReconnecting={true}
          reconnectAttempt={2}
          error="Request timed out"
        />
      </MemoryRouter>
    )

    // Must show PROCESSING CONTINUES, NOT ANALYSIS FAILED
    expect(screen.getAllByText(/PROCESSING CONTINUES/).length).toBeGreaterThan(0)
    expect(screen.queryByText('ANALYSIS FAILED')).not.toBeInTheDocument()
    expect(screen.getByText(/The request exceeded the response window, but the analysis job is still running\./)).toBeInTheDocument()
    expect(screen.getAllByText(/RECONSTRUCTING FLOWS/).length).toBeGreaterThan(0)
  })

  it('backend FAILED status displays ANALYSIS FAILED', () => {
    const failedJob: JobStatusResponse = {
      ...sampleJob,
      status: 'FAILED',
      error: {
        code: 'PARSING_ERROR',
        message: 'Invalid Ethernet frame at offset 128',
      },
    }

    render(
      <MemoryRouter>
        <AnalysisPipelineVisualizer
          jobId="job-failed"
          stage="PARSING"
          progress={0.2}
          job={failedJob}
          error="Invalid Ethernet frame at offset 128"
        />
      </MemoryRouter>
    )

    expect(screen.getAllByText('ANALYSIS FAILED').length).toBeGreaterThan(0)
    expect(screen.getAllByText(/Invalid Ethernet frame at offset 128/).length).toBeGreaterThan(0)
  })

  it('backend RESOURCE_LIMIT_EXCEEDED displays ANALYSIS TIMED OUT', () => {
    const timedOutJob: JobStatusResponse = {
      ...sampleJob,
      status: 'RESOURCE_LIMIT_EXCEEDED',
      error: {
        resource: 'processing_duration',
        limit: 300,
        observed: 305,
        explanation: 'The capture exceeded the maximum processing time limit.',
      },
    }

    render(
      <MemoryRouter>
        <AnalysisPipelineVisualizer
          jobId="job-timed-out"
          stage="WINDOWING"
          progress={0.5}
          job={timedOutJob}
          errorCode="ANALYSIS_TIMED_OUT"
        />
      </MemoryRouter>
    )

    expect(screen.getAllByText('ANALYSIS TIMED OUT').length).toBeGreaterThan(0)
  })

  it('completion stops ETA updates and shows 0s', () => {
    const completedJob: JobStatusResponse = {
      ...sampleJob,
      status: 'COMPLETED',
      progress: 1.0,
      completed_at: '2026-09-17T12:00:20Z',
    }

    render(
      <MemoryRouter>
        <AnalysisPipelineVisualizer
          jobId="job-complete"
          stage="COMPLETE"
          progress={1.0}
          job={completedJob}
          isComplete={true}
        />
      </MemoryRouter>
    )

    expect(screen.getAllByText(/ANALYSIS COMPLETE/).length).toBeGreaterThan(0)
    expect(screen.getByText('0s')).toBeInTheDocument()
  })
})

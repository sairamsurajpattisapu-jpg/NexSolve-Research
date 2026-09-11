import { act, fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { DemoModeSelector } from '../components/DemoModeSelector'
import { JobResult } from '../components/JobResult'
import { DEMO_SCENARIO_PAYLOADS } from '../fixtures/demoScenarios'

describe('SIH Demo Mode Component Suite', () => {
  it('renders all 7 deterministic demo scenario options', () => {
    const onSelect = vi.fn()
    render(<DemoModeSelector onSelectScenario={onSelect} />)

    expect(screen.getByRole('tab', { name: /Normal Traffic Baseline/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Early Attack Signal/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Sustained Attack Forecast/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Contradictory Evidence/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Unknown \/ Out-of-Distribution Behavior/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Forecast Abstained/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Poor Capture Quality/i })).toBeInTheDocument()
  })

  it('selects a demo scenario and displays expected evaluation behavior', async () => {
    const onSelect = vi.fn()
    render(<DemoModeSelector onSelectScenario={onSelect} />)

    const sustainedBtn = screen.getByRole('tab', { name: /Sustained Attack Forecast/i })
    await act(async () => {
      fireEvent.click(sustainedBtn)
    })

    expect(
      screen.getByText(/Attack Horizon confirms SUSTAINED_ATTACK_FORECAST spanning 3 windows/i)
    ).toBeInTheDocument()

    await vi.waitFor(() => {
      expect(onSelect).toHaveBeenCalled()
    })
  })

  it('JobResult renders DEMO MODE badge and scenario guidance when is_demo is true', () => {
    const demoPayload = DEMO_SCENARIO_PAYLOADS.SUSTAINED_ATTACK_FORECAST
    render(<JobResult result={demoPayload} />)

    expect(screen.getByText('DEMO MODE')).toBeInTheDocument()
    expect(screen.getByText(/SIH Demo: Sustained Attack Forecast/i)).toBeInTheDocument()
    expect(screen.getByText(/Scenario Context & Evaluation Guidance:/i)).toBeInTheDocument()
    expect(screen.getByText(/Total Pipeline:/i)).toBeInTheDocument()
  })

  it('JobResult renders deliberate abstention safety gate for FORECAST_ABSTAINED scenario', () => {
    const demoPayload = DEMO_SCENARIO_PAYLOADS.FORECAST_ABSTAINED
    render(<JobResult result={demoPayload} />)

    expect(screen.getByText('DEMO MODE')).toBeInTheDocument()
    expect(screen.getByText('FORECAST WITHHELD')).toBeInTheDocument()
    expect(
      screen.getAllByText(/NexSolve does not have enough reliable evidence/i).length
    ).toBeGreaterThan(0)
    expect(
      screen.getAllByText(/INSUFFICIENT_LOOKBACK_HISTORY/i).length
    ).toBeGreaterThan(0)
  })

  it('verifies state isolation across sequential scenario selections A -> B -> C -> A', async () => {
    const onSelect = vi.fn()
    render(<DemoModeSelector onSelectScenario={onSelect} />)

    // Select Scenario A (Normal)
    const normalBtn = screen.getByRole('tab', { name: /Normal Traffic Baseline/i })
    await act(async () => {
      fireEvent.click(normalBtn)
    })
    expect(screen.getByText(/Standard business hours traffic/i)).toBeInTheDocument()

    // Select Scenario B (Early Signal)
    const earlyBtn = screen.getByRole('tab', { name: /Early Attack Signal/i })
    await act(async () => {
      fireEvent.click(earlyBtn)
    })
    expect(screen.getByText(/Traffic activity begins shifting/i)).toBeInTheDocument()

    // Select Scenario C (Poor Quality)
    const poorBtn = screen.getByRole('tab', { name: /Poor Capture Quality/i })
    await act(async () => {
      fireEvent.click(poorBtn)
    })
    expect(screen.getByText(/22.4% packet loss/i)).toBeInTheDocument()

    // Return to Scenario A (Normal)
    await act(async () => {
      fireEvent.click(normalBtn)
    })
    expect(screen.getByText(/Standard business hours traffic/i)).toBeInTheDocument()
    expect(screen.queryByText(/22.4% packet loss/i)).not.toBeInTheDocument()
  })

  it('verifies report actions and latency metrics render on all non-abstained scenarios', () => {
    const normalPayload = DEMO_SCENARIO_PAYLOADS.NORMAL_TRAFFIC
    const { unmount } = render(<JobResult result={normalPayload} />)

    expect(screen.getAllByText(/Open HTML Report/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/JSON/i).length).toBeGreaterThan(0)
    expect(screen.getByText(/Total Pipeline:/i)).toBeInTheDocument()
    unmount()

    const contradictoryPayload = DEMO_SCENARIO_PAYLOADS.CONTRADICTORY_EVIDENCE
    render(<JobResult result={contradictoryPayload} />)
    expect(screen.getAllByText(/Open HTML Report/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/Contradictory Evidence/i).length).toBeGreaterThan(0)
  })
})

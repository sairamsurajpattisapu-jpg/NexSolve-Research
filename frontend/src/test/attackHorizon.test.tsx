import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AttackHorizonCard } from '../components/AttackHorizonCard'
import { attackHorizonFixtures } from '../fixtures/attackHorizonFixtures'

describe('AttackHorizonCard', () => {
  it('renders default sustained attack state and metrics cleanly', () => {
    render(<AttackHorizonCard />)

    expect(screen.getByText('Attack Horizon & Lead Time')).toBeInTheDocument()
    expect(screen.getByText('Sustained Attack Forecast')).toBeInTheDocument()
    expect(screen.getByText('3 windows')).toBeInTheDocument()
    expect(screen.getByText('60s')).toBeInTheDocument()
    expect(screen.getByText('100%')).toBeInTheDocument()
    expect(screen.getByText('UNSUPPORTED')).toBeInTheDocument()
    expect(screen.getByText(/Sustained attack forecast spanning 3 windows/)).toBeInTheDocument()
    expect(screen.getByText('T+1')).toBeInTheDocument()
    expect(screen.getByText('T+5')).toBeInTheDocument()
  })

  it('switches deterministically between all 5 states via fixture switcher', () => {
    render(<AttackHorizonCard />)

    // Switch to Early Signal
    fireEvent.click(screen.getByRole('button', { name: 'Early' }))
    expect(screen.getByText('Early Signal')).toBeInTheDocument()
    expect(screen.getByText('1 windows')).toBeInTheDocument()

    // Switch to Baseline / No Attack
    fireEvent.click(screen.getByRole('button', { name: 'Baseline' }))
    expect(screen.getByText('No Attack Forecast')).toBeInTheDocument()
    expect(screen.getByText('0 windows')).toBeInTheDocument()

    // Switch to Uncertain
    fireEvent.click(screen.getByRole('button', { name: 'Uncertain' }))
    expect(screen.getByText('Uncertain Forecast')).toBeInTheDocument()

    // Switch to Abstained
    fireEvent.click(screen.getByRole('button', { name: 'Abstained' }))
    expect(screen.getByText('Abstained', { selector: '.status' })).toBeInTheDocument()
    expect(screen.getByText(/Abstention reason:/)).toBeInTheDocument()
  })

  it('renders custom payload when passed as initialPayload without fixture buttons', () => {
    render(
      <AttackHorizonCard
        initialPayload={attackHorizonFixtures.noAttack}
        allowStateSwitching={false}
      />
    )
    expect(screen.getByText('No Attack Forecast')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Sustained' })).toBeNull()
  })
})

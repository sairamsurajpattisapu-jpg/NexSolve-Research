import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ClosingPlasma } from '../components/ui/ClosingPlasma'
import { ClosingPlasmaBackground } from '../components/ClosingPlasmaBackground'

describe('ClosingPlasma & ClosingPlasmaBackground Suite', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('1. ClosingPlasma renders canvas with pointer-events: none and accessible container', () => {
    const { container } = render(
      <ClosingPlasma
        speed={0.35}
        turbulence={0.55}
        mouseInfluence={0.35}
        grain={0.18}
        sparkle={0.12}
        vignette={0.75}
        opacity={0.45}
        interactive
        darkColorA="#0a0a0e"
        darkColorB="#141829"
        darkColorC="#283754"
      />
    )

    const root = container.querySelector('.closing-plasma-root')
    expect(root).toBeInTheDocument()

    const canvas = container.querySelector('canvas')
    expect(canvas).toBeInTheDocument()
    expect(canvas).toHaveAttribute('aria-hidden', 'true')
    expect(canvas).toHaveStyle({ pointerEvents: 'none' })
  })

  it('2. Supports rendering overlay children without obstructing them', () => {
    render(
      <ClosingPlasma>
        <button type="button">Action Button</button>
      </ClosingPlasma>
    )

    const btn = screen.getByRole('button', { name: 'Action Button' })
    expect(btn).toBeInTheDocument()
    fireEvent.click(btn)
  })

  it('3. Listens to window pointermove when interactive is enabled without blocking clicks', () => {
    const addEventListenerSpy = vi.spyOn(window, 'addEventListener')
    const { unmount } = render(<ClosingPlasma interactive />)

    expect(addEventListenerSpy).toHaveBeenCalledWith('pointermove', expect.any(Function), { passive: true })
    expect(addEventListenerSpy).toHaveBeenCalledWith('pointerleave', expect.any(Function), { passive: true })

    unmount()
  })

  it('4. ClosingPlasmaBackground renders fixed full-screen wrapper with z-index: 0 and zero pointer interference', () => {
    const { container } = render(<ClosingPlasmaBackground variant="landing" />)

    const wrapper = container.querySelector('.closing-plasma-background-wrapper')
    expect(wrapper).toBeInTheDocument()
    expect(wrapper).toHaveAttribute('aria-hidden', 'true')
    expect(wrapper).toHaveStyle({
      position: 'fixed',
      pointerEvents: 'none',
      zIndex: '0',
    })
  })

  it('5. Supports both landing and console variants with distinct configurations', () => {
    const { container: landingContainer } = render(<ClosingPlasmaBackground variant="landing" />)
    expect(landingContainer.querySelector('.closing-plasma-background-wrapper')).toBeInTheDocument()

    const { container: consoleContainer } = render(<ClosingPlasmaBackground variant="console" />)
    expect(consoleContainer.querySelector('.closing-plasma-background-wrapper')).toBeInTheDocument()
  })
})

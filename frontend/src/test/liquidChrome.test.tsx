import { render } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { LiquidChrome } from '../components/ui/LiquidChrome'
import { LiquidChromeBackground } from '../components/LiquidChromeBackground'

describe('LiquidChrome & LiquidChromeBackground Test Suite', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('1. LiquidChrome renders canvas element with pointer-events: none, touch-action: none, and aria-hidden', () => {
    const { container } = render(
      <LiquidChrome
        baseColor={[0.055, 0.055, 0.065]}
        speed={0.35}
        amplitude={0.42}
        interactive={true}
      />
    )

    const canvas = container.querySelector('canvas')
    expect(canvas).toBeInTheDocument()
    expect(canvas).toHaveAttribute('aria-hidden', 'true')
    expect(canvas).toHaveAttribute('tabindex', '-1')
    expect(canvas).toHaveStyle({ pointerEvents: 'none', touchAction: 'none' })
  })

  it('2. Listens to window mousemove for interaction without blocking foreground clicks', () => {
    const addEventListenerSpy = vi.spyOn(window, 'addEventListener')
    const { unmount } = render(<LiquidChrome interactive={true} />)

    expect(addEventListenerSpy).toHaveBeenCalledWith('mousemove', expect.any(Function), { passive: true })
    expect(addEventListenerSpy).toHaveBeenCalledWith('resize', expect.any(Function), { passive: true })

    unmount()
  })

  it('3. LiquidChromeBackground renders fixed full-viewport wrapper with z-index: 0 and zero pointer interference', () => {
    const { container } = render(<LiquidChromeBackground />)

    const wrapper = container.querySelector('.liquid-chrome-background-wrapper')
    expect(wrapper).toBeInTheDocument()
    expect(wrapper).toHaveAttribute('aria-hidden', 'true')
    expect(wrapper).toHaveStyle({
      position: 'fixed',
      pointerEvents: 'none',
      zIndex: '0',
    })

    // Ambient contrast veil is present to guarantee headline readability
    const veil = container.querySelector('.liquid-chrome-ambient-veil')
    expect(veil).toBeInTheDocument()
    expect(veil).toHaveStyle({ pointerEvents: 'none' })
  })

  it('4. Respects custom baseColor, speed, amplitude, and opacity configurations', () => {
    const { container } = render(
      <LiquidChromeBackground
        baseColor={[0.1, 0.1, 0.12]}
        speed={0.2}
        amplitude={0.3}
        opacity={0.5}
      />
    )

    const wrapper = container.querySelector('.liquid-chrome-background-wrapper')
    expect(wrapper).toBeInTheDocument()
    const inner = wrapper?.firstElementChild as HTMLElement
    expect(inner).toHaveStyle({ opacity: '0.5' })
  })

  it('5. Gracefully handles environments without WebGL context without throwing', () => {
    expect(() => {
      render(<LiquidChrome />)
    }).not.toThrow()
  })
})

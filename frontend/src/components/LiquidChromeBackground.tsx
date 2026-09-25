import { LiquidChrome } from './ui/LiquidChrome'

export interface LiquidChromeBackgroundProps {
  className?: string
  baseColor?: [number, number, number]
  speed?: number
  amplitude?: number
  interactive?: boolean
  opacity?: number
}

// Tuned restrained metallic dark palette for NexSolve
const DEFAULT_BASE_COLOR: [number, number, number] = [0.055, 0.055, 0.065]

export function LiquidChromeBackground({
  className = '',
  baseColor = DEFAULT_BASE_COLOR,
  speed = 0.35,
  amplitude = 0.42,
  interactive = true,
  opacity = 0.65,
}: LiquidChromeBackgroundProps) {
  return (
    <div
      className={`liquid-chrome-background-wrapper ${className}`.trim()}
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        width: '100vw',
        height: '100vh',
        pointerEvents: 'none',
        zIndex: 0,
        overflow: 'hidden',
        background: '#050505',
      }}
    >
      <div
        style={{
          width: '100%',
          height: '100%',
          opacity,
          pointerEvents: 'none',
        }}
      >
        <LiquidChrome
          baseColor={baseColor}
          speed={speed}
          amplitude={amplitude}
          interactive={interactive}
        />
      </div>

      {/* Subtle atmospheric vignette and contrast veil to ensure text readability */}
      <div
        className="liquid-chrome-ambient-veil"
        style={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          background:
            'radial-gradient(circle at 50% 25%, rgba(5, 5, 5, 0.25) 0%, rgba(5, 5, 5, 0.70) 70%, rgba(5, 5, 5, 0.95) 100%)',
        }}
      />
    </div>
  )
}

export default LiquidChromeBackground

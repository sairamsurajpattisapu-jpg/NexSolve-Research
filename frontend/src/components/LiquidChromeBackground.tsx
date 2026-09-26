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
  speed = 0.30,
  amplitude = 0.38,
  interactive = true,
  opacity = 0.28,
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
        background: '#0A0A0C',
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

      {/* Atmospheric veil ensuring text readability over canvas */}
      <div
        className="liquid-chrome-ambient-veil"
        style={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          background:
            'radial-gradient(circle at 50% 25%, rgba(10, 10, 12, 0.45) 0%, rgba(8, 9, 11, 0.75) 60%, rgba(8, 9, 11, 0.96) 100%)',
        }}
      />
    </div>
  )
}

export default LiquidChromeBackground

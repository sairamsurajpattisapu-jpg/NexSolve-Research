import { ClosingPlasma } from './ui/ClosingPlasma'

export interface ClosingPlasmaBackgroundProps {
  variant?: 'landing' | 'console'
  className?: string
  opacity?: number
}

// Tuned palette specifically for NexSolve: restrained monochrome grayscale with subtle midnight-slate atmosphere
const NEXSOLVE_DARK_PALETTE = {
  darkColorA: '#08080c', // Deep void pitch black
  darkColorB: '#131826', // Restrained midnight slate/indigo
  darkColorC: '#283754', // Atmospheric low-saturation technical slate blue
}

const NEXSOLVE_LIGHT_PALETTE = {
  lightColorA: '#f8fafc',
  lightColorB: '#e2e8f0',
  lightColorC: '#cbd5e1',
}

export function ClosingPlasmaBackground({
  variant = 'landing',
  className = '',
  opacity: customOpacity,
}: ClosingPlasmaBackgroundProps) {
  const isConsole = variant === 'console'

  // Restrained configuration tuned specifically for NexSolve readability
  const config = isConsole
    ? {
        speed: 0.2,
        turbulence: 0.45,
        mouseInfluence: 0.2,
        grain: 0.12,
        sparkle: 0.04,
        vignette: 0.88,
        opacity: customOpacity ?? 0.2,
        interactive: true,
      }
    : {
        speed: 0.35,
        turbulence: 0.55,
        mouseInfluence: 0.35,
        grain: 0.18,
        sparkle: 0.1,
        vignette: 0.75,
        opacity: customOpacity ?? 0.26,
        interactive: true,
      }

  return (
    <div
      className={`closing-plasma-background-wrapper ${className}`.trim()}
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        width: '100vw',
        height: '100vh',
        pointerEvents: 'none',
        zIndex: 0,
        overflow: 'hidden',
        background: 'transparent',
      }}
    >
      <ClosingPlasma
        speed={config.speed}
        turbulence={config.turbulence}
        mouseInfluence={config.mouseInfluence}
        grain={config.grain}
        sparkle={config.sparkle}
        vignette={config.vignette}
        opacity={config.opacity}
        interactive={config.interactive}
        darkColorA={NEXSOLVE_DARK_PALETTE.darkColorA}
        darkColorB={NEXSOLVE_DARK_PALETTE.darkColorB}
        darkColorC={NEXSOLVE_DARK_PALETTE.darkColorC}
        lightColorA={NEXSOLVE_LIGHT_PALETTE.lightColorA}
        lightColorB={NEXSOLVE_LIGHT_PALETTE.lightColorB}
        lightColorC={NEXSOLVE_LIGHT_PALETTE.lightColorC}
      />
    </div>
  )
}

export default ClosingPlasmaBackground

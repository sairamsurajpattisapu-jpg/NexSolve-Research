import { useCallback, useEffect, useRef } from 'react'
import { useTheme } from '../../hooks/useTheme'

/* ─────────────────────────────────────────────────────────────────────────────
 * NexSolveBackground — subtle canvas‑rendered blinking‑dot field
 *
 * Visual metaphor: a quiet abstraction of network telemetry —
 * dots represent entities/signals at rest, not real-time packets.
 *
 * • Single global instance (rendered once in the application shell)
 * • pointer‑events: none  — never intercepts UI interaction
 * • Respects prefers‑reduced‑motion
 * • Adapts to light/dark theme via CSS custom properties
 * ──────────────────────────────────────────────────────────────────────────── */

/* ── Configuration ───────────────────────────────────────────────────────── */

const DOT_SPACING = 36           // px between grid centres
const DOT_RADIUS = 0.9           // base radius
const SIZE_VARIATION = 0.2       // ± random variation on radius
const MAX_OPACITY = 0.14         // peak dot opacity (dark theme, ultra subtle)
const MAX_OPACITY_LIGHT = 0.08   // peak dot opacity (light theme)
const TWINKLE_SPEED = 0.0004     // radians per ms — very calm, slow pulse
const JITTER = 0.8               // max px random offset from grid
const PHASE_SPREAD = Math.PI * 2 // full‑circle phase randomisation
const VIGNETTE_STRENGTH = 0.7    // how aggressively edges fade out

/* Monochrome editorial palette (no cyan/teal/blue/purple) */
const DOT_COLORS_DARK = [
  { r: 255, g: 255, b: 255 },   // pure white
  { r: 220, g: 220, b: 220 },   // light gray
  { r: 160, g: 160, b: 160 },   // medium gray
]

const DOT_COLORS_LIGHT = [
  { r: 40,  g: 40,  b: 40  },   // dark neutral
  { r: 80,  g: 80,  b: 80  },   // mid neutral
  { r: 120, g: 120, b: 120 },   // light neutral
]

/* ── Types ───────────────────────────────────────────────────────────────── */

interface Dot {
  x: number
  y: number
  r: number
  phase: number
  colorIdx: number
}

/* ── Component ───────────────────────────────────────────────────────────── */

export function NexSolveBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const dotsRef = useRef<Dot[]>([])
  const animRef = useRef(0)
  const { isDark } = useTheme()

  /* Check prefers‑reduced‑motion once, on mount */
  const reducedMotion = useRef(
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
      : false,
  )

  /* Build dot grid for given canvas size */
  const buildGrid = useCallback((w: number, h: number) => {
    const dots: Dot[] = []
    const cols = Math.ceil(w / DOT_SPACING) + 1
    const rows = Math.ceil(h / DOT_SPACING) + 1

    for (let row = 0; row < rows; row++) {
      for (let col = 0; col < cols; col++) {
        dots.push({
          x: col * DOT_SPACING + (Math.random() - 0.5) * JITTER * 2,
          y: row * DOT_SPACING + (Math.random() - 0.5) * JITTER * 2,
          r: DOT_RADIUS + (Math.random() - 0.5) * SIZE_VARIATION * 2,
          phase: Math.random() * PHASE_SPREAD,
          colorIdx: Math.floor(Math.random() * DOT_COLORS_DARK.length),
        })
      }
    }
    dotsRef.current = dots
  }, [])

  /* Resize handler */
  const handleResize = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    const w = window.innerWidth
    const h = window.innerHeight
    canvas.width = w * dpr
    canvas.height = h * dpr
    canvas.style.width = `${w}px`
    canvas.style.height = `${h}px`
    buildGrid(w, h)
  }, [buildGrid])

  useEffect(() => {
    handleResize()
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [handleResize])

  /* Animation loop */
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d', { alpha: true })
    if (!ctx) return

    let lastTime = 0

    const draw = (time: number) => {
      const dt = time - lastTime
      lastTime = time

      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      const w = canvas.width / dpr
      const h = canvas.height / dpr

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, w, h)

      const palette = isDark ? DOT_COLORS_DARK : DOT_COLORS_LIGHT
      const peakOpacity = isDark ? MAX_OPACITY : MAX_OPACITY_LIGHT
      const cx = w / 2
      const cy = h / 2
      const maxDist = Math.sqrt(cx * cx + cy * cy)

      for (const dot of dotsRef.current) {
        /* Twinkle: sinusoidal oscillation */
        let alpha: number
        if (reducedMotion.current) {
          // Static dots at half-brightness when reduced motion
          alpha = peakOpacity * 0.5
        } else {
          dot.phase += TWINKLE_SPEED * dt
          alpha = ((Math.sin(dot.phase) + 1) / 2) * peakOpacity
        }

        /* Vignette: fade dots towards edges */
        const dx = dot.x - cx
        const dy = dot.y - cy
        const dist = Math.sqrt(dx * dx + dy * dy)
        const vignette = 1 - (dist / maxDist) * VIGNETTE_STRENGTH
        alpha *= Math.max(0, vignette)

        if (alpha < 0.005) continue // skip invisible dots

        const c = palette[dot.colorIdx]
        ctx.fillStyle = `rgba(${c.r},${c.g},${c.b},${alpha.toFixed(3)})`
        ctx.beginPath()
        ctx.arc(dot.x, dot.y, dot.r, 0, Math.PI * 2)
        ctx.fill()
      }

      animRef.current = requestAnimationFrame(draw)
    }

    animRef.current = requestAnimationFrame(draw)

    return () => {
      cancelAnimationFrame(animRef.current)
    }
  }, [isDark])

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: -1,
        pointerEvents: 'none',
        width: '100%',
        height: '100%',
      }}
    />
  )
}

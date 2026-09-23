import { useCallback, useEffect, useRef } from 'react'
import { useTheme } from '../../hooks/useTheme'

/* ─────────────────────────────────────────────────────────────────────────────
 * NexSolveBackground — Continuous Full-Viewport Cyber Circuit Environment
 *
 * Visual characteristics (matching reference):
 * • Pitch dark/black void background (#030305 / #050508)
 * • Architectural parallel circuit trace bundles (2-3 parallel tracks)
 * • Strict 45-degree routing angles and orthogonal bus corridors
 * • Precision solder vias (inner drill pad + outer concentric annular ring)
 * • Subtle connection density with generous negative space
 * • Restrained monochrome grayscale (silver/white, 0.07 - 0.12 opacity)
 * • Understated Gaussian glow on traveling signals and terminal nodes
 * • Full viewport coverage behind all application content (pointer-events: none)
 * ──────────────────────────────────────────────────────────────────────────── */

interface Point {
  x: number
  y: number
}

interface CircuitTrace {
  points: Point[]
  width: number
  isPrimary: boolean
}

interface SolderVia {
  x: number
  y: number
  outerRadius: number
  innerRadius: number
  phase: number
}

interface CircuitPulse {
  traceIdx: number
  progress: number // 0 to 1
  speed: number
  length: number
}

export function NexSolveBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const tracesRef = useRef<CircuitTrace[]>([])
  const viasRef = useRef<SolderVia[]>([])
  const pulsesRef = useRef<CircuitPulse[]>([])
  const animRef = useRef<number>(0)
  const { isDark } = useTheme()

  const reducedMotion = useRef(
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
      : false
  )

  const buildCircuitEnvironment = useCallback((w: number, h: number) => {
    const traces: CircuitTrace[] = []
    const vias: SolderVia[] = []
    const pulses: CircuitPulse[] = []

    // Major horizontal bus corridors
    const corridorSpacing = 160
    const numCorridors = Math.ceil(h / corridorSpacing) + 1

    for (let c = 0; c < numCorridors; c++) {
      const corridorY = c * corridorSpacing + 40 + ((c % 2 === 0 ? 1 : -1) * 20)
      const bundleSize = 2 + (c % 2) // 2 or 3 parallel tracks per bundle
      const bundleGap = 14 // uniform distance between parallel tracks

      // Common anchor points for the bundle to maintain parallel alignment
      const numSegments = 3 + Math.floor(w / 400)
      const segmentWidth = w / numSegments

      const bendPoints: { x: number; dy: number }[] = []
      for (let s = 1; s < numSegments; s++) {
        const bx = s * segmentWidth + (Math.random() - 0.5) * 80
        // 45-degree angle offset (dx = |dy|)
        const dy = (Math.random() > 0.45 ? 1 : -1) * (24 + Math.floor(Math.random() * 2) * 16)
        bendPoints.push({ x: bx, dy })
      }

      // Generate each parallel trace in the bundle
      for (let b = 0; b < bundleSize; b++) {
        const offsetY = b * bundleGap
        let currentX = 0
        let currentY = corridorY + offsetY
        const pts: Point[] = [{ x: currentX, y: currentY }]

        // Starting solder via
        vias.push({
          x: 16,
          y: currentY,
          outerRadius: 3.8,
          innerRadius: 1.8,
          phase: Math.random() * Math.PI * 2,
        })

        for (const bend of bendPoints) {
          if (bend.x > currentX + 30) {
            pts.push({ x: bend.x, y: currentY })

            // 45-degree bend
            const dx = Math.abs(bend.dy)
            const nextX = bend.x + dx
            const nextY = currentY + bend.dy
            pts.push({ x: nextX, y: nextY })

            // Junction via at bend corner
            if (b === 0 || b === bundleSize - 1) {
              vias.push({
                x: nextX,
                y: nextY,
                outerRadius: 3.6,
                innerRadius: 1.6,
                phase: Math.random() * Math.PI * 2,
              })
            }

            currentX = nextX
            currentY = nextY
          }
        }

        // Complete track to right boundary
        pts.push({ x: w, y: currentY })

        // Ending solder via
        vias.push({
          x: w - 16,
          y: currentY,
          outerRadius: 3.8,
          innerRadius: 1.8,
          phase: Math.random() * Math.PI * 2,
        })

        traces.push({
          points: pts,
          width: 0.85,
          isPrimary: b === 0,
        })
      }
    }

    // Vertical & 45-degree cross-connectors between corridors
    const numVerticals = Math.ceil(w / 280)
    for (let v = 0; v < numVerticals; v++) {
      const vx = v * 280 + 120 + (Math.random() - 0.5) * 60
      const startY = 60 + Math.random() * (h * 0.3)
      const length = 180 + Math.random() * 240
      const endY = Math.min(h - 40, startY + length)

      // Vertical connector with 45-degree entry
      const pts: Point[] = [
        { x: vx, y: startY },
        { x: vx, y: startY + length * 0.6 },
        { x: vx + 24, y: startY + length * 0.6 + 24 }, // 45-degree jog
        { x: vx + 24, y: endY },
      ]

      traces.push({
        points: pts,
        width: 0.75,
        isPrimary: false,
      })

      vias.push({
        x: vx,
        y: startY,
        outerRadius: 4.0,
        innerRadius: 1.8,
        phase: Math.random() * Math.PI * 2,
      })
      vias.push({
        x: vx + 24,
        y: endY,
        outerRadius: 4.0,
        innerRadius: 1.8,
        phase: Math.random() * Math.PI * 2,
      })
    }

    // Traveling signal pulses along bus tracks
    if (!reducedMotion.current) {
      const pulseCount = Math.min(9, Math.max(4, Math.floor(traces.length / 3)))
      for (let i = 0; i < pulseCount; i++) {
        pulses.push({
          traceIdx: Math.floor(Math.random() * traces.length),
          progress: Math.random(),
          speed: 0.00007 + Math.random() * 0.00010,
          length: 0.06 + Math.random() * 0.06,
        })
      }
    }

    tracesRef.current = traces
    viasRef.current = vias
    pulsesRef.current = pulses
  }, [])

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
    buildCircuitEnvironment(w, h)
  }, [buildCircuitEnvironment])

  useEffect(() => {
    handleResize()
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [handleResize])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d', { alpha: true })
    if (!ctx) return // In test environments (jsdom)

    let lastTime = 0

    const render = (time: number) => {
      const dt = lastTime ? Math.min(100, time - lastTime) : 16
      lastTime = time

      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      const w = canvas.width / dpr
      const h = canvas.height / dpr

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, w, h)

      // Visual color palette matching reference grayscale character
      const baseTraceColor = isDark ? 'rgba(255, 255, 255, 0.065)' : 'rgba(0, 0, 0, 0.045)'
      const primaryTraceColor = isDark ? 'rgba(255, 255, 255, 0.095)' : 'rgba(0, 0, 0, 0.07)'
      const outerRingColor = isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.05)'
      const innerPadColor = isDark ? 'rgba(255, 255, 255, 0.16)' : 'rgba(0, 0, 0, 0.10)'
      const pulseColor = isDark ? 'rgba(255, 255, 255, 0.40)' : 'rgba(0, 0, 0, 0.25)'

      // 1. Draw circuit trace lines
      ctx.lineCap = 'round'
      ctx.lineJoin = 'round'

      for (const t of tracesRef.current) {
        if (t.points.length < 2) continue
        ctx.strokeStyle = t.isPrimary ? primaryTraceColor : baseTraceColor
        ctx.lineWidth = t.width
        ctx.beginPath()
        ctx.moveTo(t.points[0].x, t.points[0].y)
        for (let i = 1; i < t.points.length; i++) {
          ctx.lineTo(t.points[i].x, t.points[i].y)
        }
        ctx.stroke()
      }

      // 2. Draw solder vias (annular rings + solid inner core pads)
      for (const v of viasRef.current) {
        // Outer concentric annular ring
        ctx.strokeStyle = outerRingColor
        ctx.lineWidth = 0.75
        ctx.beginPath()
        ctx.arc(v.x, v.y, v.outerRadius, 0, Math.PI * 2)
        ctx.stroke()

        // Inner core pad with subtle breathing
        let alpha = 1
        if (!reducedMotion.current) {
          v.phase += 0.0007 * dt
          alpha = 0.7 + Math.sin(v.phase) * 0.3
        }

        ctx.fillStyle = innerPadColor
        ctx.globalAlpha = alpha
        ctx.beginPath()
        ctx.arc(v.x, v.y, v.innerRadius, 0, Math.PI * 2)
        ctx.fill()
        ctx.globalAlpha = 1
      }

      // 3. Draw traveling signal pulses with understated Gaussian glow
      if (!reducedMotion.current && tracesRef.current.length > 0) {
        ctx.lineWidth = 1.3
        ctx.strokeStyle = pulseColor
        ctx.shadowBlur = 5
        ctx.shadowColor = isDark ? 'rgba(255, 255, 255, 0.35)' : 'rgba(0, 0, 0, 0.2)'

        for (const pulse of pulsesRef.current) {
          pulse.progress += pulse.speed * dt
          if (pulse.progress > 1) {
            pulse.progress = 0
            pulse.traceIdx = Math.floor(Math.random() * tracesRef.current.length)
          }

          const trace = tracesRef.current[pulse.traceIdx]
          if (!trace || trace.points.length < 2) continue

          const totalPoints = trace.points.length
          const segFloat = pulse.progress * (totalPoints - 1)
          const segIdx = Math.min(totalPoints - 2, Math.floor(segFloat))
          const segFrac = segFloat - segIdx

          const p1 = trace.points[segIdx]
          const p2 = trace.points[segIdx + 1]

          const px = p1.x + (p2.x - p1.x) * segFrac
          const py = p1.y + (p2.y - p1.y) * segFrac

          const tailLen = pulse.length * 36
          const dx = p2.x - p1.x
          const dy = p2.y - p1.y
          const len = Math.hypot(dx, dy) || 1
          const ux = dx / len
          const uy = dy / len

          ctx.beginPath()
          ctx.moveTo(px - ux * tailLen, py - uy * tailLen)
          ctx.lineTo(px, py)
          ctx.stroke()
        }

        ctx.shadowBlur = 0
      }

      animRef.current = requestAnimationFrame(render)
    }

    animRef.current = requestAnimationFrame(render)

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
        width: '100vw',
        height: '100vh',
        pointerEvents: 'none',
        zIndex: 0,
        background: isDark ? '#030305' : '#ffffff',
      }}
    />
  )
}

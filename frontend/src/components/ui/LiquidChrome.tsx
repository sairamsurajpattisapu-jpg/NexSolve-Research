import { useEffect, useRef } from 'react'

export interface LiquidChromeProps {
  /** Additional CSS classes for custom styling */
  className?: string
  /** Base color tint for the chrome. Default is restrained monochrome graphite. */
  baseColor?: [number, number, number]
  /** Animation speed multiplier. Default is 0.35 */
  speed?: number
  /** Detail level of the fluid waves. Default is 0.42 */
  amplitude?: number
  /** Enables mouse interaction if true */
  interactive?: boolean
  /** Inline styles */
  style?: React.CSSProperties
}

const vertexShaderSource = `
  attribute vec2 position;
  void main() {
    gl_Position = vec4(position, 0.0, 1.0);
  }
`

const fragmentShaderSource = `
  precision highp float;

  uniform vec2 u_resolution;
  uniform float u_time;
  uniform vec2 u_mouse;
  uniform vec3 u_baseColor;
  uniform float u_amplitude;

  // Simple 2D noise
  const mat2 m = mat2( 0.80,  0.60, -0.60,  0.80 );

  float hash( vec2 p ) {
      float h = dot(p,vec2(127.1,311.7));
      return fract(sin(h)*43758.5453123);
  }

  float noise( in vec2 p ) {
      vec2 i = floor( p );
      vec2 f = fract( p );
      vec2 u = f*f*(3.0-2.0*f);
      return mix( mix( hash( i + vec2(0.0,0.0) ), 
                       hash( i + vec2(1.0,0.0) ), u.x),
                  mix( hash( i + vec2(0.0,1.0) ), 
                       hash( i + vec2(1.0,1.0) ), u.x), u.y);
  }

  float fbm( vec2 p ) {
      float f = 0.0;
      f += 0.5000*noise( p ); p = m*p*2.02;
      f += 0.2500*noise( p ); p = m*p*2.03;
      f += 0.1250*noise( p ); p = m*p*2.01;
      f += 0.0625*noise( p );
      return f/0.9375;
  }

  void main() {
    vec2 uv = gl_FragCoord.xy / u_resolution.xy;
    vec2 p = -1.0 + 2.0 * uv;
    if (u_resolution.y > 0.0) {
        p.x *= u_resolution.x / u_resolution.y;
    }

    // Mouse interaction
    vec2 mouse = (u_mouse - 0.5) * 2.0;
    if (u_resolution.y > 0.0) {
        mouse.x *= u_resolution.x / u_resolution.y;
    }
    
    // Distort based on distance to mouse
    vec2 diff = p - mouse;
    float dist = length(diff);
    vec2 distortion = vec2(0.0);
    if (dist > 0.0) {
        distortion = (diff / dist) * exp(-dist * 3.0) * 0.1;
    }
    p += distortion;

    float time = u_time * 0.5;

    // Domain warping
    vec2 q = vec2(0.0);
    q.x = fbm(p + vec2(0.0, 0.0) + time * 0.1);
    q.y = fbm(p + vec2(5.2, 1.3) + time * 0.15);

    vec2 r = vec2(0.0);
    r.x = fbm(p + 4.0 * q + vec2(1.7, 9.2) + time * 0.2);
    r.y = fbm(p + 4.0 * q + vec2(8.3, 2.8) + time * 0.25);

    float f = fbm(p + r * 4.0 * u_amplitude);

    // Color mixing (Chrome / Liquid Metal style)
    vec3 col = u_baseColor;
    
    // Add bright highlights based on the warped noise
    float highlight = smoothstep(0.4, 0.6, f);
    float highlight2 = smoothstep(0.6, 0.8, f);
    float dark = smoothstep(0.1, 0.3, f);
    
    col = mix(col, vec3(0.0), 1.0 - dark); // add shadows
    col = mix(col, vec3(0.8, 0.8, 0.9), highlight); // add silver midtones
    col = mix(col, vec3(1.0, 1.0, 1.0), highlight2); // add bright white specular
    
    // Vignette
    float v = 16.0 * uv.x * uv.y * (1.0 - uv.x) * (1.0 - uv.y);
    col *= 0.5 + 0.5 * pow(max(0.0, v), 0.2);

    gl_FragColor = vec4(col, 1.0);
  }
`

export function LiquidChrome({
  className = '',
  baseColor = [0.055, 0.055, 0.065],
  speed = 0.35,
  amplitude = 0.42,
  interactive = true,
  style,
}: LiquidChromeProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const colorRef = useRef(baseColor)
  colorRef.current = baseColor
  const speedRef = useRef(speed)
  speedRef.current = speed
  const amplitudeRef = useRef(amplitude)
  amplitudeRef.current = amplitude
  const interactiveRef = useRef(interactive)
  interactiveRef.current = interactive

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const isReducedMotion =
      typeof window !== 'undefined' && typeof window.matchMedia === 'function'
        ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
        : false

    const mouse: [number, number] = [0.5, 0.5]
    let animationFrameId = 0
    let resolutionLocation: WebGLUniformLocation | null = null
    const startTime = performance.now()

    const handleMouseMove = (e: MouseEvent) => {
      if (!interactiveRef.current || isReducedMotion) return
      const rect = canvas.getBoundingClientRect()
      if (rect.width > 0 && rect.height > 0) {
        mouse[0] = (e.clientX - rect.left) / rect.width
        mouse[1] = 1.0 - (e.clientY - rect.top) / rect.height
      }
    }

    const resize = () => {
      if (!canvas) return
      const rect = canvas.getBoundingClientRect()
      const dpr = Math.min(window.devicePixelRatio || 1, 1.75)
      canvas.width = Math.max(1, Math.floor(rect.width * dpr))
      canvas.height = Math.max(1, Math.floor(rect.height * dpr))
      if (gl) {
        gl.viewport(0, 0, canvas.width, canvas.height)
        if (resolutionLocation) {
          gl.uniform2f(resolutionLocation, canvas.width, canvas.height)
        }
      }
    }

    window.addEventListener('resize', resize, { passive: true })
    window.addEventListener('mousemove', handleMouseMove, { passive: true })

    const gl = canvas.getContext('webgl', { antialias: false, alpha: false })
    if (!gl) {
      // In non-WebGL environments (e.g. headless jsdom test suites), fail gracefully
      return () => {
        window.removeEventListener('resize', resize)
        window.removeEventListener('mousemove', handleMouseMove)
      }
    }

    const compileShader = (type: number, source: string) => {
      const shader = gl.createShader(type)
      if (!shader) return null
      gl.shaderSource(shader, source)
      gl.compileShader(shader)
      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        gl.deleteShader(shader)
        return null
      }
      return shader
    }

    const vertexShader = compileShader(gl.VERTEX_SHADER, vertexShaderSource)
    const fragmentShader = compileShader(gl.FRAGMENT_SHADER, fragmentShaderSource)
    if (!vertexShader || !fragmentShader) {
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', handleMouseMove)
      return
    }

    const program = gl.createProgram()
    if (!program) {
      gl.deleteShader(vertexShader)
      gl.deleteShader(fragmentShader)
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', handleMouseMove)
      return
    }

    gl.attachShader(program, vertexShader)
    gl.attachShader(program, fragmentShader)
    gl.linkProgram(program)
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      gl.deleteProgram(program)
      gl.deleteShader(vertexShader)
      gl.deleteShader(fragmentShader)
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', handleMouseMove)
      return
    }
    gl.useProgram(program)

    const positionBuffer = gl.createBuffer()
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer)
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]),
      gl.STATIC_DRAW
    )

    const positionLocation = gl.getAttribLocation(program, 'position')
    gl.enableVertexAttribArray(positionLocation)
    gl.vertexAttribPointer(positionLocation, 2, gl.FLOAT, false, 0, 0)

    resolutionLocation = gl.getUniformLocation(program, 'u_resolution')
    const timeLocation = gl.getUniformLocation(program, 'u_time')
    const mouseLocation = gl.getUniformLocation(program, 'u_mouse')
    const baseColorLocation = gl.getUniformLocation(program, 'u_baseColor')
    const amplitudeLocation = gl.getUniformLocation(program, 'u_amplitude')

    resize()

    const render = (time: number) => {
      const effectiveSpeed = isReducedMotion ? 0 : speedRef.current
      const elapsedTime = (time - startTime) * 0.001 * effectiveSpeed

      if (timeLocation) gl.uniform1f(timeLocation, elapsedTime)
      if (mouseLocation) gl.uniform2f(mouseLocation, mouse[0], mouse[1])
      if (baseColorLocation) {
        gl.uniform3f(
          baseColorLocation,
          colorRef.current[0],
          colorRef.current[1],
          colorRef.current[2]
        )
      }
      if (amplitudeLocation) {
        gl.uniform1f(amplitudeLocation, amplitudeRef.current)
      }

      gl.drawArrays(gl.TRIANGLES, 0, 6)

      if (!isReducedMotion) {
        animationFrameId = requestAnimationFrame(render)
      }
    }

    if (isReducedMotion) {
      render(startTime)
    } else {
      animationFrameId = requestAnimationFrame(render)
    }

    return () => {
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', handleMouseMove)
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId)
      }
      gl.deleteBuffer(positionBuffer)
      gl.deleteProgram(program)
      gl.deleteShader(vertexShader)
      gl.deleteShader(fragmentShader)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      tabIndex={-1}
      className={`liquid-chrome-canvas ${className}`.trim()}
      style={{
        display: 'block',
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        touchAction: 'none',
        ...style,
      }}
    />
  )
}

export default LiquidChrome

import { describe, expect, it } from 'vitest'
import { calculateEta, formatDuration, formatElapsedDuration, formatEtaDuration } from '../utils/etaEstimator'

describe('etaEstimator', () => {
  describe('formatElapsedDuration', () => {
    it('formats elapsed duration cleanly matching section 5 specification', () => {
      expect(formatElapsedDuration(10)).toBe('10s')
      expect(formatElapsedDuration(84)).toBe('1m 24s')
      expect(formatElapsedDuration(248)).toBe('4m 08s')
      expect(formatElapsedDuration(0)).toBe('0s')
    })

    it('guards against negative, NaN, and Infinity', () => {
      expect(formatElapsedDuration(-5)).toBe('0s')
      expect(formatElapsedDuration(NaN)).toBe('0s')
      expect(formatElapsedDuration(Infinity)).toBe('0s')
    })
  })

  describe('formatEtaDuration', () => {
    it('formats ETA durations with tilde and colon notation for minutes', () => {
      expect(formatEtaDuration(45)).toBe('~45s')
      expect(formatEtaDuration(130)).toBe('~02:10')
      expect(formatEtaDuration(3)).toBe('< 5s')
      expect(formatEtaDuration(0)).toBe('0s')
    })
  })

  describe('formatDuration', () => {
    it('formats seconds correctly', () => {
      expect(formatDuration(0)).toBe('0s')
      expect(formatDuration(45)).toBe('45s')
      expect(formatDuration(59)).toBe('59s')
      expect(formatDuration(60)).toBe('1m')
      expect(formatDuration(75)).toBe('1m 15s')
      expect(formatDuration(120)).toBe('2m')
      expect(formatDuration(125)).toBe('2m 5s')
    })

    it('handles negative, NaN, and Infinity safely', () => {
      expect(formatDuration(-10)).toBe('0s')
      expect(formatDuration(NaN)).toBe('0s')
      expect(formatDuration(Infinity)).toBe('0s')
    })
  })

    // Required 12 test specifications from user prompt
    it('Case 1: No progress -> Calculating...', () => {
      expect(calculateEta({ elapsedSeconds: 10, progress: 0 })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
    })

    it('Case 2: Very low progress -> Calculating...', () => {
      expect(calculateEta({ elapsedSeconds: 10, progress: 0.02 })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
    })

    it('Case 3: Real 50% progress after 10 seconds -> 10s remaining (~10s)', () => {
      const res = calculateEta({ elapsedSeconds: 10, progress: 0.5 })
      expect(res.remainingSeconds).toBe(10)
      expect(res.formattedEta).toBe('~10s')
      expect(res.isCalculating).toBe(false)
    })

    it('Case 4: 50% after 130 seconds -> ~02:10', () => {
      const res = calculateEta({ elapsedSeconds: 130, progress: 0.5 })
      expect(res.remainingSeconds).toBe(130)
      expect(res.formattedEta).toBe('~02:10')
      expect(res.isCalculating).toBe(false)
    })

    it('Case 5: Completed -> 0s', () => {
      expect(calculateEta({ elapsedSeconds: 15, progress: 1.0, status: 'COMPLETED' })).toEqual({
        remainingSeconds: 0,
        formattedEta: '0s',
        isCalculating: false,
      })
    })

    it('Case 6: Failed -> --', () => {
      expect(calculateEta({ elapsedSeconds: 15, progress: 0.5, status: 'FAILED' })).toEqual({
        remainingSeconds: null,
        formattedEta: '--',
        isCalculating: false,
      })
      expect(calculateEta({ elapsedSeconds: 15, progress: 0.5, status: 'RESOURCE_LIMIT_EXCEEDED' })).toEqual({
        remainingSeconds: null,
        formattedEta: '--',
        isCalculating: false,
      })
    })

    it('Case 7: Negative elapsed -> safe (Calculating...)', () => {
      expect(calculateEta({ elapsedSeconds: -5, progress: 0.5 })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
    })

    it('Case 8: NaN -> safe (Calculating...)', () => {
      expect(calculateEta({ elapsedSeconds: NaN, progress: 0.5 })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
      expect(calculateEta({ elapsedSeconds: 10, progress: NaN })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
    })

    it('Case 9: Infinity -> safe', () => {
      expect(calculateEta({ elapsedSeconds: Infinity, progress: 0.5 })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
    })

    it('Case 10: No measurable telemetry -> Calculating...', () => {
      expect(calculateEta({ elapsedSeconds: 15 })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
      expect(calculateEta({ elapsedSeconds: 15, packetsProcessed: 0, totalPackets: 0 })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
    })

    it('Case 11: No stage-weighted fallback (never fabricates ETA from stage name)', () => {
      // Even in late stages like FORECAST or EVIDENCE, zero progress must return Calculating...
      expect(calculateEta({ elapsedSeconds: 20, stage: 'FORECAST', progress: 0 })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
      expect(calculateEta({ elapsedSeconds: 30, stage: 'EVIDENCE', progress: 0 })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
      expect(calculateEta({ elapsedSeconds: 5, stage: 'NETWORK_STATE', progress: 0 })).toEqual({
        remainingSeconds: null,
        formattedEta: 'Calculating...',
        isCalculating: true,
      })
    })

    it('Case 12: ETA never becomes negative', () => {
      const res = calculateEta({ elapsedSeconds: 10, progress: 0.999 })
      expect(res.remainingSeconds).toBeGreaterThanOrEqual(0)
      expect(res.isCalculating).toBe(false)
    })

    it('calculates ETA from actual packet telemetry (packetsProcessed / totalPackets)', () => {
      // 12,000,000 / 20,000,000 = 60% in 15 seconds -> remaining 10s
      const res = calculateEta({
        elapsedSeconds: 15,
        packetsProcessed: 12000000,
        totalPackets: 20000000,
      })
      expect(res.remainingSeconds).toBe(10)
      expect(res.formattedEta).toBe('~10s')
      expect(res.isCalculating).toBe(false)
    })

    it('uses authoritative backendEtaSeconds when provided', () => {
      const res = calculateEta({
        elapsedSeconds: 5,
        backendEtaSeconds: 45,
      })
      expect(res.remainingSeconds).toBe(45)
      expect(res.formattedEta).toBe('~45s')
      expect(res.isCalculating).toBe(false)
    })
})

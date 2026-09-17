/**
 * Deterministic ETA Estimator for NexSolve PCAP Processing Pipeline.
 *
 * Computes remaining execution time based on observed elapsed duration and deterministic stage progress.
 * Guarantees that ETA values are never negative, NaN, or Infinity.
 * Returns 'Calculating...' when insufficient observations are available.
 */

export interface EtaCalculationParams {
  elapsedSeconds: number
  progress?: number // normalized 0.0 to 1.0 (or 0 to 100 if passed as integer percentage)
  stage?: string // (optional context, NEVER used to fabricate or stage-weight ETA)
  status?: string
  backendEtaSeconds?: number | null
  packetsProcessed?: number | null
  totalPackets?: number | null
  windowsProcessed?: number | null
  totalWindows?: number | null
  bytesProcessed?: number | null
  totalBytes?: number | null
}

export interface EtaCalculationResult {
  remainingSeconds: number | null
  formattedEta: string
  isCalculating: boolean
}

/**
 * Format elapsed duration into clean string: "10s", "1m 24s", "4m 08s".
 * Never includes milliseconds.
 */
export function formatElapsedDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || Number.isNaN(seconds) || seconds < 0) {
    return '0s'
  }
  const total = Math.max(0, Math.floor(seconds))
  if (total < 60) {
    return `${total}s`
  }
  const mins = Math.floor(total / 60)
  const secs = total % 60
  return `${mins}m ${secs < 10 ? '0' : ''}${secs}s`
}

/**
 * Format remaining ETA duration: "< 5s", "~45s", "~02:10".
 */
export function formatEtaDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || Number.isNaN(seconds) || seconds < 0) {
    return '0s'
  }
  const total = Math.max(0, Math.round(seconds))
  if (total === 0) {
    return '0s'
  }
  if (total < 5) {
    return '< 5s'
  }
  if (total < 60) {
    return `~${total}s`
  }
  const mins = Math.floor(total / 60)
  const secs = total % 60
  return `~${mins < 10 ? '0' : ''}${mins}:${secs < 10 ? '0' : ''}${secs}`
}

/**
 * Format a positive number of seconds into human-readable duration string (e.g., "45s", "1m 15s").
 */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || Number.isNaN(seconds) || seconds < 0) {
    return '0s'
  }
  const total = Math.max(0, Math.round(seconds))
  if (total < 60) {
    return `${total}s`
  }
  const mins = Math.floor(total / 60)
  const remainingSecs = total % 60
  return remainingSecs > 0 ? `${mins}m ${remainingSecs}s` : `${mins}m`
}

/**
 * Calculates remaining processing time safely and strictly from real measurable telemetry.
 *
 * ALLOWED SOURCES:
 * 1. backend-provided ETA (backendEtaSeconds)
 * 2. actual packets processed / total packets
 * 3. actual bytes processed / total bytes
 * 4. actual windows processed / total windows
 * 5. actual progress fraction + elapsed time
 *
 * PROHIBITED:
 * - NO stage number weighting
 * - NO assumed stage complexity
 * - NO hardcoded stage durations
 * - NO arbitrary percentages
 * - NO fake countdowns
 */
export function calculateEta({
  elapsedSeconds,
  progress = 0,
  status,
  backendEtaSeconds,
  packetsProcessed,
  totalPackets,
  windowsProcessed,
  totalWindows,
  bytesProcessed,
  totalBytes,
}: EtaCalculationParams): EtaCalculationResult {
  // 1. Completed status
  if (status === 'COMPLETED' || (progress !== undefined && (progress >= 1.0 || progress >= 100))) {
    return {
      remainingSeconds: 0,
      formattedEta: '0s',
      isCalculating: false,
    }
  }

  // 2. Terminal failure or cancelled status
  if (
    status === 'FAILED' ||
    status === 'RESOURCE_LIMIT_EXCEEDED' ||
    status === 'ABORTED' ||
    status === 'CANCELLED'
  ) {
    return {
      remainingSeconds: null,
      formattedEta: '--',
      isCalculating: false,
    }
  }

  // 3. Backend-provided authoritative ETA
  if (
    backendEtaSeconds !== undefined &&
    backendEtaSeconds !== null &&
    Number.isFinite(backendEtaSeconds) &&
    !Number.isNaN(backendEtaSeconds) &&
    backendEtaSeconds >= 0
  ) {
    const rounded = Math.max(0, Math.round(backendEtaSeconds))
    return {
      remainingSeconds: rounded,
      formattedEta: formatEtaDuration(rounded),
      isCalculating: false,
    }
  }

  // 4. Guard against invalid or non-positive elapsed time
  if (
    !Number.isFinite(elapsedSeconds) ||
    Number.isNaN(elapsedSeconds) ||
    elapsedSeconds < 2
  ) {
    return {
      remainingSeconds: null,
      formattedEta: 'Calculating...',
      isCalculating: true,
    }
  }

  // 5. Derive objectively measurable progress fraction
  let measurableFraction: number | null = null

  if (
    packetsProcessed !== undefined &&
    packetsProcessed !== null &&
    totalPackets !== undefined &&
    totalPackets !== null &&
    totalPackets > 0 &&
    packetsProcessed > 0
  ) {
    measurableFraction = Math.min(1.0, Math.max(0, packetsProcessed / totalPackets))
  } else if (
    bytesProcessed !== undefined &&
    bytesProcessed !== null &&
    totalBytes !== undefined &&
    totalBytes !== null &&
    totalBytes > 0 &&
    bytesProcessed > 0
  ) {
    measurableFraction = Math.min(1.0, Math.max(0, bytesProcessed / totalBytes))
  } else if (
    windowsProcessed !== undefined &&
    windowsProcessed !== null &&
    totalWindows !== undefined &&
    totalWindows !== null &&
    totalWindows > 0 &&
    windowsProcessed > 0
  ) {
    measurableFraction = Math.min(1.0, Math.max(0, windowsProcessed / totalWindows))
  } else if (progress !== undefined && progress !== null && progress > 0) {
    const norm = progress > 1 ? progress / 100 : progress
    if (norm > 0) {
      measurableFraction = Math.min(1.0, Math.max(0, norm))
    }
  }

  // 6. If no measurable telemetry fraction or very low progress (< 5%), return Calculating...
  if (
    measurableFraction === null ||
    !Number.isFinite(measurableFraction) ||
    Number.isNaN(measurableFraction) ||
    measurableFraction < 0.05
  ) {
    return {
      remainingSeconds: null,
      formattedEta: 'Calculating...',
      isCalculating: true,
    }
  }

  // 7. Rate-based linear kinematics: elapsed / fraction = total expected duration
  const totalEstimatedSeconds = elapsedSeconds / measurableFraction
  const remaining = totalEstimatedSeconds - elapsedSeconds

  // 8. Numerical safety guards
  if (
    !Number.isFinite(remaining) ||
    Number.isNaN(remaining) ||
    remaining < 0
  ) {
    return {
      remainingSeconds: null,
      formattedEta: 'Calculating...',
      isCalculating: true,
    }
  }

  const roundedSeconds = Math.max(0, Math.round(remaining))

  if (roundedSeconds === 0) {
    return {
      remainingSeconds: 0,
      formattedEta: '< 5s',
      isCalculating: false,
    }
  }

  return {
    remainingSeconds: roundedSeconds,
    formattedEta: formatEtaDuration(roundedSeconds),
    isCalculating: false,
  }
}

export type ProductServiceState =
  | 'READY'
  | 'ANALYZING'
  | 'RESULT_READY'
  | 'RECONNECTING'
  | 'TEMPORARILY_UNAVAILABLE'
  | 'ERROR'

export interface ServiceStateDefinition {
  state: ProductServiceState
  label: string
  description: string
  tone: 'success' | 'warning' | 'accent' | 'muted' | 'danger'
}

export const PRODUCT_SERVICE_STATES: Record<ProductServiceState, ServiceStateDefinition> = {
  READY: {
    state: 'READY',
    label: 'READY',
    description: 'Ready for analysis',
    tone: 'success',
  },
  ANALYZING: {
    state: 'ANALYZING',
    label: 'ANALYZING',
    description: 'Analyzing network telemetry',
    tone: 'warning',
  },
  RESULT_READY: {
    state: 'RESULT_READY',
    label: 'RESULT READY',
    description: 'Result ready',
    tone: 'accent',
  },
  RECONNECTING: {
    state: 'RECONNECTING',
    label: 'RECONNECTING',
    description: 'Reconnecting securely…',
    tone: 'warning',
  },
  TEMPORARILY_UNAVAILABLE: {
    state: 'TEMPORARILY_UNAVAILABLE',
    label: 'TEMPORARILY UNAVAILABLE',
    description: 'Analysis service temporarily unavailable',
    tone: 'muted',
  },
  ERROR: {
    state: 'ERROR',
    label: 'ERROR',
    description: 'Analysis could not be completed',
    tone: 'danger',
  },
}

export function getServiceStateInfo(status: string, isReconnecting = false): ServiceStateDefinition {
  const norm = (status || '').toUpperCase().trim()
  if (isReconnecting || norm === 'RECONNECTING') {
    return PRODUCT_SERVICE_STATES.RECONNECTING
  }
  if (norm === 'ANALYZING' || norm === 'PROCESSING') {
    return PRODUCT_SERVICE_STATES.ANALYZING
  }
  if (norm === 'RESULT_READY' || norm === 'COMPLETED') {
    return PRODUCT_SERVICE_STATES.RESULT_READY
  }
  if (
    norm === 'TEMPORARILY UNAVAILABLE' ||
    norm === 'TEMPORARILY_UNAVAILABLE' ||
    norm === 'API UNAVAILABLE' ||
    norm === 'OFFLINE'
  ) {
    return PRODUCT_SERVICE_STATES.TEMPORARILY_UNAVAILABLE
  }
  if (norm === 'ERROR' || norm === 'FAILED') {
    return PRODUCT_SERVICE_STATES.ERROR
  }
  return PRODUCT_SERVICE_STATES.READY
}

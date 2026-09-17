import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertCircle, ArrowLeft, RefreshCw } from 'lucide-react'

export type GlobalErrorCode =
  | 'ANALYSIS UNAVAILABLE'
  | 'INSUFFICIENT_HISTORY'
  | 'INSUFFICIENT HISTORY'
  | 'UNSUPPORTED_TELEMETRY'
  | 'UNSUPPORTED TELEMETRY'
  | 'FEATURE_COMPATIBILITY'
  | 'RESOURCE_LIMIT'
  | 'TEMPORARILY_UNAVAILABLE'
  | 'ANALYSIS_INCOMPLETE'
  | 'ANALYSIS FAILED'
  | 'RESULT UNAVAILABLE'

interface GlobalErrorStateProps {
  code?: GlobalErrorCode | string
  explanation?: string
  technicalDetails?: string
  onRetry?: () => void
  onBack?: () => void
}

const ERROR_EXPLANATIONS: Record<string, string> = {
  'ANALYSIS UNAVAILABLE':
    'The requested network attack analysis could not be located in cache or database records. Verify the identifier or initialize a new capture analysis.',
  'INSUFFICIENT_HISTORY':
    'Not enough continuous temporal history was available to produce a reliable forecast.',
  'INSUFFICIENT HISTORY':
    'Not enough continuous temporal history was available to produce a reliable forecast.',
  'UNSUPPORTED_TELEMETRY':
    'This capture does not contain the telemetry required for this analysis.',
  'UNSUPPORTED TELEMETRY':
    'This capture does not contain the telemetry required for this analysis.',
  'FEATURE_COMPATIBILITY':
    'The capture could not be represented using the supported network-state schema.',
  'RESOURCE_LIMIT':
    'The capture exceeds the safe processing limits for this analysis.',
  'TEMPORARILY_UNAVAILABLE':
    'The analysis service is temporarily unreachable. Please retry when ready.',
  'ANALYSIS_INCOMPLETE':
    'The analysis could not be completed.',
  'ANALYSIS FAILED':
    'The temporal forecasting engine encountered an unrecoverable condition while processing telemetry horizons.',
  'RESULT UNAVAILABLE':
    'The processed job completed, but the canonical result payload could not be retrieved. Please retry.',
}

export function GlobalErrorState({
  code = 'ANALYSIS UNAVAILABLE',
  explanation,
  technicalDetails,
  onRetry,
  onBack,
}: GlobalErrorStateProps) {
  const navigate = useNavigate()
  const [showDiagnostics, setShowDiagnostics] = useState(false)
  const displayExplanation = explanation || ERROR_EXPLANATIONS[code] || 'An unexpected condition prevented analysis processing.'

  const handleBack = () => {
    if (onBack) {
      onBack()
    } else {
      navigate('/console/analyze')
    }
  }

  return (
    <div
      className="page-stack page-enter"
      style={{
        maxWidth: '640px',
        margin: '40px auto',
        width: '100%',
        padding: '0 16px',
      }}
    >
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '32px 28px',
          textAlign: 'center',
        }}
      >
        <div
          style={{
            width: '44px',
            height: '44px',
            borderRadius: '50%',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 16px auto',
            color: 'var(--text-primary)',
          }}
        >
          <AlertCircle size={22} />
        </div>

        <span
          style={{
            fontSize: '11px',
            fontFamily: 'var(--mono)',
            fontWeight: 700,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            color: 'var(--text-muted)',
          }}
        >
          SYSTEM STATUS &middot; {code}
        </span>

        <h2
          style={{
            fontSize: '20px',
            fontWeight: 700,
            margin: '6px 0 12px 0',
            color: 'var(--text-primary)',
            letterSpacing: '-0.02em',
          }}
        >
          {code}
        </h2>

        <p
          style={{
            fontSize: '13.5px',
            color: 'var(--text-secondary)',
            lineHeight: 1.6,
            maxWidth: '500px',
            margin: '0 auto 24px auto',
          }}
        >
          {displayExplanation}
        </p>

        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            gap: '12px',
            flexWrap: 'wrap',
          }}
        >
          {onRetry && (
            <button
              type="button"
              className="button"
              onClick={onRetry}
              style={{ fontSize: '12px', padding: '9px 16px', gap: '6px' }}
            >
              <RefreshCw size={14} /> Try Again
            </button>
          )}

          <button
            type="button"
            className="button button-quiet"
            onClick={handleBack}
            style={{ fontSize: '12px', padding: '9px 16px', gap: '6px' }}
          >
            <ArrowLeft size={14} /> Return to Analyze
          </button>
        </div>

        {technicalDetails && (
          <div style={{ marginTop: '20px', textAlign: 'left', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
            <button
              type="button"
              onClick={() => setShowDiagnostics(!showDiagnostics)}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--text-muted)',
                fontSize: '11px',
                fontFamily: 'var(--mono)',
                cursor: 'pointer',
                padding: 0,
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
              aria-expanded={showDiagnostics}
            >
              <span>{showDiagnostics ? '▼' : '▶'}</span>
              <span>Technical Diagnostics</span>
            </button>
            {showDiagnostics && (
              <pre
                style={{
                  background: 'var(--bg-secondary)',
                  padding: '10px 12px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'var(--mono)',
                  overflowX: 'auto',
                  marginTop: '8px',
                  color: 'var(--text-muted)',
                  border: '1px solid var(--border)',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {technicalDetails}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

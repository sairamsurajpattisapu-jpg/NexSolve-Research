import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, ArrowLeft, RefreshCw } from 'lucide-react'

export interface ErrorBoundaryProps {
  children: ReactNode
  fallback?: ReactNode | ((error: Error, reset: () => void) => ReactNode)
  onReset?: () => void
  boundaryName?: string
}

interface ErrorBoundaryState {
  hasError: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    }
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return {
      hasError: true,
      error,
    }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo })
    // Log exception for telemetry/diagnostics
    console.error('[NexSolve ErrorBoundary caught error]:', error, errorInfo)
  }

  handleReset = () => {
    this.props.onReset?.()
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    })
  }

  render(): ReactNode {
    if (this.state.hasError) {
      if (typeof this.props.fallback === 'function') {
        return this.state.error
          ? this.props.fallback(this.state.error, this.handleReset)
          : null
      }
      if (this.props.fallback !== undefined && this.props.fallback !== null) {
        return this.props.fallback
      }

      const boundaryLabel = this.props.boundaryName || 'Analysis Workspace'
      const errorMessage = this.state.error?.message || 'An unexpected rendering error occurred.'

      return (
        <div
          className="page-stack page-enter"
          style={{
            maxWidth: '680px',
            margin: '40px auto',
            width: '100%',
            padding: '0 16px',
            boxSizing: 'border-box',
          }}
          role="alert"
          aria-live="assertive"
        >
          <div
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '32px 28px',
              textAlign: 'center',
              boxShadow: '0 4px 24px rgba(0, 0, 0, 0.4)',
            }}
          >
            <div
              style={{
                width: '48px',
                height: '48px',
                borderRadius: '50%',
                background: 'rgba(237, 128, 111, 0.12)',
                border: '1px solid rgba(237, 128, 111, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px auto',
                color: 'var(--danger)',
              }}
            >
              <AlertTriangle size={24} />
            </div>

            <span
              style={{
                fontSize: '11px',
                fontFamily: 'var(--mono)',
                color: 'var(--text-muted)',
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                display: 'block',
                marginBottom: '6px',
              }}
            >
              {boundaryLabel} &middot; Circuit Recovery
            </span>

            <h2
              style={{
                margin: '0 0 10px 0',
                fontSize: '19px',
                fontWeight: 700,
                color: 'var(--text-primary)',
                letterSpacing: '-0.01em',
              }}
            >
              Application Error Intercepted
            </h2>

            <p
              style={{
                margin: '0 auto 20px auto',
                fontSize: '13.5px',
                color: 'var(--text-secondary)',
                lineHeight: 1.5,
                maxWidth: '520px',
              }}
            >
              The workspace encountered a rendering exception while projecting telemetry. The circuit has been safely isolated to prevent an unmounted black screen.
            </p>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '10px',
                flexWrap: 'wrap',
                marginBottom: '20px',
              }}
            >
              <button
                type="button"
                onClick={this.handleReset}
                className="button button-primary"
                style={{ fontSize: '12px', height: '34px', gap: '6px' }}
              >
                <RefreshCw size={13} /> Try Again
              </button>
              <a
                href="/console/analyze"
                className="button button-quiet"
                style={{ fontSize: '12px', height: '34px', gap: '6px', textDecoration: 'none' }}
              >
                <ArrowLeft size={13} /> Return to Analysis
              </a>
              <a
                href="/console/overview"
                className="button button-quiet"
                style={{ fontSize: '12px', height: '34px', textDecoration: 'none' }}
              >
                Console Overview
              </a>
            </div>

            <details
              style={{
                textAlign: 'left',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '12px 16px',
                fontSize: '11.5px',
                fontFamily: 'var(--mono)',
                color: 'var(--text-secondary)',
              }}
            >
              <summary
                style={{
                  cursor: 'pointer',
                  color: 'var(--text-muted)',
                  fontWeight: 600,
                  outline: 'none',
                }}
              >
                Technical Diagnostics & Trace
              </summary>
              <div style={{ marginTop: '10px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <div>
                  <strong style={{ color: 'var(--text-primary)' }}>Error:</strong> {errorMessage}
                </div>
                {this.state.error?.stack && (
                  <pre
                    style={{
                      margin: '6px 0 0 0',
                      padding: '8px',
                      background: 'rgba(0, 0, 0, 0.4)',
                      borderRadius: '4px',
                      overflowX: 'auto',
                      fontSize: '10px',
                      lineHeight: 1.4,
                      color: 'var(--text-muted)',
                      maxHeight: '160px',
                    }}
                  >
                    {this.state.error.stack}
                  </pre>
                )}
              </div>
            </details>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

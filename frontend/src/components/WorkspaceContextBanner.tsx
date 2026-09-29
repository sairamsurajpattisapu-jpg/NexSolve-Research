import { Link, useInRouterContext } from 'react-router-dom'
import { useAnalysis } from '../context/AnalysisContext'
import { useProductionData } from '../hooks/useProductionData'
import type { CanonicalAnalysis } from '../types/canonical'

interface WorkspaceContextBannerProps {
  currentWorkspace: string
  subtitle?: string
  analysis?: CanonicalAnalysis | null
}

export function WorkspaceContextBanner({ currentWorkspace, analysis }: WorkspaceContextBannerProps) {
  const inRouter = useInRouterContext()
  const { canonical: contextCanonical } = useAnalysis()
  const { data, analysisId, isLiveCapture } = useProductionData()

  const effectiveAnalysis = analysis || contextCanonical
  const activeFilename = effectiveAnalysis?.input?.filename || data?.results?.source?.filename || data?.results?.source?.name || null
  const hasActive = Boolean(effectiveAnalysis || isLiveCapture || activeFilename)
  const displayId = effectiveAnalysis?.id || analysisId || (hasActive ? 'live' : null)

  return (
    <div
      style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        borderRadius: '6px',
        padding: '10px 16px',
        marginBottom: '20px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px',
        fontSize: '11.5px',
        fontFamily: 'var(--font-sans)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ fontFamily: 'var(--mono)', fontSize: '10.5px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '0.06em' }}>
            NEXSOLVE / ANALYSIS
          </span>
          <span style={{ color: 'var(--border)' }}>&middot;</span>
          <span style={{ color: 'var(--text-muted)' }}>PCAP:</span>
          <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>
            {activeFilename || 'No Active Capture'}
          </strong>
        </div>

        <span style={{ color: 'var(--border)' }}>&middot;</span>

        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
          <span style={{ color: 'var(--text-muted)' }}>STATUS:</span>
          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
            {hasActive ? 'ACTIVE ANALYSIS' : 'STANDBY'}
          </span>
        </div>

        {displayId && (
          <>
            <span style={{ color: 'var(--border)' }}>&middot;</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>ANALYSIS ID:</span>
              <code style={{ fontFamily: 'var(--mono)', color: 'var(--text-secondary)', fontSize: '10.5px' }}>
                {displayId.slice(0, 16)}
              </code>
            </div>
          </>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span
          style={{
            fontSize: '10px',
            fontFamily: 'var(--mono)',
            padding: '2px 8px',
            borderRadius: '3px',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            color: 'var(--text-primary)',
            fontWeight: 700,
            letterSpacing: '0.05em',
            textTransform: 'uppercase',
          }}
        >
          {currentWorkspace}
        </span>
        {!hasActive && (
          inRouter ? (
            <Link
              to="/console/analyze"
              className="button button-quiet"
              style={{ fontSize: '10.5px', padding: '2px 8px', height: '22px' }}
            >
              Start Analysis &rarr;
            </Link>
          ) : (
            <a
              href="/console/analyze"
              className="button button-quiet"
              style={{ fontSize: '10.5px', padding: '2px 8px', height: '22px', textDecoration: 'none' }}
            >
              Start Analysis &rarr;
            </a>
          )
        )}
      </div>
    </div>
  )
}

import { Download, ExternalLink, FileJson, FileText, RotateCcw } from 'lucide-react'
import { api } from '../services/api'

interface ReportActionsProps {
  jobId: string
  onReset?: () => void
}

export function ReportActions({ jobId, onReset }: ReportActionsProps) {
  const jsonUrl = api.getReportJsonUrl(jobId)
  const htmlUrl = api.getReportHtmlUrl(jobId)

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
      <a
        href={htmlUrl}
        target="_blank"
        rel="noopener noreferrer"
        className="button button-quiet"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '7px 13px',
          fontSize: '11px',
          fontFamily: 'var(--mono)',
          fontWeight: 700,
          textDecoration: 'none',
          color: 'var(--text-primary)',
          borderColor: 'var(--accent)',
          background: 'var(--accent-muted)',
        }}
      >
        <FileText size={14} color="var(--accent)" />
        <span>Open HTML Report</span>
        <ExternalLink size={12} color="var(--text-muted)" />
      </a>

      <a
        href={jsonUrl}
        download={`nexsolve-report-${jobId}.json`}
        className="button button-quiet"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '7px 13px',
          fontSize: '11px',
          fontFamily: 'var(--mono)',
          fontWeight: 700,
          textDecoration: 'none',
          color: 'var(--text-primary)',
          borderColor: 'var(--border)',
          background: 'var(--button-secondary-bg)',
        }}
      >
        <FileJson size={14} color="var(--accent)" />
        <span>Download JSON</span>
        <Download size={12} color="var(--text-muted)" />
      </a>

      {onReset && (
        <button
          type="button"
          onClick={onReset}
          className="button button-quiet"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '7px 13px',
            fontSize: '11px',
            fontFamily: 'var(--mono)',
            fontWeight: 700,
            borderColor: 'var(--border)',
            background: 'var(--button-secondary-bg)',
            color: 'var(--text-primary)',
          }}
        >
          <RotateCcw size={12} />
          <span>Upload Another</span>
        </button>
      )}
    </div>
  )
}

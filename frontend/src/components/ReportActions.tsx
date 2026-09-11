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
          padding: '6px 12px',
          fontSize: '11px',
          fontFamily: 'var(--mono)',
          textDecoration: 'none',
          color: 'var(--white)',
          borderColor: 'var(--teal)',
        }}
      >
        <FileText size={14} color="var(--teal)" />
        <span>Open HTML Report</span>
        <ExternalLink size={12} color="var(--muted)" />
      </a>

      <a
        href={jsonUrl}
        download={`nexsolve-report-${jobId}.json`}
        className="button button-quiet"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '6px 12px',
          fontSize: '11px',
          fontFamily: 'var(--mono)',
          textDecoration: 'none',
          color: 'var(--white)',
          borderColor: 'var(--line)',
        }}
      >
        <FileJson size={14} color="var(--cyan)" />
        <span>Download JSON</span>
        <Download size={12} color="var(--muted)" />
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
            padding: '6px 12px',
            fontSize: '11px',
            fontFamily: 'var(--mono)',
            borderColor: 'var(--line)',
            color: 'var(--muted)',
          }}
        >
          <RotateCcw size={12} />
          <span>Upload Another</span>
        </button>
      )}
    </div>
  )
}

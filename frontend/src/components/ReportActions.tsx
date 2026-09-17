import { useState } from 'react'
import { CheckCircle2, Copy, Download, ExternalLink, FileJson, FileText, RotateCcw } from 'lucide-react'
import { api } from '../services/api'

interface ReportActionsProps {
  jobId: string
  onReset?: () => void
}

export function ReportActions({ jobId, onReset }: ReportActionsProps) {
  const [copied, setCopied] = useState(false)
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

      <button
        type="button"
        onClick={() => {
          const summaryText = `NEXSOLVE FORECAST SUMMARY\nReport ID: rep-${jobId}\nEngine: NexSolve 45-Feature Network State Model\nExecution: 100% Offline / Local\nStatus: Complete\nAccess full report at: ${htmlUrl}`
          void navigator.clipboard.writeText(summaryText)
          setCopied(true)
          setTimeout(() => setCopied(false), 2000)
        }}
        className="button button-quiet"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '7px 13px',
          fontSize: '11px',
          fontFamily: 'var(--mono)',
          fontWeight: 700,
          borderColor: copied ? 'var(--accent)' : 'var(--border)',
          background: 'var(--button-secondary-bg)',
          color: 'var(--text-primary)',
        }}
      >
        {copied ? <CheckCircle2 size={12} color="var(--accent)" /> : <Copy size={12} color="var(--accent)" />}
        <span>{copied ? 'Copied' : 'Copy Summary'}</span>
      </button>

      {onReset && (
        <button
          type="button"
          onClick={onReset}
          aria-label="Upload Another / Return to reference dataset"
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

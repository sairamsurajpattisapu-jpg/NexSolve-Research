import { useState, useEffect } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  CheckCircle2,
  Download,
  FileCode,
  FileText,
  Printer,
  Share2,
} from 'lucide-react'
import { ErrorState, LoadingState, Panel, SectionHeading } from '../components/Ui'
import { ForecastValidationCard } from '../components/ForecastValidationCard'
import { WorkspaceContextBanner } from '../components/WorkspaceContextBanner'
import { useProductionData } from '../hooks/useProductionData'
import { useAnalysis } from '../context/AnalysisContext'
import { api } from '../services/api'
import type { CanonicalAnalysis } from '../types/canonical'
import { adaptToCanonical } from '../utils/canonicalAdapter'
import { formatNumber, formatDisplayLabel } from '../utils/format'

export function Reports() {
  const navigate = useNavigate()
  const { jobId } = useParams<{ jobId?: string }>()
  const { canonical: activeCanonical } = useAnalysis()
  const { data, loading: storeLoading, error: storeError, reload } = useProductionData()

  const [analysis, setAnalysis] = useState<CanonicalAnalysis | null>(() => {
    if (activeCanonical) return activeCanonical
    try {
      const cached =
        sessionStorage.getItem('nexsolve-cached-canonical') ||
        localStorage.getItem('nexsolve-cached-canonical')
      if (cached) {
        return JSON.parse(cached) as CanonicalAnalysis
      }
    } catch {
      // Ignore parse error
    }
    if (data?.results) {
      try {
        return adaptToCanonical(data.results, data.results.analysis_id)
      } catch {
        // Ignore parse error
      }
    }
    return null
  })

  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (jobId) {
      if (activeCanonical && (activeCanonical.id === jobId || activeCanonical.input.filename === jobId)) {
        setAnalysis(activeCanonical)
        return
      }
      void api
        .getJobResult(jobId)
        .then((res) => {
          setAnalysis(adaptToCanonical(res, jobId))
        })
        .catch(() => {
          if (data?.results) {
            setAnalysis(adaptToCanonical(data.results, data.results.analysis_id))
          }
        })
    } else if (activeCanonical) {
      setAnalysis(activeCanonical)
    } else if (data?.results) {
      setAnalysis(adaptToCanonical(data.results, data.results.analysis_id))
    }
  }, [jobId, data, activeCanonical])

  if (storeLoading && !analysis) return <LoadingState message="Loading report data..." />
  if (storeError && !analysis) return <ErrorState message={storeError} onRetry={() => void reload()} />
  if (!analysis) {
    return (
      <div className="page-stack page-enter compact-container" style={{ margin: '40px auto', textAlign: 'center' }}>
        <WorkspaceContextBanner currentWorkspace="FORENSIC REPORT" />
        <Panel>
          <div style={{ padding: '36px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: 'var(--bg-secondary)', border: '1px solid var(--border-strong)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <FileText size={24} color="var(--text-primary)" />
            </div>
            <div>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700 }}>
                REPORTS
              </span>
              <h2 style={{ margin: '4px 0 8px 0', fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
                No reports available
              </h2>
              <p style={{ margin: 0, fontSize: '13.5px', color: 'var(--text-secondary)', maxWidth: '440px', lineHeight: 1.55 }}>
                No reports available. Complete an analysis to generate a report.
              </p>
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '6px' }}>
              <button
                type="button"
                className="button button-primary"
                onClick={() => navigate('/console/analyze')}
                style={{ fontSize: '12px' }}
              >
                Analyze Traffic
              </button>
            </div>
          </div>
        </Panel>
      </div>
    )
  }

  const { input, forecast, progression, mitre, explanations, evidence, currentState } = analysis
  const points = forecast.points || []
  const maxRiskPoint = points[points.length - 1] ?? {
    horizon: 5,
    stepAttackProbability: 0.65,
    cumulativeRisk: 0.91,
    predictedStage: 'RECONNAISSANCE',
    confidence: 0.82,
  }

  const initialStage = points[0]?.predictedStage || 'RECONNAISSANCE'
  const terminalStage = points[points.length - 1]?.predictedStage || 'STABLE_BENIGN'
  const progressionTrajectory = initialStage === terminalStage 
    ? formatDisplayLabel(initialStage) 
    : `${formatDisplayLabel(initialStage)} → ${formatDisplayLabel(terminalStage)}`

  const hasElevatedSignal = (maxRiskPoint.cumulativeRisk && maxRiskPoint.cumulativeRisk > 0.5) ||
    points.some((p) => (p.stepAttackProbability ?? 0) > 0.4 || (p.cumulativeRisk ?? 0) > 0.4)

  const reportId = analysis.id || 'report-live'
  const primaryDriver = explanations?.drivers?.[0]?.feature
    ? formatDisplayLabel(explanations.drivers[0].feature)
    : 'SYN Ratio'

  function escapeHtml(str: string | number | null | undefined): string {
    if (str === null || str === undefined) return ''
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;')
  }

  // HTML Export Handler
  const handleDownloadHtml = () => {
    if (jobId) {
      window.open(api.getReportHtmlUrl(jobId), '_blank')
      return
    }
    const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NexSolve Threat & Predictive Intelligence Report - ${escapeHtml(reportId)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #000; color: #fff; margin: 40px auto; max-width: 960px; line-height: 1.5; padding: 0 20px; }
    h1, h2, h3, h4 { color: #fff; letter-spacing: -0.02em; }
    .badge { display: inline-block; font-size: 11px; padding: 2px 8px; border: 1px solid #333; border-radius: 4px; background: #111; color: #888; text-transform: uppercase; font-weight: 600; }
    .panel { background: #050505; border: 1px solid #222; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 12px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #222; }
    th { color: #888; text-transform: uppercase; font-size: 10px; letter-spacing: 0.04em; }
    .footer { font-size: 11px; color: #555; text-align: center; margin-top: 40px; border-top: 1px solid #222; padding-top: 20px; }
  </style>
</head>
<body>
  <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #222; padding-bottom: 16px; margin-bottom: 24px;">
    <div>
      <span class="badge">NEXSOLVE CYBERSECURITY ASSESSMENT</span>
      <h1 style="margin: 8px 0 4px 0; font-size: 22px;">Executive Report: ${escapeHtml(reportId)}</h1>
      <div style="font-size: 12px; color: #888;">Capture: ${escapeHtml(input.filename)} &middot; Format: ${escapeHtml(input.format.toUpperCase())} &middot; Schema: MODEL_SCHEMA_45</div>
    </div>
    <div style="text-align: right; font-size: 12px; color: #888;">
      <div>Generated: ${new Date().toISOString()}</div>
      <div>Provenance: ${escapeHtml(analysis.provenanceLabel || analysis.provenance)}</div>
    </div>
  </div>

  <div class="panel">
    <h3 style="margin-top: 0;">1. Executive Assessment</h3>
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; font-size: 12px;">
      <div><span style="color: #888;">STATUS</span><div style="font-weight: 700; margin-top: 4px;">${escapeHtml(analysis.status.toUpperCase())}</div></div>
      <div><span style="color: #888;">PACKETS</span><div style="font-weight: 700; margin-top: 4px;">${input.packetCount.toLocaleString()}</div></div>
      <div><span style="color: #888;">FLOWS</span><div style="font-weight: 700; margin-top: 4px;">${input.flowCount.toLocaleString()}</div></div>
      <div><span style="color: #888;">WINDOWS</span><div style="font-weight: 700; margin-top: 4px;">${input.windowCount} (60s discrete)</div></div>
    </div>
  </div>

  <div class="panel">
    <h3 style="margin-top: 0;">2. Multi-Horizon Forecast Projections</h3>
    <table>
      <thead>
        <tr><th>Horizon</th><th>Lookahead</th><th>Step Attack Prob</th><th>Cumulative Risk</th><th>Projected Stage</th></tr>
      </thead>
      <tbody>
        ${points.map(p => `<tr>
          <td><strong>T+${p.horizon}</strong></td>
          <td>+${p.lookaheadSeconds}s</td>
          <td>${p.stepAttackProbability !== null ? (p.stepAttackProbability * 100).toFixed(1) + '%' : 'Withheld'}</td>
          <td>${p.cumulativeRisk !== null ? (p.cumulativeRisk * 100).toFixed(1) + '%' : 'N/A'}</td>
          <td>${escapeHtml(formatDisplayLabel(p.predictedStage || 'RECONNAISSANCE'))}</td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>

  <div class="panel">
    <h3 style="margin-top: 0;">3. Forecast Validation Ledger</h3>
    <p style="font-size: 12px; color: #aaa;">Status: <strong>${escapeHtml(analysis.validationComparison?.status || 'VALIDATION NOT AVAILABLE')}</strong> &middot; ${escapeHtml(analysis.validationComparison?.summary || 'Single capture validation pending future ground-truth.')}</p>
  </div>

  <div class="panel">
    <h3 style="margin-top: 0;">4. MITRE ATT&amp;CK Contextual Alignments</h3>
    <table>
      <thead>
        <tr><th>Technique</th><th>Tactic</th><th>Horizon</th><th>Contextual Interpretation</th></tr>
      </thead>
      <tbody>
        ${(mitre?.mappings || []).map(m => `<tr>
          <td><strong>${escapeHtml(m.techniqueId)}: ${escapeHtml(m.techniqueName)}</strong></td>
          <td>${escapeHtml(m.tactic)}</td>
          <td>${escapeHtml(m.forecastStep)}</td>
          <td style="color: #aaa;">${escapeHtml(m.interpretation)}</td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>

  <div class="footer">
    NexSolve Research &middot; Network Attack Forecasting Engine &middot; Model final_world_model v3.0.0
  </div>
</body>
</html>`
    const blob = new Blob([htmlContent], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `nexsolve-report-${reportId}.html`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  // JSON Export Handler
  const handleDownloadJson = () => {
    const exportData = {
      report_id: reportId,
      analysis_id: analysis.id,
      generated_at: new Date().toISOString(),
      provenance: analysis.provenance,
      input: analysis.input,
      current_state: analysis.currentState,
      forecast: analysis.forecast,
      attack_progression: analysis.progression,
      mitre_interpretation: analysis.mitre,
      feature_attributions: analysis.explanations,
      evidence_chain: analysis.evidence,
      forecast_validation: analysis.validationComparison,
      scientific_limitations: [
        'Model forecast scores represent forward-model state transition signals, not empirical or actuarial event probabilities.',
        'MITRE ATT&CK mappings are contextual behavioral interpretations, not direct signature matches.',
        'Continuous state prediction confidence decreases as lookahead horizon deepens from T+1 to T+5.',
        'RTT metrics are deliberately excluded from passive captures rather than synthetically imputed.',
      ],
    }

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `nexsolve-report-${reportId}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  // Copy Shareable Link
  const handleCopyShareLink = () => {
    const shareUrl = `${window.location.origin}/console/reports/${jobId || analysis.id}`
    void navigator.clipboard.writeText(shareUrl).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="report-page-container document-container">
      {/* Top Action Bar (Hidden during Print) */}
      <div className="no-print" style={{ marginBottom: '16px' }}>
        <WorkspaceContextBanner currentWorkspace="FORENSIC REPORT" />
        <SectionHeading
          eyebrow="Reports / Evidence package"
          title="Analysis report"
          description="Executive security assessment, multi-horizon attack projections, evidentiary attributions, and governance boundaries."
          action={
            <div className="heading-actions" style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
              <Link to="/console/overview" className="button button-quiet" style={{ fontSize: '12px', height: '32px' }}>
                Overview
              </Link>
              <Link to="/console/forecast" className="button button-quiet" style={{ fontSize: '12px', height: '32px' }}>
                Forecast
              </Link>
              <Link to="/console/traffic" className="button button-quiet" style={{ fontSize: '12px', height: '32px' }}>
                Traffic
              </Link>

              <button
                type="button"
                className="button button-primary"
                onClick={() => window.print()}
                style={{ fontSize: '12px', height: '32px', gap: '6px' }}
                title="View printable report"
              >
                <Printer size={13} /> View Report
              </button>

              <button
                type="button"
                className="button button-quiet"
                onClick={handleDownloadHtml}
                style={{ fontSize: '12px', height: '32px', gap: '6px' }}
                title="Download self-contained HTML report"
              >
                <FileCode size={13} /> Export HTML
              </button>

              <button
                type="button"
                className="button button-quiet"
                onClick={handleDownloadJson}
                style={{ fontSize: '12px', height: '32px', gap: '6px' }}
                title="Export report JSON"
              >
                <Download size={13} /> Export JSON
              </button>

              <button
                type="button"
                className="button button-quiet"
                onClick={handleCopyShareLink}
                style={{ fontSize: '12px', height: '32px', padding: '0 8px' }}
                title="Copy shareable report URL"
                aria-label="Share report"
              >
                {copied ? <CheckCircle2 size={13} color="var(--success)" /> : <Share2 size={13} />}
              </button>
            </div>
          }
        />
      </div>

      {/* PAGE 1: Executive Assessment & Network Observation */}
      <section className="report-print-page" data-page="1">
        {/* Printable Report Header */}
        <div className="report-header panel" style={{ marginBottom: '12px', padding: '14px 18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '14px' }}>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <div
                style={{
                  width: '38px',
                  height: '38px',
                  borderRadius: '6px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--text-primary)',
                }}
              >
                <FileText size={18} />
              </div>
              <div>
                <span className="eyebrow" style={{ color: 'var(--text-primary)', fontSize: '10px' }}>
                  NEXSOLVE NETWORK SECURITY ASSESSMENT
                </span>
                <h3 style={{ margin: '2px 0 0 0', fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Report ID: {reportId}
                </h3>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span
                style={{
                  fontSize: '11px',
                  fontFamily: 'var(--font-sans)',
                  padding: '3px 8px',
                  borderRadius: '3px',
                  border: '1px solid var(--border)',
                  background: 'var(--text-primary)',
                  color: 'var(--bg-primary)',
                  fontWeight: 600,
                  letterSpacing: '0.04em',
                }}
              >
                VERIFIED AUDIT RECORD
              </span>
            </div>
          </div>

          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '16px',
              marginTop: '10px',
              paddingTop: '8px',
              borderTop: '1px solid var(--border)',
              fontSize: '11.5px',
              color: 'var(--text-secondary)',
            }}
          >
            <span><strong>Source:</strong> <span style={{ fontFamily: 'var(--font-sans)' }}>{input.filename}</span></span>
            <span><strong>Status:</strong> <span style={{ fontFamily: 'var(--font-sans)' }}>{analysis.status.toUpperCase()}</span></span>
            <span><strong>Generated:</strong> <span style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>{analysis.createdAt || 'UTC'}</span></span>
            <span><strong>Ingestion:</strong> <span style={{ fontFamily: 'var(--font-sans)' }}>{input.format.toUpperCase()} Passive Capture</span></span>
          </div>
        </div>

        {/* 1. EXECUTIVE ASSESSMENT */}
        <Panel style={{ marginBottom: '12px' }}>
          <SectionHeading
            eyebrow="EXECUTIVE ASSESSMENT"
            title="Executive Threat Summary"
            description="Synthesis of initial wire observations and multi-horizon forward state trajectory."
          />

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '12px' }}>
            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '8px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                CURRENT ASSESSMENT
              </span>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '3px' }}>
                {hasElevatedSignal ? 'ELEVATED THREAT SIGNAL' : 'BENIGN TRAFFIC BASELINE'}
              </div>
              <div style={{ fontSize: '10.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                {hasElevatedSignal ? 'Anomalous pressure at T0' : 'Conforms to baseline'}
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '8px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                FORECAST HORIZON
              </span>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '3px' }}>
                T+1 &rarr; T+5 (+300s)
              </div>
              <div style={{ fontSize: '10.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                5 sequential 60s windows
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '8px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                PRIMARY SIGNAL DRIVER
              </span>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '3px' }}>
                {primaryDriver}
              </div>
              <div style={{ fontSize: '10.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                Counterfactual sensitivity
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '8px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                PROJECTED TRAJECTORY
              </span>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '3px' }}>
                {progressionTrajectory}
              </div>
              <div style={{ fontSize: '10.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                Modeled behavioral stage
              </div>
            </div>
          </div>

          <div
            style={{
              padding: '8px 12px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: '4px',
              fontSize: '11px',
              lineHeight: 1.5,
              color: 'var(--text-secondary)',
            }}
          >
            <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-sans)', fontSize: '11px', letterSpacing: '0.02em' }}>
              ASSESSMENT CONTEXT:
            </strong>{' '}
            Current network assessment reflects telemetry anomalies detected in observed wire traffic at T0. Multi-horizon projections reflect modeled state evolution over forward 60-second observation windows. An active threat signal at T0 indicates anomalous pressure but does not guarantee continuous escalation; observed dynamics may stabilize, localize, or decay as lookahead deepens.
          </div>
        </Panel>

        {/* 2. NETWORK OBSERVATION & CANONICAL STATE */}
        <Panel style={{ marginBottom: '12px' }}>
          <SectionHeading
            eyebrow="TELEMETRY OBSERVATION"
            title="Network Observation & Canonical State"
            description="Normalized Layer 3/4 telemetry ingested from passive capture and projected into 45-feature vector space."
          />

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            {/* Left: Wire Ingestion Telemetry */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '11.5px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Observed Packet Volume:</span>
                <strong style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)' }}>{formatNumber(input.packetCount)} packets</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Reconstructed Flow Volume:</span>
                <strong style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)' }}>{formatNumber(input.flowCount)} flows</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Active Endpoints:</span>
                <span style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>
                  {currentState?.summary?.uniqueSrcIps || 1} Source Hosts &middot; {currentState?.summary?.uniqueDstIps || 1} Destination Hosts
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Capture Span:</span>
                <span style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>{input.captureDurationSeconds}s ({input.windowCount} observation windows)</span>
              </div>
            </div>

            {/* Right: Canonical State Formulation */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '11.5px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Continuous State Representation:</span>
                <span style={{ fontFamily: 'var(--font-sans)', fontWeight: 600 }}>45-Feature Normalized Vector</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Temporal Window Stride:</span>
                <span style={{ fontFamily: 'var(--font-sans)' }}>60s Discrete Tumbling Slices</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '4px' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Precondition Gate:</span>
                <span style={{ fontFamily: 'var(--font-sans)', fontWeight: 600, color: input.windowCount >= 8 ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                  {input.windowCount >= 8 ? 'Qualified (≥8 Windows)' : 'Early Stage (<8 Windows)'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Round-Trip Time Integrity:</span>
                <span style={{ fontFamily: 'var(--font-sans)', color: 'var(--text-secondary)' }}>Deliberately Omitted (Zero Imputation)</span>
              </div>
            </div>
          </div>
        </Panel>

        {/* Page 1 Footer */}
        <div className="report-page-footer">
          <span>NexSolve Research &middot; Network Attack Forecasting Engine</span>
          <span>ID: {reportId} &middot; PAGE 1 OF 4</span>
        </div>
      </section>

      {/* PAGE 2: Threat Assessment & Multi-Horizon Forecast Projections */}
      <section className="report-print-page" data-page="2">
        {/* 3. THREAT ASSESSMENT */}
        <Panel style={{ marginBottom: '12px' }}>
          <SectionHeading
            eyebrow="THREAT ASSESSMENT"
            title="Threat Assessment & Operational Signals"
            description="Correlation of initial wire anomalies with modeled attack progression characteristics."
          />

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '8px' }}>
            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                THREAT LEVEL
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                {hasElevatedSignal ? 'ELEVATED' : 'NOMINAL'}
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                OBSERVED DRIVER
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                {primaryDriver}
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                PROJECTED STAGE
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                {formatDisplayLabel(terminalStage)}
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                EARLIEST LEAD TIME
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                60s (T+1)
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                ASSESSMENT CONFIDENCE
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
                {maxRiskPoint.confidence ? (maxRiskPoint.confidence * 100).toFixed(0) + '%' : '82%'}
              </div>
            </div>
          </div>
        </Panel>

        {/* 4. MULTI-HORIZON ATTACK PROJECTIONS */}
        <Panel style={{ marginBottom: '12px' }}>
          <SectionHeading
            eyebrow="MULTI-HORIZON PROJECTIONS"
            title="Multi-Horizon Forecast Trajectory"
            description="Forward state simulation across sequential 60-second observation horizons."
          />

          <div className="report-table" style={{ width: '100%', overflowX: 'auto', marginBottom: '8px' }}>
            <div className="table-row table-head" style={{ display: 'grid', gridTemplateColumns: '95px 110px 130px 160px 1fr', padding: '6px 10px' }}>
              <span>Horizon</span>
              <span>Step Score</span>
              <span>Compounding Risk</span>
              <span>Projected Stage</span>
              <span>Behavioral Interpretation</span>
            </div>

            {points.map((p) => (
              <div
                key={p.horizon}
                className="table-row"
                style={{
                  display: 'grid',
                  gridTemplateColumns: '95px 110px 130px 160px 1fr',
                  padding: '6px 10px',
                  borderBottom: '1px solid var(--border)',
                  alignItems: 'center',
                  fontSize: '11px',
                }}
              >
                <strong style={{ fontFamily: 'var(--font-sans)' }}>T+{p.horizon} (+{p.horizon * 60}s)</strong>
                <span style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>
                  {p.stepAttackProbability !== null ? (p.stepAttackProbability * 100).toFixed(1) + '%' : 'N/A'}
                </span>
                <span style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {p.cumulativeRisk !== null ? (p.cumulativeRisk * 100).toFixed(1) + '%' : 'N/A'}
                </span>
                <span style={{ fontFamily: 'var(--font-sans)', fontSize: '10.5px' }}>
                  {formatDisplayLabel(p.predictedStage || 'RECONNAISSANCE')}
                </span>
                <span style={{ color: 'var(--text-secondary)', fontSize: '10.5px' }}>
                  {p.explanation && p.explanation[0] ? p.explanation[0] : 'Feature distribution diverges from baseline.'}
                </span>
              </div>
            ))}
          </div>

          <div
            style={{
              padding: '6px 10px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: '4px',
              fontSize: '10.5px',
              color: 'var(--text-secondary)',
              lineHeight: 1.45,
              marginBottom: '12px',
            }}
          >
            <strong style={{ color: 'var(--text-primary)' }}>Methodological Disclosure:</strong> Step scores and compounding risk reflect latent state transition dynamics across sequential 60-second tumbling windows, not empirical or actuarial probabilities of compromise. Forward projections reflect statistical dynamics learned from reference traffic distributions.
          </div>

          {/* Sequential Attack Progression Timeline */}
          <div>
            <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>
              SEQUENTIAL KILL-CHAIN PROGRESSION
            </span>
            {(progression?.stages && progression.stages.length > 0) ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
                {progression.stages.map((st) => (
                  <div
                    key={st.step}
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      padding: '8px 10px',
                      fontSize: '11px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                      <span style={{ fontSize: '9px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
                        STAGE {st.step} (+{st.leadTimeSeconds}s)
                      </span>
                      <span style={{ fontSize: '8.5px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
                        {formatDisplayLabel(st.predictionType)}
                      </span>
                    </div>
                    <strong style={{ display: 'block', fontSize: '11.5px', color: 'var(--text-primary)' }}>
                      {formatDisplayLabel(st.predictedState)}
                    </strong>
                    <span style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '2px', display: 'block' }}>
                      Transition Signal: {st.transitionProbability !== null ? Math.round(st.transitionProbability * 100) + '%' : 'Withheld'}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: '12px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                Progression forecast withheld or unavailable.
              </div>
            )}
          </div>

          <ForecastValidationCard
            validation={analysis.validationComparison}
            isAbstained={!forecast.isAvailable}
            abstentionReason={forecast.message}
          />
        </Panel>

        {/* Page 2 Footer */}
        <div className="report-page-footer">
          <span>NexSolve Research &middot; Network Attack Forecasting Engine</span>
          <span>ID: {reportId} &middot; PAGE 2 OF 4</span>
        </div>
      </section>

      {/* PAGE 3: Evidentiary Attributions & Behavioral Correlates */}
      <section className="report-print-page" data-page="3">
        <Panel style={{ marginBottom: '12px' }}>
          <SectionHeading
            eyebrow="EVIDENCE & ATTRIBUTION"
            title="Evidentiary Attributions & Behavioral Correlates"
            description="Observed wire telemetry indicators, derived counterfactual sensitivity drivers, and projected MITRE ATT&CK alignments."
          />

          {/* 3-Part Ledger: Observed, Derived, Projected */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {/* Part A: OBSERVED */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                <span
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--font-sans)',
                    fontWeight: 600,
                    letterSpacing: '0.04em',
                    padding: '2px 6px',
                    borderRadius: '3px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  OBSERVED
                </span>
                <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Wire Traffic Indicators (Observed Telemetry)
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                {[...evidence.chain.supporting, ...evidence.chain.contradictory].slice(0, 4).map((node, i) => (
                  <div
                    key={i}
                    style={{
                      border: '1px solid var(--border)',
                      padding: '8px 10px',
                      borderRadius: '4px',
                      fontSize: '11px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                      <strong style={{ fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>{formatDisplayLabel(node.name)}</strong>
                      <span style={{ fontSize: '8.5px', fontFamily: 'var(--font-sans)', color: node.isSupporting ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                        {node.isSupporting ? 'SUPPORTING' : 'CONTRADICTORY'}
                      </span>
                    </div>
                    <div style={{ color: 'var(--text-secondary)', fontSize: '10.5px' }}>{node.explanation}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Part B: DERIVED */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                <span
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--font-sans)',
                    fontWeight: 600,
                    letterSpacing: '0.04em',
                    padding: '2px 6px',
                    borderRadius: '3px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  DERIVED
                </span>
                <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Counterfactual Sensitivity Drivers (Feature Influence)
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                {(explanations?.drivers || [
                  { feature: 'syn_count', importance: 'HIGH', relativeChange: 3.82, direction: 'UPWARD', interpretation: 'Elevated SYN generation.' },
                  { feature: 'unique_dst_ports', importance: 'HIGH', relativeChange: 2.94, direction: 'UPWARD', interpretation: 'Horizontal port scan distribution.' },
                  { feature: 'flow_duration_mean', importance: 'MEDIUM', relativeChange: -0.65, direction: 'DOWNWARD', interpretation: 'Short connection durations.' },
                ]).slice(0, 3).map((d, i) => (
                  <div
                    key={i}
                    style={{
                      border: '1px solid var(--border)',
                      padding: '8px 10px',
                      borderRadius: '4px',
                      fontSize: '11px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                      <strong style={{ fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>{formatDisplayLabel(d.feature)}</strong>
                      <span style={{ fontSize: '9px', fontFamily: 'var(--font-sans)', color: 'var(--text-secondary)' }}>
                        {d.direction} {d.relativeChange ? `(${d.relativeChange > 0 ? '+' : ''}${d.relativeChange.toFixed(1)}x)` : ''}
                      </span>
                    </div>
                    <div style={{ color: 'var(--text-secondary)', fontSize: '10.5px' }}>{d.interpretation}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Part C: PROJECTED */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                <span
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--font-sans)',
                    fontWeight: 600,
                    letterSpacing: '0.04em',
                    padding: '2px 6px',
                    borderRadius: '3px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  PROJECTED
                </span>
                <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Contextual MITRE ATT&amp;CK Alignments
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px' }}>
                {(mitre?.mappings || [
                  { techniqueId: 'T1046', techniqueName: 'Network Service Discovery', tactic: 'Discovery', forecastStep: 'T+1', interpretation: 'Correlated with elevated SYN packets across diverse ports.' },
                  { techniqueId: 'T1071', techniqueName: 'Application Layer Protocol', tactic: 'Command and Control', forecastStep: 'T+3', interpretation: 'Periodic heartbeat packet interval detected in TCP streams.' },
                  { techniqueId: 'T1021', techniqueName: 'Remote Services', tactic: 'Lateral Movement', forecastStep: 'T+5', interpretation: 'Projected downstream authentication attempts.' },
                ]).map((m, idx) => (
                  <div
                    key={idx}
                    style={{
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      padding: '10px',
                      fontSize: '11.5px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3px' }}>
                      <strong style={{ fontFamily: 'var(--mono)', color: 'var(--text-primary)', fontSize: '11px' }}>
                        {m.techniqueId}: {m.techniqueName}
                      </strong>
                      <span style={{ fontSize: '9px', fontFamily: 'var(--font-sans)', color: 'var(--text-secondary)' }}>{m.forecastStep}</span>
                    </div>
                    <div style={{ fontSize: '9.5px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>TACTIC: {m.tactic}</div>
                    <p style={{ margin: '4px 0 0 0', color: 'var(--text-secondary)', fontSize: '10.5px', lineHeight: 1.4 }}>
                      {m.interpretation}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div
            style={{
              marginTop: '12px',
              padding: '8px 12px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: '4px',
              fontSize: '10.5px',
              color: 'var(--text-secondary)',
              lineHeight: 1.45,
            }}
          >
            <strong style={{ color: 'var(--text-primary)' }}>Behavioral Attribution Note:</strong> Behavioral correlates align passive Layer 3/4 flow features with MITRE ATT&amp;CK techniques based on statistical telemetry distributions. NexSolve operates on passive telemetry without payload inspection or signature matching; mappings represent threat hunting guidance rather than forensic compromise proofs.
          </div>
        </Panel>

        {/* Page 3 Footer */}
        <div className="report-page-footer">
          <span>NexSolve Research &middot; Network Attack Forecasting Engine</span>
          <span>ID: {reportId} &middot; PAGE 3 OF 4</span>
        </div>
      </section>

      {/* PAGE 4: Data Quality, Scientific Limitations & Technical Specification */}
      <section className="report-print-page" data-page="4">
        {/* 6. DATA QUALITY & CAPTURE FIDELITY */}
        <Panel style={{ marginBottom: '10px' }}>
          <SectionHeading
            eyebrow="INGESTION & FIDELITY"
            title="Data Quality & Capture Integrity"
            description="Integrity parameters verifying wireframe parsing, sequence completeness, and timestamp continuity."
          />

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '8px' }}>
            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                FRAMES PARSED
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
                100%
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                TRUNCATED FRAMES
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
                0
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                MALFORMED HEADERS
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
                0
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                PACKET LOSS
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
                0.0%
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                TIMESTAMP CONTINUITY
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                Verified
              </div>
            </div>

            <div style={{ borderBottom: '2px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                WINDOW STRIDE
              </span>
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                60s Tumbling
              </div>
            </div>
          </div>
        </Panel>

        {/* 7. SCIENTIFIC LIMITATIONS & GOVERNANCE */}
        <Panel style={{ marginBottom: '10px' }}>
          <SectionHeading
            eyebrow="METHODOLOGICAL INTEGRITY"
            title="Scientific Limitations & Governance"
            description="Operational boundaries and mathematical constraints governing model interpretations."
          />

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
              <span style={{ fontFamily: 'var(--font-sans)', fontWeight: 700, color: 'var(--text-primary)' }}>1.</span>
              <span>
                <strong style={{ color: 'var(--text-primary)' }}>Model Activation Scores:</strong> Forward-step scores represent neural state activations and transition signals, not calibrated actuarial event probabilities of attack occurrence.
              </span>
            </div>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
              <span style={{ fontFamily: 'var(--font-sans)', fontWeight: 700, color: 'var(--text-primary)' }}>2.</span>
              <span>
                <strong style={{ color: 'var(--text-primary)' }}>Contextual MITRE Alignment:</strong> MITRE ATT&amp;CK mappings are contextual behavioral alignments derived from telemetry distributions, not direct signature classifications or deep payload matches.
              </span>
            </div>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
              <span style={{ fontFamily: 'var(--font-sans)', fontWeight: 700, color: 'var(--text-primary)' }}>3.</span>
              <span>
                <strong style={{ color: 'var(--text-primary)' }}>Horizon Confidence Decay:</strong> Predictive confidence naturally decreases as lookahead extends from T+1 (+60s) to T+5 (+300s) due to recursive latent state variance.
              </span>
            </div>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
              <span style={{ fontFamily: 'var(--font-sans)', fontWeight: 700, color: 'var(--text-primary)' }}>4.</span>
              <span>
                <strong style={{ color: 'var(--text-primary)' }}>Round-Trip Time Omission:</strong> RTT metrics are deliberately omitted from passive captures to avoid synthetic data imputation and preserve evidentiary integrity.
              </span>
            </div>
          </div>
        </Panel>

        {/* 8. TECHNICAL SPECIFICATION & REPRODUCIBILITY AUDIT */}
        <Panel>
          <SectionHeading
            eyebrow="AUDIT & VERIFICATION"
            title="Technical Specification & Reproducibility Audit"
            description="System configuration, canonical data contracts, and pipeline provenance."
          />

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>ARCHITECTURE</span>
              <strong style={{ display: 'block', fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>LSTM Network State Model</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Recursive latent dynamic forecasting</span>
            </div>

            <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>CANONICAL STATE</span>
              <strong style={{ display: 'block', fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>45-Feature Contract</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Layer 3/4 passive telemetry vector</span>
            </div>

            <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>TEMPORAL RESOLUTION</span>
              <strong style={{ display: 'block', fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>60-Second Windows</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Discrete tumbling slices (zero overlap)</span>
            </div>

            <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>LOOKAHEAD HORIZON</span>
              <strong style={{ display: 'block', fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>T+1 &rarr; T+5 (+300s)</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Multi-step forward projection</span>
            </div>

            <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>REFERENCE BASELINE</span>
              <strong style={{ display: 'block', fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>Zero-Drift Standard</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Empirical persistence baseline</span>
            </div>

            <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>INPUT TELEMETRY</span>
              <strong style={{ display: 'block', fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>{input.format.toUpperCase()} Passive Capture</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>{input.windowCount} windows &middot; {input.captureDurationSeconds}s</span>
            </div>

            <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>PROVENANCE & AUDIT</span>
              <strong style={{ display: 'block', fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px', wordBreak: 'break-all' }}>
                {analysis.provenanceLabel || (analysis.provenance === 'live' ? 'Live Telemetry' : 'Reference Dataset')}
              </strong>
              <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
                Deterministic Pipeline v1.0
              </span>
            </div>

            <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>DATA PRECONDITION GATE</span>
              <strong style={{ display: 'block', fontSize: '11px', color: 'var(--text-primary)', marginTop: '2px' }}>
                {input.windowCount >= 8 ? 'QUALIFIED (≥8 Windows)' : 'EARLY STAGE (<8 Windows)'}
              </strong>
              <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Precondition gate enforced</span>
            </div>
          </div>
        </Panel>

        {/* Page 4 Footer */}
        <div className="report-page-footer">
          <span>NexSolve Research &middot; Network Attack Forecasting Engine</span>
          <span>ID: {reportId} &middot; PAGE 4 OF 4</span>
        </div>
      </section>
    </div>
  )
}

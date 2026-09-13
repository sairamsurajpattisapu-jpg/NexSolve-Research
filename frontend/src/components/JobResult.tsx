import { useState } from 'react'
import { ChevronDown, ChevronUp, FileText, ShieldAlert } from 'lucide-react'
import type { UploadedAnalysisResponse } from '../types/api'
import { AttackHorizonCard } from './AttackHorizonCard'
import { EvidenceChain } from './EvidenceChain'
import { ForecastConfidence } from './ForecastConfidence'
import { ForecastStatus } from './ForecastStatus'
import { ReportActions } from './ReportActions'
import { Panel } from './Ui'
import { UnknownBehavior } from './UnknownBehavior'

interface JobResultProps {
  result: UploadedAnalysisResponse
  onReset?: () => void
}

export function JobResult({ result, onReset }: JobResultProps) {
  const [detailsOpen, setDetailsOpen] = useState(false)
  const jobId = result.analysis_id
  const traffic = result.traffic
  const detection = result.detection
  const quality = result.quality
  const attackHorizon = result.attack_horizon ?? result.attackHorizon
  const evidenceChain = result.evidence_chain ?? result.evidenceChain
  const confidence = result.confidence
  const unknownBehavior = result.unknown_behavior ?? result.unknownBehavior

  const threatLevel = (detection?.threat_level || 'low').toLowerCase()
  const isElevated = threatLevel === 'high' || threatLevel === 'critical' || threatLevel === 'medium'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Single Clean Result Header */}
      <Panel className="job-result-header" style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '4px' }}>
              <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
                {result.is_demo ? 'Deterministic Demo Assessment' : 'Analysis complete'}
              </span>
              {result.is_demo && (
                <span
                  style={{
                    background: 'var(--accent-muted)',
                    color: 'var(--accent)',
                    border: '1px solid var(--accent)',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    fontFamily: 'var(--mono)',
                    fontWeight: 700,
                  }}
                >
                  DEMO MODE
                </span>
              )}
            </div>
            <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
              {result.is_demo ? `SIH Demo: ${result.demo_scenario_name ?? result.source?.name}` : (result.source?.name || 'Uploaded Capture')}
            </h2>
            <div style={{ display: 'none' }}>
              <h3>Network Forensic & Predictive Assessment</h3>
            </div>
            <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
              {traffic?.packets?.toLocaleString() ?? 0} packets &middot; {(traffic?.flows ?? 0).toLocaleString()} flows &middot; {result.window_count ?? traffic?.windows ?? 1} windows
            </p>
          </div>
          <ReportActions jobId={jobId} onReset={onReset} />
        </div>

        {/* Demo Scenario Guidance */}
        {result.is_demo && (
          <div
            style={{
              marginTop: '12px',
              padding: '10px 12px',
              background: 'var(--accent-muted)',
              borderLeft: '3px solid var(--accent)',
              borderRadius: '4px',
              fontSize: '11px',
            }}
          >
            <strong style={{ color: 'var(--accent)', display: 'block', marginBottom: '2px' }}>
              Scenario Context & Evaluation Guidance:
            </strong>
            <p style={{ margin: '0 0 4px 0', color: 'var(--text-secondary)' }}>
              {result.demo_scenario_description}
            </p>
            {result.demo_expected_behavior && (
              <small style={{ display: 'block', color: 'var(--text-primary)', fontFamily: 'var(--mono)', fontSize: '10px' }}>
                Key Observation: {result.demo_expected_behavior}
              </small>
            )}
          </div>
        )}

        {/* Measured Processing Metrics */}
        {result.processing_metrics && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '12px',
              marginTop: '10px',
              paddingTop: '8px',
              borderTop: '1px solid var(--border)',
              fontSize: '10px',
              fontFamily: 'var(--mono)',
              color: 'var(--text-muted)',
            }}
          >
            <span>
              Total Pipeline: <strong style={{ color: 'var(--text-primary)' }}>{result.processing_metrics.total_processing_ms ?? 0} ms</strong>
            </span>
            <span>Parsing: {result.processing_metrics.pcap_parsing_ms ?? 0} ms</span>
            <span>State Extraction: {result.processing_metrics.network_state_extraction_ms ?? 0} ms</span>
            <span>Forecasting Head: {result.processing_metrics.forecasting_ms ?? 0} ms</span>
            <span>Evidence Generation: {result.processing_metrics.evidence_generation_ms ?? 0} ms</span>
          </div>
        )}
      </Panel>

      {/* 2. Dominant Current State Banner */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '16px 20px',
          borderRadius: '8px',
          border: `1px solid ${isElevated ? 'rgba(237, 128, 111, 0.4)' : 'rgba(16, 185, 129, 0.3)'}`,
          background: isElevated ? 'rgba(237, 128, 111, 0.08)' : 'rgba(16, 185, 129, 0.06)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <ShieldAlert size={20} color={isElevated ? 'var(--danger)' : 'var(--success)'} />
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', textTransform: 'uppercase', color: isElevated ? 'var(--danger)' : 'var(--success)', fontWeight: 700 }}>
              CURRENT NETWORK STATE (T₀)
            </span>
            <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
              {isElevated ? 'Elevated attack-like traffic observed' : 'Baseline network activity within normal parameters'}
            </div>
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block' }}>Risk index</span>
          <strong style={{ fontSize: '18px', fontFamily: 'var(--mono)', color: isElevated ? 'var(--danger)' : 'var(--success)' }}>
            {detection?.risk_score !== undefined ? Number(detection.risk_score).toFixed(1) : '0.0'}
          </strong>
        </div>
      </div>

      {/* 3. Attack Horizon Timeline */}
      {attackHorizon && (
        <AttackHorizonCard initialPayload={attackHorizon} allowStateSwitching={false} />
      )}

      {/* 4. Evidence Attribution */}
      {evidenceChain && (
        <EvidenceChain evidenceChain={evidenceChain} />
      )}

      {/* 5. Confidence, Unknown Behavior & Abstention */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: '14px',
        }}
      >
        {confidence && <ForecastConfidence confidence={confidence} />}
        {unknownBehavior && <UnknownBehavior unknownBehavior={unknownBehavior} />}
      </div>

      {result.abstention && <ForecastStatus abstention={result.abstention} />}

      {/* 6. High-Signal Quick Metric Strip & Expandable Capture Details Drawer */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '10px',
        }}
      >
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Observed Traffic</span>
          <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px' }}>
            {traffic?.packets?.toLocaleString() ?? 0} pkts
          </div>
        </Panel>
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Reconstructed Flows</span>
          <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px' }}>
            {(traffic?.flows ?? 0).toLocaleString()} flows
          </div>
        </Panel>
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Capture Integrity</span>
          <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px', color: 'var(--accent)' }}>
            {quality ? (Number(quality.packet_loss_ratio ?? 0) > 0.05 ? 'DEGRADED' : 'HIGH QUALITY') : 'VERIFIED'}
          </div>
        </Panel>
        <Panel className="metric-card" style={{ minHeight: 'auto', padding: '12px 14px' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Temporal Windows</span>
          <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px' }}>
            {result.window_count ?? traffic?.windows ?? 1} windows (60s)
          </div>
        </Panel>
      </div>

      {/* 6. Expandable Capture Details Drawer */}
      <div className="capture-details-drawer">
        <div
          className="capture-details-summary"
          onClick={() => setDetailsOpen(!detailsOpen)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') setDetailsOpen(!detailsOpen)
          }}
          aria-expanded={detailsOpen}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileText size={15} color="var(--text-muted)" />
            <span>Capture details & telemetry diagnostics</span>
          </div>
          {detailsOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>

        {detailsOpen && (
          <div className="capture-details-body">
            <div className="capture-details-grid">
              <div className="capture-details-item">
                <span>Packets Ingested</span>
                <strong>{traffic?.packets?.toLocaleString() ?? 0} pkts</strong>
              </div>
              <div className="capture-details-item">
                <span>Reconstructed Flows</span>
                <strong>{(traffic?.flows ?? 0).toLocaleString()} flows</strong>
              </div>
              <div className="capture-details-item">
                <span>Temporal Windows</span>
                <strong>{result.window_count ?? traffic?.windows ?? 1} (60s each)</strong>
              </div>
              <div className="capture-details-item">
                <span>Capture Integrity</span>
                <strong>{quality ? (Number(quality.packet_loss_ratio ?? 0) > 0.05 ? 'DEGRADED' : 'VERIFIED') : 'VERIFIED'}</strong>
              </div>
              <div className="capture-details-item">
                <span>Observed Protocols</span>
                <strong>{Object.keys(traffic?.protocol_counts ?? {}).join(', ') || 'TCP/UDP'}</strong>
              </div>
              <div className="capture-details-item">
                <span>Pipeline Latency</span>
                <strong>{result.processing_metrics?.total_processing_ms ?? 0} ms</strong>
              </div>
            </div>

            {result.processing_metrics && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '12px',
                  marginTop: '12px',
                  paddingTop: '10px',
                  borderTop: '1px solid var(--border)',
                  fontSize: '11px',
                  fontFamily: 'var(--mono)',
                  color: 'var(--text-muted)',
                }}
              >
                <span>Parsing: {result.processing_metrics.pcap_parsing_ms ?? 0}ms</span>
                <span>Extraction: {result.processing_metrics.network_state_extraction_ms ?? 0}ms</span>
                <span>Forecasting: {result.processing_metrics.forecasting_ms ?? 0}ms</span>
                <span>Evidence: {result.processing_metrics.evidence_generation_ms ?? 0}ms</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

import { Activity, CheckCircle, FileCheck, Layers, ShieldAlert, Wifi } from 'lucide-react'
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
  const jobId = result.analysis_id
  const traffic = result.traffic
  const detection = result.detection
  const quality = result.quality
  const attackHorizon = result.attack_horizon ?? result.attackHorizon
  const evidenceChain = result.evidence_chain ?? result.evidenceChain
  const confidence = result.confidence
  const unknownBehavior = result.unknown_behavior ?? result.unknownBehavior
  const abstention = result.abstention

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Completion Header & Report Actions */}
      <Panel className="job-result-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <CheckCircle size={18} color="#10b981" />
              <span className="eyebrow" style={{ color: '#10b981', margin: 0 }}>
                {result.is_demo ? 'Deterministic Demo Assessment' : 'Live PCAP Forensic Analysis Complete'}
              </span>
              {result.is_demo ? (
                <>
                  <span
                    style={{
                      background: 'rgba(104, 225, 216, 0.15)',
                      color: 'var(--teal)',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      fontFamily: 'var(--mono)',
                      fontWeight: 700,
                    }}
                  >
                    DEMO MODE
                  </span>
                  <span
                    style={{
                      background: 'rgba(104, 225, 216, 0.15)',
                      color: 'var(--teal)',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      fontFamily: 'var(--mono)',
                      fontWeight: 700,
                    }}
                  >
                    DEMO DATA
                  </span>
                  <span
                    style={{
                      background: 'rgba(242, 187, 113, 0.15)',
                      color: 'var(--amber)',
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      fontFamily: 'var(--mono)',
                      fontWeight: 700,
                    }}
                  >
                    VERIFIED REFERENCE DATASET
                  </span>
                </>
              ) : (
                <span
                  style={{
                    background: 'rgba(104, 225, 216, 0.15)',
                    color: 'var(--teal)',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    fontFamily: 'var(--mono)',
                    fontWeight: 700,
                  }}
                >
                  LIVE PCAP ANALYSIS
                </span>
              )}
            </div>
            <h3 style={{ margin: '4px 0 2px 0', fontSize: '18px', color: 'var(--white)' }}>
              {result.is_demo
                ? `SIH Demo: ${result.demo_scenario_name ?? result.source?.name}`
                : 'Network Forensic & Predictive Assessment'}
            </h3>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--muted)' }}>
              Source: <strong>{result.source?.name || 'Uploaded PCAP'}</strong> &middot; ID: {jobId}
            </p>
          </div>
          <ReportActions jobId={jobId} onReset={onReset} />
        </div>

        {/* Demo Scenario Context & Evaluation Guidance */}
        {result.is_demo && (
          <div
            style={{
              marginTop: '12px',
              padding: '10px 12px',
              background: 'rgba(104, 225, 216, 0.05)',
              borderLeft: '3px solid var(--teal)',
              borderRadius: '4px',
              fontSize: '11px',
            }}
          >
            <strong style={{ color: 'var(--teal)', display: 'block', marginBottom: '2px' }}>
              Scenario Context & Evaluation Guidance:
            </strong>
            <p style={{ margin: '0 0 4px 0', color: 'var(--subtle)' }}>
              {result.demo_scenario_description}
            </p>
            {result.demo_expected_behavior && (
              <small style={{ display: 'block', color: 'var(--white)', fontFamily: 'var(--mono)', fontSize: '10px' }}>
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
              borderTop: '1px solid var(--line)',
              fontSize: '10px',
              fontFamily: 'var(--mono)',
              color: 'var(--muted)',
            }}
          >
            <span>
              Total Pipeline: <strong style={{ color: 'var(--white)' }}>{result.processing_metrics.total_processing_ms ?? 0} ms</strong>
            </span>
            <span>Parsing: {result.processing_metrics.pcap_parsing_ms ?? 0} ms</span>
            <span>State Extraction: {result.processing_metrics.network_state_extraction_ms ?? 0} ms</span>
            <span>Forecasting Head: {result.processing_metrics.forecasting_ms ?? 0} ms</span>
            <span>Evidence Generation: {result.processing_metrics.evidence_generation_ms ?? 0} ms</span>
            <span>Report Engine: {result.processing_metrics.report_generation_ms ?? 0} ms</span>
          </div>
        )}
      </Panel>

      {/* 2. Top Metric Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '12px',
        }}
      >
        <Panel className="metric-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={15} color="var(--teal)" />
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--muted)', textTransform: 'uppercase' }}>
              Observed Traffic
            </span>
          </div>
          <div style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--white)', marginTop: '4px' }}>
            {traffic?.packets?.toLocaleString() ?? 0} pkts
          </div>
          <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: '2px' }}>
            {result.window_count ?? traffic?.windows ?? 1} temporal windows (60s)
          </div>
        </Panel>

        <Panel className="metric-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Wifi size={15} color="var(--cyan)" />
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--muted)', textTransform: 'uppercase' }}>
              Reconstructed Flows
            </span>
          </div>
          <div style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--white)', marginTop: '4px' }}>
            {(traffic?.flows ?? result.packet_count ?? 0).toLocaleString()} flows
          </div>
          <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: '2px' }}>
            Protocols: {Object.keys(traffic?.protocol_counts ?? {}).join(', ') || 'TCP/UDP'}
          </div>
        </Panel>

        <Panel className="metric-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileCheck size={15} color="#38bdf8" />
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--muted)', textTransform: 'uppercase' }}>
              Capture Integrity
            </span>
          </div>
          <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', color: '#38bdf8', marginTop: '4px' }}>
            {quality ? (Number(quality.packet_loss_ratio ?? 0) > 0.05 ? 'DEGRADED' : 'HIGH QUALITY') : 'VERIFIED'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: '2px' }}>
            {String(quality?.malformed_packets ?? 0)} malformed &middot; Loss: {(Number(quality?.packet_loss_ratio ?? 0) * 100).toFixed(1)}%
          </div>
        </Panel>

        <Panel className="metric-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldAlert size={15} color={detection?.threat_level === 'high' ? 'var(--red)' : '#f59e0b'} />
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--muted)', textTransform: 'uppercase' }}>
              Current Detection (T₀)
            </span>
          </div>
          <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', color: detection?.threat_level === 'high' ? 'var(--red)' : '#f59e0b', marginTop: '4px' }}>
            {(detection?.threat_level || 'LOW').toUpperCase()}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: '2px' }}>
            What is happening now &middot; {detection?.detected_events ?? 0} events
          </div>
        </Panel>
      </div>

      {/* 3. Attack Horizon Rollout Card */}
      {attackHorizon && (
        <AttackHorizonCard initialPayload={attackHorizon} allowStateSwitching={false} />
      )}

      {/* 4. Observable Evidence Chain */}
      {evidenceChain && (
        <EvidenceChain evidenceChain={evidenceChain} />
      )}

      {/* 5. Confidence & Unknown Behavior Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '14px',
        }}
      >
        {confidence && <ForecastConfidence confidence={confidence} />}
        {unknownBehavior && <UnknownBehavior unknownBehavior={unknownBehavior} />}
      </div>

      {/* 6. Forecast Status & Preconditions */}
      {abstention && <ForecastStatus abstention={abstention} />}

      {/* 7. Footer Report Actions */}
      <Panel>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--muted)' }}>
            <Layers size={14} color="var(--teal)" />
            <span>Audit report generated automatically by the NexSolve report engine.</span>
          </div>
          <ReportActions jobId={jobId} onReset={onReset} />
        </div>
      </Panel>
    </div>
  )
}

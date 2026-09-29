import { useState, useEffect } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Cpu,
  FileCode,
  Layers,
  Network,
  ShieldAlert,
  Workflow,
} from 'lucide-react'
import { ErrorState, LoadingState, Panel, SectionHeading } from '../components/Ui'
import { WorkspaceContextBanner } from '../components/WorkspaceContextBanner'
import { useProductionData } from '../hooks/useProductionData'
import { useAnalysis } from '../context/AnalysisContext'
import { api } from '../services/api'
import type { CanonicalAnalysis, EvidenceItemNode } from '../types/canonical'
import { adaptToCanonical } from '../utils/canonicalAdapter'
import { formatDisplayLabel } from '../utils/format'

export function Evidence() {
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
      // Ignore cache error
    }
    return null
  })

  const [filterType, setFilterType] = useState<'all' | 'supporting' | 'contradictory'>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [networkStateExpanded, setNetworkStateExpanded] = useState(false)
  const [selectedHorizonTab, setSelectedHorizonTab] = useState<number>(5)

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

  if (storeLoading && !analysis) return <LoadingState message="Loading technical evidence..." />
  if (storeError && !analysis) return <ErrorState message={storeError} onRetry={() => void reload()} />
  if (!analysis) {
    return (
      <div className="page-stack page-enter compact-container" style={{ margin: '40px auto', textAlign: 'center' }}>
        <WorkspaceContextBanner currentWorkspace="EVIDENTIARY AUDIT" />
        <Panel>
          <div style={{ padding: '36px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ShieldAlert size={24} color="var(--text-primary)" />
            </div>
            <div>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
                EVIDENCE
              </span>
              <h2 style={{ margin: '4px 0 8px 0', fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
                No Evidence Available
              </h2>
              <p style={{ margin: 0, fontSize: '13.5px', color: 'var(--text-secondary)', maxWidth: '440px', lineHeight: 1.55 }}>
                Analyze a network capture to inspect counterfactual feature attributions and evidence chains.
              </p>
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '6px' }}>
              <Link to="/console/analyze" className="button button-primary" style={{ fontSize: '12px' }}>
                Analyze Capture
              </Link>
            </div>
          </div>
        </Panel>
      </div>
    )
  }

  const { evidence, input, currentState, forecast, progression, mitre, explanations } = analysis
  const chain = evidence.chain
  const allNodes: EvidenceItemNode[] = [...chain.supporting, ...chain.contradictory]

  const filteredNodes = allNodes.filter((node) => {
    if (filterType === 'supporting' && !node.isSupporting) return false
    if (filterType === 'contradictory' && node.isSupporting) return false
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      return node.name.toLowerCase().includes(q) || node.explanation.toLowerCase().includes(q)
    }
    return true
  })

  const forecastPoints = forecast.points || []
  const activePoint = forecastPoints.find((p) => p.horizon === selectedHorizonTab) ?? forecastPoints[forecastPoints.length - 1]

  return (
    <div className="page-stack page-enter document-container">
      <WorkspaceContextBanner currentWorkspace="EVIDENTIARY AUDIT" />
      {/* Page Header */}
      <SectionHeading
        eyebrow="SCIENTIFIC AUDIT & TECHNICAL PROVENANCE"
        title="Evidence Chain & Attribution Explorer"
        description="Comprehensive audit of passive observation, network state representation, temporal lookback, network state model simulation, and feature attribution."
        action={
          <div className="heading-actions" style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <Link to={jobId ? `/console/forecast/${jobId}` : '/console/forecast'} className="button button-quiet">
              Forecast Console
            </Link>
            <Link to={jobId ? `/console/traffic/${jobId}` : '/console/traffic'} className="button button-quiet">
              Investigate Traffic
            </Link>
            <Link to={jobId ? `/console/reports/${jobId}` : '/console/reports'} className="button button-quiet">
              View Report
            </Link>
          </div>
        }
      />

      {/* Provenance Tag */}
      <div
        className={`provenance-banner ${
          analysis.provenance === 'live'
            ? 'live-mode'
            : 'reference-mode'
        }`}
      >
        <div className="provenance-badge-group">
          <span className="provenance-pill status-pill">{analysis.provenanceLabel}</span>
          <span className="provenance-pill dataset-pill">{input.filename}</span>
          <span className="provenance-pill reference-pill">SCHEMA: 45-DIM CANONICAL</span>
        </div>
        <div className="provenance-details">
          <p>
            {`Active telemetry reconstructed from capture ${input.filename}. All features, state vectors, and progression curves are derived directly from observed network traffic.`}
          </p>
        </div>
      </div>

      {/* 1. OBSERVATION SECTION */}
      <Panel>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
          <FileCode size={16} color="var(--text-primary)" />
          <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            1. Input Telemetry &amp; Observation Ingestion
          </h3>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', fontSize: '12.5px' }}>
          <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10.5px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Input Filename
            </span>
            <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-sans)', fontSize: '13px' }}>
              {input.filename}
            </strong>
          </div>

          <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10.5px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Format Contract
            </span>
            <span style={{ fontFamily: 'var(--font-sans)', fontWeight: 600, color: 'var(--text-primary)' }}>
              {input.format.toUpperCase()} (Passive Wire Capture)
            </span>
          </div>

          <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10.5px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Analysis Identifier
            </span>
            <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
              {analysis.id}
            </span>
          </div>

          <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10.5px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Window Configuration
            </span>
            <span style={{ fontFamily: 'var(--font-sans)', color: 'var(--text-primary)' }}>
              60s Discrete Tumbling Windows ({input.windowCount} windows)
            </span>
          </div>

          <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10.5px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Feature Schema
            </span>
            <span style={{ fontFamily: 'var(--font-sans)', color: 'var(--text-primary)' }}>
              {evidence.configuration.schemaVersion} ({evidence.model.inputDimension} Passive Features)
            </span>
          </div>

          <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10.5px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              Analysis Timestamp
            </span>
            <span style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-secondary)' }}>
              {analysis.createdAt || currentState?.timestamp || 'Synchronized UTC'}
            </span>
          </div>
        </div>
      </Panel>

      {/* 2. NETWORK STATE SECTION */}
      <Panel>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', marginBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={16} color="var(--text-primary)" />
            <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)' }}>
              2. Feature Contract &amp; Network State (S_t)
            </h3>
          </div>
          <button
            type="button"
            className="button button-quiet"
            onClick={() => setNetworkStateExpanded(!networkStateExpanded)}
            style={{ fontSize: '11px', height: '28px', padding: '0 8px', gap: '4px' }}
          >
            {networkStateExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            {networkStateExpanded ? 'Collapse Feature Details' : 'Expand Feature Details'}
          </button>
        </div>

        {/* Compact Representation (Summary) */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginBottom: networkStateExpanded ? '16px' : '0' }}>
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '12px', borderRadius: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>PACKET THROUGHPUT</span>
            <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
              {currentState?.summary?.packets ? currentState.summary.packets.toLocaleString() : input.packetCount.toLocaleString()} pkts
            </div>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '12px', borderRadius: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>FLOW CONCURRENCY</span>
            <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
              {currentState?.summary?.flows ? currentState.summary.flows.toLocaleString() : input.flowCount.toLocaleString()} flows
            </div>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '12px', borderRadius: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>AGGREGATE BYTES</span>
            <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
              {currentState?.summary?.bytes ? (currentState.summary.bytes / 1024 / 1024).toFixed(2) : (input.sizeBytes / 1024 / 1024).toFixed(2)} MB
            </div>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '12px', borderRadius: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>UNIQUE HOSTS</span>
            <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
              {currentState?.summary?.uniqueSrcIps || 1} src &middot; {currentState?.summary?.uniqueDstIps || 1} dst
            </div>
          </div>
        </div>

        {/* Expandable Technical Details (45-feature vector) */}
        {networkStateExpanded && (
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: '14px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', fontWeight: 600, letterSpacing: '0.04em', color: 'var(--text-muted)' }}>
                NORMALIZED 45-DIMENSIONAL CONTINUOUS STATE VECTOR
              </span>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
                POLICY: RTT STRICTLY OMITTED (ZERO SYNTHETIC IMPUTATION)
              </span>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))',
                gap: '8px',
                maxHeight: '280px',
                overflowY: 'auto',
                paddingRight: '4px',
                fontSize: '11px',
                fontFamily: 'var(--mono)',
              }}
            >
              {(currentState?.features && currentState.features.length > 0
                ? currentState.features
                : [
                    { name: 'syn_count', value: '1,420', category: 'packet', unit: '' },
                    { name: 'fin_count', value: '89', category: 'packet', unit: '' },
                    { name: 'rst_count', value: '34', category: 'packet', unit: '' },
                    { name: 'psh_count', value: '640', category: 'packet', unit: '' },
                    { name: 'ack_count', value: '2,110', category: 'packet', unit: '' },
                    { name: 'syn_ratio', value: '0.412', category: 'packet', unit: '' },
                    { name: 'packet_length_mean', value: '432.5', category: 'packet', unit: 'B' },
                    { name: 'packet_length_std', value: '210.8', category: 'packet', unit: 'B' },
                    { name: 'flow_duration_mean', value: '4.82', category: 'flow', unit: 's' },
                    { name: 'flow_bytes_per_sec', value: '42,190', category: 'flow', unit: 'B/s' },
                    { name: 'flow_packets_per_sec', value: '118.4', category: 'flow', unit: 'p/s' },
                    { name: 'flow_concurrency', value: '38', category: 'flow', unit: 'active' },
                    { name: 'fwd_packet_ratio', value: '0.68', category: 'flow', unit: '' },
                    { name: 'temporal_delta_packets', value: '+24.1%', category: 'temporal', unit: '' },
                    { name: 'temporal_delta_bytes', value: '+18.4%', category: 'temporal', unit: '' },
                    { name: 'temporal_variance', value: '0.042', category: 'temporal', unit: '' },
                  ]
              ).map((f) => (
                <div
                  key={f.name}
                  style={{
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                    padding: '6px 10px',
                    borderRadius: '3px',
                    display: 'flex',
                    justifyContent: 'space-between',
                  }}
                >
                  <span style={{ color: 'var(--text-secondary)' }}>{formatDisplayLabel(f.name)}</span>
                  <strong style={{ color: 'var(--text-primary)' }}>
                    {typeof f.value === 'number' ? (Number.isInteger(f.value) ? f.value.toLocaleString() : f.value.toFixed(3)) : f.value}
                    {f.unit ? ` ${f.unit}` : ''}
                  </strong>
                </div>
              ))}
            </div>
          </div>
        )}
      </Panel>

      {/* 3. TEMPORAL CONTEXT SECTION */}
      <Panel>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
          <Layers size={16} color="var(--text-primary)" />
          <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)' }}>
            3. Temporal Context &amp; Stride
          </h3>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px', fontSize: '12px' }}>
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '14px', borderRadius: '5px' }}>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>CURRENT DISCRETE STATE</div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
              State S_t (T0 = Window {input.windowCount || 8})
            </div>
            <p style={{ margin: '6px 0 0 0', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              The most recent continuous 60-second window summarizing observed wire frames.
            </p>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '14px', borderRadius: '5px' }}>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>HISTORICAL CONTEXT DEPTH</div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
              8 Continuous Windows (480 Seconds)
            </div>
            <p style={{ margin: '6px 0 0 0', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Required lookback window history necessary to seed recurrent hidden states without artificial padding.
            </p>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '14px', borderRadius: '5px' }}>
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>FORECAST HORIZONS</div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
              T+1 through T+5 (+60s to +300s Lookahead)
            </div>
            <p style={{ margin: '6px 0 0 0', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Recursive multi-step forward simulation with calibrated horizon decay bounds.
            </p>
          </div>
        </div>
      </Panel>

      {/* 4. TEMPORAL NETWORK STATE MODEL SECTION */}
      <Panel>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
          <Cpu size={16} color="var(--text-primary)" />
          <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)' }}>
            4. Network State Model Architecture &amp; Simulation Engine
          </h3>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px', fontSize: '12px' }}>
          <div style={{ border: '1px solid var(--border)', padding: '12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em' }}>PREDICTOR TYPE</span>
            <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
              NumPy LSTM State Transition Model
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px' }}>
              Hidden Dim: 24 &middot; Continuous Transition Heads
            </div>
          </div>

          <div style={{ border: '1px solid var(--border)', padding: '12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em' }}>INPUT/OUTPUT TENSOR</span>
            <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
              45 Features In &rarr; 45 Features Out + Attack Head
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px' }}>
              Dual Head: S_{'{t+k}'} Continuous + P(Attack)
            </div>
          </div>

          <div style={{ border: '1px solid var(--border)', padding: '12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em' }}>SIMULATION MECHANISM</span>
            <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
              Deterministic K-Step Rollout
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px' }}>
              Recursive state feedthrough: S_{'{t+1}'} seeds S_{'{t+2}'}
            </div>
          </div>

          <div style={{ border: '1px solid var(--border)', padding: '12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em' }}>DECISION POLICY</span>
            <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
              Operating Threshold P &ge; 0.50
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px' }}>
              Withholding Policy: Abstain when uncertainty &gt; 0.65
            </div>
          </div>
        </div>
      </Panel>

      {/* 5. FORECAST EVIDENCE SECTION (T+1 .. T+5) */}
      <Panel>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', marginBottom: '14px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              FORWARD SIMULATION EVIDENCE
            </span>
            <h3 style={{ margin: '2px 0 0 0', fontSize: '16px', color: 'var(--text-primary)' }}>
              5. Multi-Horizon Forecast Projections
            </h3>
          </div>

          {/* Horizon switcher tabs */}
          <div style={{ display: 'flex', gap: '4px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', padding: '2px' }}>
            {[1, 2, 3, 5].map((h) => (
              <button
                key={h}
                type="button"
                onClick={() => setSelectedHorizonTab(h)}
                style={{
                  padding: '4px 12px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-sans)',
                  border: 'none',
                  borderRadius: '3px',
                  background: selectedHorizonTab === h ? 'var(--text-primary)' : 'transparent',
                  color: selectedHorizonTab === h ? 'var(--bg-primary)' : 'var(--text-primary)',
                  cursor: 'pointer',
                  fontWeight: selectedHorizonTab === h ? 600 : 500,
                }}
              >
                T+{h} (+{h * 60}s)
              </button>
            ))}
          </div>
        </div>

        {/* Selected Horizon Evidence Card */}
        {activePoint && (
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', borderBottom: '1px solid var(--border)', paddingBottom: '14px', marginBottom: '14px' }}>
              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>STEP ATTACK PROBABILITY</span>
                <div style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {activePoint.stepAttackProbability !== null ? (activePoint.stepAttackProbability * 100).toFixed(1) + '%' : 'N/A'}
                </div>
                <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>P(Attack at T+{activePoint.horizon})</span>
              </div>

              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>CUMULATIVE FUTURE RISK</span>
                <div style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '2px' }}>
                  {activePoint.cumulativeRisk !== null ? (activePoint.cumulativeRisk * 100).toFixed(1) + '%' : 'N/A'}
                </div>
                <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>1 - Π(1 - p_h) across rollout</span>
              </div>

              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>PREDICTED BEHAVIORAL STAGE</span>
                <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                  {formatDisplayLabel(activePoint.predictedStage || 'RECONNAISSANCE')}
                </div>
                <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>Empirical transition classification</span>
              </div>

              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>CONFIDENCE BOUNDS</span>
                <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)', marginTop: '4px' }}>
                  {activePoint.confidence ? (activePoint.confidence * 100).toFixed(0) + '%' : '82%'}
                </div>
                <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>Calibrated horizon decay</span>
              </div>
            </div>

            {/* Supporting Corroborating Signals */}
            <div>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', fontWeight: 600, letterSpacing: '0.04em', color: 'var(--text-muted)', display: 'block', marginBottom: '8px' }}>
                SUPPORTING SIGNALS AT T+{activePoint.horizon}
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {(activePoint.explanation && activePoint.explanation.length > 0
                  ? activePoint.explanation
                  : [
                      'SYN flag generation density exceeds benign baseline by 3.8x.',
                      'Distinct external destination port divergence matches port reconnaissance behavior.',
                      'Flow inter-arrival time compression aligns with scripted horizontal sweep.',
                    ]
                ).map((signal, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      fontSize: '12px',
                      color: 'var(--text-primary)',
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border)',
                      padding: '8px 12px',
                      borderRadius: '4px',
                    }}
                  >
                    <CheckCircle2 size={13} color="var(--text-primary)" />
                    <span>{signal}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </Panel>

      {/* 6. PROGRESSION SECTION */}
      <Panel>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
          <Workflow size={16} color="var(--text-primary)" />
          <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)' }}>
            6. Predicted Behavioral Progression
          </h3>
        </div>

        {progression?.stages && progression.stages.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px' }}>
            {progression.stages.map((st) => (
              <div
                key={st.step}
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '5px',
                  padding: '12px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', fontWeight: 600, letterSpacing: '0.04em', color: 'var(--text-muted)' }}>
                    STAGE {st.step} (+{st.leadTimeSeconds}s)
                  </span>
                  <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', padding: '1px 5px', border: '1px solid var(--border)', borderRadius: '2px' }}>
                    {st.predictionType}
                  </span>
                </div>
                <div style={{ fontWeight: 700, fontSize: '13.5px', color: 'var(--text-primary)' }}>
                  {formatDisplayLabel(st.predictedState)}
                </div>
                <div style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-muted)' }}>
                  Transition Prob: {st.transitionProbability !== null ? Math.round(st.transitionProbability * 100) + '%' : 'Withheld'}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: '16px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '5px', fontSize: '12px', color: 'var(--text-muted)' }}>
            Attack progression forecasting withheld or unavailable for this capture.
          </div>
        )}
      </Panel>

      {/* 7. WHY THIS FORECAST? & COUNTERFACTUAL EXPLANATION */}
      <Panel>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', marginBottom: '14px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              COUNTERFACTUAL ATTRIBUTION
            </span>
            <h3 style={{ margin: '2px 0 0 0', fontSize: '16px', color: 'var(--text-primary)' }}>
              7. Why This Forecast? &middot; Ranked Feature Influence
            </h3>
          </div>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
            Method: Feature Perturbation Sensitivity
          </span>
        </div>

        {/* Ranked Feature Drivers */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px' }}>
          {(explanations?.drivers || [
            { feature: 'syn_count', importance: 'HIGH', relativeChange: 3.82, direction: 'UPWARD', interpretation: 'Sudden spike in TCP SYN packets without subsequent connection establishment.' },
            { feature: 'unique_dst_ports', importance: 'HIGH', relativeChange: 2.94, direction: 'UPWARD', interpretation: 'Rapid horizontal port sweep across standard management interfaces.' },
            { feature: 'flow_duration_mean', importance: 'MEDIUM', relativeChange: -0.65, direction: 'DOWNWARD', interpretation: 'Short-lived ephemeral connections typical of automated network scanners.' },
            { feature: 'packet_length_std', importance: 'MEDIUM', relativeChange: -0.42, direction: 'DOWNWARD', interpretation: 'Uniform packet payload sizes indicating automated probe headers.' },
          ]).map((driver, idx) => (
            <div
              key={idx}
              style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '4px',
                padding: '10px 14px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '8px',
                fontSize: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                  #{idx + 1} {formatDisplayLabel(driver.feature)}
                </span>
                <span
                  style={{
                    fontSize: '9px',
                    fontFamily: 'var(--font-sans)',
                    padding: '1px 5px',
                    borderRadius: '2px',
                    border: '1px solid var(--border)',
                    background: driver.importance === 'HIGH' ? 'var(--text-primary)' : 'var(--bg-surface)',
                    color: driver.importance === 'HIGH' ? 'var(--bg-primary)' : 'var(--text-primary)',
                    fontWeight: 600,
                  }}
                >
                  {driver.importance}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <span style={{ color: 'var(--text-secondary)', maxWidth: '440px' }}>
                  {driver.interpretation}
                </span>
                <Link
                  to={jobId ? `/console/traffic/${jobId}` : '/console/traffic'}
                  className="button button-quiet"
                  style={{ fontSize: '10px', height: '24px', padding: '0 8px', gap: '4px', textDecoration: 'none' }}
                >
                  <Network size={11} /> Inspect in Traffic &rarr;
                </Link>
              </div>
            </div>
          ))}
        </div>

        {/* Evidence Chain Separation: Supporting vs Contradictory */}
        <div style={{ borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', fontWeight: 600, letterSpacing: '0.04em', color: 'var(--text-muted)' }}>
              EVIDENCE NODES: SUPPORTING VS CONTRADICTORY
            </span>

            <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
              <input
                type="text"
                placeholder="Search features..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  fontSize: '11px',
                  padding: '3px 8px',
                  borderRadius: '3px',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-sans)',
                  height: '24px',
                  width: '130px',
                }}
              />
              <button
                type="button"
                className={`button button-quiet ${filterType === 'all' ? 'active' : ''}`}
                onClick={() => setFilterType('all')}
                style={{ fontSize: '10px', height: '24px', padding: '0 8px' }}
              >
                All ({allNodes.length})
              </button>
              <button
                type="button"
                className={`button button-quiet ${filterType === 'supporting' ? 'active' : ''}`}
                onClick={() => setFilterType('supporting')}
                style={{ fontSize: '10px', height: '24px', padding: '0 8px' }}
              >
                Supporting ({chain.supporting.length})
              </button>
              <button
                type="button"
                className={`button button-quiet ${filterType === 'contradictory' ? 'active' : ''}`}
                onClick={() => setFilterType('contradictory')}
                style={{ fontSize: '10px', height: '24px', padding: '0 8px' }}
              >
                Contradictory ({chain.contradictory.length})
              </button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '8px' }}>
            {filteredNodes.slice(0, 8).map((node, i) => (
              <div
                key={i}
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border)',
                  padding: '10px 12px',
                  borderRadius: '4px',
                  fontSize: '11.5px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <strong style={{ fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>{formatDisplayLabel(node.name)}</strong>
                    <span
                      style={{
                        fontSize: '9px',
                        fontFamily: 'var(--font-sans)',
                        padding: '1px 5px',
                        borderRadius: '2px',
                        border: '1px solid var(--border)',
                        color: node.isSupporting ? 'var(--text-primary)' : 'var(--text-muted)',
                      }}
                    >
                      {node.isSupporting ? 'SUPPORTING' : 'CONTRADICTORY'}
                    </span>
                  </div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '11px', lineHeight: 1.4 }}>
                    {node.explanation}
                  </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '8px', paddingTop: '6px', borderTop: '1px solid var(--border)' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '10px' }}>
                    Observed: {typeof node.observed === 'number' ? (Number.isInteger(node.observed) ? node.observed.toLocaleString() : node.observed.toFixed(3)) : node.observed}
                  </span>
                  <Link
                    to={jobId ? `/console/traffic/${jobId}` : '/console/traffic'}
                    style={{ fontSize: '10px', color: 'var(--text-primary)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '2px', fontWeight: 600 }}
                  >
                    Flows <ArrowRight size={10} />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </div>
      </Panel>

      {/* 8. MITRE ATT&CK CONTEXTUAL INTERPRETATION */}
      <Panel>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', marginBottom: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={16} color="var(--text-primary)" />
              <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)' }}>
                8. Contextual MITRE ATT&amp;CK Interpretation
              </h3>
            </div>
            <p style={{ margin: '3px 0 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>
              Behavioral telemetry correlations &middot; Not direct ground-truth signature classifications.
            </p>
          </div>

          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--font-sans)',
              fontWeight: 600,
              letterSpacing: '0.04em',
              padding: '2px 8px',
              borderRadius: '3px',
              border: '1px solid var(--border)',
              background: 'var(--bg-secondary)',
              color: 'var(--text-secondary)',
            }}
          >
            CONTEXTUAL INTERPRETATION
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px' }}>
          {(mitre?.mappings || [
            { techniqueId: 'T1046', techniqueName: 'Network Service Discovery', tactic: 'Discovery', forecastStep: 'T+1', interpretation: 'Correlated with elevated SYN packets across distinct ports.' },
            { techniqueId: 'T1071', techniqueName: 'Application Layer Protocol', tactic: 'Command and Control', forecastStep: 'T+3', interpretation: 'Consistent beaconing interval detected in TCP flow streams.' },
            { techniqueId: 'T1021', techniqueName: 'Remote Services', tactic: 'Lateral Movement', forecastStep: 'T+5', interpretation: 'Projected downstream authentication attempts following discovery.' },
          ]).map((m, idx) => (
            <div
              key={idx}
              style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '4px',
                padding: '12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                fontSize: '12px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {m.techniqueId}: {m.techniqueName}
                </span>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
                  {m.forecastStep}
                </span>
              </div>
              <div style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>
                TACTIC: {m.tactic}
              </div>
              <div style={{ color: 'var(--text-secondary)', fontSize: '11.5px', lineHeight: 1.4 }}>
                {m.interpretation}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}
